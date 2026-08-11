use std::{fs, path::Path, sync::OnceLock};

use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

use crate::{
    RULE_PACK_VERSION,
    config::Config,
    db,
    error::{AppError, Result},
    ingest::{self, stable_id},
    models::{
        Application, EspResource, EvidenceLink, ExecutionAttempt, Finding, ManagedEntity,
        ProvisioningStep, Session,
    },
    parsers,
};

#[derive(Serialize)]
struct Progress<'a> {
    phase: &'a str,
    percent: u8,
    stage: &'a str,
}

pub fn run_worker(config: &Config, job_dir: &Path) -> Result<()> {
    let upload = job_dir.join("upload.bin");
    let source_name =
        fs::read_to_string(job_dir.join("source.name")).map_err(|_| AppError::BadRequest)?;
    let source_name = source_name.trim();
    let upload_sha = hash_file(&upload)?;
    let partial_db = job_dir.join("analysis.partial.sqlite");
    let final_db = job_dir.join(db::DB_FILE);
    let _ = fs::remove_file(&partial_db);
    let _ = fs::remove_file(&final_db);
    let _ = fs::remove_dir_all(job_dir.join("objects"));
    progress(job_dir, "extracting", 20, "Validating archive")?;

    let mut conn = db::open(&partial_db)?;
    db::initialize(&conn)?;
    let report = {
        let tx = conn.transaction()?;
        let report =
            ingest::ingest_upload(config, &tx, job_dir, &upload, source_name, &upload_sha)?;
        tx.commit()?;
        report
    };
    progress(job_dir, "parsing", 50, "Parsing diagnostic sources")?;
    {
        let tx = conn.transaction()?;
        parsers::parse_all(&tx, &report.artifacts, config)?;
        tx.commit()?;
    }
    progress(job_dir, "correlating", 82, "Correlating evidence")?;
    {
        let tx = conn.transaction()?;
        correlate(&tx)?;
        tx.commit()?;
    }
    conn.execute("PRAGMA optimize", [])?;
    drop(conn);
    fs::rename(&partial_db, &final_db)?;
    progress(job_dir, "ready", 100, "Analysis ready")?;
    Ok(())
}

fn correlate(conn: &Connection) -> Result<()> {
    build_sessions(conn)?;
    build_device_snapshot(conn)?;
    build_applications_and_attempts(conn)?;
    build_esp(conn)?;
    evaluate_msi_transactions(conn)?;
    evaluate_unmapped_exits(conn)?;
    evaluate_identity_context(conn)?;
    evaluate_ime_and_enrollment(conn)?;
    evaluate_time_integrity(conn)?;
    Ok(())
}

fn build_sessions(conn: &Connection) -> Result<()> {
    #[derive(Clone)]
    struct Boundary {
        timestamp: String,
        evidence: String,
    }
    let mut stmt = conn.prepare(
        "SELECT e.timestamp_utc,COALESCE((SELECT id FROM evidence_links x WHERE x.event_id=e.id LIMIT 1),'') FROM events e WHERE e.timestamp_utc IS NOT NULL AND ((lower(COALESCE(e.provider,''))='user32' AND e.event_code='1074') OR lower(e.message) LIKE '%reboot%' OR lower(e.message) LIKE '%restart initiated%') ORDER BY e.timestamp_utc,e.sequence"
    )?;
    let boundaries: Vec<Boundary> = stmt
        .query_map([], |r| {
            Ok(Boundary {
                timestamp: r.get(0)?,
                evidence: r.get(1)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    let range: (Option<String>, Option<String>) = conn.query_row(
        "SELECT MIN(timestamp_utc),MAX(timestamp_utc) FROM events WHERE timestamp_utc IS NOT NULL",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let range = range.0.zip(range.1);
    let Some((min_time, max_time)) = range else {
        let id = stable_id("session", "undated");
        db::insert_session(
            conn,
            &Session {
                id,
                kind: "undated".into(),
                current: true,
                started_at: None,
                ended_at: None,
                label: "Current undated evidence".into(),
                evidence_ids: Vec::new(),
            },
        )?;
        conn.execute(
            "UPDATE events SET current=1, session_id=?1",
            [stable_id("session", "undated")],
        )?;
        return Ok(());
    };
    let mut starts = vec![(min_time.clone(), None::<String>)];
    for boundary in &boundaries {
        starts.push((boundary.timestamp.clone(), Some(boundary.evidence.clone())));
    }
    starts.sort();
    starts.dedup_by(|a, b| a.0 == b.0);
    for index in 0..starts.len() {
        let start = &starts[index].0;
        let end = starts
            .get(index + 1)
            .map(|v| v.0.clone())
            .or_else(|| Some(max_time.clone()));
        let current = index + 1 == starts.len();
        let id = stable_id(
            "session",
            &format!("{start}:{}", end.as_deref().unwrap_or("")),
        );
        db::insert_session(
            conn,
            &Session {
                id: id.clone(),
                kind: if index == 0 {
                    "historical"
                } else {
                    "reboot-bounded"
                }
                .into(),
                current,
                started_at: Some(start.clone()),
                ended_at: end.clone(),
                label: if current {
                    "Latest relevant session".into()
                } else {
                    format!("Historical session {}", index + 1)
                },
                evidence_ids: starts[index]
                    .1
                    .clone()
                    .into_iter()
                    .filter(|s| !s.is_empty())
                    .collect(),
            },
        )?;
        if current {
            conn.execute(
                "UPDATE events SET current=1,session_id=?1 WHERE timestamp_utc>=?2",
                params![id, start],
            )?;
        } else if let Some(end) = end {
            conn.execute(
                "UPDATE events SET session_id=?1 WHERE timestamp_utc>=?2 AND timestamp_utc<?3",
                params![id, start, end],
            )?;
        }
    }
    conn.execute("UPDATE events SET current=1,session_id=(SELECT id FROM sessions WHERE current=1 LIMIT 1) WHERE timestamp_utc IS NULL",[])?;
    Ok(())
}

fn build_device_snapshot(conn: &Connection) -> Result<()> {
    static GUID: OnceLock<Regex> = OnceLock::new();
    let guid = GUID.get_or_init(|| {
        Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
            .expect("static regex")
    });
    let mut stmt=conn.prepare("SELECT id,message FROM events WHERE lower(message) LIKE '%deviceid%' OR lower(message) LIKE '%azureadjoined%' OR lower(message) LIKE '%deviceauthstatus%' OR lower(message) LIKE '%azureadprt%' ORDER BY current DESC,sequence DESC LIMIT 500")?;
    let rows: Vec<(String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let identity = rows
        .iter()
        .find_map(|(_, m)| guid.find(m).map(|v| stable_id("device", v.as_str())));
    let join_state = state_value(&rows, "azureadjoined");
    let auth = state_value(&rows, "deviceauthstatus");
    let prt = state_value(&rows, "azureadprt");
    let context = if rows.iter().any(|(_, m)| m.contains('$')) {
        "machine"
    } else {
        "unknown"
    };
    let evidence_ids = rows
        .iter()
        .filter_map(|(id, _)| evidence_for_event(conn, id).ok().flatten().map(|e| e.id))
        .collect::<Vec<_>>();
    conn.execute("INSERT OR REPLACE INTO device_snapshots(id,captured_at,device_identity_hash,join_state,device_auth_state,user_prt_state,context,evidence_ids) VALUES (?1,(SELECT MAX(timestamp_utc) FROM events),?2,?3,?4,?5,?6,?7)",params![stable_id("snapshot","current"),identity,join_state,auth,prt,context,serde_json::to_string(&evidence_ids).unwrap_or_else(|_|"[]".into())])?;
    Ok(())
}

fn build_applications_and_attempts(conn: &Connection) -> Result<()> {
    static GUID: OnceLock<Regex> = OnceLock::new();
    static EXIT: OnceLock<Regex> = OnceLock::new();
    let guid = GUID.get_or_init(|| {
        Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
            .expect("static regex")
    });
    let exit = EXIT.get_or_init(|| {
        Regex::new(r"(?i)(?:exit(?:ed)?(?:\s+with)?(?:\s+code)?|return\s+code)\D{0,12}(-?\d{1,10})")
            .expect("static regex")
    });
    let mut stmt=conn.prepare("SELECT id,timestamp_utc,message,current FROM events WHERE lower(message) LIKE '%app%' OR lower(message) LIKE '%msi%' OR lower(message) LIKE '%installer%' OR lower(message) LIKE '%exit code%' ORDER BY sequence")?;
    let rows: Vec<(String, Option<String>, String, bool)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut tracked_apps = std::collections::HashSet::new();
    let mut generic_tracked = false;
    let mut tracked_stmt=conn.prepare("SELECT e.message FROM events e JOIN artifacts a ON a.id=e.artifact_id WHERE lower(a.normalized_path) LIKE '%esptracking%' OR lower(a.normalized_path) LIKE '%enrollmentstatustracking%'")?;
    let tracked_messages = tracked_stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for message in tracked_messages {
        let mut matched = false;
        for value in guid.find_iter(&message) {
            tracked_apps.insert(stable_id("app", &value.as_str().to_ascii_lowercase()));
            matched = true;
        }
        generic_tracked |= !matched && message.to_ascii_lowercase().contains("app");
    }
    let mut apps = std::collections::BTreeMap::<
        String,
        (String, Vec<String>, u64, bool, Option<(String, bool)>),
    >::new();
    for (event_id, timestamp, message, current) in &rows {
        let key = guid
            .find(message)
            .map(|m| m.as_str().to_ascii_lowercase())
            .unwrap_or_else(|| "generic-win32".into());
        let app_id = stable_id("app", &key);
        let evidence = evidence_for_event(conn, event_id)?
            .map(|e| e.id)
            .unwrap_or_default();
        let item = apps
            .entry(app_id.clone())
            .or_insert((key.clone(), Vec::new(), 0, false, None));
        if !evidence.is_empty() {
            item.1.push(evidence.clone());
        }
        item.3 |= *current;
        if let Some(caps) = exit.captures(message) {
            let code = caps.get(1).and_then(|m| m.as_str().parse::<i64>().ok());
            item.2 += 1;
            let state = match code {
                Some(0 | 3010 | 1641) => "succeeded",
                Some(_) => "failed",
                None => "unknown",
            };
            item.4 = Some((state.into(), *current));
            let attempt_id = stable_id("attempt", &format!("{app_id}:{event_id}"));
            db::insert_attempt(
                conn,
                &ExecutionAttempt {
                    id: attempt_id,
                    application_id: Some(app_id.clone()),
                    started_at: timestamp.clone(),
                    ended_at: timestamp.clone(),
                    exit_code: code,
                    detection_result: None,
                    reboot_during_attempt: false,
                    state: state.into(),
                    evidence_ids: if evidence.is_empty() {
                        Vec::new()
                    } else {
                        vec![evidence]
                    },
                },
            )?;
        }
    }
    for (id, (name, evidence, attempt_count, observed_current, latest)) in apps {
        let (state, current) = latest.unwrap_or_else(|| ("observed".into(), observed_current));
        let tracked = tracked_apps.contains(&id) || (name == "generic-win32" && generic_tracked);
        db::insert_application(
            conn,
            &Application {
                id: id.clone(),
                name: name.clone(),
                app_type: if name == "generic-win32" {
                    "Win32"
                } else {
                    "Managed"
                }
                .into(),
                intent: None,
                install_context: None,
                state: state.clone(),
                esp_tracked: tracked,
                attempt_count,
                evidence_ids: evidence.clone(),
            },
        )?;
        db::insert_entity(
            conn,
            &ManagedEntity {
                id,
                entity_type: "application".into(),
                name,
                state,
                current,
                evidence_ids: evidence,
            },
        )?;
    }
    Ok(())
}

#[allow(clippy::type_complexity)]
fn build_esp(conn: &Connection) -> Result<()> {
    let mut stmt=conn.prepare("SELECT e.id,e.entity_id,e.timestamp_utc,e.message,e.current,a.normalized_path FROM events e JOIN artifacts a ON a.id=e.artifact_id WHERE lower(a.normalized_path) LIKE '%esptracking%' OR lower(a.normalized_path) LIKE '%enrollmentstatustracking%' OR lower(e.message) LIKE '%esp %' ORDER BY e.timestamp_utc,e.sequence")?;
    let rows: Vec<(String, Option<String>, Option<String>, String, bool, String)> = stmt
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut first_failure = true;
    for (index, (event_id, entity_id, time, message, current, path)) in rows.into_iter().enumerate()
    {
        let lower = message.to_ascii_lowercase();
        let failed = lower.contains("fail") || lower.contains("error") || lower.contains("timeout");
        let tracked = path.to_ascii_lowercase().contains("tracking")
            && (lower.contains("app")
                || lower.contains("policy")
                || lower.contains("certificate")
                || lower.contains("profile"));
        let evidence = evidence_for_event(conn, &event_id)?
            .map(|e| e.id)
            .into_iter()
            .collect::<Vec<_>>();
        let resource_type = if lower.contains("policy") {
            "policy"
        } else if lower.contains("certificate") || lower.contains("scep") {
            "certificate"
        } else if lower.contains("network") {
            "network"
        } else {
            "application"
        };
        let id = stable_id("esp-resource", &format!("{event_id}:{index}"));
        db::insert_esp_resource(
            conn,
            &EspResource {
                id: id.clone(),
                entity_id: entity_id.clone(),
                resource_type: resource_type.into(),
                phase: "Device setup".into(),
                substep: format!("{} tracking", title(resource_type)),
                expected_state: "complete".into(),
                actual_state: if failed { "failed" } else { "observed" }.into(),
                blocking_proven: failed && tracked,
                first_failure: failed && tracked && first_failure,
                evidence_ids: evidence.clone(),
            },
        )?;
        db::insert_step(
            conn,
            &ProvisioningStep {
                id: stable_id("step", &id),
                session_id: None,
                phase: "Device setup".into(),
                substep: format!("{} tracking", title(resource_type)),
                state: if failed { "failed" } else { "observed" }.into(),
                started_at: time.clone(),
                ended_at: time,
                evidence_ids: evidence.clone(),
            },
        )?;
        if failed && tracked {
            if first_failure {
                let ev = evidence_for_event(conn, &event_id)?.into_iter().collect();
                insert_finding(
                    conn,
                    "esp.first-blocker.v1",
                    if current { "critical" } else { "medium" },
                    "high",
                    current,
                    true,
                    entity_id,
                    "ESP tracked resource failed",
                    "Authoritative enrollment-status tracking links a failed resource to the blocking inventory.",
                    "Review the linked tracked resource and its first failing execution evidence before retrying provisioning.",
                    ev,
                )?;
            }
            first_failure = false;
        }
    }
    Ok(())
}

fn evaluate_msi_transactions(conn: &Connection) -> Result<()> {
    let mut stmt=conn.prepare("SELECT id,timestamp_utc,current FROM events WHERE lower(provider)='msiinstaller' AND event_code='1040' ORDER BY timestamp_utc,sequence")?;
    let starts: Vec<(String, Option<String>, bool)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (id, time, current) in starts {
        let closed: bool = if let Some(time) = &time {
            conn.query_row("SELECT EXISTS(SELECT 1 FROM events WHERE lower(provider)='msiinstaller' AND event_code='1042' AND datetime(timestamp_utc)>=datetime(?1) AND datetime(timestamp_utc)<=datetime(?1,'+2 hours'))",[time],|r|r.get(0))?
        } else {
            false
        };
        if closed {
            continue;
        }
        let reboot: Option<(String, String)> = if let Some(time) = &time {
            conn.query_row("SELECT id,timestamp_utc FROM events WHERE lower(provider)='user32' AND event_code='1074' AND datetime(timestamp_utc)>=datetime(?1) AND datetime(timestamp_utc)<=datetime(?1,'+2 hours') ORDER BY timestamp_utc LIMIT 1",[time],|r|Ok((r.get(0)?,r.get(1)?))).optional()?
        } else {
            None
        };
        let mut evidence = evidence_for_event(conn, &id)?
            .into_iter()
            .collect::<Vec<_>>();
        if let Some((reboot_event, _)) = &reboot
            && let Some(e) = evidence_for_event(conn, reboot_event)?
        {
            evidence.push(e)
        }
        if let Some((_, reboot_time)) = &reboot {
            db::insert_attempt(
                conn,
                &ExecutionAttempt {
                    id: stable_id("attempt", &format!("msi:{id}:{reboot_time}")),
                    application_id: None,
                    started_at: time.clone(),
                    ended_at: Some(reboot_time.clone()),
                    exit_code: None,
                    detection_result: None,
                    reboot_during_attempt: true,
                    state: "interrupted".into(),
                    evidence_ids: evidence.iter().map(|item| item.id.clone()).collect(),
                },
            )?;
        }
        insert_finding(
            conn,
            "msi.transaction.unclosed.v1",
            if reboot.is_some() { "critical" } else { "high" },
            if reboot.is_some() { "high" } else { "medium" },
            current,
            false,
            None,
            "MSI transaction did not close",
            if reboot.is_some() {
                "An MSI 1040 start has no matching 1042 or result, and a User32 1074 reboot occurred inside the open execution window. Any later installer exit is a consequence, not the cause."
            } else {
                "An MSI 1040 start has no matching 1042 or result. The available evidence does not prove a reboot interruption."
            },
            "Inspect the linked installer transaction, determine why it remained open, and retry only after confirming Windows Installer is idle.",
            evidence,
        )?;
    }
    Ok(())
}

fn evaluate_unmapped_exits(conn: &Connection) -> Result<()> {
    let mut stmt=conn.prepare("SELECT x.id,x.exit_code,x.application_id,COALESCE(e.current,0) FROM execution_attempts x LEFT JOIN evidence_links l ON l.id=json_extract(x.evidence_ids,'$[0]') LEFT JOIN events e ON e.id=l.event_id WHERE x.exit_code IS NOT NULL AND x.exit_code NOT IN (0,3010,1641,1603,1618)")?;
    let rows: Vec<(String, i64, Option<String>, bool)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (attempt, code, app, current) in rows {
        let tracked = app.as_deref().is_some_and(|id| {
            conn.query_row(
                "SELECT esp_tracked FROM applications WHERE id=?1",
                [id],
                |r| r.get::<_, bool>(0),
            )
            .unwrap_or(false)
        });
        let evidence_ids: String = conn.query_row(
            "SELECT evidence_ids FROM execution_attempts WHERE id=?1",
            [&attempt],
            |r| r.get(0),
        )?;
        let evidence = serde_json::from_str::<Vec<String>>(&evidence_ids)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|id| evidence_by_id(conn, &id).ok().flatten())
            .collect();
        insert_finding(
            conn,
            "ime.app.unmapped-exit.v1",
            "medium",
            "high",
            current,
            tracked,
            app,
            "Application returned an unmapped exit code",
            &format!(
                "An application attempt returned code {code}. The application failure is actionable; ESP impact is {} by the available tracking evidence.",
                if tracked { "proven" } else { "not proven" }
            ),
            "Map the return code only after verifying the installer's documented semantics and the linked detection result.",
            evidence,
        )?;
    }
    Ok(())
}

fn evaluate_identity_context(conn: &Connection) -> Result<()> {
    let machine:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM events WHERE lower(message) LIKE '%azureadprt%' AND lower(message) LIKE '%no%' AND (context='machine' OR message LIKE '%$%'))",[],|r|r.get(0))?;
    if machine {
        db::insert_rule_evaluation(
            conn,
            &stable_id("evaluation", "identity.machine-prt"),
            "identity.machine-prt-noise.v1",
            "known_noise",
            &[],
        )?;
    }
    Ok(())
}

fn evaluate_ime_and_enrollment(conn: &Connection) -> Result<()> {
    for (rule, needle, title_text, recommendation) in [
        (
            "ime.crash.v1",
            "management extension%crash",
            "Intune Management Extension crash evidence",
            "Restart the IME service only after collecting the linked crash context and checking service health.",
        ),
        (
            "enrollment.failure.v1",
            "enrollment%fail",
            "Current enrollment failure evidence",
            "Resolve the provider-specific enrollment error shown in evidence, then retry enrollment.",
        ),
        (
            "certificate.failure.v1",
            "scep%fail",
            "Certificate or SCEP failure evidence",
            "Validate the certificate request, connector, and provider-specific result before retrying.",
        ),
    ] {
        let pattern = format!("%{needle}%");
        let row:Option<(String,bool)>=conn.query_row("SELECT id,current FROM events WHERE lower(message) LIKE lower(?1) ORDER BY current DESC,sequence DESC LIMIT 1",[pattern],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if let Some((event, current)) = row {
            insert_finding(
                conn,
                rule,
                "high",
                "medium",
                current,
                false,
                None,
                title_text,
                "Provider-specific evidence indicates a failure. It is reported without assuming ESP impact unless authoritative tracking also links it.",
                recommendation,
                evidence_for_event(conn, &event)?.into_iter().collect(),
            )?;
        }
    }
    Ok(())
}

fn evaluate_time_integrity(conn: &Connection) -> Result<()> {
    let future:Option<(String,bool)>=conn.query_row("SELECT id,current FROM events WHERE timestamp_utc>datetime('now','+1 day') ORDER BY timestamp_utc LIMIT 1",[],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    if let Some((event, current)) = future {
        insert_finding(
            conn,
            "time.future-event.v1",
            "low",
            "high",
            current,
            false,
            None,
            "Future-dated evidence detected",
            "At least one source timestamp is more than 24 hours ahead of the analysis clock. Time ordering may be unreliable.",
            "Correct endpoint time synchronization and recollect diagnostics before relying on event order.",
            evidence_for_event(conn, &event)?.into_iter().collect(),
        )?;
    }
    let mut stmt = conn.prepare(
        "SELECT id,timestamp_utc FROM events WHERE timestamp_utc IS NOT NULL ORDER BY sequence",
    )?;
    let rows: Vec<(String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut previous: Option<(String, DateTime<Utc>)> = None;
    for (id, raw) in rows {
        let Ok(time) = DateTime::parse_from_rfc3339(&raw).map(|d| d.to_utc()) else {
            continue;
        };
        if let Some((prev_id, prev)) = &previous
            && time < *prev - Duration::minutes(5)
        {
            let mut evidence = evidence_for_event(conn, prev_id)?
                .into_iter()
                .collect::<Vec<_>>();
            evidence.extend(evidence_for_event(conn, &id)?);
            insert_finding(
                conn,
                "time.clock-jump.v1",
                "low",
                "medium",
                true,
                false,
                None,
                "Clock jump detected",
                "Source sequence moves backward by more than five minutes. MDM Doctor preserves source order and lowers time-based correlation confidence.",
                "Review endpoint time-service events and use sequence and provider evidence alongside timestamps.",
                evidence,
            )?;
            break;
        }
        previous = Some((id, time));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_finding(
    conn: &Connection,
    rule_id: &str,
    severity: &str,
    confidence: &str,
    current: bool,
    esp_tracked: bool,
    entity_id: Option<String>,
    title: &str,
    explanation: &str,
    recommendation: &str,
    evidence: Vec<EvidenceLink>,
) -> Result<()> {
    let evidence_key = evidence
        .iter()
        .map(|e| e.id.as_str())
        .collect::<Vec<_>>()
        .join(":");
    let id = stable_id("finding", &format!("{rule_id}:{evidence_key}"));
    let finding = Finding {
        id: id.clone(),
        rule_id: rule_id.into(),
        rule_pack: RULE_PACK_VERSION.into(),
        severity: severity.into(),
        confidence: confidence.into(),
        current,
        esp_tracked,
        entity_id,
        title: title.into(),
        explanation: explanation.into(),
        recommendation: recommendation.into(),
        evidence,
    };
    db::insert_finding(conn, &finding)?;
    db::insert_rule_evaluation(
        conn,
        &stable_id("evaluation", &id),
        rule_id,
        "matched",
        &finding
            .evidence
            .iter()
            .map(|e| e.id.clone())
            .collect::<Vec<_>>(),
    )?;
    Ok(())
}

fn evidence_for_event(conn: &Connection, event_id: &str) -> Result<Option<EvidenceLink>> {
    conn.query_row("SELECT id,artifact_id,event_id,source_span,label FROM evidence_links WHERE event_id=?1 ORDER BY id LIMIT 1",[event_id],|r|Ok(EvidenceLink{id:r.get(0)?,artifact_id:r.get(1)?,event_id:r.get(2)?,source_span:r.get(3)?,label:r.get(4)?})).optional().map_err(Into::into)
}
fn evidence_by_id(conn: &Connection, id: &str) -> Result<Option<EvidenceLink>> {
    conn.query_row(
        "SELECT id,artifact_id,event_id,source_span,label FROM evidence_links WHERE id=?1",
        [id],
        |r| {
            Ok(EvidenceLink {
                id: r.get(0)?,
                artifact_id: r.get(1)?,
                event_id: r.get(2)?,
                source_span: r.get(3)?,
                label: r.get(4)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}
fn state_value(rows: &[(String, String)], key: &str) -> Option<String> {
    rows.iter()
        .find(|(_, m)| m.to_ascii_lowercase().contains(key))
        .map(|(_, m)| {
            m.split([':', '='])
                .nth(1)
                .unwrap_or("unknown")
                .split_whitespace()
                .next()
                .unwrap_or("unknown")
                .into()
        })
}
fn title(value: &str) -> String {
    let mut c = value.chars();
    c.next()
        .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
        .unwrap_or_default()
}
fn hash_file(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn progress(job_dir: &Path, phase: &str, percent: u8, stage: &str) -> Result<()> {
    let body = serde_json::to_vec(&Progress {
        phase,
        percent,
        stage,
    })?;
    let temp = job_dir.join("progress.tmp");
    fs::write(&temp, body)?;
    fs::rename(temp, job_dir.join("progress.json"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::NewArtifact;

    fn database(path: &Path, artifact_path: &str) -> Connection {
        let conn = db::open(path).unwrap();
        db::initialize(&conn).unwrap();
        db::insert_artifact(
            &conn,
            &NewArtifact {
                id: "artifact:synthetic",
                parent_id: None,
                layer: 0,
                normalized_path: artifact_path,
                original_path: artifact_path,
                object_path: "upload.bin",
                size: 1,
                sha256: "00",
                detected_type: "text",
                duplicate_of: None,
                warning: None,
            },
        )
        .unwrap();
        conn
    }

    #[allow(clippy::too_many_arguments)]
    fn event(
        conn: &Connection,
        key: &str,
        timestamp: Option<&str>,
        provider: Option<&str>,
        code: Option<&str>,
        context: Option<&str>,
        message: &str,
    ) {
        let id = stable_id("event", key);
        db::insert_event(
            conn,
            &id,
            "artifact:synthetic",
            timestamp,
            timestamp,
            Some(0),
            provider,
            Some("Synthetic"),
            code,
            Some("synthetic"),
            context,
            "info",
            None,
            message,
            Some(key),
        )
        .unwrap();
        db::insert_evidence(
            conn,
            None,
            &EvidenceLink {
                id: stable_id("evidence", key),
                artifact_id: "artifact:synthetic".into(),
                event_id: Some(id),
                source_span: Some(key.into()),
                label: "Synthetic evidence".into(),
            },
        )
        .unwrap();
    }

    #[test]
    fn fresh_provisioning_links_authoritative_first_blocker() {
        let root = tempfile::tempdir().unwrap();
        let conn = database(
            &root.path().join("analysis.sqlite"),
            "EnrollmentStatusTracking.log",
        );
        event(
            &conn,
            "esp-1",
            Some("2025-08-11T09:00:00+00:00"),
            Some("ESP"),
            None,
            Some("machine"),
            "ESP application tracking failed with provider error",
        );
        correlate(&conn).unwrap();

        let finding: (bool, bool) = conn
            .query_row(
                "SELECT current,esp_tracked FROM findings WHERE rule_id='esp.first-blocker.v1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(finding, (true, true));
        let unresolved: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM findings f WHERE NOT EXISTS (SELECT 1 FROM evidence_links e JOIN artifacts a ON a.id=e.artifact_id WHERE e.finding_id=f.id)",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unresolved, 0);
    }

    #[test]
    fn reboot_interrupted_msi_is_an_explicit_attempt() {
        let root = tempfile::tempdir().unwrap();
        let conn = database(
            &root.path().join("analysis.sqlite"),
            "DeviceManagement.evtx",
        );
        event(
            &conn,
            "msi-start",
            Some("2025-08-11T09:00:00+00:00"),
            Some("MsiInstaller"),
            Some("1040"),
            Some("machine"),
            "MSI transaction started for application",
        );
        event(
            &conn,
            "reboot",
            Some("2025-08-11T09:20:00+00:00"),
            Some("User32"),
            Some("1074"),
            Some("machine"),
            "System reboot initiated",
        );
        correlate(&conn).unwrap();

        let interrupted: bool = conn
            .query_row(
                "SELECT reboot_during_attempt FROM execution_attempts WHERE state='interrupted'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(interrupted);
        let severity: String = conn
            .query_row(
                "SELECT severity FROM findings WHERE rule_id='msi.transaction.unclosed.v1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(severity, "critical");
    }

    #[test]
    fn latest_success_supersedes_historical_application_failure() {
        let root = tempfile::tempdir().unwrap();
        let conn = database(
            &root.path().join("analysis.sqlite"),
            "IntuneManagementExtension.log",
        );
        event(
            &conn,
            "old-failure",
            Some("2025-08-11T09:00:00+00:00"),
            Some("IME"),
            None,
            Some("machine"),
            "application installer exit code 1603",
        );
        event(
            &conn,
            "boundary",
            Some("2025-08-11T10:00:00+00:00"),
            Some("User32"),
            Some("1074"),
            Some("machine"),
            "System reboot initiated",
        );
        event(
            &conn,
            "new-success",
            Some("2025-08-11T10:30:00+00:00"),
            Some("IME"),
            None,
            Some("machine"),
            "application installer exit code 0",
        );
        correlate(&conn).unwrap();

        let state: (String, i64) = conn
            .query_row(
                "SELECT state,attempt_count FROM applications LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, ("succeeded".into(), 2));
        let current: bool = conn
            .query_row("SELECT current FROM managed_entities LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(current);
    }

    #[test]
    fn machine_context_prt_absence_is_known_noise() {
        let root = tempfile::tempdir().unwrap();
        let conn = database(&root.path().join("analysis.sqlite"), "dsregcmd.txt");
        event(
            &conn,
            "identity",
            Some("2025-08-11T09:00:00+00:00"),
            Some("dsregcmd"),
            None,
            Some("machine"),
            "HOST$ AzureAdJoined : YES DeviceAuthStatus : SUCCESS AzureAdPrt : NO",
        );
        correlate(&conn).unwrap();

        let outcome: String = conn
            .query_row(
                "SELECT outcome FROM rule_evaluations WHERE rule_id='identity.machine-prt-noise.v1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(outcome, "known_noise");
        let false_findings: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM findings WHERE rule_id LIKE 'identity.%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(false_findings, 0);
    }
}
