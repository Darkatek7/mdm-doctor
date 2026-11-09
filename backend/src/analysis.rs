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
    #[serde(skip_serializing_if = "Option::is_none")]
    processed_artifacts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_artifacts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unique_events: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duplicate_events: Option<u64>,
}

pub fn run_worker(config: &Config, job_dir: &Path) -> Result<()> {
    let upload = job_dir.join("upload.bin");
    let source_name =
        fs::read_to_string(job_dir.join("source.name")).map_err(|_| AppError::BadRequest)?;
    let source_name = source_name.trim();
    let upload_sha = fs::read_to_string(job_dir.join("upload.sha256"))
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()))
        .map_or_else(|| hash_file(&upload), Ok)?;
    let partial_db = job_dir.join("analysis.partial.sqlite");
    let final_db = job_dir.join(db::DB_FILE);
    let _ = fs::remove_file(&partial_db);
    let _ = fs::remove_file(&final_db);
    let _ = fs::remove_dir_all(job_dir.join("objects"));
    progress(
        job_dir,
        "extracting",
        20,
        "Validating archive",
        None,
        None,
        None,
        None,
    )?;

    let mut conn = db::open(&partial_db)?;
    db::initialize(&conn)?;
    let report = {
        let tx = conn.transaction()?;
        let report =
            ingest::ingest_upload(config, &tx, job_dir, &upload, source_name, &upload_sha)?;
        tx.commit()?;
        report
    };
    let total_artifacts = report.artifacts.len() as u64;
    progress(
        job_dir,
        "parsing",
        35,
        "Parsing diagnostic sources",
        Some(0),
        Some(total_artifacts),
        Some(0),
        Some(0),
    )?;
    let parse_stats = {
        let tx = conn.transaction()?;
        let stats =
            parsers::parse_all(&tx, &report.artifacts, config, |processed, total, stats| {
                let percent = 35_u8
                    .saturating_add(((processed.saturating_mul(43) / total.max(1)) as u8).min(43));
                if processed == total || processed % 20 == 0 {
                    progress(
                        job_dir,
                        "parsing",
                        percent,
                        "Parsing diagnostic sources",
                        Some(processed),
                        Some(total),
                        Some(stats.unique_events),
                        Some(stats.duplicate_events),
                    )?;
                }
                Ok(())
            })?;
        tx.commit()?;
        stats
    };
    progress(
        job_dir,
        "parsing",
        80,
        "Building search index",
        Some(total_artifacts),
        Some(total_artifacts),
        Some(parse_stats.unique_events),
        Some(parse_stats.duplicate_events),
    )?;
    db::finalize_event_index(&conn)?;
    progress(
        job_dir,
        "correlating",
        86,
        "Correlating evidence",
        Some(total_artifacts),
        Some(total_artifacts),
        Some(parse_stats.unique_events),
        Some(parse_stats.duplicate_events),
    )?;
    {
        let tx = conn.transaction()?;
        correlate(&tx)?;
        tx.commit()?;
    }
    conn.execute("PRAGMA optimize", [])?;
    drop(conn);
    fs::rename(&partial_db, &final_db)?;
    progress(
        job_dir,
        "ready",
        100,
        "Analysis ready",
        Some(total_artifacts),
        Some(total_artifacts),
        Some(parse_stats.unique_events),
        Some(parse_stats.duplicate_events),
    )?;
    Ok(())
}

fn correlate(conn: &Connection) -> Result<()> {
    build_sessions(conn)?;
    build_device_snapshot(conn)?;
    build_applications_and_attempts(conn)?;
    build_named_managed_entities(conn)?;
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
            "UPDATE events SET current=0, temporal_scope='unknown', session_id=?1",
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
                "UPDATE events SET current=1,temporal_scope='current',session_id=?1 WHERE timestamp_utc>=?2",
                params![id, start],
            )?;
        } else if let Some(end) = end {
            conn.execute(
                "UPDATE events SET current=0,temporal_scope='historical',session_id=?1 WHERE timestamp_utc>=?2 AND timestamp_utc<?3",
                params![id, start, end],
            )?;
        }
    }
    conn.execute("UPDATE events SET current=0,temporal_scope='unknown',session_id=NULL WHERE timestamp_utc IS NULL",[])?;
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
    static NAME: OnceLock<Regex> = OnceLock::new();
    static APP_ID: OnceLock<Regex> = OnceLock::new();
    static SCRIPT: OnceLock<Regex> = OnceLock::new();
    static NAME_PAIR: OnceLock<Regex> = OnceLock::new();
    let guid = GUID.get_or_init(|| {
        Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
            .expect("static regex")
    });
    let exit = EXIT.get_or_init(|| {
        Regex::new(r"(?i)\b(?:exit(?:ed)?(?:\s*with)?[\s_]*code|return(?:ed)?[\s_]*code)\b\D{0,6}?(-?\d{1,10})\b")
            .expect("static regex")
    });
    let name = NAME.get_or_init(|| Regex::new(r#"(?i)[\"']?(?:app(?:lication)?(?:\s+display)?\s*name|displayname|productname)[\"']?\s*[:=]\s*[\"']?([^\"'\r\n,;}\]]{2,160})"#).expect("static regex"));
    let app_id = APP_ID.get_or_init(|| Regex::new(r#"(?i)(?:app(?:lication)?(?:\s+policy)?(?:\s+with)?\s+id|applicationid|applicatonid|app_id)[\"']?\s*[:=]\s*[\"']?([0-9a-f]{8}-[0-9a-f-]{27,36})"#).expect("static regex"));
    let script = SCRIPT.get_or_init(|| Regex::new(r"(?i)(?:detectionscripts|remediationscripts|installscripts|content)\\([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})").expect("static regex"));
    let name_pair = NAME_PAIR.get_or_init(|| {
        Regex::new(
            r"(?i)\bid\s*=\s*([0-9a-f]{8}-[0-9a-f-]{27,31})\s*,\s*name\s*=\s*([^)\r\n]{2,160})",
        )
        .expect("static regex")
    });
    #[derive(Clone)]
    struct Row {
        event_id: String,
        artifact_id: String,
        timestamp: Option<String>,
        message: String,
        current: bool,
        component: Option<String>,
        path: String,
        sequence: u64,
    }
    let mut stmt=conn.prepare("SELECT e.id,e.artifact_id,e.timestamp_utc,e.message,e.current,e.component,a.normalized_path,e.sequence FROM events e JOIN artifacts a ON a.id=e.artifact_id WHERE lower(a.normalized_path) LIKE '%intunemanagementextension%' OR lower(a.normalized_path) LIKE '%appworkload%' OR lower(a.normalized_path) LIKE '%agentexecutor%' OR lower(a.normalized_path) LIKE '%esptracking%' OR lower(a.normalized_path) LIKE '%enrollmentstatustracking%' OR lower(COALESCE(e.component,'')) IN ('intunemanagementextension','appworkload','appactionprocessor','agentexecutor','msiinstaller') ORDER BY e.sequence")?;
    let rows: Vec<Row> = stmt
        .query_map([], |r| {
            Ok(Row {
                event_id: r.get(0)?,
                artifact_id: r.get(1)?,
                timestamp: r.get(2)?,
                message: r.get(3)?,
                current: r.get(4)?,
                component: r.get(5)?,
                path: r.get(6)?,
                sequence: r.get::<_, i64>(7)? as u64,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    #[derive(Default)]
    struct AppBuild {
        name: Option<String>,
        evidence: std::collections::BTreeSet<String>,
        attempts: u64,
        current: bool,
        tracked: bool,
        state: String,
        latest_sequence: u64,
        app_type: String,
        guid_key: Option<String>,
    }
    let explicit_name = |message: &str| -> Option<String> {
        let raw = name
            .captures(message)?
            .get(1)?
            .as_str()
            .trim()
            .trim_matches(['"', '\''])
            .to_owned();
        let lower = raw.to_ascii_lowercase();
        (!guid.is_match(&raw)
            && !matches!(lower.as_str(), "application" | "app" | "unknown" | "null")
            && raw.len() >= 2)
            .then_some(raw)
    };
    let mut name_by_key = std::collections::HashMap::<String, String>::new();
    for row in &rows {
        for (key, display) in app_descriptors(&row.message, guid) {
            name_by_key.entry(key).or_insert(display);
        }
        if let (Some(key), Some(display)) = (
            app_id
                .captures(&row.message)
                .and_then(|captures| captures.get(1))
                .map(|value| value.as_str().to_ascii_lowercase()),
            explicit_name(&row.message),
        ) {
            name_by_key.entry(key).or_insert(display);
        }
        // "[Win32App] Content cache miss for app (id = <guid>, name = <app>)".
        for (key, display) in name_pair
            .captures_iter(&row.message)
            .filter_map(|captures| Some((captures.get(1)?.as_str(), captures.get(2)?.as_str())))
        {
            let display = display.trim().trim_matches(['"', '\'']);
            if display.len() >= 2 {
                name_by_key
                    .entry(key.to_ascii_lowercase())
                    .or_insert_with(|| display.to_owned());
            }
        }
    }
    let mut apps = std::collections::BTreeMap::<String, AppBuild>::new();
    let mut last_app = std::collections::HashMap::<String, String>::new();
    for row in &rows {
        let lower = row.message.to_ascii_lowercase();
        let tracking = row.path.to_ascii_lowercase().contains("esptracking")
            || row
                .path
                .to_ascii_lowercase()
                .contains("enrollmentstatustracking");
        let lifecycle = tracking
            || [
                "app id",
                "application id",
                "detection",
                "install",
                "uninstall",
                "exit code",
                "return code",
                "applicability",
            ]
            .iter()
            .any(|needle| lower.contains(needle));
        if !lifecycle {
            continue;
        }
        let mut keys = app_id
            .captures_iter(&row.message)
            .filter_map(|captures| captures.get(1))
            .map(|value| value.as_str().to_ascii_lowercase())
            .collect::<Vec<_>>();
        keys.extend(
            app_descriptors(&row.message, guid)
                .into_iter()
                .map(|(key, _)| key),
        );
        // AgentExecutor runs app scripts as ...\DetectionScripts\<app-id>_N.ps1;
        // the path GUID is the policy Id, so exit lines join to the named app.
        keys.extend(
            script
                .captures_iter(&row.message)
                .filter_map(|captures| captures.get(1))
                .map(|value| value.as_str().to_ascii_lowercase()),
        );
        let display = explicit_name(&row.message);
        if keys.is_empty() {
            if let Some(display) = &display {
                keys.push(format!("name:{}", display.to_ascii_lowercase()));
            } else if let Some(previous) = last_app.get(&row.artifact_id) {
                keys.push(previous.clone());
            } else if exit.is_match(&row.message) {
                keys.push(format!("artifact:{}", row.artifact_id));
            }
        }
        keys.sort();
        keys.dedup();
        let evidence = evidence_for_event(conn, &row.event_id)?.map(|value| value.id);
        for key in keys {
            let app_id = stable_id("app", &key);
            last_app.insert(row.artifact_id.clone(), key.clone());
            let item = apps.entry(app_id.clone()).or_default();
            if item.guid_key.is_none() && key.len() == 36 && guid.is_match(&key) {
                item.guid_key = Some(key.clone());
            }
            item.name = item
                .name
                .take()
                .or_else(|| display.clone())
                .or_else(|| name_by_key.get(&key).cloned());
            item.current |= row.current;
            item.tracked |= tracking;
            item.app_type = if row
                .component
                .as_deref()
                .is_some_and(|v| v.eq_ignore_ascii_case("MsiInstaller"))
            {
                "MSI".into()
            } else {
                "Managed".into()
            };
            if let Some(evidence) = &evidence
                && item.evidence.len() < 100
            {
                item.evidence.insert(evidence.clone());
            }
            if let Some(caps) = exit.captures(&row.message) {
                let code = caps
                    .get(1)
                    .and_then(|value| value.as_str().parse::<i64>().ok());
                let state = match code {
                    Some(0 | 3010 | 1641) => "succeeded",
                    Some(_) => "failed",
                    None => "unknown",
                };
                item.attempts += 1;
                if row.sequence >= item.latest_sequence {
                    item.latest_sequence = row.sequence;
                    item.state = state.into();
                }
                db::insert_attempt(
                    conn,
                    &ExecutionAttempt {
                        id: stable_id("attempt", &format!("{app_id}:{}", row.event_id)),
                        application_id: Some(app_id.clone()),
                        started_at: row.timestamp.clone(),
                        ended_at: row.timestamp.clone(),
                        exit_code: code,
                        detection_result: None,
                        reboot_during_attempt: false,
                        state: state.into(),
                        evidence_ids: evidence.clone().into_iter().collect(),
                    },
                )?;
            }
        }
    }
    for (id, item) in apps {
        let state = if item.state.is_empty() {
            "observed".into()
        } else {
            item.state
        };
        // Apps identified only by their policy GUID (Win32 content that was
        // already cached never logs a display name) stay distinguishable.
        let display_name = item.name.unwrap_or_else(|| match &item.guid_key {
            Some(key) => format!("Unknown application ({}…)", &key[..8]),
            None => "Unknown application".into(),
        });
        let evidence = item.evidence.into_iter().collect::<Vec<_>>();
        db::insert_application(
            conn,
            &Application {
                id: id.clone(),
                name: display_name.clone(),
                app_type: if item.app_type.is_empty() {
                    "Managed".into()
                } else {
                    item.app_type
                },
                intent: None,
                install_context: None,
                state: state.clone(),
                esp_tracked: item.tracked,
                attempt_count: item.attempts,
                evidence_ids: evidence.clone(),
            },
        )?;
        db::insert_entity(
            conn,
            &ManagedEntity {
                id,
                entity_type: "application".into(),
                name: display_name,
                state,
                current: item.current,
                evidence_ids: evidence,
            },
        )?;
    }
    Ok(())
}

fn app_descriptors(message: &str, guid: &Regex) -> Vec<(String, String)> {
    let Some(start) = message.find("[{").or_else(|| message.find('{')) else {
        return Vec::new();
    };
    let Some(Ok(value)) = serde_json::Deserializer::from_str(&message[start..])
        .into_iter::<serde_json::Value>()
        .next()
    else {
        return Vec::new();
    };
    fn walk(value: &serde_json::Value, guid: &Regex, out: &mut Vec<(String, String)>) {
        match value {
            serde_json::Value::Object(map) => {
                let id = map.iter().find_map(|(key, value)| {
                    matches!(
                        key.to_ascii_lowercase().as_str(),
                        "id" | "applicationid" | "applicatonid" | "app_id"
                    )
                    .then(|| value.as_str())
                    .flatten()
                    .filter(|raw| guid.is_match(raw))
                });
                let name = map.iter().find_map(|(key, value)| {
                    matches!(
                        key.to_ascii_lowercase().as_str(),
                        "name" | "displayname" | "applicationname" | "productname"
                    )
                    .then(|| value.as_str())
                    .flatten()
                    .map(str::trim)
                    .filter(|raw| raw.len() >= 2 && !guid.is_match(raw))
                });
                if let Some((id, name)) = id.zip(name) {
                    out.push((id.to_ascii_lowercase(), name.to_owned()));
                }
                for child in map.values() {
                    walk(child, guid, out);
                }
            }
            serde_json::Value::Array(items) => {
                for child in items {
                    walk(child, guid, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(&value, guid, &mut out);
    out.sort();
    out.dedup();
    out
}

fn build_named_managed_entities(conn: &Connection) -> Result<()> {
    static TYPED_NAME: OnceLock<Regex> = OnceLock::new();
    static DISPLAY_NAME: OnceLock<Regex> = OnceLock::new();
    static GUID: OnceLock<Regex> = OnceLock::new();
    let typed_name = TYPED_NAME.get_or_init(|| {
        Regex::new(r#"(?i)(policy|profile|package|certificate|network)(?:\s+display)?\s*name[\"']?\s*[:=]\s*[\"']?([^\"'\r\n,;}\]]{2,160})"#)
            .expect("static regex")
    });
    let display_name = DISPLAY_NAME.get_or_init(|| {
        Regex::new(r#"(?i)[\"']?displayname[\"']?\s*[:=]\s*[\"']([^\"'\r\n]{2,160})"#)
            .expect("static regex")
    });
    let guid = GUID.get_or_init(|| {
        Regex::new(r"(?i)^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$")
            .expect("static regex")
    });
    let mut stmt = conn.prepare(
        "SELECT e.id,e.message,e.current,a.normalized_path FROM events e JOIN artifacts a ON a.id=e.artifact_id WHERE lower(e.message) LIKE '%policy%' OR lower(e.message) LIKE '%profile%' OR lower(e.message) LIKE '%package%' OR lower(e.message) LIKE '%certificate%' OR lower(e.message) LIKE '%scep%' OR lower(a.normalized_path) LIKE '%policy%' OR lower(a.normalized_path) LIKE '%profile%' OR lower(a.normalized_path) LIKE '%certificate%' OR lower(a.normalized_path) LIKE '%scep%' ORDER BY e.sequence",
    )?;
    let rows: Vec<(String, String, bool, String)> = stmt
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    #[derive(Default)]
    struct EntityBuild {
        current: bool,
        state: String,
        evidence: std::collections::BTreeSet<String>,
    }
    let mut entities = std::collections::BTreeMap::<(String, String), EntityBuild>::new();
    for (event_id, message, current, path) in rows {
        let lower = message.to_ascii_lowercase();
        let inferred_type = infer_entity_type(&lower, &path);
        let named = typed_name
            .captures_iter(&message)
            .filter_map(|captures| {
                Some((
                    normalize_entity_type(captures.get(1)?.as_str()).to_owned(),
                    captures.get(2)?.as_str(),
                ))
            })
            .chain(display_name.captures_iter(&message).filter_map(|captures| {
                Some((inferred_type?.to_owned(), captures.get(1)?.as_str()))
            }));
        for (entity_type, raw_name) in named {
            let mut name = raw_name
                .trim()
                .trim_matches(['"', '\'', ' ', '.'])
                .to_owned();
            let normalized_name = name.to_ascii_lowercase();
            for suffix in [
                " applied successfully",
                " applied",
                " completed",
                " succeeded",
                " observed",
                " failed",
            ] {
                if normalized_name.ends_with(suffix) {
                    name.truncate(name.len() - suffix.len());
                    break;
                }
            }
            if name.len() < 2 || guid.is_match(&name) {
                continue;
            }
            let key = (entity_type, name);
            let entity = entities.entry(key).or_default();
            entity.current |= current;
            entity.state = if lower.contains("fail") || lower.contains("error") {
                "failed"
            } else if lower.contains("success")
                || lower.contains("applied")
                || lower.contains("complete")
            {
                "succeeded"
            } else {
                "observed"
            }
            .into();
            if entity.evidence.len() < 20 {
                entity.evidence.insert(format!("evidence:{event_id}"));
            }
        }
    }
    for ((entity_type, name), entity) in entities {
        db::insert_entity(
            conn,
            &ManagedEntity {
                id: stable_id(
                    "entity",
                    &format!("{}:{}", entity_type, name.to_ascii_lowercase()),
                ),
                entity_type,
                name,
                state: entity.state,
                current: entity.current,
                evidence_ids: entity.evidence.into_iter().collect(),
            },
        )?;
    }
    Ok(())
}

fn infer_entity_type<'a>(message: &str, path: &str) -> Option<&'a str> {
    let context = format!("{} {}", message, path.to_ascii_lowercase());
    if context.contains("certificate") || context.contains("scep") {
        Some("certificate")
    } else if context.contains("package") {
        Some("package")
    } else if context.contains("network") || context.contains("wifi") || context.contains("vpn") {
        Some("network profile")
    } else if context.contains("profile") {
        Some("profile")
    } else if context.contains("policy") {
        Some("policy")
    } else {
        None
    }
}

fn normalize_entity_type(value: &str) -> &str {
    match value.to_ascii_lowercase().as_str() {
        "network" => "network profile",
        "certificate" => "certificate",
        "package" => "package",
        "profile" => "profile",
        _ => "policy",
    }
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

pub(crate) fn exit_semantics(code: i64) -> Option<(&'static str, &'static str)> {
    Some(match code {
        1602 => (
            "User cancelled the installation",
            "Confirm the install runs unattended without interactive prompts, then retry.",
        ),
        1603 => (
            "Fatal error during installation",
            "Inspect the linked MSI log and installer prerequisites before retrying the application.",
        ),
        1618 => (
            "Another installation was already in progress",
            "Wait for Windows Installer to become idle, confirm the competing transaction, and retry the application.",
        ),
        1619 => (
            "Installation package could not be opened",
            "Verify the installer package is present, complete, and readable on the device.",
        ),
        1625 => (
            "Blocked by system policy",
            "Review Group Policy or AppLocker settings that block Windows Installer packages.",
        ),
        1628 => (
            "Installation service could not be reached",
            "Confirm the Windows Installer service is running and reachable, then retry.",
        ),
        1633 => (
            "Package is not supported on this platform or architecture",
            "Deploy an installer build that matches the device platform and architecture.",
        ),
        1638 => (
            "Another version of this product is already installed",
            "Uninstall or upgrade the existing version, or correct the installer's detection logic before retrying.",
        ),
        1639 => (
            "Invalid installer command line",
            "Correct the installer command line in the deployment configuration.",
        ),
        1708 => (
            "Package could not be registered",
            "Verify package registration prerequisites and installer integrity.",
        ),
        -2147024891 => (
            "Access denied (0x80070005)",
            "Check file and registry permissions for the install context, then retry.",
        ),
        -2147024894 => (
            "Required file not found (0x80070002)",
            "Verify the referenced file exists and the install source is complete.",
        ),
        -2147024893 => (
            "Required path not found (0x80070003)",
            "Verify the referenced path exists on the device.",
        ),
        -2147023276 => (
            "Another installation was in progress (0x80070652)",
            "Wait for the competing installation to finish, then retry.",
        ),
        -1073741510 => (
            "Installation was cancelled or the process was terminated (0xC000013A)",
            "Identify what terminated the installer (user, policy, timeout, reboot) and retry.",
        ),
        -2146233079 => (
            ".NET runtime or configuration error (0x80131509)",
            "Verify the required .NET runtime and application configuration on the device.",
        ),
        5 => (
            "Access denied",
            "Check permissions for the install context, then retry.",
        ),
        2 => (
            "Required file not found",
            "Verify the referenced file exists and the install source is complete.",
        ),
        3 => (
            "Required path not found",
            "Verify the referenced path exists on the device.",
        ),
        _ => return None,
    })
}

fn evaluate_unmapped_exits(conn: &Connection) -> Result<()> {
    let mut stmt=conn.prepare("SELECT x.id,x.exit_code,x.application_id,COALESCE(e.temporal_scope,'unknown'),e.timestamp_utc FROM execution_attempts x LEFT JOIN evidence_links l ON l.id=json_extract(x.evidence_ids,'$[0]') LEFT JOIN events e ON e.id=COALESCE(l.event_id,CASE WHEN json_extract(x.evidence_ids,'$[0]') LIKE 'evidence:event:%' THEN substr(json_extract(x.evidence_ids,'$[0]'),10) END) WHERE x.exit_code IS NOT NULL AND x.exit_code NOT IN (0,3010,1641) AND x.application_id IS NOT NULL")?;
    let rows: Vec<(String, i64, String, String, Option<String>)> = stmt
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    #[derive(Default)]
    struct Group {
        count: u64,
        evidence: Vec<EvidenceLink>,
        tracked: bool,
        last_seen: Option<String>,
    }
    let mut groups = std::collections::BTreeMap::<(String, i64, String), Group>::new();
    for (attempt, code, app, scope, timestamp) in rows {
        let group = groups.entry((app.clone(), code, scope)).or_default();
        group.count += 1;
        group.tracked = conn
            .query_row(
                "SELECT esp_tracked FROM applications WHERE id=?1",
                [&app],
                |r| r.get::<_, bool>(0),
            )
            .unwrap_or(false);
        if timestamp > group.last_seen {
            group.last_seen = timestamp;
        }
        let evidence_ids: String = conn.query_row(
            "SELECT evidence_ids FROM execution_attempts WHERE id=?1",
            [&attempt],
            |r| r.get(0),
        )?;
        let evidence = serde_json::from_str::<Vec<String>>(&evidence_ids)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|id| evidence_by_id(conn, &id).ok().flatten())
            .collect::<Vec<_>>();
        for value in evidence {
            if group.evidence.len() < 10 && !group.evidence.iter().any(|e| e.id == value.id) {
                group.evidence.push(value);
            }
        }
    }
    for ((app, code, scope), group) in groups {
        let name: String = conn
            .query_row("SELECT name FROM applications WHERE id=?1", [&app], |r| {
                r.get(0)
            })
            .unwrap_or_else(|_| "An application".into());
        let (rule, severity, title, explanation, recommendation) = match code {
            1603 => (
                "ime.app.msi-1603.v1",
                "high",
                format!("{name}: MSI installation returned fatal error 1603"),
                "A recognized application attempt returned MSI code 1603. ESP impact is reported only when authoritative tracking links the application.".to_owned(),
                "Inspect the linked MSI log and installer prerequisites before retrying the application.".to_owned(),
            ),
            1618 => (
                "ime.app.msi-1618.v1",
                "medium",
                format!("{name}: Another MSI installation was already running"),
                "A recognized application attempt returned MSI code 1618, indicating installer contention rather than an application-content diagnosis.".to_owned(),
                "Wait for Windows Installer to become idle, confirm the competing transaction, and retry the application.".to_owned(),
            ),
            _ => match exit_semantics(code) {
                Some((meaning, action)) => (
                    "ime.app.unmapped-exit.v1",
                    "medium",
                    format!("{name} failed with exit code {code}"),
                    format!("The latest failing attempt returned exit code {code}: {meaning}. ESP impact is reported only when authoritative tracking links the application."),
                    action.to_owned(),
                ),
                None => (
                    "ime.app.unmapped-exit.v1",
                    "medium",
                    format!("{name} failed with exit code {code}"),
                    format!("A recognized application attempt returned exit code {code} without a built-in semantic mapping. ESP impact is reported only when authoritative tracking links the application."),
                    "Verify the installer's documented return-code semantics and the linked detection result before retrying.".to_owned(),
                ),
            },
        };
        insert_finding_occurrences(
            conn,
            rule,
            severity,
            "high",
            scope == "current",
            group.tracked,
            Some(app.clone()),
            &title,
            &explanation,
            &recommendation,
            group.evidence,
            group.count,
            Some(&format!("{app}:{code}:{scope}")),
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
    insert_finding_occurrences(
        conn,
        rule_id,
        severity,
        confidence,
        current,
        esp_tracked,
        entity_id,
        title,
        explanation,
        recommendation,
        evidence,
        1,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn insert_finding_occurrences(
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
    occurrence_count: u64,
    group_key: Option<&str>,
) -> Result<()> {
    let evidence_key = evidence
        .iter()
        .map(|e| e.id.as_str())
        .collect::<Vec<_>>()
        .join(":");
    let id = stable_id(
        "finding",
        &format!("{rule_id}:{}", group_key.unwrap_or(&evidence_key)),
    );
    let mut scopes = Vec::new();
    let mut last_seen_at: Option<String> = None;
    for item in &evidence {
        if let Some(event_id) = &item.event_id
            && let Some((scope, timestamp)) = conn
                .query_row(
                    "SELECT temporal_scope,timestamp_utc FROM events WHERE id=?1",
                    [event_id],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
                )
                .optional()?
        {
            scopes.push(scope);
            if timestamp > last_seen_at {
                last_seen_at = timestamp;
            }
        }
    }
    let temporal_scope = if current || scopes.iter().any(|scope| scope == "current") {
        "current"
    } else if scopes.iter().any(|scope| scope == "unknown") || scopes.is_empty() {
        "unknown"
    } else {
        "historical"
    };
    let finding = Finding {
        id: id.clone(),
        rule_id: rule_id.into(),
        rule_pack: RULE_PACK_VERSION.into(),
        severity: severity.into(),
        confidence: confidence.into(),
        current: temporal_scope == "current",
        temporal_scope: temporal_scope.into(),
        occurrence_count,
        last_seen_at,
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
    conn.query_row("SELECT artifact_id,id,source_span,COALESCE(component,provider,'source')||' evidence' FROM events WHERE id=?1",[event_id],|r|Ok(EvidenceLink{id:format!("evidence:{event_id}"),artifact_id:r.get(0)?,event_id:Some(r.get(1)?),source_span:r.get(2)?,label:r.get(3)?})).optional().map_err(Into::into)
}
fn evidence_by_id(conn: &Connection, id: &str) -> Result<Option<EvidenceLink>> {
    if let Some(event_id) = id.strip_prefix("evidence:") {
        return evidence_for_event(conn, event_id);
    }
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
#[allow(clippy::too_many_arguments)]
fn progress(
    job_dir: &Path,
    phase: &str,
    percent: u8,
    stage: &str,
    processed_artifacts: Option<u64>,
    total_artifacts: Option<u64>,
    unique_events: Option<u64>,
    duplicate_events: Option<u64>,
) -> Result<()> {
    let body = serde_json::to_vec(&Progress {
        phase,
        percent,
        stage,
        processed_artifacts,
        total_artifacts,
        unique_events,
        duplicate_events,
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
    fn resolves_display_name_and_aggregates_current_attempt_failures() {
        let root = tempfile::tempdir().unwrap();
        let conn = database(
            &root.path().join("analysis.sqlite"),
            "IntuneManagementExtension.log",
        );
        let app_id = "11111111-2222-3333-4444-555555555555";
        for (key, time) in [
            ("attempt-1", "2026-08-12T09:00:00+00:00"),
            ("attempt-2", "2026-08-12T09:01:00+00:00"),
        ] {
            event(
                &conn,
                key,
                Some(time),
                Some("IntuneManagementExtension"),
                None,
                Some("machine"),
                &format!(
                    "application id: {app_id}, application name: Contoso Secure Client, installer exit code 1603"
                ),
            );
        }
        correlate(&conn).unwrap();

        let application: (String, i64) = conn
            .query_row("SELECT name,attempt_count FROM applications", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(application, ("Contoso Secure Client".into(), 2));
        let finding: (String, i64) = conn
            .query_row(
                "SELECT temporal_scope,occurrence_count FROM findings WHERE rule_id='ime.app.msi-1603.v1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(finding, ("current".into(), 2));
    }

    #[test]
    fn undated_application_failure_is_unknown_not_current() {
        let root = tempfile::tempdir().unwrap();
        let conn = database(
            &root.path().join("analysis.sqlite"),
            "IntuneManagementExtension.log",
        );
        event(
            &conn,
            "undated-attempt",
            None,
            Some("IntuneManagementExtension"),
            None,
            Some("machine"),
            "application name: Fabrikam Support Tool, installer exit code 1",
        );
        correlate(&conn).unwrap();

        let finding: (String, bool) = conn
            .query_row(
                "SELECT temporal_scope,current FROM findings WHERE rule_id='ime.app.unmapped-exit.v1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(finding, ("unknown".into(), false));
    }

    #[test]
    fn failed_application_surfaces_in_user_impact() {
        let root = tempfile::tempdir().unwrap();
        let conn = database(
            &root.path().join("analysis.sqlite"),
            "IntuneManagementExtension.log",
        );
        event(
            &conn,
            "attempt-1638",
            Some("2026-09-14T09:00:00+00:00"),
            Some("IntuneManagementExtension"),
            None,
            Some("machine"),
            "application name: Contoso Secure Client, installer exit code 1638",
        );
        correlate(&conn).unwrap();

        let summary = crate::db::summary(&conn).unwrap();
        let impact = summary
            .user_impact
            .iter()
            .find(|item| item.kind == "application")
            .expect("application impact");
        assert_eq!(impact.name, "Contoso Secure Client");
        assert!(impact.detail.contains("1638"));
        assert!(impact.detail.contains("Another version"));
        assert_eq!(impact.severity, "high");
        let title: String = conn
            .query_row(
                "SELECT title FROM findings WHERE rule_id='ime.app.unmapped-exit.v1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(title.contains("Contoso Secure Client"));
        assert!(exit_semantics(1603).is_some());
        assert!(exit_semantics(-2147024891).is_some());
    }

    #[test]
    fn resolves_policy_package_and_profile_display_names() {
        let root = tempfile::tempdir().unwrap();
        let conn = database(
            &root.path().join("analysis.sqlite"),
            "MDMDiagnosticReport.xml",
        );
        event(
            &conn,
            "policy",
            Some("2026-08-12T09:00:00+00:00"),
            Some("PolicyManager"),
            None,
            Some("machine"),
            "Policy name: Windows Security Baseline applied successfully",
        );
        event(
            &conn,
            "profile",
            Some("2026-08-12T09:01:00+00:00"),
            Some("PolicyManager"),
            None,
            Some("machine"),
            r#"Network profile payload {"displayName":"Corporate Wi-Fi"} completed"#,
        );
        event(
            &conn,
            "package",
            Some("2026-08-12T09:02:00+00:00"),
            Some("PolicyManager"),
            None,
            Some("machine"),
            "Package name: Support Tools observed",
        );
        correlate(&conn).unwrap();

        let names: Vec<String> = conn
            .prepare("SELECT name FROM managed_entities ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(names.iter().any(|name| name.contains("Corporate Wi-Fi")));
        assert!(names.iter().any(|name| name == "Support Tools"));
        assert!(names.iter().any(|name| name == "Windows Security Baseline"));
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
    fn base64_tokens_do_not_become_installer_exit_codes() {
        let root = tempfile::tempdir().unwrap();
        let conn = database(
            &root.path().join("analysis.sqlite"),
            "IntuneManagementExtension.log",
        );
        event(
            &conn,
            "policy-json",
            Some("2026-09-14T09:00:00+00:00"),
            Some("IntuneManagementExtension"),
            None,
            Some("machine"),
            "Get policies = [{\"Id\":\"11111111-2222-3333-4444-555555555555\",\"Name\":\"Google Drive 129.0.1\",\"Token\":\"FXDb3K26ExiTGJ4033F1ksSB\",\"InstallContext\":2,\"Intent\":4}]",
        );
        correlate(&conn).unwrap();

        let attempts: i64 = conn
            .query_row("SELECT COUNT(*) FROM execution_attempts", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(attempts, 0);
        let state: String = conn
            .query_row("SELECT state FROM applications", [], |row| row.get(0))
            .unwrap();
        assert_eq!(state, "observed");
    }

    #[test]
    fn script_path_guids_attribute_results_to_named_apps() {
        let root = tempfile::tempdir().unwrap();
        let conn = database(
            &root.path().join("analysis.sqlite"),
            "IntuneManagementExtension.log",
        );
        for (key, message) in [
            (
                "policy",
                r#"Get policies = [{"Id":"11111111-2222-3333-4444-555555555555","Name":"Google Drive 129.0.1","Intent":4}]"#,
            ),
            (
                "detect",
                r#"C:\Program Files (x86)\Microsoft Intune Management Extension\Content\DetectionScripts\11111111-2222-3333-4444-555555555555_1.ps1"#,
            ),
            ("exit", "Powershell exit code is 5"),
            (
                "other-detect",
                r#"[Win32App] Detection script file C:\Program Files (x86)\Microsoft Intune Management Extension\Content\DetectionScripts\99999999-2222-3333-4444-555555555555_1.ps1 is saved."#,
            ),
            ("other-exit", "Powershell exit code is 0"),
        ] {
            event(
                &conn,
                key,
                Some("2026-09-14T09:00:00+00:00"),
                Some("IntuneManagementExtension"),
                None,
                Some("machine"),
                message,
            );
        }
        correlate(&conn).unwrap();

        let (state, attempts): (String, i64) = conn
            .query_row(
                "SELECT state,attempt_count FROM applications WHERE name='Google Drive 129.0.1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((state.as_str(), attempts), ("failed", 1));
        let exit: i64 = conn
            .query_row(
                "SELECT exit_code FROM execution_attempts LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exit, 5);
        let unnamed: String = conn
            .query_row(
                "SELECT name FROM applications WHERE name LIKE 'Unknown application (%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unnamed, "Unknown application (99999999…)");
        let anonymous: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM applications WHERE name='Unknown application'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(anonymous, 0);
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
