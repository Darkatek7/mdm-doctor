use std::{collections::HashSet, path::Path};

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use crate::{
    RULE_PACK_VERSION,
    error::{AppError, Result},
    models::{
        Application, Artifact, CoverageRecord, EspResource, EvidenceLink, ExecutionAttempt,
        Finding, Kpis, ManagedEntity, ParseWarning, ProvisioningStep, Session, Summary,
        TimelineEvent, TimelinePage, TimelineQuery,
    },
};

pub const DB_FILE: &str = "analysis.sqlite";

pub fn open(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    configure(&conn)?;
    Ok(conn)
}

pub fn open_read_only(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    configure(&conn)?;
    Ok(conn)
}

fn configure(conn: &Connection) -> Result<()> {
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "trusted_schema", "OFF")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    conn.pragma_update(None, "journal_mode", "OFF")?;
    conn.pragma_update(None, "synchronous", "OFF")?;
    Ok(())
}

pub fn initialize(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE artifacts (
            id TEXT PRIMARY KEY,
            parent_id TEXT REFERENCES artifacts(id),
            layer INTEGER NOT NULL,
            normalized_path TEXT NOT NULL,
            original_path TEXT NOT NULL,
            object_path TEXT NOT NULL,
            size INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            detected_type TEXT NOT NULL,
            parser_status TEXT NOT NULL DEFAULT 'pending',
            duplicate_of TEXT,
            warning TEXT,
            UNIQUE(parent_id, normalized_path COLLATE NOCASE)
        );
        CREATE INDEX artifacts_sha256 ON artifacts(sha256);
        CREATE INDEX artifacts_type ON artifacts(detected_type);

        CREATE TABLE collection_requests (
            id TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            result_code TEXT,
            core INTEGER NOT NULL,
            state TEXT NOT NULL,
            evidence_id TEXT
        );

        CREATE TABLE device_snapshots (
            id TEXT PRIMARY KEY,
            captured_at TEXT,
            device_identity_hash TEXT,
            os_version TEXT,
            join_state TEXT,
            device_auth_state TEXT,
            user_prt_state TEXT,
            context TEXT,
            evidence_ids TEXT NOT NULL DEFAULT '[]'
        );

        CREATE TABLE sessions (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            current INTEGER NOT NULL,
            started_at TEXT,
            ended_at TEXT,
            label TEXT NOT NULL,
            evidence_ids TEXT NOT NULL DEFAULT '[]'
        );

        CREATE TABLE events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            artifact_id TEXT NOT NULL REFERENCES artifacts(id),
            session_id TEXT,
            timestamp_utc TEXT,
            timestamp_original TEXT,
            utc_offset_minutes INTEGER,
            provider TEXT,
            channel TEXT,
            event_code TEXT,
            component TEXT,
            context TEXT,
            severity TEXT NOT NULL,
            entity_id TEXT,
            message TEXT NOT NULL,
            source_span TEXT,
            current INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX events_time ON events(timestamp_utc, sequence);
        CREATE INDEX events_provider_code ON events(provider, event_code);
        CREATE INDEX events_component ON events(component);
        CREATE INDEX events_entity ON events(entity_id);
        CREATE VIRTUAL TABLE events_fts USING fts5(
            event_id UNINDEXED, message, provider, component,
            tokenize = 'unicode61 remove_diacritics 2'
        );

        CREATE TABLE managed_entities (
            id TEXT PRIMARY KEY,
            entity_type TEXT NOT NULL,
            name TEXT NOT NULL,
            state TEXT NOT NULL,
            current INTEGER NOT NULL,
            evidence_ids TEXT NOT NULL DEFAULT '[]',
            details_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE applications (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            app_type TEXT NOT NULL,
            intent TEXT,
            install_context TEXT,
            state TEXT NOT NULL,
            esp_tracked INTEGER NOT NULL DEFAULT 0,
            attempt_count INTEGER NOT NULL DEFAULT 0,
            evidence_ids TEXT NOT NULL DEFAULT '[]',
            details_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE policies (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            policy_type TEXT NOT NULL,
            state TEXT NOT NULL,
            current INTEGER NOT NULL,
            evidence_ids TEXT NOT NULL DEFAULT '[]'
        );
        CREATE TABLE certificates (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            state TEXT NOT NULL,
            current INTEGER NOT NULL,
            evidence_ids TEXT NOT NULL DEFAULT '[]'
        );
        CREATE TABLE network_profiles (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            state TEXT NOT NULL,
            current INTEGER NOT NULL,
            evidence_ids TEXT NOT NULL DEFAULT '[]'
        );
        CREATE TABLE scripts (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            state TEXT NOT NULL,
            exit_code INTEGER,
            current INTEGER NOT NULL,
            evidence_ids TEXT NOT NULL DEFAULT '[]'
        );

        CREATE TABLE execution_attempts (
            id TEXT PRIMARY KEY,
            application_id TEXT,
            started_at TEXT,
            ended_at TEXT,
            exit_code INTEGER,
            detection_result TEXT,
            reboot_during_attempt INTEGER NOT NULL DEFAULT 0,
            state TEXT NOT NULL,
            evidence_ids TEXT NOT NULL DEFAULT '[]'
        );

        CREATE TABLE esp_resources (
            id TEXT PRIMARY KEY,
            entity_id TEXT,
            resource_type TEXT NOT NULL,
            phase TEXT NOT NULL,
            substep TEXT NOT NULL,
            expected_state TEXT NOT NULL,
            actual_state TEXT NOT NULL,
            blocking_proven INTEGER NOT NULL,
            first_failure INTEGER NOT NULL,
            evidence_ids TEXT NOT NULL DEFAULT '[]'
        );

        CREATE TABLE provisioning_steps (
            id TEXT PRIMARY KEY,
            session_id TEXT,
            phase TEXT NOT NULL,
            substep TEXT NOT NULL,
            state TEXT NOT NULL,
            started_at TEXT,
            ended_at TEXT,
            evidence_ids TEXT NOT NULL DEFAULT '[]'
        );

        CREATE TABLE findings (
            id TEXT PRIMARY KEY,
            rule_id TEXT NOT NULL,
            rule_pack TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            current INTEGER NOT NULL,
            esp_tracked INTEGER NOT NULL,
            entity_id TEXT,
            title TEXT NOT NULL,
            explanation TEXT NOT NULL,
            recommendation TEXT NOT NULL
        );

        CREATE TABLE evidence_links (
            id TEXT PRIMARY KEY,
            finding_id TEXT,
            artifact_id TEXT NOT NULL REFERENCES artifacts(id),
            event_id TEXT,
            source_span TEXT,
            label TEXT NOT NULL
        );
        CREATE INDEX evidence_finding ON evidence_links(finding_id);
        CREATE INDEX evidence_event ON evidence_links(event_id);
        CREATE INDEX evidence_artifact ON evidence_links(artifact_id);

        CREATE TABLE rule_evaluations (
            id TEXT PRIMARY KEY,
            rule_id TEXT NOT NULL,
            rule_pack TEXT NOT NULL,
            outcome TEXT NOT NULL,
            evidence_ids TEXT NOT NULL DEFAULT '[]',
            details_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE coverage (
            id TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            classification TEXT NOT NULL,
            state TEXT NOT NULL,
            result_code TEXT,
            parser TEXT NOT NULL,
            artifact_count INTEGER NOT NULL,
            explanation TEXT NOT NULL
        );

        CREATE TABLE parse_warnings (
            id TEXT PRIMARY KEY,
            artifact_id TEXT,
            code TEXT NOT NULL,
            message TEXT NOT NULL
        );

        CREATE TABLE metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        "#,
    )?;
    conn.execute(
        "INSERT INTO metadata(key, value) VALUES ('rule_pack', ?1)",
        [RULE_PACK_VERSION],
    )?;
    Ok(())
}

#[derive(Debug)]
pub struct NewArtifact<'a> {
    pub id: &'a str,
    pub parent_id: Option<&'a str>,
    pub layer: u32,
    pub normalized_path: &'a str,
    pub original_path: &'a str,
    pub object_path: &'a str,
    pub size: u64,
    pub sha256: &'a str,
    pub detected_type: &'a str,
    pub duplicate_of: Option<&'a str>,
    pub warning: Option<&'a str>,
}

pub fn insert_artifact(conn: &Connection, a: &NewArtifact<'_>) -> Result<()> {
    conn.execute(
        "INSERT INTO artifacts(id,parent_id,layer,normalized_path,original_path,object_path,size,sha256,detected_type,duplicate_of,warning) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![a.id,a.parent_id,a.layer,a.normalized_path,a.original_path,a.object_path,a.size as i64,a.sha256,a.detected_type,a.duplicate_of,a.warning],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn insert_event(
    conn: &Connection,
    id: &str,
    artifact_id: &str,
    timestamp_utc: Option<&str>,
    timestamp_original: Option<&str>,
    utc_offset_minutes: Option<i32>,
    provider: Option<&str>,
    channel: Option<&str>,
    event_code: Option<&str>,
    component: Option<&str>,
    context: Option<&str>,
    severity: &str,
    entity_id: Option<&str>,
    message: &str,
    source_span: Option<&str>,
) -> Result<u64> {
    conn.execute(
        "INSERT OR IGNORE INTO events(id,artifact_id,timestamp_utc,timestamp_original,utc_offset_minutes,provider,channel,event_code,component,context,severity,entity_id,message,source_span) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        params![id,artifact_id,timestamp_utc,timestamp_original,utc_offset_minutes,provider,channel,event_code,component,context,severity,entity_id,message,source_span],
    )?;
    let sequence: i64 = conn.query_row("SELECT sequence FROM events WHERE id=?1", [id], |row| {
        row.get(0)
    })?;
    conn.execute(
        "INSERT OR IGNORE INTO events_fts(rowid,event_id,message,provider,component) VALUES (?1,?2,?3,?4,?5)",
        params![sequence,id,message,provider,component],
    )?;
    Ok(sequence as u64)
}

pub fn set_artifact_status(
    conn: &Connection,
    id: &str,
    status: &str,
    warning: Option<&str>,
) -> Result<()> {
    conn.execute(
        "UPDATE artifacts SET parser_status=?2, warning=COALESCE(?3, warning) WHERE id=?1",
        params![id, status, warning],
    )?;
    Ok(())
}

pub fn insert_warning(conn: &Connection, warning: &ParseWarning) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO parse_warnings(id,artifact_id,code,message) VALUES (?1,?2,?3,?4)",
        params![
            warning.id,
            warning.artifact_id,
            warning.code,
            warning.message
        ],
    )?;
    Ok(())
}

pub fn upsert_coverage(conn: &Connection, c: &CoverageRecord) -> Result<()> {
    conn.execute(
        "INSERT INTO coverage(id,source,classification,state,result_code,parser,artifact_count,explanation) VALUES (?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(id) DO UPDATE SET state=excluded.state, result_code=excluded.result_code, parser=excluded.parser, artifact_count=excluded.artifact_count, explanation=excluded.explanation",
        params![c.id,c.source,c.classification,c.state,c.result_code,c.parser,c.artifact_count as i64,c.explanation],
    )?;
    Ok(())
}

pub fn insert_evidence(
    conn: &Connection,
    finding_id: Option<&str>,
    e: &EvidenceLink,
) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO evidence_links(id,finding_id,artifact_id,event_id,source_span,label) VALUES (?1,?2,?3,?4,?5,?6)",
        params![e.id,finding_id,e.artifact_id,e.event_id,e.source_span,e.label],
    )?;
    Ok(())
}

pub fn insert_finding(conn: &Connection, f: &Finding) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO findings(id,rule_id,rule_pack,severity,confidence,current,esp_tracked,entity_id,title,explanation,recommendation) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![f.id,f.rule_id,f.rule_pack,f.severity,f.confidence,f.current,f.esp_tracked,f.entity_id,f.title,f.explanation,f.recommendation],
    )?;
    for e in &f.evidence {
        insert_evidence(conn, Some(&f.id), e)?;
    }
    Ok(())
}

pub fn insert_rule_evaluation(
    conn: &Connection,
    id: &str,
    rule_id: &str,
    outcome: &str,
    evidence_ids: &[String],
) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO rule_evaluations(id,rule_id,rule_pack,outcome,evidence_ids) VALUES (?1,?2,?3,?4,?5)",
        params![id,rule_id,RULE_PACK_VERSION,outcome,json(evidence_ids)],
    )?;
    Ok(())
}

pub fn insert_session(conn: &Connection, s: &Session) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO sessions(id,kind,current,started_at,ended_at,label,evidence_ids) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![s.id,s.kind,s.current,s.started_at,s.ended_at,s.label,json(&s.evidence_ids)],
    )?;
    Ok(())
}

pub fn insert_application(conn: &Connection, a: &Application) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO applications(id,name,app_type,intent,install_context,state,esp_tracked,attempt_count,evidence_ids) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![a.id,a.name,a.app_type,a.intent,a.install_context,a.state,a.esp_tracked,a.attempt_count as i64,json(&a.evidence_ids)],
    )?;
    Ok(())
}

pub fn insert_attempt(conn: &Connection, a: &ExecutionAttempt) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO execution_attempts(id,application_id,started_at,ended_at,exit_code,detection_result,reboot_during_attempt,state,evidence_ids) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![a.id,a.application_id,a.started_at,a.ended_at,a.exit_code,a.detection_result,a.reboot_during_attempt,a.state,json(&a.evidence_ids)],
    )?;
    Ok(())
}

pub fn insert_entity(conn: &Connection, e: &ManagedEntity) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO managed_entities(id,entity_type,name,state,current,evidence_ids) VALUES (?1,?2,?3,?4,?5,?6)",
        params![e.id,e.entity_type,e.name,e.state,e.current,json(&e.evidence_ids)],
    )?;
    Ok(())
}

pub fn insert_esp_resource(conn: &Connection, e: &EspResource) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO esp_resources(id,entity_id,resource_type,phase,substep,expected_state,actual_state,blocking_proven,first_failure,evidence_ids) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![e.id,e.entity_id,e.resource_type,e.phase,e.substep,e.expected_state,e.actual_state,e.blocking_proven,e.first_failure,json(&e.evidence_ids)],
    )?;
    Ok(())
}

pub fn insert_step(conn: &Connection, s: &ProvisioningStep) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO provisioning_steps(id,session_id,phase,substep,state,started_at,ended_at,evidence_ids) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![s.id,s.session_id,s.phase,s.substep,s.state,s.started_at,s.ended_at,json(&s.evidence_ids)],
    )?;
    Ok(())
}

pub fn artifacts(conn: &Connection) -> Result<Vec<Artifact>> {
    let mut stmt = conn.prepare("SELECT id,parent_id,layer,normalized_path,original_path,size,sha256,detected_type,parser_status,duplicate_of,warning FROM artifacts ORDER BY layer, normalized_path")?;
    let rows = stmt.query_map([], |r| {
        Ok(Artifact {
            id: r.get(0)?,
            parent_id: r.get(1)?,
            layer: r.get(2)?,
            normalized_path: r.get(3)?,
            original_path: r.get(4)?,
            size: r.get::<_, i64>(5)? as u64,
            sha256: r.get(6)?,
            detected_type: r.get(7)?,
            parser_status: r.get(8)?,
            duplicate_of: r.get(9)?,
            warning: r.get(10)?,
        })
    })?;
    collect(rows)
}

pub fn artifact_object(conn: &Connection, id: &str) -> Result<Option<(String, String, String)>> {
    conn.query_row(
        "SELECT object_path, original_path, detected_type FROM artifacts WHERE id=?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .optional()
    .map_err(Into::into)
}

pub fn evidence(conn: &Connection, ids: &[String]) -> Result<Vec<EvidenceLink>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let requested: HashSet<&str> = ids.iter().map(String::as_str).collect();
    let mut stmt = conn.prepare(
        "SELECT id,artifact_id,event_id,source_span,label FROM evidence_links ORDER BY id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(EvidenceLink {
            id: r.get(0)?,
            artifact_id: r.get(1)?,
            event_id: r.get(2)?,
            source_span: r.get(3)?,
            label: r.get(4)?,
        })
    })?;
    Ok(collect(rows)?
        .into_iter()
        .filter(|e| requested.contains(e.id.as_str()))
        .collect())
}

pub fn findings(conn: &Connection) -> Result<Vec<Finding>> {
    let mut stmt = conn.prepare("SELECT id,rule_id,rule_pack,severity,confidence,current,esp_tracked,entity_id,title,explanation,recommendation FROM findings ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, current DESC, id")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let id: String = r.get(0)?;
        let mut ev = conn.prepare("SELECT id,artifact_id,event_id,source_span,label FROM evidence_links WHERE finding_id=?1 ORDER BY id")?;
        let evidence = collect(ev.query_map([&id], |e| {
            Ok(EvidenceLink {
                id: e.get(0)?,
                artifact_id: e.get(1)?,
                event_id: e.get(2)?,
                source_span: e.get(3)?,
                label: e.get(4)?,
            })
        })?)?;
        out.push(Finding {
            id,
            rule_id: r.get(1)?,
            rule_pack: r.get(2)?,
            severity: r.get(3)?,
            confidence: r.get(4)?,
            current: r.get(5)?,
            esp_tracked: r.get(6)?,
            entity_id: r.get(7)?,
            title: r.get(8)?,
            explanation: r.get(9)?,
            recommendation: r.get(10)?,
            evidence,
        });
    }
    Ok(out)
}

pub fn sessions(conn: &Connection) -> Result<Vec<Session>> {
    let mut stmt=conn.prepare("SELECT id,kind,current,started_at,ended_at,label,evidence_ids FROM sessions ORDER BY current DESC, started_at DESC")?;
    collect(stmt.query_map([], |r| {
        Ok(Session {
            id: r.get(0)?,
            kind: r.get(1)?,
            current: r.get(2)?,
            started_at: r.get(3)?,
            ended_at: r.get(4)?,
            label: r.get(5)?,
            evidence_ids: unjson(r.get::<_, String>(6)?),
        })
    })?)
}

pub fn applications(conn: &Connection) -> Result<Vec<Application>> {
    let mut stmt=conn.prepare("SELECT id,name,app_type,intent,install_context,state,esp_tracked,attempt_count,evidence_ids FROM applications ORDER BY name")?;
    collect(stmt.query_map([], |r| {
        Ok(Application {
            id: r.get(0)?,
            name: r.get(1)?,
            app_type: r.get(2)?,
            intent: r.get(3)?,
            install_context: r.get(4)?,
            state: r.get(5)?,
            esp_tracked: r.get(6)?,
            attempt_count: r.get::<_, i64>(7)? as u64,
            evidence_ids: unjson(r.get::<_, String>(8)?),
        })
    })?)
}

pub fn attempts(conn: &Connection) -> Result<Vec<ExecutionAttempt>> {
    let mut stmt=conn.prepare("SELECT id,application_id,started_at,ended_at,exit_code,detection_result,reboot_during_attempt,state,evidence_ids FROM execution_attempts ORDER BY started_at")?;
    collect(stmt.query_map([], |r| {
        Ok(ExecutionAttempt {
            id: r.get(0)?,
            application_id: r.get(1)?,
            started_at: r.get(2)?,
            ended_at: r.get(3)?,
            exit_code: r.get(4)?,
            detection_result: r.get(5)?,
            reboot_during_attempt: r.get(6)?,
            state: r.get(7)?,
            evidence_ids: unjson(r.get::<_, String>(8)?),
        })
    })?)
}

pub fn entities(conn: &Connection) -> Result<Vec<ManagedEntity>> {
    let mut stmt=conn.prepare("SELECT id,entity_type,name,state,current,evidence_ids FROM managed_entities ORDER BY entity_type,name")?;
    collect(stmt.query_map([], |r| {
        Ok(ManagedEntity {
            id: r.get(0)?,
            entity_type: r.get(1)?,
            name: r.get(2)?,
            state: r.get(3)?,
            current: r.get(4)?,
            evidence_ids: unjson(r.get::<_, String>(5)?),
        })
    })?)
}

pub fn esp_resources(conn: &Connection) -> Result<Vec<EspResource>> {
    let mut stmt=conn.prepare("SELECT id,entity_id,resource_type,phase,substep,expected_state,actual_state,blocking_proven,first_failure,evidence_ids FROM esp_resources ORDER BY phase,substep,id")?;
    collect(stmt.query_map([], |r| {
        Ok(EspResource {
            id: r.get(0)?,
            entity_id: r.get(1)?,
            resource_type: r.get(2)?,
            phase: r.get(3)?,
            substep: r.get(4)?,
            expected_state: r.get(5)?,
            actual_state: r.get(6)?,
            blocking_proven: r.get(7)?,
            first_failure: r.get(8)?,
            evidence_ids: unjson(r.get::<_, String>(9)?),
        })
    })?)
}

pub fn steps(conn: &Connection) -> Result<Vec<ProvisioningStep>> {
    let mut stmt=conn.prepare("SELECT id,session_id,phase,substep,state,started_at,ended_at,evidence_ids FROM provisioning_steps ORDER BY started_at,phase,substep")?;
    collect(stmt.query_map([], |r| {
        Ok(ProvisioningStep {
            id: r.get(0)?,
            session_id: r.get(1)?,
            phase: r.get(2)?,
            substep: r.get(3)?,
            state: r.get(4)?,
            started_at: r.get(5)?,
            ended_at: r.get(6)?,
            evidence_ids: unjson(r.get::<_, String>(7)?),
        })
    })?)
}

pub fn coverage(conn: &Connection) -> Result<Vec<CoverageRecord>> {
    let mut stmt=conn.prepare("SELECT id,source,classification,state,result_code,parser,artifact_count,explanation FROM coverage ORDER BY classification,source")?;
    collect(stmt.query_map([], |r| {
        Ok(CoverageRecord {
            id: r.get(0)?,
            source: r.get(1)?,
            classification: r.get(2)?,
            state: r.get(3)?,
            result_code: r.get(4)?,
            parser: r.get(5)?,
            artifact_count: r.get::<_, i64>(6)? as u64,
            explanation: r.get(7)?,
        })
    })?)
}

pub fn warnings(conn: &Connection) -> Result<Vec<ParseWarning>> {
    let mut stmt =
        conn.prepare("SELECT id,artifact_id,code,message FROM parse_warnings ORDER BY id")?;
    collect(stmt.query_map([], |r| {
        Ok(ParseWarning {
            id: r.get(0)?,
            artifact_id: r.get(1)?,
            code: r.get(2)?,
            message: r.get(3)?,
        })
    })?)
}

pub fn summary(conn: &Connection) -> Result<Summary> {
    let artifacts = count(conn, "artifacts")?;
    let parsed_events = count(conn, "events")?;
    let finding_rows = findings(conn)?;
    let applications = count(conn, "applications")?;
    let coverage_rows = coverage(conn)?;
    let supported = coverage_rows.iter().filter(|c| c.state == "parsed").count();
    let considered = coverage_rows
        .iter()
        .filter(|c| c.state != "not_requested")
        .count();
    let coverage_percent = if considered == 0 {
        0.0
    } else {
        (supported as f64 / considered as f64) * 100.0
    };
    let critical = findings(conn)?
        .into_iter()
        .filter(|f| f.current && f.severity == "critical")
        .count() as u64;
    let top = finding_rows
        .iter()
        .find(|f| f.current)
        .or_else(|| finding_rows.first());
    let latest_session_id: Option<String> = conn
        .query_row(
            "SELECT id FROM sessions ORDER BY current DESC, started_at DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let first_blocking_step: Option<String> = conn
        .query_row(
            "SELECT substep FROM esp_resources WHERE first_failure=1 AND blocking_proven=1 LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    Ok(Summary {
        verdict: top
            .map(|f| f.title.clone())
            .unwrap_or_else(|| "No evidence-backed blocking failure was identified.".into()),
        confidence: top
            .map(|f| f.confidence.clone())
            .unwrap_or_else(|| "low".into()),
        current_status: if top.is_some_and(|f| f.current) {
            "current finding".into()
        } else if top.is_some() {
            "historical finding".into()
        } else {
            "no current failure proven".into()
        },
        evidence_completeness: if coverage_percent >= 80.0 {
            "high".into()
        } else if coverage_percent >= 50.0 {
            "partial".into()
        } else {
            "limited".into()
        },
        first_blocking_step,
        recommended_actions: top
            .map(|f| vec![f.recommendation.clone()])
            .unwrap_or_else(|| {
                vec!["Review collection coverage before ruling out an uncollected source.".into()]
            }),
        kpis: Kpis {
            artifacts,
            parsed_events,
            findings: finding_rows.len() as u64,
            critical_findings: critical,
            applications,
            coverage_percent,
        },
        latest_session_id,
        rule_pack: RULE_PACK_VERSION.into(),
    })
}

pub fn timeline(
    conn: &Connection,
    q: &TimelineQuery,
    default_limit: usize,
    max_limit: usize,
) -> Result<TimelinePage> {
    let limit = q.limit.unwrap_or(default_limit).clamp(1, max_limit);
    let cursor = q.cursor.unwrap_or(0);
    let search = q.search.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let mut items = if let Some(term) = search {
        let safe = fts_query(term);
        let mut stmt=conn.prepare("SELECT e.id,e.sequence,e.timestamp_utc,e.timestamp_original,e.utc_offset_minutes,e.provider,e.channel,e.event_code,e.component,e.severity,e.entity_id,e.message,e.current,COALESCE((SELECT id FROM evidence_links x WHERE x.event_id=e.id LIMIT 1),'evidence:'||e.id) FROM events e JOIN events_fts f ON f.rowid=e.sequence WHERE e.sequence>?1 AND events_fts MATCH ?2 ORDER BY e.sequence LIMIT ?3")?;
        let rows = stmt.query_map(
            params![cursor as i64, safe, (limit + 1) as i64],
            timeline_row,
        )?;
        collect(rows)?
    } else {
        let mut stmt=conn.prepare("SELECT e.id,e.sequence,e.timestamp_utc,e.timestamp_original,e.utc_offset_minutes,e.provider,e.channel,e.event_code,e.component,e.severity,e.entity_id,e.message,e.current,COALESCE((SELECT id FROM evidence_links x WHERE x.event_id=e.id LIMIT 1),'evidence:'||e.id) FROM events e WHERE e.sequence>?1 ORDER BY e.sequence LIMIT ?2")?;
        let rows = stmt.query_map(params![cursor as i64, (limit + 1) as i64], timeline_row)?;
        collect(rows)?
    };
    if let Some(sev) = &q.severity {
        items.retain(|e| sev.iter().any(|s| s.eq_ignore_ascii_case(&e.severity)));
    }
    if let Some(providers) = &q.provider {
        items.retain(|e| {
            e.provider
                .as_ref()
                .is_some_and(|p| providers.iter().any(|v| v.eq_ignore_ascii_case(p)))
        });
    }
    if let Some(components) = &q.component {
        items.retain(|e| {
            e.component
                .as_ref()
                .is_some_and(|p| components.iter().any(|v| v.eq_ignore_ascii_case(p)))
        });
    }
    let next_cursor = if items.len() > limit {
        items.truncate(limit);
        items.last().map(|e| e.sequence)
    } else {
        None
    };
    Ok(TimelinePage {
        items,
        next_cursor,
        total_estimate: count(conn, "events")?,
    })
}

fn timeline_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<TimelineEvent> {
    Ok(TimelineEvent {
        id: r.get(0)?,
        sequence: r.get::<_, i64>(1)? as u64,
        timestamp_utc: r.get(2)?,
        timestamp_original: r.get(3)?,
        utc_offset_minutes: r.get(4)?,
        provider: r.get(5)?,
        channel: r.get(6)?,
        event_code: r.get(7)?,
        component: r.get(8)?,
        severity: r.get(9)?,
        entity_id: r.get(10)?,
        message: r.get(11)?,
        current: r.get(12)?,
        evidence_id: r.get(13)?,
    })
}

fn fts_query(value: &str) -> String {
    value
        .split_whitespace()
        .take(12)
        .map(|token| format!("\"{}\"", token.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" AND ")
}

fn count(conn: &Connection, table: &str) -> Result<u64> {
    let sql = match table {
        "artifacts" => "SELECT COUNT(*) FROM artifacts",
        "events" => "SELECT COUNT(*) FROM events",
        "applications" => "SELECT COUNT(*) FROM applications",
        _ => return Err(AppError::Internal),
    };
    Ok(conn.query_row(sql, [], |r| r.get::<_, i64>(0))? as u64)
}

fn json<T: serde::Serialize + ?Sized>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "[]".into())
}
fn unjson<T: serde::de::DeserializeOwned + Default>(value: String) -> T {
    serde_json::from_str(&value).unwrap_or_default()
}
fn collect<T>(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>>,
) -> Result<Vec<T>> {
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}
