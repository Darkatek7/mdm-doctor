use std::{collections::HashSet, path::Path};

use rusqlite::{Connection, OpenFlags, OptionalExtension, params, params_from_iter, types::Value};

use crate::{
    RULE_PACK_VERSION,
    error::{AppError, Result},
    models::{
        Application, ApplicationPage, ApplicationQuery, ApplicationSummary, Artifact,
        CoverageRecord, EntityPage, EntityQuery, EntitySummary, EntityTypeCount, EspResource,
        EvidenceLink, ExecutionAttempt, Finding, FindingCounts, FindingPage, FindingQuery,
        HealthCheck, Kpis, ManagedEntity, ParseWarning, PrimaryDiagnosis, ProvisioningStep,
        Session, Summary, TimelineEvent, TimelinePage, TimelineQuery,
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
            current INTEGER NOT NULL DEFAULT 0,
            temporal_scope TEXT NOT NULL DEFAULT 'unknown',
            occurrence_count INTEGER NOT NULL DEFAULT 1
        );
        CREATE VIRTUAL TABLE events_fts USING fts5(
            message, provider, component,
            content='events', content_rowid='sequence',
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
            recommendation TEXT NOT NULL,
            temporal_scope TEXT NOT NULL DEFAULT 'unknown',
            occurrence_count INTEGER NOT NULL DEFAULT 1,
            last_seen_at TEXT
        );

        CREATE TABLE evidence_links (
            id TEXT PRIMARY KEY,
            finding_id TEXT,
            artifact_id TEXT NOT NULL REFERENCES artifacts(id),
            event_id TEXT,
            source_span TEXT,
            label TEXT NOT NULL
        );
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
) -> Result<Option<u64>> {
    let inserted = conn.prepare_cached(
        "INSERT OR IGNORE INTO events(id,artifact_id,timestamp_utc,timestamp_original,utc_offset_minutes,provider,channel,event_code,component,context,severity,entity_id,message,source_span) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
    )?.execute(params![id,artifact_id,timestamp_utc,timestamp_original,utc_offset_minutes,provider,channel,event_code,component,context,severity,entity_id,message,source_span])?;
    Ok((inserted == 1).then(|| conn.last_insert_rowid() as u64))
}

pub fn add_event_occurrences(
    conn: &Connection,
    counts: &std::collections::HashMap<String, u64>,
) -> Result<()> {
    let mut stmt =
        conn.prepare_cached("UPDATE events SET occurrence_count=occurrence_count+?2 WHERE id=?1")?;
    for (id, count) in counts {
        stmt.execute(params![id, *count as i64])?;
    }
    Ok(())
}

pub fn finalize_event_index(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE INDEX IF NOT EXISTS events_time ON events(timestamp_utc, sequence);
        CREATE INDEX IF NOT EXISTS events_provider_code ON events(provider, event_code);
        CREATE INDEX IF NOT EXISTS events_component ON events(component);
        CREATE INDEX IF NOT EXISTS events_entity ON events(entity_id);
        CREATE INDEX IF NOT EXISTS events_severity_scope ON events(severity, temporal_scope, sequence);
        CREATE INDEX IF NOT EXISTS evidence_finding ON evidence_links(finding_id);
        CREATE INDEX IF NOT EXISTS evidence_event ON evidence_links(event_id);
        CREATE INDEX IF NOT EXISTS evidence_artifact ON evidence_links(artifact_id);
        INSERT INTO events_fts(events_fts) VALUES('rebuild');
        "#,
    )?;
    Ok(())
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
    conn.prepare_cached(
        "INSERT OR REPLACE INTO evidence_links(id,finding_id,artifact_id,event_id,source_span,label) VALUES (?1,?2,?3,?4,?5,?6)",
    )?.execute(params![e.id,finding_id,e.artifact_id,e.event_id,e.source_span,e.label])?;
    Ok(())
}

pub fn insert_finding(conn: &Connection, f: &Finding) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO findings(id,rule_id,rule_pack,severity,confidence,current,esp_tracked,entity_id,title,explanation,recommendation,temporal_scope,occurrence_count,last_seen_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        params![f.id,f.rule_id,f.rule_pack,f.severity,f.confidence,f.current,f.esp_tracked,f.entity_id,f.title,f.explanation,f.recommendation,f.temporal_scope,f.occurrence_count as i64,f.last_seen_at],
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
    let mut out = Vec::with_capacity(ids.len());
    let mut direct = conn.prepare_cached(
        "SELECT id,artifact_id,event_id,source_span,label FROM evidence_links WHERE id=?1",
    )?;
    let mut fallback = conn.prepare_cached(
        "SELECT artifact_id,id,source_span,COALESCE(component,provider,'source')||' evidence' FROM events WHERE id=?1",
    )?;
    for id in requested {
        if let Some(value) = direct.query_row([id], evidence_row).optional()? {
            out.push(value);
            continue;
        }
        if let Some(event_id) = id.strip_prefix("evidence:")
            && let Some(value) = fallback
                .query_row([event_id], |r| {
                    Ok(EvidenceLink {
                        id: id.to_owned(),
                        artifact_id: r.get(0)?,
                        event_id: Some(r.get(1)?),
                        source_span: r.get(2)?,
                        label: r.get(3)?,
                    })
                })
                .optional()?
        {
            out.push(value);
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

pub fn findings(conn: &Connection) -> Result<Vec<Finding>> {
    let mut stmt = conn.prepare("SELECT id,rule_id,rule_pack,severity,confidence,current,esp_tracked,entity_id,title,explanation,recommendation,temporal_scope,occurrence_count,last_seen_at FROM findings ORDER BY CASE temporal_scope WHEN 'current' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END, CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, last_seen_at DESC, id")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let id: String = r.get(0)?;
        let evidence = finding_evidence(conn, &id)?;
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
            temporal_scope: r.get(11)?,
            occurrence_count: r.get::<_, i64>(12)? as u64,
            last_seen_at: r.get(13)?,
            evidence,
        });
    }
    Ok(out)
}

pub fn query_findings(
    conn: &Connection,
    q: &FindingQuery,
    max_limit: usize,
) -> Result<FindingPage> {
    let limit = q.limit.unwrap_or(50).clamp(1, max_limit);
    let offset = q.cursor.unwrap_or(0);
    let mut where_sql = Vec::new();
    let mut values = Vec::<Value>::new();
    if let Some(search) = q.search.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        where_sql.push(
            "(lower(title) LIKE ? OR lower(explanation) LIKE ? OR lower(recommendation) LIKE ?)"
                .to_owned(),
        );
        let pattern = Value::Text(format!("%{}%", search.to_ascii_lowercase()));
        values.extend([pattern.clone(), pattern.clone(), pattern]);
    }
    push_list_filter(
        &mut where_sql,
        &mut values,
        "severity",
        q.severity.as_deref(),
    );
    push_list_filter(
        &mut where_sql,
        &mut values,
        "confidence",
        q.confidence.as_deref(),
    );
    push_list_filter(
        &mut where_sql,
        &mut values,
        "temporal_scope",
        q.temporal_scope.as_deref(),
    );
    if let Some(categories) = q.category.as_deref().filter(|v| !v.is_empty()) {
        let mut parts = Vec::new();
        for category in categories {
            let patterns: &[&str] = match category.to_ascii_lowercase().as_str() {
                "applications" => &["ime.app.%", "msi.%"],
                "esp" => &["esp.%"],
                "identity" => &["identity.%", "enrollment.%"],
                "certificates" => &["certificate.%"],
                "time" => &["time.%"],
                _ => continue,
            };
            for pattern in patterns {
                parts.push("lower(rule_id) LIKE ?".to_owned());
                values.push(Value::Text((*pattern).to_owned()));
            }
        }
        if !parts.is_empty() {
            where_sql.push(format!("({})", parts.join(" OR ")));
        }
    }
    let condition = if where_sql.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", where_sql.join(" AND "))
    };
    let total: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM findings{condition}"),
        params_from_iter(values.iter()),
        |r| r.get(0),
    )?;
    let mut page_values = values;
    page_values.push(Value::Integer((limit + 1) as i64));
    page_values.push(Value::Integer(offset as i64));
    let mut stmt = conn.prepare(&format!("SELECT id,rule_id,rule_pack,severity,confidence,current,esp_tracked,entity_id,title,explanation,recommendation,temporal_scope,occurrence_count,last_seen_at FROM findings{condition} ORDER BY CASE temporal_scope WHEN 'current' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END, CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, last_seen_at DESC,id LIMIT ? OFFSET ?"))?;
    let mut rows = stmt.query(params_from_iter(page_values.iter()))?;
    let mut items = Vec::with_capacity(limit + 1);
    while let Some(r) = rows.next()? {
        let id: String = r.get(0)?;
        items.push(Finding {
            id: id.clone(),
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
            temporal_scope: r.get(11)?,
            occurrence_count: r.get::<_, i64>(12)? as u64,
            last_seen_at: r.get(13)?,
            evidence: finding_evidence(conn, &id)?,
        });
    }
    let has_more = items.len() > limit;
    items.truncate(limit);
    Ok(FindingPage {
        items,
        next_cursor: has_more.then_some(offset + limit as u64),
        total: total as u64,
    })
}

fn evidence_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<EvidenceLink> {
    Ok(EvidenceLink {
        id: r.get(0)?,
        artifact_id: r.get(1)?,
        event_id: r.get(2)?,
        source_span: r.get(3)?,
        label: r.get(4)?,
    })
}

fn finding_evidence(conn: &Connection, id: &str) -> Result<Vec<EvidenceLink>> {
    let mut ev = conn.prepare_cached("SELECT id,artifact_id,event_id,source_span,label FROM evidence_links WHERE finding_id=?1 ORDER BY id")?;
    collect(ev.query_map([id], evidence_row)?)
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
    collect(stmt.query_map([], application_row)?)
}

fn application_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Application> {
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
}

pub fn query_applications(
    conn: &Connection,
    q: &ApplicationQuery,
    max_limit: usize,
) -> Result<ApplicationPage> {
    let limit = q.limit.unwrap_or(100).clamp(1, max_limit);
    let offset = q.cursor.unwrap_or(0);
    let mut where_sql = Vec::new();
    let mut values = Vec::<Value>::new();
    if let Some(search) = q.search.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        where_sql.push("lower(name) LIKE ?".to_owned());
        values.push(Value::Text(format!("%{}%", search.to_ascii_lowercase())));
    }
    push_list_filter(&mut where_sql, &mut values, "state", q.state.as_deref());
    push_list_filter(
        &mut where_sql,
        &mut values,
        "app_type",
        q.app_type.as_deref(),
    );
    if let Some(tracked) = q.esp_tracked {
        where_sql.push("esp_tracked=?".to_owned());
        values.push(Value::Integer(i64::from(tracked)));
    }
    if let Some(attempted) = q.attempted {
        where_sql.push(if attempted {
            "attempt_count>0".to_owned()
        } else {
            "attempt_count=0".to_owned()
        });
    }
    let condition = if where_sql.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", where_sql.join(" AND "))
    };
    let total: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM applications{condition}"),
        params_from_iter(values.iter()),
        |r| r.get(0),
    )?;
    let summary = conn.query_row(
        "SELECT COUNT(*),COALESCE(SUM(attempt_count>0),0),COALESCE(SUM(state='failed'),0),COALESCE(SUM(state='succeeded'),0),COALESCE(SUM(state='observed'),0),COALESCE(SUM(esp_tracked),0) FROM applications",
        [],
        |row| {
            Ok(ApplicationSummary {
                total: row.get::<_, i64>(0)? as u64,
                attempted: row.get::<_, i64>(1)? as u64,
                failed: row.get::<_, i64>(2)? as u64,
                succeeded: row.get::<_, i64>(3)? as u64,
                observed: row.get::<_, i64>(4)? as u64,
                esp_tracked: row.get::<_, i64>(5)? as u64,
            })
        },
    )?;
    let mut page_values = values;
    page_values.push(Value::Integer((limit + 1) as i64));
    page_values.push(Value::Integer(offset as i64));
    let mut stmt = conn.prepare(&format!("SELECT id,name,app_type,intent,install_context,state,esp_tracked,attempt_count,evidence_ids FROM applications{condition} ORDER BY name,id LIMIT ? OFFSET ?"))?;
    let mut items =
        collect(stmt.query_map(params_from_iter(page_values.iter()), application_row)?)?;
    let has_more = items.len() > limit;
    items.truncate(limit);
    Ok(ApplicationPage {
        items,
        next_cursor: has_more.then_some(offset + limit as u64),
        total: total as u64,
        summary,
    })
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
    collect(stmt.query_map([], entity_row)?)
}

fn entity_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ManagedEntity> {
    Ok(ManagedEntity {
        id: r.get(0)?,
        entity_type: r.get(1)?,
        name: r.get(2)?,
        state: r.get(3)?,
        current: r.get(4)?,
        evidence_ids: unjson(r.get::<_, String>(5)?),
    })
}

pub fn query_entities(conn: &Connection, q: &EntityQuery, max_limit: usize) -> Result<EntityPage> {
    let limit = q.limit.unwrap_or(100).clamp(1, max_limit);
    let offset = q.cursor.unwrap_or(0);
    let mut where_sql = Vec::new();
    let mut values = Vec::<Value>::new();
    if let Some(search) = q.search.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        where_sql.push("lower(name) LIKE ?".to_owned());
        values.push(Value::Text(format!("%{}%", search.to_ascii_lowercase())));
    }
    push_list_filter(
        &mut where_sql,
        &mut values,
        "entity_type",
        q.entity_type.as_deref(),
    );
    push_list_filter(&mut where_sql, &mut values, "state", q.state.as_deref());
    if let Some(current) = q.current {
        where_sql.push("current=?".to_owned());
        values.push(Value::Integer(i64::from(current)));
    }
    let condition = if where_sql.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", where_sql.join(" AND "))
    };
    let total: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM managed_entities{condition}"),
        params_from_iter(values.iter()),
        |r| r.get(0),
    )?;
    let mut scope_clauses = Vec::new();
    let mut scope_values = Vec::<Value>::new();
    push_list_filter(
        &mut scope_clauses,
        &mut scope_values,
        "entity_type",
        q.entity_type.as_deref(),
    );
    let scope_condition = if scope_clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", scope_clauses.join(" AND "))
    };
    let mut summary = conn.query_row(
        &format!("SELECT COUNT(*),COALESCE(SUM(current),0),COALESCE(SUM(NOT current),0),COALESCE(SUM(state='failed'),0),COALESCE(SUM(state='succeeded'),0),COALESCE(SUM(state='observed'),0) FROM managed_entities{scope_condition}"),
        params_from_iter(scope_values.iter()),
        |row| {
            Ok(EntitySummary {
                total: row.get::<_, i64>(0)? as u64,
                current: row.get::<_, i64>(1)? as u64,
                historical: row.get::<_, i64>(2)? as u64,
                failed: row.get::<_, i64>(3)? as u64,
                succeeded: row.get::<_, i64>(4)? as u64,
                observed: row.get::<_, i64>(5)? as u64,
                by_type: Vec::new(),
            })
        },
    )?;
    let mut type_stmt = conn.prepare(&format!(
        "SELECT entity_type,COUNT(*) FROM managed_entities{scope_condition} GROUP BY entity_type ORDER BY COUNT(*) DESC,entity_type"
    ))?;
    summary.by_type = collect(type_stmt.query_map(
        params_from_iter(scope_values.iter()),
        |row| {
            Ok(EntityTypeCount {
                entity_type: row.get(0)?,
                count: row.get::<_, i64>(1)? as u64,
            })
        },
    )?)?;
    let mut page_values = values;
    page_values.push(Value::Integer((limit + 1) as i64));
    page_values.push(Value::Integer(offset as i64));
    let mut stmt = conn.prepare(&format!("SELECT id,entity_type,name,state,current,evidence_ids FROM managed_entities{condition} ORDER BY CASE entity_type WHEN 'policy' THEN 0 WHEN 'package' THEN 1 WHEN 'profile' THEN 2 WHEN 'network profile' THEN 3 WHEN 'certificate' THEN 4 WHEN 'enrollment' THEN 5 WHEN 'identity' THEN 6 WHEN 'application' THEN 7 ELSE 8 END,name,id LIMIT ? OFFSET ?"))?;
    let mut items = collect(stmt.query_map(params_from_iter(page_values.iter()), entity_row)?)?;
    let has_more = items.len() > limit;
    items.truncate(limit);
    Ok(EntityPage {
        items,
        next_cursor: has_more.then_some(offset + limit as u64),
        total: total as u64,
        summary,
    })
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
    let critical = finding_rows
        .iter()
        .filter(|f| f.current && f.severity == "critical")
        .count() as u64;
    let top = finding_rows.iter().find(|f| f.temporal_scope == "current");
    let finding_counts = FindingCounts {
        current: finding_rows
            .iter()
            .filter(|f| f.temporal_scope == "current")
            .count() as u64,
        historical: finding_rows
            .iter()
            .filter(|f| f.temporal_scope == "historical")
            .count() as u64,
        unknown: finding_rows
            .iter()
            .filter(|f| f.temporal_scope == "unknown")
            .count() as u64,
    };
    let core_gaps = coverage_rows
        .iter()
        .filter(|c| c.classification == "core" && c.state != "parsed")
        .count();
    let event_limit: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM parse_warnings WHERE code='events.limit')",
        [],
        |r| r.get(0),
    )?;
    let parser_failures: i64 = conn.query_row(
        "SELECT COUNT(*) FROM parse_warnings WHERE code LIKE 'parser.%'",
        [],
        |r| r.get(0),
    )?;
    let coverage_warning = if event_limit {
        Some("The event safety limit was reached; conclusions are based on partial indexed evidence.".into())
    } else if core_gaps > 0 {
        Some(format!(
            "{core_gaps} core evidence categories are unavailable or incomplete."
        ))
    } else if parser_failures > 0 {
        Some(format!(
            "{parser_failures} supported artifacts could not be parsed completely."
        ))
    } else {
        None
    };
    let overall_status = if top.is_some() {
        "Action required"
    } else if coverage_warning.is_some() {
        "Inconclusive"
    } else if finding_counts.unknown > 0 || finding_counts.historical > 0 {
        "Attention"
    } else {
        "No current issue proven"
    }
    .to_owned();
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
    let primary_diagnosis = top.map(|f| PrimaryDiagnosis {
        title: f.title.clone(),
        severity: f.severity.clone(),
        confidence: f.confidence.clone(),
        affected_entity: f.entity_id.as_deref().and_then(|id| {
            conn.query_row("SELECT name FROM managed_entities WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .optional()
            .ok()
            .flatten()
        }),
        recommendation: f.recommendation.clone(),
        evidence_count: f.evidence.len() as u64,
    });
    let status_for = |prefixes: &[&str], coverage_terms: &[&str]| -> (String, String) {
        if finding_rows.iter().any(|f| {
            f.temporal_scope == "current" && prefixes.iter().any(|p| f.rule_id.starts_with(p))
        }) {
            return (
                "action_required".into(),
                "Current evidence requires attention.".into(),
            );
        }
        if finding_rows.iter().any(|f| {
            f.temporal_scope == "unknown" && prefixes.iter().any(|p| f.rule_id.starts_with(p))
        }) {
            return (
                "attention".into(),
                "Relevant evidence exists but its time scope is unknown.".into(),
            );
        }
        let covered = coverage_rows.iter().any(|c| {
            c.state == "parsed"
                && coverage_terms
                    .iter()
                    .any(|term| c.source.to_ascii_lowercase().contains(term))
        });
        if covered {
            (
                "healthy".into(),
                "No current failure is proven in the collected evidence.".into(),
            )
        } else {
            (
                "unknown".into(),
                "The bundle does not contain enough recognized evidence.".into(),
            )
        }
    };
    let checks = [
        (
            "identity",
            "Identity & enrollment",
            status_for(
                &["identity.", "enrollment."],
                &["enrollment", "device management"],
            ),
        ),
        (
            "esp",
            "Enrollment Status Page",
            status_for(&["esp."], &["enrollment status"]),
        ),
        (
            "applications",
            "Applications",
            status_for(&["ime.app.", "msi."], &["app deployment", "ime activity"]),
        ),
        (
            "policies",
            "Policies",
            status_for(&["policy."], &["mdm diagnostic", "structured"]),
        ),
        (
            "certificates",
            "Certificates & network",
            status_for(&["certificate.", "network."], &["certificate", "network"]),
        ),
    ];
    let mut health_checks = checks
        .into_iter()
        .map(|(key, label, (state, detail))| HealthCheck {
            key: key.into(),
            label: label.into(),
            state,
            detail,
        })
        .collect::<Vec<_>>();
    health_checks.push(HealthCheck {
        key: "data_quality".into(),
        label: "Data quality".into(),
        state: if coverage_warning.is_some() {
            "attention".into()
        } else {
            "healthy".into()
        },
        detail: coverage_warning.clone().unwrap_or_else(|| {
            "Core sources were parsed without a global safety-limit warning.".into()
        }),
    });
    Ok(Summary {
        verdict: top
            .map(|f| f.title.clone())
            .unwrap_or_else(|| overall_status.clone()),
        confidence: top
            .map(|f| f.confidence.clone())
            .unwrap_or_else(|| "low".into()),
        current_status: if top.is_some() {
            "current finding".into()
        } else if coverage_warning.is_some() {
            "insufficient evidence for a clean bill of health".into()
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
        overall_status,
        primary_diagnosis,
        health_checks,
        finding_counts,
        coverage_warning,
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
    let mut joins = " JOIN artifacts a ON a.id=e.artifact_id".to_owned();
    let mut where_sql = Vec::new();
    let mut values = Vec::<Value>::new();
    if let Some(term) = search {
        joins.push_str(" JOIN events_fts f ON f.rowid=e.sequence");
        where_sql.push("events_fts MATCH ?".into());
        values.push(Value::Text(fts_query(term)));
    }
    push_list_filter(
        &mut where_sql,
        &mut values,
        "e.severity",
        q.severity.as_deref(),
    );
    push_list_filter(
        &mut where_sql,
        &mut values,
        "e.provider",
        q.provider.as_deref(),
    );
    push_list_filter(
        &mut where_sql,
        &mut values,
        "e.component",
        q.component.as_deref(),
    );
    push_list_filter(
        &mut where_sql,
        &mut values,
        "a.detected_type",
        q.source.as_deref(),
    );
    push_list_filter(
        &mut where_sql,
        &mut values,
        "e.temporal_scope",
        q.temporal_scope.as_deref(),
    );
    if let Some(session) = q.session_id.as_deref() {
        where_sql.push("e.session_id=?".into());
        values.push(Value::Text(session.into()));
    }
    if let Some(since) = q.since.as_deref() {
        where_sql.push("e.timestamp_utc>=?".into());
        values.push(Value::Text(since.into()));
    }
    let base_condition = if where_sql.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", where_sql.join(" AND "))
    };
    let total_estimate: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM events e{joins}{base_condition}"),
        params_from_iter(values.iter()),
        |r| r.get(0),
    )?;
    where_sql.push("e.sequence>?".into());
    values.push(Value::Integer(cursor as i64));
    values.push(Value::Integer((limit + 1) as i64));
    let condition = format!(" WHERE {}", where_sql.join(" AND "));
    let sql = format!(
        "SELECT e.id,e.sequence,e.timestamp_utc,e.timestamp_original,e.utc_offset_minutes,e.provider,e.channel,e.event_code,e.component,e.severity,e.entity_id,e.message,e.current,e.temporal_scope,e.occurrence_count,COALESCE((SELECT id FROM evidence_links x WHERE x.event_id=e.id LIMIT 1),'evidence:'||e.id) FROM events e{joins}{condition} ORDER BY e.sequence LIMIT ?"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut items = collect(stmt.query_map(params_from_iter(values.iter()), timeline_row)?)?;
    let next_cursor = if items.len() > limit {
        items.truncate(limit);
        items.last().map(|e| e.sequence)
    } else {
        None
    };
    Ok(TimelinePage {
        items,
        next_cursor,
        total_estimate: total_estimate as u64,
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
        temporal_scope: r.get(13)?,
        occurrence_count: r.get::<_, i64>(14)? as u64,
        evidence_id: r.get(15)?,
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

fn push_list_filter(
    clauses: &mut Vec<String>,
    values: &mut Vec<Value>,
    column: &str,
    requested: Option<&[String]>,
) {
    let Some(requested) = requested.filter(|items| !items.is_empty()) else {
        return;
    };
    clauses.push(format!(
        "lower({column}) IN ({})",
        std::iter::repeat_n("?", requested.len())
            .collect::<Vec<_>>()
            .join(",")
    ));
    values.extend(
        requested
            .iter()
            .map(|value| Value::Text(value.to_ascii_lowercase())),
    );
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn timeline_filters_before_pagination_and_counts_matches() {
        let root = tempfile::tempdir().unwrap();
        let conn = open(&root.path().join("analysis.sqlite")).unwrap();
        initialize(&conn).unwrap();
        insert_artifact(
            &conn,
            &NewArtifact {
                id: "artifact:test",
                parent_id: None,
                layer: 0,
                normalized_path: "test.log",
                original_path: "test.log",
                object_path: "test.log",
                size: 1,
                sha256: "00",
                detected_type: "cmtrace-or-text",
                duplicate_of: None,
                warning: None,
            },
        )
        .unwrap();
        for (id, severity, message) in [
            ("event:info", "info", "first informational record"),
            ("event:error", "error", "second error record"),
        ] {
            insert_event(
                &conn,
                id,
                "artifact:test",
                None,
                None,
                None,
                Some("Synthetic"),
                None,
                None,
                Some("test"),
                None,
                severity,
                None,
                message,
                None,
            )
            .unwrap();
        }
        finalize_event_index(&conn).unwrap();
        let page = timeline(
            &conn,
            &TimelineQuery {
                limit: Some(1),
                severity: Some(vec!["error".into()]),
                ..Default::default()
            },
            1,
            10,
        )
        .unwrap();
        assert_eq!(page.total_estimate, 1);
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].severity, "error");
    }

    #[test]
    fn canonical_events_are_inserted_once_and_count_occurrences() {
        let root = tempfile::tempdir().unwrap();
        let conn = open(&root.path().join("analysis.sqlite")).unwrap();
        initialize(&conn).unwrap();
        insert_artifact(
            &conn,
            &NewArtifact {
                id: "artifact:test",
                parent_id: None,
                layer: 0,
                normalized_path: "test.log",
                original_path: "test.log",
                object_path: "test.log",
                size: 1,
                sha256: "00",
                detected_type: "cmtrace-or-text",
                duplicate_of: None,
                warning: None,
            },
        )
        .unwrap();
        let insert = || {
            insert_event(
                &conn,
                "event:canonical",
                "artifact:test",
                None,
                None,
                None,
                Some("Synthetic"),
                None,
                None,
                Some("test"),
                None,
                "warning",
                None,
                "same normalized record",
                Some("line:1"),
            )
            .unwrap()
        };
        assert!(insert().is_some());
        assert!(insert().is_none());
        add_event_occurrences(&conn, &HashMap::from([("event:canonical".into(), 3)])).unwrap();
        let values: (i64, i64) = conn
            .query_row(
                "SELECT COUNT(*),MAX(occurrence_count) FROM events",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(values, (1, 4));
    }

    #[test]
    fn entity_type_filter_excludes_applications_before_pagination() {
        let root = tempfile::tempdir().unwrap();
        let conn = open(&root.path().join("analysis.sqlite")).unwrap();
        initialize(&conn).unwrap();
        for (id, entity_type, name, current) in [
            ("entity:app", "application", "Contoso App", true),
            ("entity:policy", "policy", "Security Baseline", true),
            (
                "entity:network",
                "network profile",
                "Corporate Wi-Fi",
                false,
            ),
        ] {
            insert_entity(
                &conn,
                &ManagedEntity {
                    id: id.into(),
                    entity_type: entity_type.into(),
                    name: name.into(),
                    state: "observed".into(),
                    current,
                    evidence_ids: Vec::new(),
                },
            )
            .unwrap();
        }
        let page = query_entities(
            &conn,
            &EntityQuery {
                cursor: None,
                limit: Some(2),
                search: None,
                entity_type: Some(vec!["policy".into(), "network profile".into()]),
                state: None,
                current: Some(true),
            },
            100,
        )
        .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].entity_type, "policy");
        assert_eq!(page.items[0].name, "Security Baseline");
        assert_eq!(page.summary.total, 2);
        assert_eq!(page.summary.current, 1);
        assert_eq!(page.summary.historical, 1);
    }

    #[test]
    fn application_filters_prioritize_correlated_attempts() {
        let root = tempfile::tempdir().unwrap();
        let conn = open(&root.path().join("analysis.sqlite")).unwrap();
        initialize(&conn).unwrap();
        for (id, name, state, attempts) in [
            ("app:inventory", "Inventory App", "observed", 0),
            ("app:failed", "Failed App", "failed", 2),
            ("app:success", "Successful App", "succeeded", 1),
        ] {
            insert_application(
                &conn,
                &Application {
                    id: id.into(),
                    name: name.into(),
                    app_type: "Managed".into(),
                    intent: None,
                    install_context: None,
                    state: state.into(),
                    esp_tracked: false,
                    attempt_count: attempts,
                    evidence_ids: Vec::new(),
                },
            )
            .unwrap();
        }
        let page = query_applications(
            &conn,
            &ApplicationQuery {
                attempted: Some(true),
                state: Some(vec!["failed".into()]),
                ..Default::default()
            },
            100,
        )
        .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].name, "Failed App");
        assert_eq!(page.summary.total, 3);
        assert_eq!(page.summary.attempted, 2);
        assert_eq!(page.summary.failed, 1);
    }
}
