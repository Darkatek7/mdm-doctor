mod cmtrace;
mod evtx_file;
mod structured;

use std::path::Path;

use rusqlite::Connection;

use crate::{
    config::Config,
    db,
    error::Result,
    ingest::{ExtractedArtifact, stable_id},
    models::{CoverageRecord, EvidenceLink, ParseWarning},
};

#[cfg(all(unix, not(test)))]
struct ParserDeadline;

#[cfg(all(unix, not(test)))]
impl ParserDeadline {
    fn start(seconds: u64) -> Self {
        unsafe {
            libc::alarm(seconds.clamp(1, u32::MAX as u64) as u32);
        }
        Self
    }
}

#[cfg(all(unix, not(test)))]
impl Drop for ParserDeadline {
    fn drop(&mut self) {
        unsafe {
            libc::alarm(0);
        }
    }
}

pub struct ParserContext<'a> {
    pub conn: &'a Connection,
    pub max_events: u64,
    pub emitted: u64,
    pub warnings: u64,
}

pub struct EventInput<'a> {
    pub artifact_id: &'a str,
    pub timestamp_utc: Option<&'a str>,
    pub timestamp_original: Option<&'a str>,
    pub utc_offset_minutes: Option<i32>,
    pub provider: Option<&'a str>,
    pub channel: Option<&'a str>,
    pub event_code: Option<&'a str>,
    pub component: Option<&'a str>,
    pub context: Option<&'a str>,
    pub severity: &'a str,
    pub entity_id: Option<&'a str>,
    pub message: &'a str,
    pub source_span: Option<&'a str>,
}

impl ParserContext<'_> {
    pub fn emit(&mut self, event: EventInput<'_>) -> Result<Option<String>> {
        if self.emitted >= self.max_events {
            return Ok(None);
        }
        let signature = format!(
            "{}\0{}\0{}\0{}\0{}\0{}",
            event.timestamp_utc.unwrap_or(""),
            event.provider.unwrap_or(""),
            event.channel.unwrap_or(""),
            event.event_code.unwrap_or(""),
            event.component.unwrap_or(""),
            event.message
        );
        let event_id = stable_id("event", &signature);
        db::insert_event(
            self.conn,
            &event_id,
            event.artifact_id,
            event.timestamp_utc,
            event.timestamp_original,
            event.utc_offset_minutes,
            event.provider,
            event.channel,
            event.event_code,
            event.component,
            event.context,
            event.severity,
            event.entity_id,
            event.message,
            event.source_span,
        )?;
        let evidence_id = stable_id(
            "evidence",
            &format!(
                "{}:{}:{}",
                event.artifact_id,
                event_id,
                event.source_span.unwrap_or("")
            ),
        );
        db::insert_evidence(
            self.conn,
            None,
            &EvidenceLink {
                id: evidence_id,
                artifact_id: event.artifact_id.to_owned(),
                event_id: Some(event_id.clone()),
                source_span: event.source_span.map(str::to_owned),
                label: format!(
                    "{} evidence",
                    event.component.or(event.provider).unwrap_or("source")
                ),
            },
        )?;
        self.emitted += 1;
        Ok(Some(event_id))
    }

    pub fn warn(&mut self, artifact_id: Option<&str>, code: &str, message: &str) -> Result<()> {
        let id = stable_id(
            "warning",
            &format!("{}:{code}:{message}", artifact_id.unwrap_or("")),
        );
        db::insert_warning(
            self.conn,
            &ParseWarning {
                id,
                artifact_id: artifact_id.map(str::to_owned),
                code: code.to_owned(),
                message: message.to_owned(),
            },
        )?;
        self.warnings += 1;
        Ok(())
    }
}

pub fn parse_all(
    conn: &Connection,
    artifacts: &[ExtractedArtifact],
    config: &Config,
) -> Result<u64> {
    let mut ctx = ParserContext {
        conn,
        max_events: config.max_events,
        emitted: 0,
        warnings: 0,
    };
    let mut coverage = std::collections::BTreeMap::<String, (u64, String, String)>::new();
    for artifact in artifacts {
        #[cfg(all(unix, not(test)))]
        let _deadline = ParserDeadline::start(config.parser_timeout.as_secs());
        let result = match artifact.detected_type.as_str() {
            "zip" | "cab" => Ok("archive"),
            "cmtrace-or-text" => cmtrace::parse(&mut ctx, artifact),
            "evtx" => evtx_file::parse(&mut ctx, artifact),
            "registry" => structured::parse_registry(&mut ctx, artifact),
            "xml" => structured::parse_xml(&mut ctx, artifact),
            "html" => structured::parse_html(&mut ctx, artifact),
            "json" => structured::parse_json(&mut ctx, artifact),
            "csv" => structured::parse_csv(&mut ctx, artifact),
            "text" => structured::parse_text(&mut ctx, artifact),
            "etl-unsupported" | "sqlite-unsupported" | "binary-unsupported" => {
                db::set_artifact_status(
                    conn,
                    &artifact.id,
                    "unsupported",
                    Some("No safe Linux parser is enabled for this source."),
                )?;
                Ok("unsupported")
            }
            "zip-invalid-magic" | "cab-invalid-magic" => {
                ctx.warn(
                    Some(&artifact.id),
                    "archive.magic_mismatch",
                    "The extension indicates an archive but the file signature does not.",
                )?;
                db::set_artifact_status(
                    conn,
                    &artifact.id,
                    "failed",
                    Some("Archive signature mismatch."),
                )?;
                Ok("failed")
            }
            _ => Ok("unsupported"),
        };
        match result {
            Ok(state) => {
                if state != "failed" {
                    db::set_artifact_status(
                        conn,
                        &artifact.id,
                        if state == "unsupported" {
                            "unsupported"
                        } else {
                            "parsed"
                        },
                        None,
                    )?;
                }
                let category =
                    coverage_category(&artifact.normalized_path, &artifact.detected_type);
                let entry = coverage.entry(category.0.to_owned()).or_insert((
                    0,
                    category.1.to_owned(),
                    state.to_owned(),
                ));
                entry.0 += 1;
                if state == "parsed" || state == "archive" {
                    entry.2 = "parsed".into();
                }
            }
            Err(_) => {
                ctx.warn(
                    Some(&artifact.id),
                    "parser.failed",
                    "The parser rejected this artifact; other sources remain available.",
                )?;
                db::set_artifact_status(
                    conn,
                    &artifact.id,
                    "failed",
                    Some("Parser rejected the artifact."),
                )?;
            }
        }
        if ctx.emitted >= config.max_events {
            ctx.warn(
                None,
                "events.limit",
                "The configured event limit was reached; coverage is partial.",
            )?;
            break;
        }
    }
    for (source, (count, classification, state)) in coverage {
        let id = stable_id("coverage", &source);
        db::upsert_coverage(
            conn,
            &CoverageRecord {
                id,
                source,
                classification,
                state: if state == "unsupported" {
                    "unsupported".into()
                } else if state == "failed" {
                    "failed".into()
                } else {
                    "parsed".into()
                },
                result_code: None,
                parser: "mdm-doctor/2026.08".into(),
                artifact_count: count,
                explanation: if state == "unsupported" {
                    "The source is present but no safe parser is enabled.".into()
                } else {
                    "The source was inspected by a typed parser.".into()
                },
            },
        )?;
    }
    add_expected_coverage(conn)?;
    Ok(ctx.emitted)
}

fn add_expected_coverage(conn: &Connection) -> Result<()> {
    for (source, classification) in [
        ("IME activity", "core"),
        ("Device management events", "core"),
        ("MDM diagnostic report", "core"),
        ("Enrollment status tracking", "core"),
        ("AppX deployment", "optional"),
        ("Certificate and SCEP", "optional"),
        ("Network profiles", "optional"),
    ] {
        let id = stable_id("coverage", source);
        conn.execute(
            "INSERT OR IGNORE INTO coverage(id,source,classification,state,parser,artifact_count,explanation) VALUES (?1,?2,?3,'unavailable','mdm-doctor/2026.08',0,'The collection did not include a recognized source for this category.')",
            rusqlite::params![id,source,classification],
        )?;
    }
    Ok(())
}

fn coverage_category(path: &str, detected: &str) -> (&'static str, &'static str) {
    let lower = path.to_ascii_lowercase();
    if lower.contains("intunemanagementextension")
        || lower.contains("appworkload")
        || lower.contains("agentexecutor")
        || lower.contains("healthscripts")
    {
        return ("IME activity", "core");
    }
    if lower.contains("mdmdiag") || lower.contains("devicemanagement-enterprise") {
        return ("MDM diagnostic report", "core");
    }
    if lower.contains("enrollmentstatus") || lower.contains("esptracking") {
        return ("Enrollment status tracking", "core");
    }
    if lower.contains("appx") || lower.contains("msi") {
        return ("App deployment", "core");
    }
    if lower.contains("scep") || lower.contains("certificate") {
        return ("Certificate and SCEP", "optional");
    }
    if lower.contains("network") || lower.contains("wlan") {
        return ("Network profiles", "optional");
    }
    match detected {
        "evtx" => ("Device management events", "core"),
        "etl-unsupported" => ("ETL trace", "optional"),
        "registry" => ("Registry state", "core"),
        "xml" | "html" | "json" | "csv" => ("Structured reports", "core"),
        "zip" | "cab" => ("Archive layers", "core"),
        _ => ("Other artifacts", "optional"),
    }
}

pub fn is_text_like(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.len() <= 256 * 1024 * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_collection_gaps_are_coverage_not_findings() {
        let root = tempfile::tempdir().unwrap();
        let conn = db::open(&root.path().join("analysis.sqlite")).unwrap();
        db::initialize(&conn).unwrap();
        add_expected_coverage(&conn).unwrap();

        let optional_missing: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM coverage WHERE classification='optional' AND state='unavailable'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let findings: i64 = conn
            .query_row("SELECT COUNT(*) FROM findings", [], |row| row.get(0))
            .unwrap();
        assert!(optional_missing >= 3);
        assert_eq!(findings, 0);
    }
}
