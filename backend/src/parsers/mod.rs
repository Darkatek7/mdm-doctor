mod cmtrace;
mod evtx_file;
mod structured;
mod text_reader;

use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use rusqlite::Connection;

use crate::{
    config::Config,
    db,
    error::Result,
    ingest::{ExtractedArtifact, stable_id},
    models::{CoverageRecord, ParseWarning},
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
    pub attempted: u64,
    pub duplicate_events: u64,
    seen: HashSet<String>,
    duplicate_counts: HashMap<String, u64>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ParseStats {
    pub unique_events: u64,
    pub duplicate_events: u64,
    pub attempted_events: u64,
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
        self.attempted += 1;
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
        if !self.seen.insert(event_id.clone()) {
            self.duplicate_events += 1;
            *self.duplicate_counts.entry(event_id.clone()).or_default() += 1;
            return Ok(Some(event_id));
        }
        if self.emitted >= self.max_events {
            self.seen.remove(&event_id);
            return Ok(None);
        }
        let inserted = db::insert_event(
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
        if inserted.is_none() {
            self.duplicate_events += 1;
            *self.duplicate_counts.entry(event_id.clone()).or_default() += 1;
            return Ok(Some(event_id));
        }
        self.emitted += 1;
        Ok(Some(event_id))
    }

    pub fn limit_reached(&self) -> bool {
        self.emitted >= self.max_events
    }

    fn stats(&self) -> ParseStats {
        ParseStats {
            unique_events: self.emitted,
            duplicate_events: self.duplicate_events,
            attempted_events: self.attempted,
            warnings: self.warnings,
        }
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

pub fn parse_all<F>(
    conn: &Connection,
    artifacts: &[ExtractedArtifact],
    config: &Config,
    mut on_progress: F,
) -> Result<ParseStats>
where
    F: FnMut(u64, u64, ParseStats) -> Result<()>,
{
    let mut ctx = ParserContext {
        conn,
        max_events: config.max_events,
        emitted: 0,
        warnings: 0,
        attempted: 0,
        duplicate_events: 0,
        seen: HashSet::with_capacity(config.max_events.min(500_000) as usize),
        duplicate_counts: HashMap::new(),
    };
    let mut coverage = std::collections::BTreeMap::<String, (u64, String, String)>::new();
    let total = artifacts.len() as u64;
    let mut limit_warned = false;
    for (index, artifact) in artifacts.iter().enumerate() {
        if artifact.duplicate_of.is_some() {
            db::set_artifact_status(
                conn,
                &artifact.id,
                "deduplicated",
                Some("Identical content was parsed through its canonical artifact."),
            )?;
            on_progress(index as u64 + 1, total, ctx.stats())?;
            continue;
        }
        if ctx.limit_reached() {
            if !limit_warned {
                ctx.warn(None, "events.limit", "The configured unique-event limit was reached; remaining sources were classified but not indexed.")?;
                limit_warned = true;
            }
            db::set_artifact_status(
                conn,
                &artifact.id,
                "skipped",
                Some("Unique-event safety limit reached before this artifact."),
            )?;
            let category = coverage_category(&artifact.normalized_path, &artifact.detected_type);
            let entry = coverage.entry(category.0.to_owned()).or_insert((
                0,
                category.1.to_owned(),
                "partial".into(),
            ));
            entry.0 += 1;
            entry.2 = "partial".into();
            on_progress(index as u64 + 1, total, ctx.stats())?;
            continue;
        }
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
            Err(error) => {
                let (code, message) = safe_parser_error(&error);
                ctx.warn(Some(&artifact.id), code, message)?;
                db::set_artifact_status(conn, &artifact.id, "failed", Some(message))?;
            }
        }
        on_progress(index as u64 + 1, total, ctx.stats())?;
    }
    db::add_event_occurrences(conn, &ctx.duplicate_counts)?;
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
                } else if state == "partial" {
                    "partial".into()
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
                } else if state == "partial" {
                    "The source was recognized but the unique-event safety limit prevented complete indexing.".into()
                } else {
                    "The source was inspected by a typed parser.".into()
                },
            },
        )?;
    }
    add_expected_coverage(conn)?;
    Ok(ctx.stats())
}

fn safe_parser_error(error: &crate::error::AppError) -> (&'static str, &'static str) {
    match error {
        crate::error::AppError::Timeout => (
            "parser.timeout",
            "The artifact parser exceeded its bounded time limit.",
        ),
        crate::error::AppError::BadRequest => (
            "parser.malformed",
            "The artifact format is malformed or exceeds the parser's bounded format limit.",
        ),
        _ => (
            "parser.io",
            "The artifact could not be decoded completely; other recognized sources remain available.",
        ),
    }
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
