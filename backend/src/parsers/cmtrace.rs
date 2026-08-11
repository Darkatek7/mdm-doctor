use std::{
    fs::File,
    io::{BufRead, BufReader},
    sync::OnceLock,
};

use chrono::{FixedOffset, NaiveDate, NaiveDateTime, NaiveTime, TimeZone};
use regex::Regex;

use crate::{
    error::Result,
    ingest::ExtractedArtifact,
    parsers::{EventInput, ParserContext},
};

struct Pending {
    message: String,
    timestamp_utc: Option<String>,
    original: Option<String>,
    offset: Option<i32>,
    component: Option<String>,
    context: Option<String>,
    severity: &'static str,
    start_line: u64,
    end_line: u64,
}

pub fn parse(ctx: &mut ParserContext<'_>, artifact: &ExtractedArtifact) -> Result<&'static str> {
    if !super::is_text_like(&artifact.object_path) {
        ctx.warn(
            Some(&artifact.id),
            "text.size",
            "The text artifact exceeds the parser safety limit.",
        )?;
        return Ok("failed");
    }
    let file = File::open(&artifact.object_path)?;
    let mut reader = BufReader::with_capacity(128 * 1024, file);
    let mut raw = Vec::new();
    let mut line_number = 0_u64;
    let mut pending: Option<Pending> = None;
    let mut cmtrace_records = 0_u64;

    loop {
        raw.clear();
        let count = reader.read_until(b'\n', &mut raw)?;
        if count == 0 {
            break;
        }
        line_number += 1;
        if raw.len() > 1_048_576 {
            ctx.warn(
                Some(&artifact.id),
                "text.line_too_long",
                "A text record exceeded the one-megabyte line limit.",
            )?;
            raw.truncate(1_048_576);
        }
        let line = String::from_utf8_lossy(&raw)
            .trim_end_matches(['\r', '\n'])
            .to_owned();
        if let Some(record) = parse_line(&line, line_number) {
            if let Some(previous) = pending.take() {
                emit(ctx, artifact, previous)?;
            }
            pending = Some(record);
            cmtrace_records += 1;
        } else if let Some(previous) = &mut pending
            && !line.is_empty()
            && previous.message.len() < 1_048_576
        {
            previous.message.push('\n');
            previous.message.push_str(&line);
            previous.end_line = line_number;
        }
    }
    if let Some(previous) = pending {
        emit(ctx, artifact, previous)?;
    }
    if cmtrace_records == 0 {
        super::structured::parse_text(ctx, artifact)?;
    }
    Ok("parsed")
}

fn emit(ctx: &mut ParserContext<'_>, artifact: &ExtractedArtifact, record: Pending) -> Result<()> {
    let span = format!("lines:{}-{}", record.start_line, record.end_line);
    ctx.emit(EventInput {
        artifact_id: &artifact.id,
        timestamp_utc: record.timestamp_utc.as_deref(),
        timestamp_original: record.original.as_deref(),
        utc_offset_minutes: record.offset,
        provider: None,
        channel: None,
        event_code: None,
        component: record.component.as_deref(),
        context: record.context.as_deref(),
        severity: record.severity,
        entity_id: None,
        message: &record.message,
        source_span: Some(&span),
    })?;
    Ok(())
}

fn parse_line(line: &str, line_number: u64) -> Option<Pending> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"(?s)^<!\[LOG\[(?P<message>.*?)\]LOG\]!><time=\"(?P<time>[^\"]*)\"\s+date=\"(?P<date>[^\"]*)\"\s+component=\"(?P<component>[^\"]*)\"\s+context=\"(?P<context>[^\"]*)\"\s+type=\"(?P<type>[^\"]*)\""#).expect("static regex"));
    let captures = re.captures(line)?;
    let time = captures.name("time")?.as_str();
    let date = captures.name("date")?.as_str();
    let original = format!("{date} {time}");
    let (timestamp_utc, offset) = parse_timestamp(date, time);
    let severity = match captures.name("type").map(|m| m.as_str()) {
        Some("3") => "error",
        Some("2") => "warning",
        _ => "info",
    };
    Some(Pending {
        message: captures
            .name("message")
            .map_or("", |m| m.as_str())
            .to_owned(),
        timestamp_utc,
        original: Some(original),
        offset,
        component: captures
            .name("component")
            .map(|m| m.as_str().to_owned())
            .filter(|s| !s.is_empty()),
        context: captures
            .name("context")
            .map(|m| m.as_str().to_owned())
            .filter(|s| !s.is_empty()),
        severity,
        start_line: line_number,
        end_line: line_number,
    })
}

fn parse_timestamp(date: &str, value: &str) -> (Option<String>, Option<i32>) {
    static OFFSET: OnceLock<Regex> = OnceLock::new();
    let re = OFFSET.get_or_init(|| {
        Regex::new(r"(?P<clock>^\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)(?P<offset>[+-]\d+)?$")
            .expect("static regex")
    });
    let captures = match re.captures(value) {
        Some(v) => v,
        None => return (None, None),
    };
    let clock = captures.name("clock").map_or(value, |m| m.as_str());
    let offset = captures
        .name("offset")
        .and_then(|m| m.as_str().parse::<i32>().ok());
    let date = ["%-m-%-d-%Y", "%m-%d-%Y"]
        .into_iter()
        .find_map(|f| NaiveDate::parse_from_str(date, f).ok());
    let time = NaiveTime::parse_from_str(clock, "%H:%M:%S%.f").ok();
    let Some((date, time, offset)) = date.zip(time).zip(offset).map(|((a, b), c)| (a, b, c)) else {
        return (None, offset);
    };
    let Some(zone) = FixedOffset::east_opt(offset.saturating_mul(60)) else {
        return (None, Some(offset));
    };
    let local = NaiveDateTime::new(date, time);
    let utc = zone
        .from_local_datetime(&local)
        .single()
        .map(|d| d.to_utc().to_rfc3339());
    (utc, Some(offset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{db, db::NewArtifact};
    #[test]
    fn parses_cmtrace_record() {
        let line = r#"<![LOG[synthetic message]LOG]!><time="10:20:30.123+60" date="8-11-2026" component="Synthetic" context="machine" type="2" thread="1" file="x">"#;
        let item = parse_line(line, 7).unwrap();
        assert_eq!(item.message, "synthetic message");
        assert_eq!(item.severity, "warning");
        assert_eq!(item.offset, Some(60));
        assert!(
            item.timestamp_utc
                .unwrap()
                .starts_with("2026-08-11T09:20:30")
        );
    }

    #[test]
    fn plain_logs_are_filtered_once_instead_of_double_indexed() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("plain.log");
        std::fs::write(
            &path,
            b"ordinary status line\nenrollment failed with synthetic error\n",
        )
        .unwrap();
        let conn = db::open(&root.path().join("analysis.sqlite")).unwrap();
        db::initialize(&conn).unwrap();
        db::insert_artifact(
            &conn,
            &NewArtifact {
                id: "artifact:plain",
                parent_id: None,
                layer: 0,
                normalized_path: "plain.log",
                original_path: "plain.log",
                object_path: "plain.log",
                size: 58,
                sha256: "00",
                detected_type: "cmtrace-or-text",
                duplicate_of: None,
                warning: None,
            },
        )
        .unwrap();
        let artifact = ExtractedArtifact {
            id: "artifact:plain".into(),
            object_path: path,
            normalized_path: "plain.log".into(),
            detected_type: "cmtrace-or-text".into(),
        };
        let mut ctx = ParserContext {
            conn: &conn,
            max_events: 100,
            emitted: 0,
            warnings: 0,
        };
        parse(&mut ctx, &artifact).unwrap();
        assert_eq!(ctx.emitted, 1);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
}
