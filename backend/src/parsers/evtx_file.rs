use evtx::EvtxParser;
use serde_json::Value;

use crate::{
    error::Result,
    ingest::ExtractedArtifact,
    parsers::{EventInput, ParserContext},
};

pub fn parse(ctx: &mut ParserContext<'_>, artifact: &ExtractedArtifact) -> Result<&'static str> {
    let mut parser = match EvtxParser::from_path(&artifact.object_path) {
        Ok(value) => value,
        Err(_) => {
            ctx.warn(
                Some(&artifact.id),
                "evtx.header",
                "The EVTX header is malformed or unsupported.",
            )?;
            return Ok("failed");
        }
    };
    let mut errors = 0_u64;
    for record in parser.records_json_value() {
        if ctx.emitted >= ctx.max_events {
            break;
        }
        let record = match record {
            Ok(value) => value,
            Err(_) => {
                errors += 1;
                continue;
            }
        };
        let provider = find_string(&record.data, &["Provider", "Name"])
            .or_else(|| find_attribute(&record.data, "Provider", "Name"));
        let channel = find_key(&record.data, "Channel").and_then(value_string);
        let event_code = find_key(&record.data, "EventID").and_then(value_string);
        let level = find_key(&record.data, "Level").and_then(value_string);
        let severity = match level.as_deref() {
            Some("1") => "critical",
            Some("2") => "error",
            Some("3") => "warning",
            _ => "info",
        };
        let timestamp = record.timestamp.to_string();
        let mut message = serde_json::to_string(&record.data).unwrap_or_else(|_| "{}".into());
        if message.len() > 65_536 {
            message.truncate(65_536);
        }
        let span = format!("record:{}", record.event_record_id);
        ctx.emit(EventInput {
            artifact_id: &artifact.id,
            timestamp_utc: Some(&timestamp),
            timestamp_original: Some(&timestamp),
            utc_offset_minutes: Some(0),
            provider: provider.as_deref(),
            channel: channel.as_deref(),
            event_code: event_code.as_deref(),
            component: provider.as_deref(),
            context: None,
            severity,
            entity_id: None,
            message: &message,
            source_span: Some(&span),
        })?;
    }
    if errors > 0 {
        ctx.warn(
            Some(&artifact.id),
            "evtx.records_skipped",
            "One or more EVTX records were malformed; valid records were retained.",
        )?;
    }
    Ok("parsed")
}

fn find_key<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => map
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v)
            .or_else(|| map.values().find_map(|v| find_key(v, key))),
        Value::Array(items) => items.iter().find_map(|v| find_key(v, key)),
        _ => None,
    }
}
fn value_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Object(m) => m.get("#text").and_then(value_string),
        _ => None,
    }
}
fn find_string(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = find_key(current, key)?;
    }
    value_string(current)
}
fn find_attribute(value: &Value, container: &str, attribute: &str) -> Option<String> {
    let node = find_key(value, container)?;
    if let Value::Object(map) = node {
        for key in [format!("@{attribute}"), attribute.into()] {
            if let Some(v) = map.get(&key).and_then(value_string) {
                return Some(v);
            }
        }
        if let Some(Value::Object(attrs)) = map.get("#attributes") {
            return attrs.get(attribute).and_then(value_string);
        }
    }
    None
}
