use std::{
    fs::File,
    io::{BufReader, Read},
};

use quick_xml::{Reader, events::Event};
use scraper::Html;
use serde_json::Value;

use crate::{
    error::Result,
    ingest::ExtractedArtifact,
    parsers::{EventInput, ParserContext, text_reader::DecodedLines},
};

const STRUCTURED_LIMIT: u64 = 64 * 1024 * 1024;

pub fn parse_registry(
    ctx: &mut ParserContext<'_>,
    artifact: &ExtractedArtifact,
) -> Result<&'static str> {
    let mut lines = DecodedLines::open(&artifact.object_path)?;
    let mut section = String::new();
    let mut index = 0_usize;
    let mut replacements = 0_usize;
    while index < 500_000 {
        let Some(decoded) = lines.next_line()? else {
            break;
        };
        index += 1;
        replacements += decoded.replacements;
        if decoded.truncated {
            ctx.warn(
                Some(&artifact.id),
                "text.line_too_long",
                "A registry record exceeded the one-megabyte line limit and was truncated safely.",
            )?;
        }
        let line = decoded.text;
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed.to_owned();
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with(';') || !trimmed.contains('=') {
            continue;
        }
        let context = format!("{} {}", section, trimmed);
        if relevant(&context) {
            let span = format!("line:{index}");
            ctx.emit(EventInput {
                artifact_id: &artifact.id,
                timestamp_utc: None,
                timestamp_original: None,
                utc_offset_minutes: None,
                provider: Some("Registry"),
                channel: None,
                event_code: None,
                component: Some(classify(&context)),
                context: None,
                severity: infer(&context),
                entity_id: None,
                message: &context,
                source_span: Some(&span),
            })?;
        }
    }
    warn_decoding(ctx, artifact, replacements)?;
    Ok("parsed")
}

pub fn parse_xml(
    ctx: &mut ParserContext<'_>,
    artifact: &ExtractedArtifact,
) -> Result<&'static str> {
    if std::fs::metadata(&artifact.object_path)?.len() > STRUCTURED_LIMIT {
        return Ok("failed");
    }
    let file = File::open(&artifact.object_path)?;
    let mut reader = Reader::from_reader(BufReader::new(file));
    reader.config_mut().trim_text(true);
    let mut buffer = Vec::new();
    let mut stack = Vec::<String>::new();
    let mut index = 0_u64;
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(e)) => {
                stack.push(String::from_utf8_lossy(e.name().as_ref()).into_owned())
            }
            Ok(Event::End(_)) => {
                stack.pop();
            }
            Ok(Event::Text(e)) => {
                let value = String::from_utf8_lossy(e.as_ref());
                let key = stack.last().map(String::as_str).unwrap_or("xml");
                if relevant(key) || relevant(&value) {
                    index += 1;
                    let message = format!("{key}: {}", truncate(&value, 4096));
                    let span = format!("xml-node:{index}");
                    ctx.emit(EventInput {
                        artifact_id: &artifact.id,
                        timestamp_utc: None,
                        timestamp_original: None,
                        utc_offset_minutes: None,
                        provider: Some("MDM diagnostic report"),
                        channel: None,
                        event_code: None,
                        component: Some(classify(&message)),
                        context: None,
                        severity: infer(&message),
                        entity_id: None,
                        message: &message,
                        source_span: Some(&span),
                    })?;
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => {
                ctx.warn(
                    Some(&artifact.id),
                    "xml.malformed",
                    "The XML report is malformed; records parsed before the error were retained.",
                )?;
                break;
            }
            _ => {}
        }
        buffer.clear();
    }
    Ok("parsed")
}

pub fn parse_html(
    ctx: &mut ParserContext<'_>,
    artifact: &ExtractedArtifact,
) -> Result<&'static str> {
    let content = read_bounded(&artifact.object_path)?;
    let html = Html::parse_document(&String::from_utf8_lossy(&content));
    let root = html.root_element();
    let mut index = 0_u64;
    for text in root.text() {
        let text = text.trim();
        if text.is_empty() || !relevant(text) {
            continue;
        }
        index += 1;
        let message = truncate(text, 4096);
        let span = format!("html-text:{index}");
        ctx.emit(EventInput {
            artifact_id: &artifact.id,
            timestamp_utc: None,
            timestamp_original: None,
            utc_offset_minutes: None,
            provider: Some("MDM HTML report"),
            channel: None,
            event_code: None,
            component: Some(classify(&message)),
            context: None,
            severity: infer(&message),
            entity_id: None,
            message: &message,
            source_span: Some(&span),
        })?;
    }
    Ok("parsed")
}

pub fn parse_json(
    ctx: &mut ParserContext<'_>,
    artifact: &ExtractedArtifact,
) -> Result<&'static str> {
    let content = read_bounded(&artifact.object_path)?;
    let value: Value = match serde_json::from_slice(&content) {
        Ok(v) => v,
        Err(_) => {
            ctx.warn(
                Some(&artifact.id),
                "json.malformed",
                "The JSON document is malformed.",
            )?;
            return Ok("failed");
        }
    };
    let mut leaves = Vec::new();
    collect_json("", &value, &mut leaves, 50_000);
    for (index, (key, value)) in leaves.into_iter().enumerate() {
        let message = format!("{key}: {}", truncate(&value, 4096));
        if !relevant(&message) {
            continue;
        }
        let span = format!("json-value:{}", index + 1);
        ctx.emit(EventInput {
            artifact_id: &artifact.id,
            timestamp_utc: None,
            timestamp_original: None,
            utc_offset_minutes: None,
            provider: Some("Structured JSON"),
            channel: None,
            event_code: None,
            component: Some(classify(&message)),
            context: None,
            severity: infer(&message),
            entity_id: None,
            message: &message,
            source_span: Some(&span),
        })?;
    }
    Ok("parsed")
}

pub fn parse_csv(
    ctx: &mut ParserContext<'_>,
    artifact: &ExtractedArtifact,
) -> Result<&'static str> {
    let file = File::open(&artifact.object_path)?;
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(BufReader::new(file));
    let headers = reader.headers().cloned().unwrap_or_default();
    for (index, row) in reader.records().take(100_000).enumerate() {
        let row = match row {
            Ok(r) => r,
            Err(_) => continue,
        };
        let message = row
            .iter()
            .enumerate()
            .map(|(i, v)| format!("{}={}", headers.get(i).unwrap_or("field"), v))
            .collect::<Vec<_>>()
            .join("; ");
        if !relevant(&message) {
            continue;
        }
        let message = truncate(&message, 8192);
        let span = format!("csv-row:{}", index + 2);
        ctx.emit(EventInput {
            artifact_id: &artifact.id,
            timestamp_utc: None,
            timestamp_original: None,
            utc_offset_minutes: None,
            provider: Some("Structured CSV"),
            channel: None,
            event_code: None,
            component: Some(classify(&message)),
            context: None,
            severity: infer(&message),
            entity_id: None,
            message: &message,
            source_span: Some(&span),
        })?;
    }
    Ok("parsed")
}

pub fn parse_text(
    ctx: &mut ParserContext<'_>,
    artifact: &ExtractedArtifact,
) -> Result<&'static str> {
    let mut lines = DecodedLines::open(&artifact.object_path)?;
    let mut index = 0_usize;
    let mut replacements = 0_usize;
    while index < 500_000 {
        let Some(decoded) = lines.next_line()? else {
            break;
        };
        index += 1;
        replacements += decoded.replacements;
        if decoded.truncated {
            ctx.warn(
                Some(&artifact.id),
                "text.line_too_long",
                "A text record exceeded the one-megabyte line limit and was truncated safely.",
            )?;
        }
        let line = decoded.text;
        if line.trim().is_empty() || !relevant(&line) {
            continue;
        }
        let message = truncate(&line, 8192);
        let span = format!("line:{index}");
        ctx.emit(EventInput {
            artifact_id: &artifact.id,
            timestamp_utc: None,
            timestamp_original: None,
            utc_offset_minutes: None,
            provider: Some("Text report"),
            channel: None,
            event_code: None,
            component: Some(classify(&message)),
            context: machine_context(&message),
            severity: infer(&message),
            entity_id: None,
            message: &message,
            source_span: Some(&span),
        })?;
    }
    warn_decoding(ctx, artifact, replacements)?;
    Ok("parsed")
}

fn warn_decoding(
    ctx: &mut ParserContext<'_>,
    artifact: &ExtractedArtifact,
    replacements: usize,
) -> Result<()> {
    if replacements > 0 {
        ctx.warn(Some(&artifact.id), "text.decode_replacement", "Invalid text byte sequences were replaced while preserving the remainder of the artifact.")?;
    }
    Ok(())
}

fn read_bounded(path: &std::path::Path) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    if file.metadata()?.len() > STRUCTURED_LIMIT {
        return Err(crate::error::AppError::BadRequest);
    }
    let mut value = Vec::new();
    file.read_to_end(&mut value)?;
    Ok(value)
}
fn collect_json(prefix: &str, value: &Value, out: &mut Vec<(String, String)>, limit: usize) {
    if out.len() >= limit {
        return;
    }
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                collect_json(&format!("{prefix}/{k}"), v, out, limit)
            }
        }
        Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                collect_json(&format!("{prefix}/{i}"), v, out, limit)
            }
        }
        Value::String(v) => out.push((prefix.into(), v.clone())),
        Value::Number(v) => out.push((prefix.into(), v.to_string())),
        Value::Bool(v) => out.push((prefix.into(), v.to_string())),
        _ => {}
    }
}
fn relevant(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    [
        "error",
        "fail",
        "warning",
        "esp",
        "enrollment",
        "policy",
        "csp",
        "application",
        " app",
        "certificate",
        "scep",
        "network",
        "azuread",
        "devicestate",
        "prt",
        "reboot",
        "restart",
        "installer",
        "msi",
        "exit code",
        "detection",
        "sidecar",
        "tracking",
        "provision",
    ]
    .iter()
    .any(|k| v.contains(k))
}
fn classify(value: &str) -> &'static str {
    let v = value.to_ascii_lowercase();
    if v.contains("certificate") || v.contains("scep") {
        "certificate"
    } else if v.contains("policy") || v.contains("csp") {
        "policy"
    } else if v.contains("enrollment") || v.contains("azuread") || v.contains("prt") {
        "enrollment"
    } else if v.contains("network") {
        "network"
    } else if v.contains("esp") || v.contains("provision") {
        "esp"
    } else if v.contains("app") || v.contains("msi") || v.contains("installer") {
        "application"
    } else {
        "structured"
    }
}
fn infer(value: &str) -> &'static str {
    let v = value.to_ascii_lowercase();
    if v.contains("failed") || v.contains("failure") || v.contains("error") {
        "error"
    } else if v.contains("warning") || v.contains("pending") || v.contains("timeout") {
        "warning"
    } else {
        "info"
    }
}
fn machine_context(value: &str) -> Option<&'static str> {
    if value.contains('$') || value.to_ascii_lowercase().contains("system") {
        Some("machine")
    } else {
        None
    }
}
fn truncate(value: &str, limit: usize) -> String {
    if value.len() <= limit {
        return value.into();
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1
    }
    format!("{}…", &value[..end])
}
