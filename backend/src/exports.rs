use printpdf::{
    BuiltinFont, Mm, Op, PdfDocument, PdfFontHandle, PdfPage, PdfSaveOptions, Point, Pt, TextItem,
};
use rusqlite::Connection;
use serde::Serialize;

use crate::{
    db,
    error::Result,
    models::{ExportFormat, ExportRequest, RedactionMode, TimelineQuery},
    redaction,
};

pub struct Exported {
    pub bytes: Vec<u8>,
    pub content_type: &'static str,
    pub filename: &'static str,
}

#[derive(Serialize)]
struct EvidencePack<T, U, V, W> {
    schema_version: &'static str,
    generated_by: &'static str,
    summary: T,
    findings: U,
    sessions: V,
    coverage: W,
    artifacts: serde_json::Value,
    timeline: serde_json::Value,
}

pub fn generate(
    conn: &Connection,
    request: &ExportRequest,
    mode: RedactionMode,
) -> Result<Exported> {
    match request.format {
        ExportFormat::Html => html(conn, mode),
        ExportFormat::FindingsCsv => findings_csv(conn, mode),
        ExportFormat::TimelineCsv => timeline_csv(conn, mode),
        ExportFormat::EvidenceJson => json(conn, mode),
        ExportFormat::Pdf => pdf(conn, mode),
    }
}

fn html(conn: &Connection, mode: RedactionMode) -> Result<Exported> {
    let summary = redaction::summary(db::summary(conn)?, mode);
    let findings = redaction::findings(db::findings(conn)?, mode);
    let coverage = redaction::coverage(db::coverage(conn)?, mode);
    let mut out = String::from(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><meta name=\"referrer\" content=\"no-referrer\"><title>MDM Doctor report</title><style>body{font:15px system-ui;margin:2rem;max-width:1100px;color:#17212b}h1{color:#0b6b62}.card{border:1px solid #ccd8d5;border-radius:12px;padding:1rem;margin:1rem 0}.critical,.high{border-left:5px solid #b42318}.medium{border-left:5px solid #b7791f}table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #ddd;text-align:left;padding:.5rem}</style></head><body><h1>MDM Doctor</h1><p>Transient diagnostic report. Identifiers are ",
    );
    out.push_str(if mode == RedactionMode::Redacted {
        "redacted."
    } else {
        "included by explicit operator choice."
    });
    out.push_str("</p><section class=\"card\"><h2>Verdict</h2><p>");
    out.push_str(&escape_html(&summary.verdict));
    out.push_str("</p><p>Confidence: ");
    out.push_str(&escape_html(&summary.confidence));
    out.push_str("</p></section><h2>Findings</h2>");
    for finding in findings {
        out.push_str(&format!("<article class=\"card {}\"><h3>{}</h3><p>{}</p><p><strong>Recommendation:</strong> {}</p><small>{} · {} · evidence {}</small></article>",escape_attr(&finding.severity),escape_html(&finding.title),escape_html(&finding.explanation),escape_html(&finding.recommendation),escape_html(&finding.severity),escape_html(&finding.confidence),finding.evidence.len()));
    }
    out.push_str("<h2>Collection coverage</h2><table><thead><tr><th>Source</th><th>Class</th><th>State</th><th>Count</th></tr></thead><tbody>");
    for row in coverage {
        out.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape_html(&row.source),
            escape_html(&row.classification),
            escape_html(&row.state),
            row.artifact_count
        ));
    }
    out.push_str("</tbody></table></body></html>");
    Ok(Exported {
        bytes: out.into_bytes(),
        content_type: "text/html; charset=utf-8",
        filename: "mdm-doctor-report.html",
    })
}

fn findings_csv(conn: &Connection, mode: RedactionMode) -> Result<Exported> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer
        .write_record([
            "rule_id",
            "severity",
            "confidence",
            "current",
            "esp_tracked",
            "title",
            "explanation",
            "recommendation",
            "evidence_count",
        ])
        .map_err(crate::error::AppError::internal)?;
    for f in redaction::findings(db::findings(conn)?, mode) {
        writer
            .write_record([
                safe_csv(&f.rule_id),
                safe_csv(&f.severity),
                safe_csv(&f.confidence),
                f.current.to_string(),
                f.esp_tracked.to_string(),
                safe_csv(&f.title),
                safe_csv(&f.explanation),
                safe_csv(&f.recommendation),
                f.evidence.len().to_string(),
            ])
            .map_err(crate::error::AppError::internal)?;
    }
    let bytes = writer
        .into_inner()
        .map_err(crate::error::AppError::internal)?;
    Ok(Exported {
        bytes,
        content_type: "text/csv; charset=utf-8",
        filename: "mdm-doctor-findings.csv",
    })
}

fn timeline_csv(conn: &Connection, mode: RedactionMode) -> Result<Exported> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer
        .write_record([
            "sequence",
            "timestamp_utc",
            "provider",
            "channel",
            "event_code",
            "component",
            "severity",
            "current",
            "message",
            "evidence_id",
        ])
        .map_err(crate::error::AppError::internal)?;
    let mut cursor = 0;
    loop {
        let page = redaction::timeline(
            db::timeline(
                conn,
                &TimelineQuery {
                    cursor: Some(cursor),
                    limit: Some(500),
                    ..Default::default()
                },
                500,
                500,
            )?,
            mode,
        );
        if page.items.is_empty() {
            break;
        }
        for e in &page.items {
            writer
                .write_record([
                    e.sequence.to_string(),
                    safe_csv(e.timestamp_utc.as_deref().unwrap_or("")),
                    safe_csv(e.provider.as_deref().unwrap_or("")),
                    safe_csv(e.channel.as_deref().unwrap_or("")),
                    safe_csv(e.event_code.as_deref().unwrap_or("")),
                    safe_csv(e.component.as_deref().unwrap_or("")),
                    safe_csv(&e.severity),
                    e.current.to_string(),
                    safe_csv(&e.message),
                    safe_csv(&e.evidence_id),
                ])
                .map_err(crate::error::AppError::internal)?;
            cursor = e.sequence;
        }
    }
    let bytes = writer
        .into_inner()
        .map_err(crate::error::AppError::internal)?;
    Ok(Exported {
        bytes,
        content_type: "text/csv; charset=utf-8",
        filename: "mdm-doctor-timeline.csv",
    })
}

fn json(conn: &Connection, mode: RedactionMode) -> Result<Exported> {
    let mut timeline = Vec::new();
    let mut cursor = 0;
    loop {
        let page = redaction::timeline(
            db::timeline(
                conn,
                &TimelineQuery {
                    cursor: Some(cursor),
                    limit: Some(500),
                    ..Default::default()
                },
                500,
                500,
            )?,
            mode,
        );
        if page.items.is_empty() {
            break;
        }
        for e in page.items {
            cursor = e.sequence;
            timeline.push(e);
        }
    }
    let pack = EvidencePack {
        schema_version: "1",
        generated_by: "MDM Doctor",
        summary: redaction::summary(db::summary(conn)?, mode),
        findings: redaction::findings(db::findings(conn)?, mode),
        sessions: redaction::sessions(db::sessions(conn)?, mode),
        coverage: redaction::coverage(db::coverage(conn)?, mode),
        artifacts: serde_json::to_value(redaction::artifacts(db::artifacts(conn)?, mode))?,
        timeline: serde_json::to_value(timeline)?,
    };
    Ok(Exported {
        bytes: serde_json::to_vec(&pack)?,
        content_type: "application/json",
        filename: "mdm-doctor-evidence.json",
    })
}

fn pdf(conn: &Connection, mode: RedactionMode) -> Result<Exported> {
    let summary = redaction::summary(db::summary(conn)?, mode);
    let findings = redaction::findings(db::findings(conn)?, mode);
    let mut lines = vec![
        "MDM Doctor".to_owned(),
        format!("Verdict: {}", summary.verdict),
        format!("Confidence: {}", summary.confidence),
        format!("Evidence completeness: {}", summary.evidence_completeness),
        String::new(),
        "Findings".into(),
    ];
    for finding in findings {
        lines.push(format!(
            "[{}] {}",
            finding.severity.to_uppercase(),
            finding.title
        ));
        lines.extend(wrap(&finding.explanation, 92));
        lines.push(format!("Recommendation: {}", finding.recommendation));
        lines.push(String::new());
    }
    if lines.len() == 6 {
        lines.push("No evidence-backed finding was generated.".into())
    }
    let mut pages = Vec::new();
    for chunk in lines.chunks(43) {
        let mut ops = vec![
            Op::StartTextSection,
            Op::SetTextCursor {
                pos: Point::new(Mm(18.0), Mm(278.0)),
            },
            Op::SetFont {
                font: PdfFontHandle::Builtin(BuiltinFont::Helvetica),
                size: Pt(10.0),
            },
            Op::SetLineHeight { lh: Pt(14.0) },
        ];
        for line in chunk {
            ops.push(Op::ShowText {
                items: vec![TextItem::Text(ascii(line))],
            });
            ops.push(Op::AddLineBreak);
        }
        ops.push(Op::EndTextSection);
        pages.push(PdfPage::new(Mm(210.0), Mm(297.0), ops));
    }
    let mut doc = PdfDocument::new("MDM Doctor report");
    doc.with_pages(pages);
    let mut bytes = Vec::new();
    doc.save_writer(&mut bytes, &PdfSaveOptions::default(), &mut Vec::new());
    Ok(Exported {
        bytes,
        content_type: "application/pdf",
        filename: "mdm-doctor-report.pdf",
    })
}

fn safe_csv(value: &str) -> String {
    let clean = value.replace(['\r', '\n'], " ");
    if clean.starts_with(['=', '+', '-', '@']) {
        format!("'{clean}")
    } else {
        clean
    }
}
fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn escape_attr(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect()
}
fn ascii(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii() && !c.is_control() {
                c
            } else {
                '?'
            }
        })
        .collect()
}
fn wrap(value: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut line = String::new();
    for word in value.split_whitespace() {
        if !line.is_empty() && line.len() + word.len() + 1 > width {
            out.push(line);
            line = String::new();
        }
        if !line.is_empty() {
            line.push(' ')
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        out.push(line)
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn csv_formula_is_neutralized() {
        assert_eq!(safe_csv("=cmd"), "'=cmd");
    }
    #[test]
    fn html_is_escaped() {
        assert_eq!(escape_html("<script>"), "&lt;script&gt;");
    }

    #[test]
    fn pdf_is_generated_from_normalized_database_data() {
        let root = tempfile::tempdir().unwrap();
        let conn = db::open(&root.path().join("analysis.sqlite")).unwrap();
        db::initialize(&conn).unwrap();
        let export = pdf(&conn, RedactionMode::Redacted).unwrap();
        assert_eq!(export.content_type, "application/pdf");
        assert!(export.bytes.starts_with(b"%PDF-"));
        assert!(export.bytes.len() > 500);
    }
}
