use std::sync::OnceLock;

use regex::{Captures, Regex};

use crate::models::{
    Application, ApplicationPage, Artifact, ComparisonSummary, CoverageRecord, EntityPage,
    EvidenceLink, ExecutionAttempt, Finding, FindingPage, ManagedEntity, ParseWarning,
    ProvisioningStep, RedactionMode, Session, Summary, TimelinePage,
};

fn email_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b").expect("static regex")
    })
}
fn guid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab0-9][0-9a-f]{3}-[0-9a-f]{12}\b",
        )
        .expect("static regex")
    })
}
fn ip_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("static regex"))
}
fn sid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bS-1-(?:\d+-){2,14}\d+\b").expect("static regex"))
}
fn unc_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\\\\[^\\\s]+\\[^\s]+|(?i)\b[A-Z]:\\[^\r\n]+\b").expect("static regex")
    })
}
fn device_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:device|hostname|computername|tenant|user|upn|serial)\s*[:=]\s*([^\s,;]+)",
        )
        .expect("static regex")
    })
}

pub fn text(value: &str, mode: RedactionMode) -> String {
    if mode == RedactionMode::Original {
        return value.to_owned();
    }
    let mut out = email_re().replace_all(value, "[EMAIL]").into_owned();
    out = guid_re().replace_all(&out, "[GUID]").into_owned();
    out = sid_re().replace_all(&out, "[SID]").into_owned();
    out = ip_re().replace_all(&out, "[IP]").into_owned();
    out = unc_re().replace_all(&out, "[PATH]").into_owned();
    device_re()
        .replace_all(&out, |caps: &Captures<'_>| {
            let key = caps
                .get(0)
                .map_or("identifier", |m| m.as_str())
                .split([':', '='])
                .next()
                .unwrap_or("identifier");
            format!("{key}: [IDENTIFIER]")
        })
        .into_owned()
}

pub fn summary(mut value: Summary, mode: RedactionMode) -> Summary {
    value.verdict = text(&value.verdict, mode);
    value.current_status = text(&value.current_status, mode);
    value.evidence_completeness = text(&value.evidence_completeness, mode);
    value.first_blocking_step = value.first_blocking_step.map(|v| text(&v, mode));
    value.recommended_actions = value
        .recommended_actions
        .into_iter()
        .map(|v| text(&v, mode))
        .collect();
    if let Some(diagnosis) = &mut value.primary_diagnosis {
        diagnosis.title = text(&diagnosis.title, mode);
        diagnosis.recommendation = text(&diagnosis.recommendation, mode);
        // Display names are operational labels. Source identifiers are never
        // stored in this field and remain subject to redaction elsewhere.
    }
    for check in &mut value.health_checks {
        check.detail = text(&check.detail, mode);
    }
    for item in &mut value.user_impact {
        item.detail = text(&item.detail, mode);
        if item.kind != "application" {
            // Application display names are operational labels (see primary_diagnosis).
            item.name = text(&item.name, mode);
        }
    }
    value.coverage_warning = value.coverage_warning.map(|v| text(&v, mode));
    value
}

pub fn findings(mut values: Vec<Finding>, mode: RedactionMode) -> Vec<Finding> {
    if mode == RedactionMode::Original {
        return values;
    }
    for value in &mut values {
        value.title = text(&value.title, mode);
        value.explanation = text(&value.explanation, mode);
        value.recommendation = text(&value.recommendation, mode);
        for evidence in &mut value.evidence {
            evidence.label = text(&evidence.label, mode);
        }
    }
    values
}

pub fn finding_page(mut page: FindingPage, mode: RedactionMode) -> FindingPage {
    page.items = findings(page.items, mode);
    page
}

pub fn applications(values: Vec<Application>, _mode: RedactionMode) -> Vec<Application> {
    values
}

pub fn application_page(page: ApplicationPage, _mode: RedactionMode) -> ApplicationPage {
    page
}

pub fn entities(values: Vec<ManagedEntity>, _mode: RedactionMode) -> Vec<ManagedEntity> {
    values
}

pub fn entity_page(page: EntityPage, _mode: RedactionMode) -> EntityPage {
    page
}

pub fn artifacts(mut values: Vec<Artifact>, mode: RedactionMode) -> Vec<Artifact> {
    if mode == RedactionMode::Original {
        return values;
    }
    for (index, value) in values.iter_mut().enumerate() {
        let extension = std::path::Path::new(&value.normalized_path)
            .extension()
            .and_then(|v| v.to_str())
            .unwrap_or("bin");
        let label = format!("artifact-{:05}.{extension}", index + 1);
        value.normalized_path = label.clone();
        value.original_path = label;
        value.sha256 = "[SHA-256 REDACTED]".into();
    }
    values
}

pub fn timeline(mut page: TimelinePage, mode: RedactionMode) -> TimelinePage {
    if mode == RedactionMode::Original {
        return page;
    }
    for item in &mut page.items {
        item.message = text(&item.message, mode);
    }
    page
}

pub fn evidence(mut values: Vec<EvidenceLink>, mode: RedactionMode) -> Vec<EvidenceLink> {
    if mode == RedactionMode::Original {
        return values;
    }
    for value in &mut values {
        value.label = text(&value.label, mode);
    }
    values
}

pub fn comparison(mut value: ComparisonSummary, mode: RedactionMode) -> ComparisonSummary {
    value.analysis_a = summary(value.analysis_a, mode);
    value.analysis_b = summary(value.analysis_b, mode);
    value.new_findings = findings(value.new_findings, mode);
    value.resolved_findings = findings(value.resolved_findings, mode);
    value.identity_explanation = text(&value.identity_explanation, mode);
    value
}

pub fn sessions(mut values: Vec<Session>, mode: RedactionMode) -> Vec<Session> {
    if mode == RedactionMode::Original {
        return values;
    }
    for value in &mut values {
        value.label = text(&value.label, mode);
    }
    values
}

pub fn attempts(values: Vec<ExecutionAttempt>, _mode: RedactionMode) -> Vec<ExecutionAttempt> {
    values
}
pub fn steps(values: Vec<ProvisioningStep>, _mode: RedactionMode) -> Vec<ProvisioningStep> {
    values
}
pub fn coverage(mut values: Vec<CoverageRecord>, mode: RedactionMode) -> Vec<CoverageRecord> {
    if mode == RedactionMode::Original {
        return values;
    }
    for value in &mut values {
        value.explanation = text(&value.explanation, mode);
    }
    values
}
pub fn warnings(mut values: Vec<ParseWarning>, mode: RedactionMode) -> Vec<ParseWarning> {
    if mode == RedactionMode::Original {
        return values;
    }
    for value in &mut values {
        value.message = text(&value.message, mode);
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_common_identifiers() {
        let value = "user: person@example.test device=HOST-123 ip 192.0.2.42 id 00000000-0000-4000-8000-000000000001";
        let output = text(value, RedactionMode::Redacted);
        assert!(!output.contains("person"));
        assert!(!output.contains("HOST-123"));
        assert!(!output.contains("192.0.2.42"));
        assert!(!output.contains("00000000"));
    }

    #[test]
    fn keeps_operational_application_names_in_redacted_mode() {
        let values = vec![Application {
            id: "app:synthetic".into(),
            name: "Contoso Support Tool".into(),
            app_type: "Win32".into(),
            intent: None,
            install_context: None,
            state: "observed".into(),
            esp_tracked: false,
            attempt_count: 0,
            evidence_ids: Vec::new(),
        }];
        assert_eq!(
            applications(values, RedactionMode::Redacted)[0].name,
            "Contoso Support Tool"
        );
    }
}
