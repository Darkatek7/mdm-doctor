use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RedactionMode {
    #[default]
    Redacted,
    Original,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum JobPhase {
    Uploading,
    Queued,
    Extracting,
    Parsing,
    Correlating,
    Ready,
    Cancelling,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct JobView {
    pub phase: JobPhase,
    pub progress_percent: u8,
    pub stage: String,
    pub created_at: String,
    pub expires_at: String,
    pub can_reanalyze: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct BuildInfo {
    pub name: String,
    pub version: String,
    pub rule_pack: String,
    pub build: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
pub struct Kpis {
    pub artifacts: u64,
    pub parsed_events: u64,
    pub findings: u64,
    pub critical_findings: u64,
    pub applications: u64,
    pub coverage_percent: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct Summary {
    pub verdict: String,
    pub confidence: String,
    pub current_status: String,
    pub evidence_completeness: String,
    pub first_blocking_step: Option<String>,
    pub recommended_actions: Vec<String>,
    pub kpis: Kpis,
    pub latest_session_id: Option<String>,
    pub rule_pack: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct EvidenceLink {
    pub id: String,
    pub artifact_id: String,
    pub event_id: Option<String>,
    pub source_span: Option<String>,
    pub label: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub rule_pack: String,
    pub severity: String,
    pub confidence: String,
    pub current: bool,
    pub esp_tracked: bool,
    pub entity_id: Option<String>,
    pub title: String,
    pub explanation: String,
    pub recommendation: String,
    pub evidence: Vec<EvidenceLink>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct Session {
    pub id: String,
    pub kind: String,
    pub current: bool,
    pub started_at: Option<String>,
    pub ended_at: Option<String>,
    pub label: String,
    pub evidence_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct Application {
    pub id: String,
    pub name: String,
    pub app_type: String,
    pub intent: Option<String>,
    pub install_context: Option<String>,
    pub state: String,
    pub esp_tracked: bool,
    pub attempt_count: u64,
    pub evidence_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct ExecutionAttempt {
    pub id: String,
    pub application_id: Option<String>,
    pub started_at: Option<String>,
    pub ended_at: Option<String>,
    pub exit_code: Option<i64>,
    pub detection_result: Option<String>,
    pub reboot_during_attempt: bool,
    pub state: String,
    pub evidence_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct ManagedEntity {
    pub id: String,
    pub entity_type: String,
    pub name: String,
    pub state: String,
    pub current: bool,
    pub evidence_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct EspResource {
    pub id: String,
    pub entity_id: Option<String>,
    pub resource_type: String,
    pub phase: String,
    pub substep: String,
    pub expected_state: String,
    pub actual_state: String,
    pub blocking_proven: bool,
    pub first_failure: bool,
    pub evidence_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct ProvisioningStep {
    pub id: String,
    pub session_id: Option<String>,
    pub phase: String,
    pub substep: String,
    pub state: String,
    pub started_at: Option<String>,
    pub ended_at: Option<String>,
    pub evidence_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct CoverageRecord {
    pub id: String,
    pub source: String,
    pub classification: String,
    pub state: String,
    pub result_code: Option<String>,
    pub parser: String,
    pub artifact_count: u64,
    pub explanation: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct ParseWarning {
    pub id: String,
    pub artifact_id: Option<String>,
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct Artifact {
    pub id: String,
    pub parent_id: Option<String>,
    pub layer: u32,
    pub normalized_path: String,
    pub original_path: String,
    pub size: u64,
    pub sha256: String,
    pub detected_type: String,
    pub parser_status: String,
    pub duplicate_of: Option<String>,
    pub warning: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct TimelineEvent {
    pub id: String,
    pub sequence: u64,
    pub timestamp_utc: Option<String>,
    pub timestamp_original: Option<String>,
    pub utc_offset_minutes: Option<i32>,
    pub provider: Option<String>,
    pub channel: Option<String>,
    pub event_code: Option<String>,
    pub component: Option<String>,
    pub severity: String,
    pub entity_id: Option<String>,
    pub message: String,
    pub current: bool,
    pub evidence_id: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
pub struct TimelineQuery {
    pub cursor: Option<u64>,
    pub limit: Option<usize>,
    pub search: Option<String>,
    pub severity: Option<Vec<String>>,
    pub source: Option<Vec<String>>,
    pub provider: Option<Vec<String>>,
    pub component: Option<Vec<String>>,
    pub session_id: Option<String>,
    pub since: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct TimelinePage {
    pub items: Vec<TimelineEvent>,
    pub next_cursor: Option<u64>,
    pub total_estimate: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct EvidenceRequest {
    pub evidence_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct ArtifactRequest {
    pub artifact_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct PreviewResponse {
    pub content_type: String,
    pub content: String,
    pub truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    Html,
    FindingsCsv,
    TimelineCsv,
    EvidenceJson,
    Pdf,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct ExportRequest {
    pub format: ExportFormat,
    pub session_id: Option<String>,
    pub include_raw_evidence: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct ComparisonSummary {
    pub identity_confidence: String,
    pub identity_explanation: String,
    pub mode: String,
    pub analysis_a: Summary,
    pub analysis_b: Summary,
    pub new_findings: Vec<Finding>,
    pub resolved_findings: Vec<Finding>,
    pub persistent_rule_ids: Vec<String>,
    pub coverage_changes: Vec<String>,
}
