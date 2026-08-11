// Generated from ../openapi.json. Do not edit.

export type Application = {
  "app_type": string;
  "attempt_count": number;
  "esp_tracked": boolean;
  "evidence_ids": Array<string>;
  "id": string;
  "install_context"?: string | null;
  "intent"?: string | null;
  "name": string;
  "state": string;
};

export type Artifact = {
  "detected_type": string;
  "duplicate_of"?: string | null;
  "id": string;
  "layer": number;
  "normalized_path": string;
  "original_path": string;
  "parent_id"?: string | null;
  "parser_status": string;
  "sha256": string;
  "size": number;
  "warning"?: string | null;
};

export type ArtifactRequest = {
  "artifact_id": string;
};

export type BuildInfo = {
  "build": string;
  "name": string;
  "rule_pack": string;
  "version": string;
};

export type ComparisonSummary = {
  "analysis_a": Summary;
  "analysis_b": Summary;
  "coverage_changes": Array<string>;
  "identity_confidence": string;
  "identity_explanation": string;
  "mode": string;
  "new_findings": Array<Finding>;
  "persistent_rule_ids": Array<string>;
  "resolved_findings": Array<Finding>;
};

export type CoverageRecord = {
  "artifact_count": number;
  "classification": string;
  "explanation": string;
  "id": string;
  "parser": string;
  "result_code"?: string | null;
  "source": string;
  "state": string;
};

export type ErrorBody = {
  "code": string;
  "message": string;
};

export type EspResource = {
  "actual_state": string;
  "blocking_proven": boolean;
  "entity_id"?: string | null;
  "evidence_ids": Array<string>;
  "expected_state": string;
  "first_failure": boolean;
  "id": string;
  "phase": string;
  "resource_type": string;
  "substep": string;
};

export type EvidenceLink = {
  "artifact_id": string;
  "event_id"?: string | null;
  "id": string;
  "label": string;
  "source_span"?: string | null;
};

export type EvidenceRequest = {
  "evidence_ids": Array<string>;
};

export type ExecutionAttempt = {
  "application_id"?: string | null;
  "detection_result"?: string | null;
  "ended_at"?: string | null;
  "evidence_ids": Array<string>;
  "exit_code"?: number | null;
  "id": string;
  "reboot_during_attempt": boolean;
  "started_at"?: string | null;
  "state": string;
};

export type ExportFormat = "html" | "findings_csv" | "timeline_csv" | "evidence_json" | "pdf";

export type ExportRequest = {
  "format": ExportFormat;
  "include_raw_evidence": boolean;
  "session_id"?: string | null;
};

export type Finding = {
  "confidence": string;
  "current": boolean;
  "entity_id"?: string | null;
  "esp_tracked": boolean;
  "evidence": Array<EvidenceLink>;
  "explanation": string;
  "id": string;
  "recommendation": string;
  "rule_id": string;
  "rule_pack": string;
  "severity": string;
  "title": string;
};

export type HealthResponse = {
  "status": string;
};

export type JobPhase = "uploading" | "queued" | "extracting" | "parsing" | "correlating" | "ready" | "cancelling" | "failed";

export type JobView = {
  "can_reanalyze": boolean;
  "created_at": string;
  "expires_at": string;
  "phase": JobPhase;
  "progress_percent": number;
  "stage": string;
};

export type Kpis = {
  "applications": number;
  "artifacts": number;
  "coverage_percent": number;
  "critical_findings": number;
  "findings": number;
  "parsed_events": number;
};

export type ManagedEntity = {
  "current": boolean;
  "entity_type": string;
  "evidence_ids": Array<string>;
  "id": string;
  "name": string;
  "state": string;
};

export type ParseWarning = {
  "artifact_id"?: string | null;
  "code": string;
  "id": string;
  "message": string;
};

export type PreviewResponse = {
  "content": string;
  "content_type": string;
  "truncated": boolean;
};

export type ProvisioningStep = {
  "ended_at"?: string | null;
  "evidence_ids": Array<string>;
  "id": string;
  "phase": string;
  "session_id"?: string | null;
  "started_at"?: string | null;
  "state": string;
  "substep": string;
};

export type PublicLimits = {
  "job_ttl_seconds": number;
  "max_active_jobs": number;
  "max_archive_files": number;
  "max_events": number;
  "max_expanded_bytes": number;
  "max_file_bytes": number;
  "max_job_ttl_seconds": number;
  "max_nesting_depth": number;
  "max_upload_bytes": number;
  "timeline_page_max": number;
  "timeline_page_size": number;
};

export type Session = {
  "current": boolean;
  "ended_at"?: string | null;
  "evidence_ids": Array<string>;
  "id": string;
  "kind": string;
  "label": string;
  "started_at"?: string | null;
};

export type Summary = {
  "confidence": string;
  "current_status": string;
  "evidence_completeness": string;
  "first_blocking_step"?: string | null;
  "kpis": Kpis;
  "latest_session_id"?: string | null;
  "recommended_actions": Array<string>;
  "rule_pack": string;
  "verdict": string;
};

export type TimelineEvent = {
  "channel"?: string | null;
  "component"?: string | null;
  "current": boolean;
  "entity_id"?: string | null;
  "event_code"?: string | null;
  "evidence_id": string;
  "id": string;
  "message": string;
  "provider"?: string | null;
  "sequence": number;
  "severity": string;
  "timestamp_original"?: string | null;
  "timestamp_utc"?: string | null;
  "utc_offset_minutes"?: number | null;
};

export type TimelinePage = {
  "items": Array<TimelineEvent>;
  "next_cursor"?: number | null;
  "total_estimate": number;
};

export type TimelineQuery = {
  "component"?: Array<string> | null;
  "cursor"?: number | null;
  "limit"?: number | null;
  "provider"?: Array<string> | null;
  "search"?: string | null;
  "session_id"?: string | null;
  "severity"?: Array<string> | null;
  "since"?: string | null;
  "source"?: Array<string> | null;
};

export type ApiSchemaName = "Application" | "Artifact" | "ArtifactRequest" | "BuildInfo" | "ComparisonSummary" | "CoverageRecord" | "ErrorBody" | "EspResource" | "EvidenceLink" | "EvidenceRequest" | "ExecutionAttempt" | "ExportFormat" | "ExportRequest" | "Finding" | "HealthResponse" | "JobPhase" | "JobView" | "Kpis" | "ManagedEntity" | "ParseWarning" | "PreviewResponse" | "ProvisioningStep" | "PublicLimits" | "Session" | "Summary" | "TimelineEvent" | "TimelinePage" | "TimelineQuery";
export const apiSchemaNames = [
  "Application",
  "Artifact",
  "ArtifactRequest",
  "BuildInfo",
  "ComparisonSummary",
  "CoverageRecord",
  "ErrorBody",
  "EspResource",
  "EvidenceLink",
  "EvidenceRequest",
  "ExecutionAttempt",
  "ExportFormat",
  "ExportRequest",
  "Finding",
  "HealthResponse",
  "JobPhase",
  "JobView",
  "Kpis",
  "ManagedEntity",
  "ParseWarning",
  "PreviewResponse",
  "ProvisioningStep",
  "PublicLimits",
  "Session",
  "Summary",
  "TimelineEvent",
  "TimelinePage",
  "TimelineQuery"
] as const;
