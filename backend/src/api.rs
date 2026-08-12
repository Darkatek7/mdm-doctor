use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    Json, Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::StreamExt;
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::io::ReaderStream;
use tower_http::{compression::CompressionLayer, services::ServeDir};
use utoipa::OpenApi;

use crate::{
    APP_NAME, RULE_PACK_VERSION,
    config::PublicLimits,
    db,
    error::{AppError, ErrorBody, Result},
    exports, ingest,
    models::{
        Application, ApplicationPage, ApplicationQuery, ApplicationSummary, Artifact,
        ArtifactRequest, BuildInfo, ComparisonSummary, CoverageRecord, EntityPage, EntityQuery,
        EntitySummary, EntityTypeCount, EspResource, EvidenceLink, EvidenceRequest,
        ExecutionAttempt, ExportRequest, Finding, FindingCounts, FindingPage, FindingQuery,
        HealthCheck, HealthResponse, JobPhase, JobView, ManagedEntity, ParseWarning,
        PreviewResponse, PrimaryDiagnosis, ProvisioningStep, RedactionMode, Session, Summary,
        TimelinePage, TimelineQuery,
    },
    redaction,
    store::{AppState, Job},
};

pub const JOB_HEADER: &str = "x-mdm-job-handle";
pub const COMPARE_HEADER: &str = "x-mdm-compare-handle";
pub const REDACTION_HEADER: &str = "x-mdm-redaction-mode";
pub const SOURCE_HEADER: &str = "x-mdm-source-name";

#[derive(OpenApi)]
#[openapi(
    info(
        title = "MDM Doctor transient API",
        version = "1.0.0",
        description = "No-auth, no-persistence API for the active transient analysis only."
    ),
    components(schemas(
        ErrorBody,
        PublicLimits,
        BuildInfo,
        HealthResponse,
        JobView,
        Summary,
        PrimaryDiagnosis,
        HealthCheck,
        FindingCounts,
        Finding,
        FindingQuery,
        FindingPage,
        EvidenceLink,
        Session,
        Application,
        ApplicationQuery,
        ApplicationPage,
        ApplicationSummary,
        ExecutionAttempt,
        ManagedEntity,
        EntityQuery,
        EntityPage,
        EntitySummary,
        EntityTypeCount,
        EspResource,
        ProvisioningStep,
        CoverageRecord,
        ParseWarning,
        Artifact,
        TimelineQuery,
        TimelinePage,
        EvidenceRequest,
        ArtifactRequest,
        PreviewResponse,
        ExportRequest,
        ComparisonSummary
    ))
)]
pub struct ApiDoc;

pub fn router(state: AppState) -> Router {
    let static_dir = state.config().static_dir.clone();
    Router::new()
        .route("/api/v1/health/live", get(live))
        .route("/api/v1/health/ready", get(ready))
        .route("/api/v1/limits", get(limits))
        .route("/api/v1/build", get(build))
        .route("/api/v1/openapi.json", get(openapi))
        .route("/api/v1/local-import/claim", post(claim_local_import))
        .route("/api/v1/job", post(upload).get(job_state).delete(purge))
        .route("/api/v1/job/cancel", post(cancel))
        .route("/api/v1/job/reanalyze", post(reanalyze))
        .route("/api/v1/job/summary", get(summary))
        .route("/api/v1/job/sessions", get(sessions))
        .route("/api/v1/job/findings", get(findings))
        .route("/api/v1/job/applications", get(applications))
        .route("/api/v1/job/attempts", get(attempts))
        .route("/api/v1/job/entities", get(entities))
        .route("/api/v1/job/esp", get(esp))
        .route("/api/v1/job/provisioning", get(provisioning))
        .route("/api/v1/job/coverage", get(coverage))
        .route("/api/v1/job/warnings", get(warnings))
        .route("/api/v1/job/artifacts", get(artifacts))
        .route("/api/v1/job/query/timeline", post(timeline))
        .route("/api/v1/job/query/findings", post(query_findings))
        .route("/api/v1/job/query/applications", post(query_applications))
        .route("/api/v1/job/query/entities", post(query_entities))
        .route("/api/v1/job/evidence/resolve", post(resolve_evidence))
        .route("/api/v1/job/artifact/preview", post(preview))
        .route("/api/v1/job/artifact/download", post(download_artifact))
        .route("/api/v1/job/export", post(export))
        .route("/api/v1/compare/summary", post(compare))
        .fallback_service(ServeDir::new(static_dir).append_index_html_on_directories(true))
        .layer(CompressionLayer::new())
        .layer(middleware::from_fn(security_middleware))
        .with_state(state)
}

pub fn openapi_document() -> serde_json::Value {
    let mut value = serde_json::to_value(ApiDoc::openapi())
        .unwrap_or_else(|_| serde_json::json!({"openapi":"3.1.0"}));
    value["paths"] = serde_json::json!({
        "/api/v1/job":{"post":{"summary":"Stream an archive and create a transient job","parameters":[{"in":"header","name":"X-MDM-Source-Name","required":false,"schema":{"type":"string"}}],"responses":{"202":{"description":"Upload accepted; the 256-bit handle is returned only in X-MDM-Job-Handle"}}},"get":{"summary":"Get active job state","responses":{"200":{"description":"Current state"}}},"delete":{"summary":"Immediately purge the active job","responses":{"204":{"description":"Purged or already absent"}}}},
        "/api/v1/job/cancel":{"post":{"summary":"Cancel and purge analysis","responses":{"204":{"description":"Cancelled"}}}},
        "/api/v1/job/reanalyze":{"post":{"summary":"Reanalyze while the transient upload exists","responses":{"202":{"description":"Queued"}}}},
        "/api/v1/job/summary":{"get":{"summary":"Evidence-based summary","responses":{"200":{"description":"Summary"}}}},
        "/api/v1/job/sessions":{"get":{"summary":"Sessions","responses":{"200":{"description":"Sessions"}}}},
        "/api/v1/job/findings":{"get":{"summary":"Evidence-linked findings","responses":{"200":{"description":"Findings"}}}},
        "/api/v1/job/query/findings":{"post":{"summary":"Body-based filtered findings query","responses":{"200":{"description":"Finding page"}}}},
        "/api/v1/job/applications":{"get":{"summary":"Applications","responses":{"200":{"description":"Applications"}}}},
        "/api/v1/job/query/applications":{"post":{"summary":"Body-based filtered applications query","responses":{"200":{"description":"Application page"}}}},
        "/api/v1/job/attempts":{"get":{"summary":"Execution attempts","responses":{"200":{"description":"Attempts"}}}},
        "/api/v1/job/entities":{"get":{"summary":"Managed entities","responses":{"200":{"description":"Entities"}}}},
        "/api/v1/job/query/entities":{"post":{"summary":"Body-based filtered managed-entity query","responses":{"200":{"description":"Entity page"}}}},
        "/api/v1/job/esp":{"get":{"summary":"ESP resources","responses":{"200":{"description":"ESP state"}}}},
        "/api/v1/job/provisioning":{"get":{"summary":"Provisioning steps","responses":{"200":{"description":"Steps"}}}},
        "/api/v1/job/coverage":{"get":{"summary":"Parser and collection coverage","responses":{"200":{"description":"Coverage records"}}}},
        "/api/v1/job/warnings":{"get":{"summary":"Sanitized parser warnings","responses":{"200":{"description":"Warnings"}}}},
        "/api/v1/job/artifacts":{"get":{"summary":"Active artifact tree","responses":{"200":{"description":"Artifacts"}}}},
        "/api/v1/job/query/timeline":{"post":{"summary":"Body-based bounded timeline query","responses":{"200":{"description":"Timeline page"}}}},
        "/api/v1/job/evidence/resolve":{"post":{"summary":"Resolve active evidence identifiers from a request body","responses":{"200":{"description":"Evidence links"}}}},
        "/api/v1/job/artifact/preview":{"post":{"summary":"Return an inert bounded text preview","responses":{"200":{"description":"Safe preview"}}}},
        "/api/v1/job/artifact/download":{"post":{"summary":"Stream an active transient artifact","responses":{"200":{"description":"Artifact stream"}}}},
        "/api/v1/job/export":{"post":{"summary":"Stream an on-demand report","responses":{"200":{"description":"HTML, CSV, JSON, or PDF"}}}},
        "/api/v1/compare/summary":{"post":{"summary":"Compare two active jobs using two capability headers","responses":{"200":{"description":"Transient comparison"}}}},
        "/api/v1/health/live":{"get":{"summary":"Liveness","responses":{"200":{"description":"Alive"}}}},
        "/api/v1/health/ready":{"get":{"summary":"Readiness","responses":{"200":{"description":"Ready"}}}},
        "/api/v1/limits":{"get":{"summary":"Sanitized configured limits","responses":{"200":{"description":"Limits"}}}},
        "/api/v1/build":{"get":{"summary":"Sanitized build metadata","responses":{"200":{"description":"Build metadata"}}}},
        "/api/v1/openapi.json":{"get":{"summary":"OpenAPI 3.1 document","responses":{"200":{"description":"OpenAPI document"}}}}
    });
    value
}

async fn live() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "alive".into(),
    })
}
async fn ready(State(state): State<AppState>) -> Result<Json<HealthResponse>> {
    if !state.config().workspace.is_dir() {
        return Err(AppError::Internal);
    }
    Ok(Json(HealthResponse {
        status: "ready".into(),
    }))
}
async fn limits(State(state): State<AppState>) -> Json<PublicLimits> {
    Json(state.config().public_limits())
}
async fn build() -> Json<BuildInfo> {
    Json(BuildInfo {
        name: APP_NAME.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        rule_pack: RULE_PACK_VERSION.into(),
        build: option_env!("MDM_DOCTOR_BUILD")
            .unwrap_or("development")
            .into(),
    })
}
async fn openapi() -> Json<serde_json::Value> {
    Json(openapi_document())
}
async fn claim_local_import(State(state): State<AppState>) -> Result<Response> {
    let (handle, job) = match state.claim_local_import().await {
        Ok(value) => value,
        Err(AppError::NotFound) => return Ok(StatusCode::NO_CONTENT.into_response()),
        Err(error) => return Err(error),
    };
    let mut response =
        (StatusCode::OK, Json(job.view(state.config().job_ttl).await)).into_response();
    response.headers_mut().insert(
        HeaderName::from_static(JOB_HEADER),
        HeaderValue::from_str(&handle).map_err(|_| AppError::Internal)?,
    );
    Ok(response)
}

async fn upload(State(state): State<AppState>, headers: HeaderMap, body: Body) -> Result<Response> {
    reject_cross_site(&headers)?;
    if let Some(length) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        && length > state.config().max_upload_bytes
    {
        return Err(AppError::UploadTooLarge);
    }
    let source = headers
        .get(SOURCE_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("diagnostics.zip");
    let normalized = ingest::normalize_member_path(source)?;
    if normalized.contains('/') {
        return Err(AppError::BadRequest);
    }
    let _permit = state.acquire_upload().await?;
    let (handle, job) = state.create_job().await?;
    let result = receive_upload(&state, &job, source, body).await;
    if let Err(error) = result {
        state.delete(&handle).await?;
        return Err(error);
    }
    state.start_analysis(job.clone()).await?;
    let view = job.view(state.config().job_ttl).await;
    let mut response = (StatusCode::ACCEPTED, Json(view)).into_response();
    response.headers_mut().insert(
        HeaderName::from_static(JOB_HEADER),
        HeaderValue::from_str(&handle).map_err(|_| AppError::Internal)?,
    );
    Ok(response)
}

async fn receive_upload(state: &AppState, job: &Job, source: &str, body: Body) -> Result<String> {
    let partial = job.dir.join("upload.partial");
    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&partial)
        .await?;
    let mut stream = body.into_data_stream();
    let mut total = 0_u64;
    let mut hash = Sha256::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| AppError::BadRequest)?;
        total = total
            .checked_add(chunk.len() as u64)
            .ok_or(AppError::UploadTooLarge)?;
        if total > state.config().max_upload_bytes {
            return Err(AppError::UploadTooLarge);
        }
        hash.update(&chunk);
        file.write_all(&chunk).await?;
    }
    if total == 0 {
        return Err(AppError::BadRequest);
    }
    file.sync_data().await?;
    drop(file);
    tokio::fs::rename(&partial, job.dir.join("upload.bin")).await?;
    tokio::fs::write(job.dir.join("source.name"), source.as_bytes()).await?;
    let digest = format!("{:x}", hash.finalize());
    tokio::fs::write(job.dir.join("upload.sha256"), digest.as_bytes()).await?;
    Ok(digest)
}

async fn job_state(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<JobView>> {
    let job = job(&state, &headers).await?;
    Ok(Json(job.view(state.config().job_ttl).await))
}
async fn cancel(State(state): State<AppState>, headers: HeaderMap) -> Result<StatusCode> {
    let handle = handle(&headers)?;
    state.cancel(handle).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn purge(State(state): State<AppState>, headers: HeaderMap) -> Result<StatusCode> {
    let handle = handle(&headers).unwrap_or("");
    state.delete(handle).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn reanalyze(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<JobView>)> {
    let handle = handle(&headers)?;
    let job = state.reanalyze(handle).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(job.view(state.config().job_ttl).await),
    ))
}

macro_rules! db_get {
    ($name:ident,$ty:ty,$query:path,$redact:path) => {
        async fn $name(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<$ty>> {
            let mode = redaction_mode(&headers);
            let job = ready_job(&state, &headers).await?;
            let value = query_db(job, |conn| $query(&conn)).await?;
            Ok(Json($redact(value, mode)))
        }
    };
}
db_get!(summary, Summary, db::summary, redaction::summary);
db_get!(sessions, Vec<Session>, db::sessions, redaction::sessions);
db_get!(findings, Vec<Finding>, db::findings, redaction::findings);
db_get!(
    applications,
    Vec<Application>,
    db::applications,
    redaction::applications
);
db_get!(
    attempts,
    Vec<ExecutionAttempt>,
    db::attempts,
    redaction::attempts
);
db_get!(
    entities,
    Vec<ManagedEntity>,
    db::entities,
    redaction::entities
);
db_get!(
    provisioning,
    Vec<ProvisioningStep>,
    db::steps,
    redaction::steps
);
db_get!(
    coverage,
    Vec<CoverageRecord>,
    db::coverage,
    redaction::coverage
);
db_get!(
    warnings,
    Vec<ParseWarning>,
    db::warnings,
    redaction::warnings
);
db_get!(
    artifacts,
    Vec<Artifact>,
    db::artifacts,
    redaction::artifacts
);

async fn esp(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Vec<EspResource>>> {
    let job = ready_job(&state, &headers).await?;
    Ok(Json(query_db(job, |conn| db::esp_resources(&conn)).await?))
}

async fn timeline(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(query): Json<TimelineQuery>,
) -> Result<Json<TimelinePage>> {
    let mode = redaction_mode(&headers);
    let job = ready_job(&state, &headers).await?;
    let default = state.config().timeline_page_size;
    let max = state.config().timeline_page_max;
    let page = query_db(job, move |conn| db::timeline(&conn, &query, default, max)).await?;
    Ok(Json(redaction::timeline(page, mode)))
}
async fn query_findings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(query): Json<FindingQuery>,
) -> Result<Json<FindingPage>> {
    let mode = redaction_mode(&headers);
    let job = ready_job(&state, &headers).await?;
    let max = state.config().timeline_page_max;
    let page = query_db(job, move |conn| db::query_findings(&conn, &query, max)).await?;
    Ok(Json(redaction::finding_page(page, mode)))
}
async fn query_applications(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(query): Json<ApplicationQuery>,
) -> Result<Json<ApplicationPage>> {
    let mode = redaction_mode(&headers);
    let job = ready_job(&state, &headers).await?;
    let max = state.config().timeline_page_max;
    let page = query_db(job, move |conn| db::query_applications(&conn, &query, max)).await?;
    Ok(Json(redaction::application_page(page, mode)))
}
async fn query_entities(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(query): Json<EntityQuery>,
) -> Result<Json<EntityPage>> {
    let mode = redaction_mode(&headers);
    let job = ready_job(&state, &headers).await?;
    let max = state.config().timeline_page_max;
    let page = query_db(job, move |conn| db::query_entities(&conn, &query, max)).await?;
    Ok(Json(redaction::entity_page(page, mode)))
}
async fn resolve_evidence(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<EvidenceRequest>,
) -> Result<Json<Vec<EvidenceLink>>> {
    if request.evidence_ids.len() > 100 {
        return Err(AppError::BadRequest);
    }
    let mode = redaction_mode(&headers);
    let job = ready_job(&state, &headers).await?;
    let ids = request.evidence_ids;
    let value = query_db(job, move |conn| db::evidence(&conn, &ids)).await?;
    Ok(Json(redaction::evidence(value, mode)))
}

async fn preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ArtifactRequest>,
) -> Result<Json<PreviewResponse>> {
    let mode = redaction_mode(&headers);
    let job = ready_job(&state, &headers).await?;
    let id = request.artifact_id.clone();
    let record = query_db(job.clone(), move |conn| db::artifact_object(&conn, &id))
        .await?
        .ok_or(AppError::NotFound)?;
    let path = resolve_object(&job.dir, &record.0)?;
    let metadata = tokio::fs::metadata(&path).await?;
    let limit = 1_048_576_u64;
    let file = tokio::fs::File::open(path).await?;
    let mut data = Vec::with_capacity(metadata.len().min(limit) as usize);
    file.take(limit).read_to_end(&mut data).await?;
    let mut content = if record.2 == "html" {
        let html = scraper::Html::parse_document(&String::from_utf8_lossy(&data));
        html.root_element().text().collect::<Vec<_>>().join(" ")
    } else {
        String::from_utf8_lossy(&data).into_owned()
    };
    content = redaction::text(&content, mode);
    Ok(Json(PreviewResponse {
        content_type: "text/plain".into(),
        content,
        truncated: metadata.len() > limit,
    }))
}

async fn download_artifact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ArtifactRequest>,
) -> Result<Response> {
    let job = ready_job(&state, &headers).await?;
    let id = request.artifact_id;
    let record = query_db(job.clone(), move |conn| db::artifact_object(&conn, &id))
        .await?
        .ok_or(AppError::NotFound)?;
    let path = resolve_object(&job.dir, &record.0)?;
    let file = tokio::fs::File::open(path).await?;
    let stream = ReaderStream::new(file);
    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"mdm-doctor-artifact.bin\""),
    );
    Ok(response)
}

async fn export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ExportRequest>,
) -> Result<Response> {
    let capability = handle(&headers)?.to_owned();
    let mode = redaction_mode(&headers);
    if mode == RedactionMode::Original && !request.include_raw_evidence {
        return Err(AppError::BadRequest);
    }
    let job = ready_job(&state, &headers).await?;
    let generated = match query_db(job, move |conn| exports::generate(&conn, &request, mode)).await
    {
        Ok(value) => value,
        Err(error) => {
            state.delete(&capability).await?;
            return Err(error);
        }
    };
    let mut response = Response::new(Body::from(generated.bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(generated.content_type),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{}\"", generated.filename))
            .map_err(|_| AppError::Internal)?,
    );
    Ok(response)
}

async fn compare(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ComparisonSummary>> {
    let mode = redaction_mode(&headers);
    let first = ready_job(&state, &headers).await?;
    let second_handle = headers
        .get(COMPARE_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::NotFound)?;
    let second = state.get(second_handle).await?;
    if second.phase().await != JobPhase::Ready {
        return Err(AppError::NotReady);
    }
    let a = first.db_path();
    let b = second.db_path();
    let value = tokio::task::spawn_blocking(move || compare_databases(&a, &b))
        .await
        .map_err(AppError::internal)??;
    Ok(Json(redaction::comparison(value, mode)))
}

fn compare_databases(a: &Path, b: &Path) -> Result<ComparisonSummary> {
    let ca = db::open_read_only(a)?;
    let cb = db::open_read_only(b)?;
    let sa = db::summary(&ca)?;
    let sb = db::summary(&cb)?;
    let fa = db::findings(&ca)?;
    let fb = db::findings(&cb)?;
    let ia:Option<String>=ca.query_row("SELECT device_identity_hash FROM device_snapshots WHERE device_identity_hash IS NOT NULL LIMIT 1",[],|r|r.get(0)).optional()?;
    let ib:Option<String>=cb.query_row("SELECT device_identity_hash FROM device_snapshots WHERE device_identity_hash IS NOT NULL LIMIT 1",[],|r|r.get(0)).optional()?;
    let identity = match (ia.as_deref(), ib.as_deref()) {
        (Some(x), Some(y)) if x == y => "same",
        (Some(_), Some(_)) => "different",
        _ => "uncertain",
    };
    let rules_a: HashSet<&str> = fa.iter().map(|f| f.rule_id.as_str()).collect();
    let rules_b: HashSet<&str> = fb.iter().map(|f| f.rule_id.as_str()).collect();
    let new_findings = if identity == "same" {
        fb.iter()
            .filter(|f| !rules_a.contains(f.rule_id.as_str()))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    let resolved_findings = if identity == "same" {
        fa.iter()
            .filter(|f| !rules_b.contains(f.rule_id.as_str()))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    let persistent_rule_ids = if identity == "same" {
        rules_a
            .intersection(&rules_b)
            .map(|s| (*s).to_owned())
            .collect()
    } else {
        Vec::new()
    };
    let ca_rows = db::coverage(&ca)?;
    let cb_rows = db::coverage(&cb)?;
    let mut coverage_changes = Vec::new();
    for row in &cb_rows {
        if let Some(old) = ca_rows.iter().find(|a| a.source == row.source)
            && old.state != row.state
        {
            coverage_changes.push(format!("{}: {} to {}", row.source, old.state, row.state));
        }
    }
    Ok(ComparisonSummary {
        identity_confidence: identity.into(),
        identity_explanation: match identity {
            "same" => "A stable device identifier agrees across both active bundles.",
            "different" => "Stable device identifiers differ; longitudinal claims are suppressed.",
            _ => "Available sources do not prove whether the bundles represent the same device.",
        }
        .into(),
        mode: if identity == "same" {
            "longitudinal"
        } else {
            "side_by_side"
        }
        .into(),
        analysis_a: sa,
        analysis_b: sb,
        new_findings,
        resolved_findings,
        persistent_rule_ids,
        coverage_changes,
    })
}

async fn query_db<T, F>(job: Arc<Job>, query: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(rusqlite::Connection) -> Result<T> + Send + 'static,
{
    let path = job.db_path();
    tokio::task::spawn_blocking(move || {
        let conn = db::open_read_only(&path)?;
        query(conn)
    })
    .await
    .map_err(AppError::internal)?
}
async fn job(state: &AppState, headers: &HeaderMap) -> Result<Arc<Job>> {
    state.get(handle(headers)?).await
}
async fn ready_job(state: &AppState, headers: &HeaderMap) -> Result<Arc<Job>> {
    let job = job(state, headers).await?;
    if job.phase().await != JobPhase::Ready || !job.db_path().is_file() {
        return Err(AppError::NotReady);
    }
    Ok(job)
}
fn handle(headers: &HeaderMap) -> Result<&str> {
    headers
        .get(JOB_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::NotFound)
}
fn redaction_mode(headers: &HeaderMap) -> RedactionMode {
    match headers.get(REDACTION_HEADER).and_then(|v| v.to_str().ok()) {
        Some(v) if v.eq_ignore_ascii_case("original") => RedactionMode::Original,
        _ => RedactionMode::Redacted,
    }
}
fn resolve_object(job_dir: &Path, relative: &str) -> Result<PathBuf> {
    let valid = relative == "upload.bin"
        || (relative.starts_with("objects/")
            && relative[8..].len() == 64
            && relative[8..].chars().all(|c| c.is_ascii_hexdigit()));
    if !valid {
        return Err(AppError::NotFound);
    }
    Ok(job_dir.join(relative))
}

async fn security_middleware(request: Request, next: Next) -> Response {
    if reject_cross_site(request.headers()).is_err() {
        return AppError::BadRequest.into_response();
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    );
    headers.insert(HeaderName::from_static("content-security-policy"),HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0, private"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}
fn reject_cross_site(headers: &HeaderMap) -> Result<()> {
    if headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("cross-site"))
    {
        return Err(AppError::BadRequest);
    }
    if let (Some(origin), Some(host)) = (
        headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()),
        headers.get(header::HOST).and_then(|v| v.to_str().ok()),
    ) && origin != format!("http://{host}")
        && origin != format!("https://{host}")
    {
        return Err(AppError::BadRequest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn security_headers_and_capability_boundary_are_enforced() {
        let workspace = tempfile::tempdir().unwrap();
        let static_dir = tempfile::tempdir().unwrap();
        let config = crate::config::Config {
            workspace: workspace.path().to_path_buf(),
            static_dir: static_dir.path().to_path_buf(),
            ..Default::default()
        };
        let state = AppState::new(config).await.unwrap();
        let app = router(state.clone());

        let public = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health/live")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(public.status(), StatusCode::OK);
        assert_eq!(
            public.headers()[header::CACHE_CONTROL],
            "no-store, max-age=0, private"
        );
        assert_eq!(public.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert!(public.headers().get(header::SET_COOKIE).is_none());
        assert!(
            public.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("object-src 'none'")
        );

        let missing = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/job")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert!(missing.headers().get(header::SET_COOKIE).is_none());

        let cross_site = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/job")
                    .header("sec-fetch-site", "cross-site")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_site.status(), StatusCode::BAD_REQUEST);
        state.shutdown().await;
    }
}
