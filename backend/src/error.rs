use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;
use utoipa::ToSchema;

pub type Result<T, E = AppError> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("invalid configuration")]
    Config,
    #[error("invalid request")]
    BadRequest,
    #[error("job not found")]
    NotFound,
    #[error("job is not ready")]
    NotReady,
    #[error("capacity exhausted")]
    Capacity,
    #[error("upload exceeds configured limit")]
    UploadTooLarge,
    #[error("archive rejected")]
    UnsafeArchive,
    #[error("operation timed out")]
    Timeout,
    #[error("operation cancelled")]
    Cancelled,
    #[error("internal operation failed")]
    Internal,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    pub code: &'static str,
    pub message: &'static str,
}

impl AppError {
    pub fn config(_detail: impl AsRef<str>) -> Self {
        Self::Config
    }

    pub fn bad_request(_detail: impl AsRef<str>) -> Self {
        Self::BadRequest
    }

    pub fn unsafe_archive(_detail: impl AsRef<str>) -> Self {
        Self::UnsafeArchive
    }

    pub fn internal<T: std::fmt::Display>(_detail: T) -> Self {
        Self::Internal
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Config => "configuration_error",
            Self::BadRequest => "invalid_request",
            Self::NotFound => "job_not_found",
            Self::NotReady => "job_not_ready",
            Self::Capacity => "capacity_exhausted",
            Self::UploadTooLarge => "upload_too_large",
            Self::UnsafeArchive => "archive_rejected",
            Self::Timeout => "operation_timed_out",
            Self::Cancelled => "operation_cancelled",
            Self::Internal => "internal_error",
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Config | Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            Self::BadRequest | Self::UnsafeArchive => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::NotReady => StatusCode::CONFLICT,
            Self::Capacity => StatusCode::SERVICE_UNAVAILABLE,
            Self::UploadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Timeout => StatusCode::REQUEST_TIMEOUT,
            Self::Cancelled => StatusCode::GONE,
        };
        let body = ErrorBody {
            code: self.code(),
            message: match self {
                Self::Config | Self::Internal => "The operation could not be completed.",
                Self::BadRequest => "The request is invalid.",
                Self::NotFound => "The transient analysis is unavailable or expired.",
                Self::NotReady => "The analysis is not ready.",
                Self::Capacity => "The service is at its configured transient capacity.",
                Self::UploadTooLarge => "The upload exceeds the configured limit.",
                Self::UnsafeArchive => "The archive failed a safety check.",
                Self::Timeout => "The operation exceeded its configured time limit.",
                Self::Cancelled => "The transient analysis was cancelled.",
            },
        };
        (status, Json(body)).into_response()
    }
}

impl From<std::io::Error> for AppError {
    fn from(_value: std::io::Error) -> Self {
        Self::Internal
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(_value: rusqlite::Error) -> Self {
        Self::Internal
    }
}

impl From<serde_json::Error> for AppError {
    fn from(_value: serde_json::Error) -> Self {
        Self::Internal
    }
}
