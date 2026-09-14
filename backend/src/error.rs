use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use utoipa::ToSchema;

pub type Result<T, E = AppError> = std::result::Result<T, E>;
pub const WORKER_FAILURE_FILE: &str = "failure.json";

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
    #[error("archive rejected: {0:?}")]
    UnsafeArchive(ArchiveRejection),
    #[error("operation timed out")]
    Timeout,
    #[error("operation cancelled")]
    Cancelled,
    #[error("internal operation failed")]
    Internal,
    #[error("worker failed safely")]
    WorkerFailure(SanitizedFailure),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveRejection {
    UnsupportedType,
    Malformed,
    UnsafePath,
    DuplicatePath,
    NestingLimit,
    FileCountLimit,
    FileSizeLimit,
    ExpandedSizeLimit,
    CompressionRatioLimit,
    SpecialEntry,
    MemberSizeMismatch,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SanitizedFailure {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

impl AppError {
    pub fn config(_detail: impl AsRef<str>) -> Self {
        Self::Config
    }

    pub fn bad_request(_detail: impl AsRef<str>) -> Self {
        Self::BadRequest
    }

    pub fn unsafe_archive(detail: impl AsRef<str>) -> Self {
        let reason = match detail.as_ref() {
            "unsupported outer archive" => ArchiveRejection::UnsupportedType,
            "malformed zip" | "malformed zip entry" | "malformed or unsupported cabinet" => {
                ArchiveRejection::Malformed
            }
            "invalid archive member name"
            | "encoded path separator"
            | "mixed path separators"
            | "absolute or UNC path"
            | "drive-qualified path"
            | "unsafe path component" => ArchiveRejection::UnsafePath,
            "case-insensitive duplicate path" => ArchiveRejection::DuplicatePath,
            "nesting depth exceeded" => ArchiveRejection::NestingLimit,
            "archive file count exceeded" => ArchiveRejection::FileCountLimit,
            "expanded file limit exceeded" | "actual expansion limit exceeded" => {
                ArchiveRejection::FileSizeLimit
            }
            "total expansion limit exceeded" => ArchiveRejection::ExpandedSizeLimit,
            "entry expansion ratio exceeded"
            | "aggregate expansion ratio exceeded"
            | "cabinet expansion ratio exceeded" => ArchiveRejection::CompressionRatioLimit,
            "special archive entry" => ArchiveRejection::SpecialEntry,
            "cabinet member size mismatch" | "cabinet entry cannot be read" => {
                ArchiveRejection::MemberSizeMismatch
            }
            _ => ArchiveRejection::Malformed,
        };
        Self::UnsafeArchive(reason)
    }

    pub fn internal<T: std::fmt::Display>(_detail: T) -> Self {
        Self::Internal
    }

    pub fn code(&self) -> &str {
        match self {
            Self::Config => "configuration_error",
            Self::BadRequest => "invalid_request",
            Self::NotFound => "job_not_found",
            Self::NotReady => "job_not_ready",
            Self::Capacity => "capacity_exhausted",
            Self::UploadTooLarge => "upload_too_large",
            Self::UnsafeArchive(reason) => reason.code(),
            Self::Timeout => "operation_timed_out",
            Self::Cancelled => "operation_cancelled",
            Self::Internal => "internal_error",
            Self::WorkerFailure(failure) => &failure.code,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Config | Self::Internal => {
                "The operation could not be completed. Try again; if the problem persists, check the service health and container resources."
            }
            Self::BadRequest => {
                "The request is invalid. Choose a ZIP or CAB diagnostic bundle and try again."
            }
            Self::NotFound => {
                "The transient analysis is unavailable or expired. Import the diagnostic bundle again."
            }
            Self::NotReady => {
                "The analysis is not ready yet. Wait for processing to finish and try again."
            }
            Self::Capacity => {
                "MDM Doctor is at its configured transient capacity. Delete an existing analysis or wait for another import to finish."
            }
            Self::UploadTooLarge => {
                "The diagnostic bundle exceeds the configured upload limit. Increase MAX_UPLOAD_BYTES or use a smaller bundle."
            }
            Self::UnsafeArchive(reason) => reason.message(),
            Self::Timeout => {
                "Analysis exceeded the configured time limit. Increase JOB_TIMEOUT_SECONDS or reduce the bundle size, then import it again."
            }
            Self::Cancelled => "The transient analysis was cancelled and its data was removed.",
            Self::WorkerFailure(failure) => &failure.message,
        }
    }

    pub fn sanitized_failure(&self) -> SanitizedFailure {
        SanitizedFailure {
            code: self.code().to_owned(),
            message: self.message().to_owned(),
        }
    }
}

impl ArchiveRejection {
    fn code(self) -> &'static str {
        match self {
            Self::UnsupportedType => "archive_type_unsupported",
            Self::Malformed => "archive_malformed",
            Self::UnsafePath => "archive_path_unsafe",
            Self::DuplicatePath => "archive_path_collision",
            Self::NestingLimit => "archive_nesting_limit",
            Self::FileCountLimit => "archive_file_count_limit",
            Self::FileSizeLimit => "archive_file_size_limit",
            Self::ExpandedSizeLimit => "archive_expanded_size_limit",
            Self::CompressionRatioLimit => "archive_compression_ratio_limit",
            Self::SpecialEntry => "archive_special_entry",
            Self::MemberSizeMismatch => "archive_member_invalid",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::UnsupportedType => {
                "This file is not a supported ZIP or CAB diagnostic bundle. Select the original Intune diagnostic archive without renaming or recompressing it."
            }
            Self::Malformed => {
                "The ZIP or CAB structure is damaged or uses an unsupported cabinet format. Recollect the diagnostics and import the original archive."
            }
            Self::UnsafePath => {
                "The archive contains an unsafe file path and was rejected before extraction. Recollect the diagnostics from a trusted source."
            }
            Self::DuplicatePath => {
                "The archive contains file names that collide on a case-insensitive filesystem. Recollect the diagnostics without combining archive contents manually."
            }
            Self::NestingLimit => {
                "The archive contains more nested archive layers than configured. Increase MAX_NESTING_DEPTH only if the bundle is trusted, or import the original collector output."
            }
            Self::FileCountLimit => {
                "The archive contains more files than configured. Increase MAX_ARCHIVE_FILES only if the bundle is trusted, or use a smaller diagnostic collection."
            }
            Self::FileSizeLimit => {
                "A file in the archive exceeds the configured expanded-file limit. Increase MAX_FILE_BYTES only if the bundle is trusted."
            }
            Self::ExpandedSizeLimit => {
                "The archive would exceed the configured total expanded-size limit. Increase MAX_EXPANDED_BYTES only if sufficient tmpfs and container memory are available."
            }
            Self::CompressionRatioLimit => {
                "The archive exceeds the configured compression-ratio safety limit. Import the original diagnostic bundle or adjust the ratio limit only after verifying the archive is trusted."
            }
            Self::SpecialEntry => {
                "The archive contains a link or special filesystem entry, which MDM Doctor does not extract. Recollect the diagnostics as regular files."
            }
            Self::MemberSizeMismatch => {
                "A CAB member could not be read at its declared size. The bundle may be truncated or damaged; recollect and import it again."
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Config | Self::Internal | Self::WorkerFailure(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::BadRequest | Self::UnsafeArchive(_) => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::NotReady => StatusCode::CONFLICT,
            Self::Capacity => StatusCode::SERVICE_UNAVAILABLE,
            Self::UploadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Timeout => StatusCode::REQUEST_TIMEOUT,
            Self::Cancelled => StatusCode::GONE,
        };
        let body = ErrorBody {
            code: self.code().to_owned(),
            message: self.message().to_owned(),
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

#[cfg(test)]
mod tests {
    use super::AppError;

    #[test]
    fn archive_rejections_have_specific_safe_guidance() {
        let cases = [
            ("unsupported outer archive", "archive_type_unsupported"),
            ("malformed zip", "archive_malformed"),
            ("absolute or UNC path", "archive_path_unsafe"),
            ("case-insensitive duplicate path", "archive_path_collision"),
            ("nesting depth exceeded", "archive_nesting_limit"),
            ("archive file count exceeded", "archive_file_count_limit"),
            ("expanded file limit exceeded", "archive_file_size_limit"),
            (
                "total expansion limit exceeded",
                "archive_expanded_size_limit",
            ),
            (
                "entry expansion ratio exceeded",
                "archive_compression_ratio_limit",
            ),
            ("special archive entry", "archive_special_entry"),
            ("cabinet member size mismatch", "archive_member_invalid"),
        ];
        for (detail, expected_code) in cases {
            let error = AppError::unsafe_archive(detail);
            assert_eq!(error.code(), expected_code);
            assert!(!error.message().contains(detail));
            assert!(error.message().contains('.') && error.message().len() > 60);
        }
    }

    #[test]
    fn worker_failure_payload_contains_only_sanitized_fields() {
        let payload =
            AppError::unsafe_archive("entry expansion ratio exceeded").sanitized_failure();
        let json = serde_json::to_value(payload).expect("serialize failure payload");
        assert_eq!(json.as_object().map(|value| value.len()), Some(2));
        assert_eq!(json["code"], "archive_compression_ratio_limit");
    }
}
