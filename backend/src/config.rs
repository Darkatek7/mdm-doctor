use std::{env, net::IpAddr, path::PathBuf, str::FromStr, time::Duration};

use serde::Serialize;
use utoipa::ToSchema;

use crate::error::{AppError, Result};

#[derive(Clone, Debug)]
pub struct Config {
    pub bind_address: IpAddr,
    pub port: u16,
    pub workspace: PathBuf,
    pub static_dir: PathBuf,
    pub job_ttl: Duration,
    pub max_upload_bytes: u64,
    pub max_expanded_bytes: u64,
    pub max_file_bytes: u64,
    pub max_archive_files: usize,
    pub max_nesting_depth: usize,
    pub max_compression_ratio: u64,
    pub max_aggregate_ratio: u64,
    pub max_events: u64,
    pub max_active_jobs: usize,
    pub max_concurrent_uploads: usize,
    pub max_workers: usize,
    pub job_timeout: Duration,
    pub parser_timeout: Duration,
    pub timeline_page_size: usize,
    pub timeline_page_max: usize,
    pub debug_sanitized: bool,
    pub default_identifiers_visible: bool,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct PublicLimits {
    pub max_upload_bytes: u64,
    pub max_expanded_bytes: u64,
    pub max_file_bytes: u64,
    pub max_archive_files: usize,
    pub max_nesting_depth: usize,
    pub max_events: u64,
    pub job_ttl_seconds: u64,
    pub max_job_ttl_seconds: u64,
    pub max_active_jobs: usize,
    pub timeline_page_size: usize,
    pub timeline_page_max: usize,
    pub default_identifiers_visible: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_address: IpAddr::from([127, 0, 0, 1]),
            port: 8080,
            workspace: PathBuf::from("/run/mdm-doctor"),
            static_dir: PathBuf::from("/app/static"),
            job_ttl: Duration::from_secs(1_800),
            max_upload_bytes: 1_073_741_824,
            max_expanded_bytes: 4_294_967_296,
            max_file_bytes: 1_073_741_824,
            max_archive_files: 100_000,
            max_nesting_depth: 4,
            max_compression_ratio: 100,
            max_aggregate_ratio: 50,
            max_events: 1_250_000,
            max_active_jobs: 4,
            max_concurrent_uploads: 2,
            max_workers: 2,
            job_timeout: Duration::from_secs(1_200),
            parser_timeout: Duration::from_secs(120),
            timeline_page_size: 100,
            timeline_page_max: 500,
            debug_sanitized: false,
            default_identifiers_visible: true,
        }
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let mut cfg = Self::default();
        cfg.bind_address = parse("BIND_ADDRESS", cfg.bind_address)?;
        cfg.port = parse("PORT", cfg.port)?;
        cfg.workspace = path("WORKSPACE_PATH", cfg.workspace);
        cfg.static_dir = path("STATIC_DIR", cfg.static_dir);
        cfg.job_ttl = Duration::from_secs(parse("JOB_TTL_SECONDS", cfg.job_ttl.as_secs())?);
        cfg.max_upload_bytes = parse("MAX_UPLOAD_BYTES", cfg.max_upload_bytes)?;
        cfg.max_expanded_bytes = parse("MAX_EXPANDED_BYTES", cfg.max_expanded_bytes)?;
        cfg.max_file_bytes = parse("MAX_FILE_BYTES", cfg.max_file_bytes)?;
        cfg.max_archive_files = parse("MAX_ARCHIVE_FILES", cfg.max_archive_files)?;
        cfg.max_nesting_depth = parse("MAX_NESTING_DEPTH", cfg.max_nesting_depth)?;
        cfg.max_compression_ratio = parse("MAX_COMPRESSION_RATIO", cfg.max_compression_ratio)?;
        cfg.max_aggregate_ratio = parse("MAX_AGGREGATE_RATIO", cfg.max_aggregate_ratio)?;
        cfg.max_events = parse("MAX_EVENTS", cfg.max_events)?;
        cfg.max_active_jobs = parse("MAX_ACTIVE_JOBS", cfg.max_active_jobs)?;
        cfg.max_concurrent_uploads = parse("MAX_CONCURRENT_UPLOADS", cfg.max_concurrent_uploads)?;
        cfg.max_workers = parse("MAX_WORKERS", cfg.max_workers)?;
        cfg.job_timeout =
            Duration::from_secs(parse("JOB_TIMEOUT_SECONDS", cfg.job_timeout.as_secs())?);
        cfg.parser_timeout = Duration::from_secs(parse(
            "PARSER_TIMEOUT_SECONDS",
            cfg.parser_timeout.as_secs(),
        )?);
        cfg.timeline_page_size = parse("TIMELINE_PAGE_SIZE", cfg.timeline_page_size)?;
        cfg.timeline_page_max = parse("TIMELINE_PAGE_MAX", cfg.timeline_page_max)?;
        cfg.debug_sanitized = parse("DEBUG_SANITIZED", cfg.debug_sanitized)?;
        cfg.default_identifiers_visible = parse(
            "DEFAULT_IDENTIFIERS_VISIBLE",
            cfg.default_identifiers_visible,
        )?;

        if cfg.job_ttl > Duration::from_secs(7_200) {
            return Err(AppError::config(
                "JOB_TTL_SECONDS exceeds the two-hour maximum",
            ));
        }
        if cfg.timeline_page_size == 0 || cfg.timeline_page_size > cfg.timeline_page_max {
            return Err(AppError::config("invalid timeline page limits"));
        }
        if cfg.max_workers == 0 || cfg.max_concurrent_uploads == 0 || cfg.max_active_jobs == 0 {
            return Err(AppError::config("concurrency limits must be non-zero"));
        }
        Ok(cfg)
    }

    pub fn public_limits(&self) -> PublicLimits {
        PublicLimits {
            max_upload_bytes: self.max_upload_bytes,
            max_expanded_bytes: self.max_expanded_bytes,
            max_file_bytes: self.max_file_bytes,
            max_archive_files: self.max_archive_files,
            max_nesting_depth: self.max_nesting_depth,
            max_events: self.max_events,
            job_ttl_seconds: self.job_ttl.as_secs(),
            max_job_ttl_seconds: 7_200,
            max_active_jobs: self.max_active_jobs,
            timeline_page_size: self.timeline_page_size,
            timeline_page_max: self.timeline_page_max,
            default_identifiers_visible: self.default_identifiers_visible,
        }
    }
}

fn parse<T>(name: &str, default: T) -> Result<T>
where
    T: FromStr,
{
    match env::var(name) {
        Ok(raw) => raw
            .parse::<T>()
            .map_err(|_| AppError::config(format!("invalid {name}"))),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(_) => Err(AppError::config(format!("invalid {name}"))),
    }
}

fn path(name: &str, default: PathBuf) -> PathBuf {
    env::var_os(name).map(PathBuf::from).unwrap_or(default)
}
