use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use tokio::{
    process::Command,
    sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore},
};
use tokio_util::sync::CancellationToken;

use crate::{
    config::Config,
    error::{AppError, Result, SanitizedFailure, WORKER_FAILURE_FILE},
    models::{JobPhase, JobView},
};

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    config: Config,
    jobs: RwLock<HashMap<[u8; 32], Arc<Job>>>,
    upload_slots: Arc<Semaphore>,
    worker_slots: Arc<Semaphore>,
    shutting_down: CancellationToken,
    bootstrap_handle: Mutex<Option<String>>,
}

pub struct Job {
    pub id: String,
    pub dir: PathBuf,
    created_at: SystemTime,
    last_access: AtomicU64,
    status: RwLock<ProgressState>,
    cancel: Mutex<CancellationToken>,
}

#[derive(Clone)]
struct ProgressState {
    phase: JobPhase,
    percent: u8,
    stage: String,
    processed_artifacts: Option<u64>,
    total_artifacts: Option<u64>,
    unique_events: Option<u64>,
    duplicate_events: Option<u64>,
    error_code: Option<String>,
    error_message: Option<String>,
}

#[derive(Deserialize)]
struct ProgressFile {
    phase: String,
    percent: u8,
    stage: String,
    processed_artifacts: Option<u64>,
    total_artifacts: Option<u64>,
    unique_events: Option<u64>,
    duplicate_events: Option<u64>,
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self> {
        tokio::fs::create_dir_all(&config.workspace).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&config.workspace, std::fs::Permissions::from_mode(0o700))
                .await?;
        }
        let state = Self {
            inner: Arc::new(Inner {
                upload_slots: Arc::new(Semaphore::new(config.max_concurrent_uploads)),
                worker_slots: Arc::new(Semaphore::new(config.max_workers)),
                config,
                jobs: RwLock::new(HashMap::new()),
                shutting_down: CancellationToken::new(),
                bootstrap_handle: Mutex::new(None),
            }),
        };
        state.spawn_ttl_sweeper();
        Ok(state)
    }

    pub fn config(&self) -> &Config {
        &self.inner.config
    }

    pub async fn acquire_upload(&self) -> Result<OwnedSemaphorePermit> {
        self.inner
            .upload_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| AppError::Capacity)
    }

    pub async fn create_job(&self) -> Result<(String, Arc<Job>)> {
        if self.inner.jobs.read().await.len() >= self.inner.config.max_active_jobs {
            return Err(AppError::Capacity);
        }
        let mut handle = [0_u8; 32];
        OsRng.fill_bytes(&mut handle);
        let encoded = URL_SAFE_NO_PAD.encode(handle);
        let digest = digest_handle(&handle);
        let id = uuid::Uuid::new_v4().simple().to_string();
        let dir = self.inner.config.workspace.join(&id);
        tokio::fs::create_dir(&dir).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).await?;
        }
        let now = now_seconds();
        let job = Arc::new(Job {
            id,
            dir,
            created_at: SystemTime::now(),
            last_access: AtomicU64::new(now),
            status: RwLock::new(ProgressState {
                phase: JobPhase::Uploading,
                percent: 0,
                stage: "Receiving upload".into(),
                processed_artifacts: None,
                total_artifacts: None,
                unique_events: None,
                duplicate_events: None,
                error_code: None,
                error_message: None,
            }),
            cancel: Mutex::new(CancellationToken::new()),
        });
        self.inner.jobs.write().await.insert(digest, job.clone());
        Ok((encoded, job))
    }

    pub async fn get(&self, encoded: &str) -> Result<Arc<Job>> {
        let raw = decode_handle(encoded)?;
        let digest = digest_handle(&raw);
        let job = self
            .inner
            .jobs
            .read()
            .await
            .get(&digest)
            .cloned()
            .ok_or(AppError::NotFound)?;
        job.touch();
        Ok(job)
    }

    pub async fn delete(&self, encoded: &str) -> Result<()> {
        let raw = match decode_handle(encoded) {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        let digest = digest_handle(&raw);
        if let Some(job) = self.inner.jobs.write().await.remove(&digest) {
            job.cancel.lock().await.cancel();
            purge_dir(&job.dir).await;
        }
        Ok(())
    }

    pub async fn start_analysis(&self, job: Arc<Job>) -> Result<()> {
        if !job.dir.join("upload.bin").is_file() {
            return Err(AppError::BadRequest);
        }
        let token = CancellationToken::new();
        *job.cancel.lock().await = token.clone();
        job.set_status(JobPhase::Queued, 10, "Waiting for an analysis worker")
            .await;
        let state = self.clone();
        tokio::spawn(async move {
            let permit = match state.inner.worker_slots.clone().acquire_owned().await {
                Ok(value) => value,
                Err(_) => return,
            };
            if token.is_cancelled() {
                return;
            }
            let result = state.run_child(&job, token.clone(), permit).await;
            match result {
                Ok(()) if job.dir.join(crate::db::DB_FILE).is_file() => {
                    job.set_status(JobPhase::Ready, 100, "Analysis ready").await;
                    job.touch();
                }
                Ok(()) => {
                    purge_dir(&job.dir).await;
                    job.set_failure(&AppError::Internal).await;
                }
                Err(error) => {
                    purge_dir(&job.dir).await;
                    job.set_failure(&error).await;
                }
            }
        });
        Ok(())
    }

    async fn run_child(
        &self,
        job: &Arc<Job>,
        token: CancellationToken,
        _permit: OwnedSemaphorePermit,
    ) -> Result<()> {
        let executable = std::env::current_exe()?;
        let cpu_seconds = self
            .inner
            .config
            .job_timeout
            .as_secs()
            .saturating_mul(4)
            .saturating_add(30);
        #[cfg(target_os = "linux")]
        let address_space = 10_u64 * 1024 * 1024 * 1024;
        let file_size = self.inner.config.max_expanded_bytes;
        let mut command = Command::new(executable);
        command
            .arg("worker")
            .arg("--job-dir")
            .arg(&job.dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(unix)]
        unsafe {
            use std::os::unix::process::CommandExt;
            command.as_std_mut().pre_exec(move || {
                let core = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let files = libc::rlimit {
                    rlim_cur: 4096,
                    rlim_max: 4096,
                };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &files) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let cpu = libc::rlimit {
                    rlim_cur: cpu_seconds,
                    rlim_max: cpu_seconds,
                };
                if libc::setrlimit(libc::RLIMIT_CPU, &cpu) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                #[cfg(target_os = "linux")]
                {
                    let memory = libc::rlimit {
                        rlim_cur: address_space,
                        rlim_max: address_space,
                    };
                    if libc::setrlimit(libc::RLIMIT_AS, &memory) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                let size = libc::rlimit {
                    rlim_cur: file_size,
                    rlim_max: file_size,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &size) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        let timeout = tokio::time::sleep(self.inner.config.job_timeout);
        tokio::pin!(timeout);
        tokio::select! {
            status = child.wait() => {
                if status?.success() {
                    Ok(())
                } else {
                    let failure = tokio::fs::read(job.dir.join(WORKER_FAILURE_FILE))
                        .await
                        .ok()
                        .and_then(|bytes| serde_json::from_slice::<SanitizedFailure>(&bytes).ok());
                    failure.map_or(Err(AppError::Internal), |failure| Err(AppError::WorkerFailure(failure)))
                }
            }
            _ = token.cancelled() => {
                let _ = child.kill().await;
                Err(AppError::Cancelled)
            }
            _ = &mut timeout => {
                let _ = child.kill().await;
                Err(AppError::Timeout)
            }
        }
    }

    pub async fn cancel(&self, encoded: &str) -> Result<()> {
        let job = self.get(encoded).await?;
        job.set_status(
            JobPhase::Cancelling,
            job.status.read().await.percent,
            "Cancelling and purging",
        )
        .await;
        self.delete(encoded).await
    }

    pub async fn reanalyze(&self, encoded: &str) -> Result<Arc<Job>> {
        let job = self.get(encoded).await?;
        if !job.dir.join("upload.bin").is_file() {
            return Err(AppError::NotReady);
        }
        self.start_analysis(job.clone()).await?;
        Ok(job)
    }

    pub async fn shutdown(&self) {
        self.inner.shutting_down.cancel();
        let jobs = std::mem::take(&mut *self.inner.jobs.write().await);
        for (_, job) in jobs {
            job.cancel.lock().await.cancel();
            purge_dir(&job.dir).await;
        }
    }

    pub async fn prepare_local_import(&self, source: PathBuf) -> Result<()> {
        if !self.inner.config.bind_address.is_loopback() || !source.is_dir() {
            return Err(AppError::BadRequest);
        }
        let (handle, job) = self.create_job().await?;
        let destination = job.dir.join("upload.bin");
        let config = self.inner.config.clone();
        let import =
            tokio::task::spawn_blocking(move || package_folder(&config, &source, &destination))
                .await
                .map_err(AppError::internal)?;
        if let Err(error) = import {
            self.delete(&handle).await?;
            return Err(error);
        }
        tokio::fs::write(job.dir.join("source.name"), b"local-import.zip").await?;
        *self.inner.bootstrap_handle.lock().await = Some(handle);
        self.start_analysis(job).await
    }

    pub async fn claim_local_import(&self) -> Result<(String, Arc<Job>)> {
        let handle = self
            .inner
            .bootstrap_handle
            .lock()
            .await
            .take()
            .ok_or(AppError::NotFound)?;
        let job = self.get(&handle).await?;
        Ok((handle, job))
    }

    fn spawn_ttl_sweeper(&self) {
        let state = self.clone();
        tokio::spawn(async move {
            let interval_secs = state.inner.config.job_ttl.as_secs().clamp(10, 60) / 2;
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs.max(5)));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let now=now_seconds();
                        let ttl=state.inner.config.job_ttl.as_secs();
                        let expired:Vec<[u8;32]>={
                            let jobs=state.inner.jobs.read().await;
                            jobs.iter().filter(|(_,job)|now.saturating_sub(job.last_access.load(Ordering::Relaxed))>=ttl).map(|(key,_)|*key).collect()
                        };
                        for key in expired {
                            if let Some(job)=state.inner.jobs.write().await.remove(&key){
                                job.cancel.lock().await.cancel();
                                purge_dir(&job.dir).await;
                            }
                        }
                    }
                    _ = state.inner.shutting_down.cancelled() => break,
                }
            }
        });
    }
}

impl Job {
    pub fn db_path(&self) -> PathBuf {
        self.dir.join(crate::db::DB_FILE)
    }
    pub fn touch(&self) {
        self.last_access.store(now_seconds(), Ordering::Relaxed);
    }

    pub async fn phase(&self) -> JobPhase {
        self.status.read().await.phase.clone()
    }

    pub async fn view(&self, ttl: Duration) -> JobView {
        self.refresh_progress().await;
        let status = self.status.read().await.clone();
        let created: DateTime<Utc> = self.created_at.into();
        let expires =
            UNIX_EPOCH + Duration::from_secs(self.last_access.load(Ordering::Relaxed)) + ttl;
        let expires: DateTime<Utc> = expires.into();
        JobView {
            phase: status.phase,
            progress_percent: status.percent,
            stage: status.stage,
            created_at: created.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
            can_reanalyze: self.dir.join("upload.bin").is_file(),
            processed_artifacts: status.processed_artifacts,
            total_artifacts: status.total_artifacts,
            unique_events: status.unique_events,
            duplicate_events: status.duplicate_events,
            error_code: status.error_code,
            error_message: status.error_message,
        }
    }

    async fn refresh_progress(&self) {
        let path = self.dir.join("progress.json");
        let Ok(bytes) = tokio::fs::read(path).await else {
            return;
        };
        let Ok(progress) = serde_json::from_slice::<ProgressFile>(&bytes) else {
            return;
        };
        let phase = match progress.phase.as_str() {
            "extracting" => JobPhase::Extracting,
            "parsing" => JobPhase::Parsing,
            "correlating" => JobPhase::Correlating,
            "ready" => JobPhase::Ready,
            _ => return,
        };
        *self.status.write().await = ProgressState {
            phase,
            percent: progress.percent.min(100),
            stage: sanitize_stage(&progress.stage),
            processed_artifacts: progress.processed_artifacts,
            total_artifacts: progress.total_artifacts,
            unique_events: progress.unique_events,
            duplicate_events: progress.duplicate_events,
            error_code: None,
            error_message: None,
        };
    }

    async fn set_status(&self, phase: JobPhase, percent: u8, stage: &str) {
        *self.status.write().await = ProgressState {
            phase,
            percent,
            stage: sanitize_stage(stage),
            processed_artifacts: None,
            total_artifacts: None,
            unique_events: None,
            duplicate_events: None,
            error_code: None,
            error_message: None,
        };
    }

    async fn set_failure(&self, error: &AppError) {
        *self.status.write().await = ProgressState {
            phase: JobPhase::Failed,
            percent: 100,
            stage: "Import failed".into(),
            processed_artifacts: None,
            total_artifacts: None,
            unique_events: None,
            duplicate_events: None,
            error_code: Some(error.code().to_owned()),
            error_message: Some(error.message().to_owned()),
        };
    }
}

fn decode_handle(encoded: &str) -> Result<[u8; 32]> {
    if encoded.len() != 43 {
        return Err(AppError::NotFound);
    }
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AppError::NotFound)?;
    raw.try_into().map_err(|_| AppError::NotFound)
}

fn digest_handle(raw: &[u8; 32]) -> [u8; 32] {
    *blake3::hash(raw).as_bytes()
}
fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn sanitize_stage(value: &str) -> String {
    match value {
        "Validating archive"
        | "Parsing diagnostic sources"
        | "Building search index"
        | "Correlating evidence"
        | "Analysis ready" => value.to_owned(),
        _ => "Processing transient analysis".into(),
    }
}
async fn purge_dir(path: &Path) {
    let _ = tokio::fs::remove_dir_all(path).await;
}

fn package_folder(config: &Config, source: &Path, destination: &Path) -> Result<()> {
    use std::io::{Read, Write};
    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};
    let output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    let mut zip = ZipWriter::new(output);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o600);
    let mut count = 0_usize;
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; 128 * 1024];
    for entry in walkdir::WalkDir::new(source).follow_links(false) {
        let entry = entry.map_err(AppError::internal)?;
        let metadata = entry.metadata().map_err(AppError::internal)?;
        if metadata.is_dir() {
            continue;
        }
        if !metadata.is_file() || entry.file_type().is_symlink() {
            return Err(AppError::unsafe_archive("archive file count exceeded"));
        }
        count += 1;
        total = total
            .checked_add(metadata.len())
            .ok_or_else(|| AppError::unsafe_archive("total expansion limit exceeded"))?;
        if count > config.max_archive_files
            || metadata.len() > config.max_file_bytes
            || total > config.max_expanded_bytes
        {
            return Err(AppError::unsafe_archive("total expansion limit exceeded"));
        }
        let relative = entry
            .path()
            .strip_prefix(source)
            .map_err(AppError::internal)?;
        let name = relative.to_string_lossy().replace('\\', "/");
        let name = crate::ingest::normalize_member_path(&name)?;
        zip.start_file(name, options).map_err(AppError::internal)?;
        let mut input = std::fs::File::open(entry.path())?;
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            zip.write_all(&buffer[..read]).map_err(AppError::internal)?;
        }
    }
    zip.finish().map_err(AppError::internal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn handles_require_full_entropy() {
        assert!(decode_handle("short").is_err());
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        assert_eq!(
            decode_handle(&URL_SAFE_NO_PAD.encode(raw)).unwrap().len(),
            32
        );
    }

    #[tokio::test]
    async fn handles_are_isolated_and_delete_purges_immediately() {
        let root = tempfile::tempdir().unwrap();
        let config = Config {
            workspace: root.path().to_path_buf(),
            ..Default::default()
        };
        let state = AppState::new(config).await.unwrap();
        let (handle_a, job_a) = state.create_job().await.unwrap();
        let (handle_b, job_b) = state.create_job().await.unwrap();

        assert_ne!(handle_a, handle_b);
        assert_eq!(handle_a.len(), 43);
        assert_eq!(state.get(&handle_a).await.unwrap().id, job_a.id);
        assert_eq!(state.get(&handle_b).await.unwrap().id, job_b.id);
        assert!(
            state
                .get("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .await
                .is_err()
        );

        state.delete(&handle_a).await.unwrap();
        assert!(state.get(&handle_a).await.is_err());
        assert!(!job_a.dir.exists());
        assert!(job_b.dir.exists());
        state.delete(&handle_a).await.unwrap();
        state.shutdown().await;
        assert!(!job_b.dir.exists());
    }
}
