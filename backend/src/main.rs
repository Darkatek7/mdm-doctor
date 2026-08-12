use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    path::PathBuf,
    time::Duration,
};

use clap::{Parser, Subcommand};
use mdm_doctor::{analysis, api, config::Config, error::Result, store::AppState};

#[derive(Parser)]
#[command(
    name = "mdm-doctor",
    version,
    about = "Transient Microsoft Intune and MDM diagnostics workbench"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long)]
        import_folder: Option<PathBuf>,
    },
    #[command(hide = true)]
    Worker {
        #[arg(long)]
        job_dir: PathBuf,
    },
    Healthcheck,
    Openapi {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    #[command(hide = true)]
    ValidateArchive {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        label: String,
    },
}

#[tokio::main]
async fn main() {
    install_sanitized_panic_hook();
    let result = match Cli::parse().command.unwrap_or(Command::Serve {
        import_folder: None,
    }) {
        Command::Serve { import_folder } => serve(import_folder).await,
        Command::Worker { job_dir } => {
            Config::from_env().and_then(|config| analysis::run_worker(&config, &job_dir))
        }
        Command::Healthcheck => healthcheck(),
        Command::Openapi { output } => {
            let document = api::openapi_document();
            match output {
                Some(path) => std::fs::File::create(path)
                    .map_err(mdm_doctor::error::AppError::internal)
                    .and_then(|file| {
                        serde_json::to_writer_pretty(file, &document)
                            .map_err(mdm_doctor::error::AppError::internal)
                    }),
                None => serde_json::to_writer(std::io::stdout().lock(), &document)
                    .map_err(mdm_doctor::error::AppError::internal),
            }
        }
        Command::ValidateArchive { input, label } => validate_archive(input, &label),
    };
    if result.is_err() {
        if std::env::var("DEBUG_SANITIZED").is_ok_and(|v| v.eq_ignore_ascii_case("true")) {
            eprintln!("MDM Doctor stopped after a sanitized fatal error.");
        }
        std::process::exit(1);
    }
}

struct ValidationWorkspace(PathBuf);

impl Drop for ValidationWorkspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn validate_archive(input: PathBuf, label: &str) -> Result<()> {
    if !input.is_file() || !matches!(label, "A" | "B") {
        return Err(mdm_doctor::error::AppError::BadRequest);
    }
    let root = std::env::temp_dir().join(format!(
        "mdm-doctor-validation-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir(&root)?;
    let workspace = ValidationWorkspace(root);
    std::fs::copy(input, workspace.0.join("upload.bin"))?;
    let source =
        if mdm_doctor::ingest::detect_type(&workspace.0.join("upload.bin"), "diagnostics.zip")?
            == "cab"
        {
            "diagnostics.cab"
        } else {
            "diagnostics.zip"
        };
    std::fs::write(workspace.0.join("source.name"), source)?;
    let started = std::time::Instant::now();
    let config = Config::from_env()?;
    if let Err(error) = analysis::run_worker(&config, &workspace.0) {
        let output = serde_json::json!({"label":label,"status":"failed","error_code":error.code()});
        serde_json::to_writer(std::io::stdout().lock(), &output)
            .map_err(mdm_doctor::error::AppError::internal)?;
        return Err(error);
    }
    let conn = mdm_doctor::db::open_read_only(&workspace.0.join(mdm_doctor::db::DB_FILE))?;
    let summary = mdm_doctor::db::summary(&conn)?;
    let coverage = mdm_doctor::db::coverage(&conn)?;
    let warnings = mdm_doctor::db::warnings(&conn)?;
    let database_bytes = std::fs::metadata(workspace.0.join(mdm_doctor::db::DB_FILE))?.len();
    let parser_failures = warnings
        .iter()
        .filter(|warning| warning.code.starts_with("parser."))
        .count();
    let event_limit_reached = warnings
        .iter()
        .any(|warning| warning.code == "events.limit");
    let unknown_applications: i64 = conn.query_row(
        "SELECT COUNT(*) FROM applications WHERE name='Unknown application'",
        [],
        |row| row.get(0),
    )?;
    let placeholder_applications: i64 = conn.query_row(
        "SELECT COUNT(*) FROM applications WHERE name GLOB 'Application [0-9]*'",
        [],
        |row| row.get(0),
    )?;
    let output = serde_json::json!({
        "label":label,
        "status":"ready",
        "analysis_seconds":started.elapsed().as_secs_f64(),
        "artifacts":summary.kpis.artifacts,
        "events":summary.kpis.parsed_events,
        "findings":summary.kpis.findings,
        "applications":summary.kpis.applications,
        "coverage_percent":summary.kpis.coverage_percent,
        "coverage_records":coverage.len(),
        "warnings":warnings.len()
        ,"parser_failures":parser_failures
        ,"event_limit_reached":event_limit_reached
        ,"database_bytes":database_bytes
        ,"unknown_applications":unknown_applications
        ,"placeholder_applications":placeholder_applications
    });
    serde_json::to_writer(std::io::stdout().lock(), &output)
        .map_err(mdm_doctor::error::AppError::internal)?;
    Ok(())
}

async fn serve(import_folder: Option<PathBuf>) -> Result<()> {
    let config = Config::from_env()?;
    let address = SocketAddr::new(config.bind_address, config.port);
    let state = AppState::new(config.clone()).await?;
    if let Some(folder) = import_folder {
        state.prepare_local_import(folder).await?;
    }
    let listener = tokio::net::TcpListener::bind(address).await?;
    let shutdown_state = state.clone();
    axum::serve(listener, api::router(state))
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            shutdown_state.shutdown().await;
        })
        .await
        .map_err(mdm_doctor::error::AppError::internal)
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("signal handler");
        tokio::select! {_ = tokio::signal::ctrl_c()=>{},_ = terminate.recv()=>{}}
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn healthcheck() -> Result<()> {
    let config = Config::from_env()?;
    let address = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), config.port);
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(
        b"GET /api/v1/health/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )?;
    let mut response = [0_u8; 32];
    let count = stream.read(&mut response)?;
    if count >= 12 && &response[..12] == b"HTTP/1.1 200" {
        Ok(())
    } else {
        Err(mdm_doctor::error::AppError::Internal)
    }
}

fn install_sanitized_panic_hook() {
    let debug = std::env::var("DEBUG_SANITIZED").is_ok_and(|v| v.eq_ignore_ascii_case("true"));
    std::panic::set_hook(Box::new(move |_| {
        if debug {
            eprintln!("MDM Doctor encountered a sanitized internal failure.");
        }
    }));
}
