use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Write},
    path::{Path, PathBuf},
};

use cab::Cabinet;
use regex::Regex;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zip::ZipArchive;

use crate::{
    config::Config,
    db::{self, NewArtifact},
    error::{AppError, Result},
};

const BUFFER_SIZE: usize = 128 * 1024;
const MAX_SPARSE_EVTX_RATIO_EXCEPTION_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct ExtractedArtifact {
    pub id: String,
    pub object_path: PathBuf,
    pub normalized_path: String,
    pub detected_type: String,
    pub duplicate_of: Option<String>,
}

#[derive(Debug)]
pub struct IngestReport {
    pub artifacts: Vec<ExtractedArtifact>,
    pub expanded_bytes: u64,
    pub duplicate_files: u64,
}

struct Context<'a> {
    config: &'a Config,
    conn: &'a Connection,
    job_dir: &'a Path,
    objects_dir: PathBuf,
    artifacts: Vec<ExtractedArtifact>,
    hashes: HashMap<String, String>,
    expanded_bytes: u64,
    file_count: usize,
    sequence: u64,
    duplicate_files: u64,
}

pub fn ingest_upload(
    config: &Config,
    conn: &Connection,
    job_dir: &Path,
    upload_path: &Path,
    source_name: &str,
    upload_sha256: &str,
) -> Result<IngestReport> {
    let objects_dir = job_dir.join("objects");
    fs::create_dir(&objects_dir)?;
    let normalized_source = normalize_member_path(source_name)?;
    let outer_type = detect_type(upload_path, &normalized_source)?;
    if outer_type != "zip" && outer_type != "cab" {
        return Err(AppError::unsafe_archive("unsupported outer archive"));
    }
    let outer_id = stable_id("artifact", &format!("{upload_sha256}:{normalized_source}"));
    db::insert_artifact(
        conn,
        &NewArtifact {
            id: &outer_id,
            parent_id: None,
            layer: 0,
            normalized_path: &normalized_source,
            original_path: source_name,
            object_path: "upload.bin",
            size: fs::metadata(upload_path)?.len(),
            sha256: upload_sha256,
            detected_type: &outer_type,
            duplicate_of: None,
            warning: None,
        },
    )?;

    let mut ctx = Context {
        config,
        conn,
        job_dir,
        objects_dir,
        artifacts: vec![ExtractedArtifact {
            id: outer_id.clone(),
            object_path: upload_path.to_path_buf(),
            normalized_path: normalized_source,
            detected_type: outer_type.to_owned(),
            duplicate_of: None,
        }],
        hashes: HashMap::new(),
        expanded_bytes: 0,
        file_count: 0,
        sequence: 0,
        duplicate_files: 0,
    };

    extract_archive(&mut ctx, upload_path, &outer_id, &outer_type, 1)?;
    Ok(IngestReport {
        artifacts: ctx.artifacts,
        expanded_bytes: ctx.expanded_bytes,
        duplicate_files: ctx.duplicate_files,
    })
}

fn extract_archive(
    ctx: &mut Context<'_>,
    path: &Path,
    parent_id: &str,
    archive_type: &str,
    layer: usize,
) -> Result<()> {
    if layer > ctx.config.max_nesting_depth {
        return Err(AppError::unsafe_archive("nesting depth exceeded"));
    }
    match archive_type {
        "zip" => extract_zip(ctx, path, parent_id, layer),
        "cab" => extract_cab(ctx, path, parent_id, layer),
        _ => Ok(()),
    }
}

fn extract_zip(ctx: &mut Context<'_>, path: &Path, parent_id: &str, layer: usize) -> Result<()> {
    let file = File::open(path)?;
    let archive_len = file.metadata()?.len().max(1);
    let mut archive = ZipArchive::new(BufReader::new(file))
        .map_err(|_| AppError::unsafe_archive("malformed zip"))?;
    let mut names = HashSet::new();
    let mut quarantined = HashSet::new();
    let mut declared_total = 0_u64;

    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|_| AppError::unsafe_archive("malformed zip entry"))?;
        if entry.is_dir() {
            let name = zip_entry_name(&entry)?;
            let directory = name.trim_end_matches(['/', '\\']);
            if !directory.is_empty() {
                let _ = normalize_member_path(directory)?;
            }
            continue;
        }
        validate_zip_mode(entry.unix_mode())?;
        let normalized = normalize_member_path(&zip_entry_name(&entry)?)?;
        if !names.insert(normalized.to_lowercase()) {
            return Err(AppError::unsafe_archive("case-insensitive duplicate path"));
        }
        let ratio_exceeded = expansion_ratio_exceeded(
            entry.size(),
            entry.compressed_size(),
            archive_len,
            ctx.config.max_compression_ratio,
        );
        let sparse_evtx_exception = ratio_exceeded
            && normalized.to_ascii_lowercase().ends_with(".evtx")
            && entry.size() <= MAX_SPARSE_EVTX_RATIO_EXCEPTION_BYTES;
        if ratio_exceeded && normalized.to_ascii_lowercase().ends_with(".etl") {
            quarantined.insert(index);
        } else if ratio_exceeded && !sparse_evtx_exception {
            return Err(AppError::unsafe_archive("entry expansion ratio exceeded"));
        }
        validate_declared_size(
            ctx,
            entry.size(),
            if ratio_exceeded && (sparse_evtx_exception || quarantined.contains(&index)) {
                entry.size().max(1)
            } else {
                entry.compressed_size()
            },
            &mut declared_total,
            archive_len,
        )?;
    }
    if declared_total > archive_len.saturating_mul(ctx.config.max_aggregate_ratio) {
        return Err(AppError::unsafe_archive(
            "aggregate expansion ratio exceeded",
        ));
    }

    for index in 0..archive.len() {
        if quarantined.contains(&index) {
            let mut entry = archive
                .by_index_raw(index)
                .map_err(|_| AppError::unsafe_archive("malformed zip entry"))?;
            let original = zip_entry_name(&entry)?;
            let normalized = normalize_member_path(&original)?;
            let declared_size = entry.size();
            record_quarantined_member(
                ctx,
                &mut entry,
                parent_id,
                layer as u32,
                &original,
                &normalized,
                declared_size,
            )?;
            continue;
        }
        let mut entry = archive
            .by_index(index)
            .map_err(|_| AppError::unsafe_archive("malformed zip entry"))?;
        if entry.is_dir() {
            continue;
        }
        let original = zip_entry_name(&entry)?;
        let normalized = normalize_member_path(&original)?;
        let written = write_member(
            ctx,
            &mut entry,
            parent_id,
            layer as u32,
            &original,
            &normalized,
        )?;
        if let Some((object_path, artifact_id, detected_type, duplicate)) = written
            && !duplicate
            && (detected_type == "zip" || detected_type == "cab")
        {
            extract_archive(ctx, &object_path, &artifact_id, &detected_type, layer + 1)?;
        }
    }
    Ok(())
}

fn zip_entry_name<R: Read>(entry: &zip::read::ZipFile<'_, R>) -> Result<String> {
    entry
        .name()
        .map(|name| name.into_owned())
        .map_err(|_| AppError::unsafe_archive("unreadable zip entry name"))
}

fn expansion_ratio_exceeded(size: u64, compressed: u64, archive_len: u64, limit: u64) -> bool {
    if compressed == 0 && size > 0 {
        size > archive_len.saturating_mul(limit)
    } else {
        compressed > 0 && size > compressed.saturating_mul(limit)
    }
}

#[allow(clippy::too_many_arguments)]
fn record_quarantined_member<R: Read>(
    ctx: &mut Context<'_>,
    reader: &mut R,
    parent_id: &str,
    layer: u32,
    original: &str,
    normalized: &str,
    declared_size: u64,
) -> Result<()> {
    ctx.file_count += 1;
    if ctx.file_count > ctx.config.max_archive_files {
        return Err(AppError::unsafe_archive("archive file count exceeded"));
    }
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    ctx.expanded_bytes = ctx.expanded_bytes.saturating_add(declared_size);
    let sha256 = format!("{:x}", hash.finalize());
    let duplicate_of = ctx.hashes.get(&sha256).cloned();
    if duplicate_of.is_some() {
        ctx.duplicate_files += 1;
    }
    let id = stable_id("artifact", &format!("{parent_id}:{normalized}:{sha256}"));
    db::insert_artifact(
        ctx.conn,
        &NewArtifact {
            id: &id,
            parent_id: Some(parent_id),
            layer,
            normalized_path: normalized,
            original_path: original,
            object_path: "unavailable",
            size: declared_size,
            sha256: &sha256,
            detected_type: "etl-unsupported",
            duplicate_of: duplicate_of.as_deref(),
            warning: Some(
                "High-ratio ETL was not expanded; SHA-256 covers its bounded compressed member bytes.",
            ),
        },
    )?;
    ctx.hashes.entry(sha256).or_insert_with(|| id.clone());
    ctx.artifacts.push(ExtractedArtifact {
        id,
        object_path: ctx.job_dir.join("unavailable"),
        normalized_path: normalized.to_owned(),
        detected_type: "etl-unsupported".into(),
        duplicate_of,
    });
    Ok(())
}

fn extract_cab(ctx: &mut Context<'_>, path: &Path, parent_id: &str, layer: usize) -> Result<()> {
    let archive_len = fs::metadata(path)?.len().max(1);
    let file = File::open(path)?;
    let cabinet = Cabinet::new(BufReader::new(file))
        .map_err(|_| AppError::unsafe_archive("malformed or unsupported cabinet"))?;
    let entries: Vec<(String, u64)> = cabinet
        .folder_entries()
        .flat_map(|folder| folder.file_entries())
        .map(|entry| {
            (
                entry.name().to_owned(),
                u64::from(entry.uncompressed_size()),
            )
        })
        .collect();
    let mut names = HashSet::new();
    let mut declared_total = 0_u64;
    for (name, size) in &entries {
        let normalized = normalize_member_path(name)?;
        if !names.insert(normalized.to_lowercase()) {
            return Err(AppError::unsafe_archive(
                "case-insensitive duplicate cabinet path",
            ));
        }
        validate_declared_size(ctx, *size, 0, &mut declared_total, archive_len)?;
    }
    if declared_total / archive_len > ctx.config.max_aggregate_ratio {
        return Err(AppError::unsafe_archive("cabinet expansion ratio exceeded"));
    }

    drop(cabinet);
    ctx.sequence += 1;
    let staging = ctx
        .objects_dir
        .join(format!(".cab-stage-{:016x}", ctx.sequence));
    fs::create_dir(&staging)?;
    let worker_count = std::thread::available_parallelism()
        .map_or(2, usize::from)
        .clamp(1, 4)
        .min(entries.len().max(1));
    let mut buckets = vec![Vec::<(usize, String, u64)>::new(); worker_count];
    for (index, (name, size)) in entries.iter().enumerate() {
        buckets[index % worker_count].push((index, name.clone(), *size));
    }
    let prepared = std::thread::scope(|scope| -> Result<Vec<(usize, PathBuf)>> {
        let mut handles = Vec::new();
        for bucket in buckets {
            let staging = staging.clone();
            handles.push(scope.spawn(move || -> Result<Vec<(usize, PathBuf)>> {
                let file = File::open(path)?;
                let mut cabinet = Cabinet::new(BufReader::new(file))
                    .map_err(|_| AppError::unsafe_archive("malformed or unsupported cabinet"))?;
                let mut paths = Vec::with_capacity(bucket.len());
                for (index, name, expected_size) in bucket {
                    let mut reader = cabinet
                        .read_file(&name)
                        .map_err(|_| AppError::unsafe_archive("cabinet entry cannot be read"))?;
                    let staged = staging.join(format!("{index:08x}"));
                    let mut output = OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .open(&staged)?;
                    let actual = std::io::copy(&mut reader, &mut output)?;
                    if actual != expected_size {
                        return Err(AppError::unsafe_archive("cabinet member size mismatch"));
                    }
                    output.sync_data()?;
                    paths.push((index, staged));
                }
                Ok(paths)
            }));
        }
        let mut paths = Vec::with_capacity(entries.len());
        for handle in handles {
            paths.extend(handle.join().map_err(|_| AppError::Internal)??);
        }
        Ok(paths)
    })?;
    let prepared = prepared.into_iter().collect::<HashMap<_, _>>();

    for (index, (original, _)) in entries.into_iter().enumerate() {
        let normalized = normalize_member_path(&original)?;
        let staged = prepared.get(&index).ok_or(AppError::Internal)?;
        let mut reader = File::open(staged)?;
        let written = write_member(
            ctx,
            &mut reader,
            parent_id,
            layer as u32,
            &original,
            &normalized,
        )?;
        if let Some((object_path, artifact_id, detected_type, duplicate)) = written
            && !duplicate
            && (detected_type == "zip" || detected_type == "cab")
        {
            extract_archive(ctx, &object_path, &artifact_id, &detected_type, layer + 1)?;
        }
        fs::remove_file(staged)?;
    }
    fs::remove_dir(&staging)?;
    Ok(())
}

fn validate_declared_size(
    ctx: &Context<'_>,
    size: u64,
    compressed: u64,
    total: &mut u64,
    archive_len: u64,
) -> Result<()> {
    if size > ctx.config.max_file_bytes {
        return Err(AppError::unsafe_archive("expanded file limit exceeded"));
    }
    *total = total
        .checked_add(size)
        .ok_or_else(|| AppError::unsafe_archive("total expansion limit exceeded"))?;
    if ctx.expanded_bytes.saturating_add(*total) > ctx.config.max_expanded_bytes {
        return Err(AppError::unsafe_archive("total expansion limit exceeded"));
    }
    if expansion_ratio_exceeded(
        size,
        compressed,
        archive_len,
        ctx.config.max_compression_ratio,
    ) {
        return Err(AppError::unsafe_archive("entry expansion ratio exceeded"));
    }
    Ok(())
}

fn write_member<R: Read>(
    ctx: &mut Context<'_>,
    reader: &mut R,
    parent_id: &str,
    layer: u32,
    original: &str,
    normalized: &str,
) -> Result<Option<(PathBuf, String, String, bool)>> {
    ctx.file_count += 1;
    if ctx.file_count > ctx.config.max_archive_files {
        return Err(AppError::unsafe_archive("archive file count exceeded"));
    }
    ctx.sequence += 1;
    let partial_name = format!(".partial-{:016x}", ctx.sequence);
    let partial = ctx.objects_dir.join(partial_name);
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&partial)?;
    let mut hash = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(count as u64)
            .ok_or_else(|| AppError::unsafe_archive("actual expansion limit exceeded"))?;
        if size > ctx.config.max_file_bytes
            || ctx.expanded_bytes.saturating_add(size) > ctx.config.max_expanded_bytes
        {
            let _ = fs::remove_file(&partial);
            return Err(AppError::unsafe_archive("actual expansion limit exceeded"));
        }
        hash.update(&buffer[..count]);
        output.write_all(&buffer[..count])?;
    }
    output.sync_data()?;
    drop(output);
    ctx.expanded_bytes = ctx.expanded_bytes.saturating_add(size);
    let sha256 = format!("{:x}", hash.finalize());
    let object_relative = format!("objects/{sha256}");
    let object_path = ctx.job_dir.join(&object_relative);
    let duplicate_of = ctx.hashes.get(&sha256).cloned();
    if duplicate_of.is_some() {
        ctx.duplicate_files += 1;
        fs::remove_file(&partial)?;
    } else {
        fs::rename(&partial, &object_path)?;
    }
    let effective_path = if duplicate_of.is_some() {
        object_path.clone()
    } else {
        object_path
    };
    let detected_type = detect_type(&effective_path, normalized)?;
    let id = stable_id("artifact", &format!("{parent_id}:{normalized}:{sha256}"));
    db::insert_artifact(
        ctx.conn,
        &NewArtifact {
            id: &id,
            parent_id: Some(parent_id),
            layer,
            normalized_path: normalized,
            original_path: original,
            object_path: &object_relative,
            size,
            sha256: &sha256,
            detected_type: &detected_type,
            duplicate_of: duplicate_of.as_deref(),
            warning: None,
        },
    )?;
    ctx.hashes.entry(sha256).or_insert_with(|| id.clone());
    ctx.artifacts.push(ExtractedArtifact {
        id: id.clone(),
        object_path: effective_path.clone(),
        normalized_path: normalized.to_owned(),
        detected_type: detected_type.clone(),
        duplicate_of: duplicate_of.clone(),
    });
    Ok(Some((
        effective_path,
        id,
        detected_type,
        duplicate_of.is_some(),
    )))
}

pub fn normalize_member_path(raw: &str) -> Result<String> {
    if raw.is_empty() || raw.len() > 4_096 || raw.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(AppError::unsafe_archive("invalid archive member name"));
    }
    let lower = raw.to_ascii_lowercase();
    if lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%252f")
        || lower.contains("%255c")
    {
        return Err(AppError::unsafe_archive("encoded path separator"));
    }
    if raw.contains('/') && raw.contains('\\') {
        return Err(AppError::unsafe_archive("mixed path separators"));
    }
    let normalized: String = raw.nfkc().collect();
    if normalized.starts_with('/')
        || normalized.starts_with('\\')
        || normalized.starts_with("//")
        || normalized.starts_with("\\\\")
    {
        return Err(AppError::unsafe_archive("absolute or UNC path"));
    }
    let drive = Regex::new(r"(?i)^[a-z]:").expect("static regex");
    if drive.is_match(&normalized) {
        return Err(AppError::unsafe_archive("drive-qualified path"));
    }
    let replaced = normalized.replace('\\', "/");
    let mut safe = Vec::new();
    for part in replaced.split('/') {
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.contains(':')
            || part.trim_end_matches([' ', '.']) != part
        {
            return Err(AppError::unsafe_archive("unsafe path component"));
        }
        safe.push(part);
    }
    Ok(safe.join("/"))
}

fn validate_zip_mode(mode: Option<u32>) -> Result<()> {
    let Some(mode) = mode else {
        return Ok(());
    };
    let kind = mode & 0o170000;
    if kind != 0 && kind != 0o100000 {
        return Err(AppError::unsafe_archive("special archive entry"));
    }
    Ok(())
}

pub fn detect_type(path: &Path, name: &str) -> Result<String> {
    let mut file = File::open(path)?;
    let mut magic = [0_u8; 16];
    let count = file.read(&mut magic)?;
    let bytes = &magic[..count];
    if bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
    {
        return Ok("zip".into());
    }
    if bytes.starts_with(b"MSCF") {
        return Ok("cab".into());
    }
    if bytes.starts_with(b"ElfFile\0") {
        return Ok("evtx".into());
    }
    if bytes.starts_with(b"SQLite format 3\0") {
        return Ok("sqlite-unsupported".into());
    }
    let extension = Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let detected = match extension.as_str() {
        "log" | "log_" | "miplog" => "cmtrace-or-text",
        "evtx" => "evtx",
        "etl" => "etl-unsupported",
        "reg" => "registry",
        "xml" => "xml",
        "html" | "htm" => "html",
        "json" => "json",
        "csv" => "csv",
        "txt" | "out" => "text",
        "db" | "sqlite" | "sqlite3" => "sqlite-unsupported",
        "zip" => "zip-invalid-magic",
        "cab" => "cab-invalid-magic",
        _ if bytes
            .iter()
            .take(512)
            .all(|b| *b == 0 || *b == 9 || *b == 10 || *b == 13 || (32..=126).contains(b)) =>
        {
            "text"
        }
        _ => "binary-unsupported",
    };
    Ok(detected.into())
}

pub fn stable_id(domain: &str, value: &str) -> String {
    let digest = blake3::hash(format!("{domain}\0{value}").as_bytes());
    format!("{domain}:{}", &digest.to_hex()[..24])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, rngs::OsRng};
    use std::io::Write;
    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

    fn archive_with(path: &Path, members: &[(&str, &[u8])], directories: &[&str]) {
        let file = File::create(path).unwrap();
        let mut writer = ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o600);
        for directory in directories {
            writer.add_directory(*directory, options).unwrap();
        }
        for (name, contents) in members {
            writer.start_file(*name, options).unwrap();
            writer.write_all(contents).unwrap();
        }
        writer.finish().unwrap();
    }

    fn ingest(path: &Path, config: &Config) -> Result<IngestReport> {
        let job = path.parent().unwrap();
        let db_path = job.join("test.sqlite");
        let conn = db::open(&db_path)?;
        db::initialize(&conn)?;
        ingest_upload(config, &conn, job, path, "diagnostics.zip", "00")
    }

    #[test]
    fn rejects_hostile_paths() {
        for path in [
            "../escape",
            "/absolute",
            "C:\\escape",
            "\\\\host\\share",
            "safe/../escape",
            "safe%2fescape",
            "a/b\\c",
            "same./file",
        ] {
            assert!(normalize_member_path(path).is_err(), "accepted {path}");
        }
    }

    #[test]
    fn normalizes_windows_paths() {
        assert_eq!(
            normalize_member_path("Logs\\IME.log").unwrap(),
            "Logs/IME.log"
        );
    }

    #[test]
    fn deterministic_ids_are_stable_and_domain_separated() {
        assert_eq!(stable_id("event", "same"), stable_id("event", "same"));
        assert_ne!(stable_id("event", "same"), stable_id("artifact", "same"));
        assert_ne!(stable_id("event", "same"), stable_id("event", "different"));
    }

    #[test]
    fn safe_directory_entries_are_accepted() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("upload.bin");
        archive_with(
            &archive,
            &[("Logs/IME.log", b"synthetic app install succeeded")],
            &["Logs/"],
        );
        let report = ingest(&archive, &Config::default()).unwrap();
        assert_eq!(report.artifacts.len(), 2);
        assert!(report.expanded_bytes >= b"synthetic app install succeeded".len() as u64);
        assert_eq!(
            report.expanded_bytes,
            fs::metadata(&report.artifacts[1].object_path)
                .unwrap()
                .len()
        );
    }

    #[test]
    fn rejects_case_and_unicode_collisions_before_extraction() {
        for members in [
            vec![
                ("Logs/IME.log", b"a".as_slice()),
                ("logs/ime.LOG", b"b".as_slice()),
            ],
            vec![
                ("Logs/é.log", b"a".as_slice()),
                ("Logs/e\u{301}.log", b"b".as_slice()),
            ],
        ] {
            let temp = tempfile::tempdir().unwrap();
            let archive = temp.path().join("upload.bin");
            archive_with(&archive, &members, &[]);
            assert!(matches!(
                ingest(&archive, &Config::default()),
                Err(AppError::UnsafeArchive(_))
            ));
            assert!(
                !temp
                    .path()
                    .join("objects")
                    .read_dir()
                    .unwrap()
                    .any(|entry| entry.is_ok())
            );
        }
    }

    #[test]
    fn rejects_traversal_size_limits_and_malformed_zip() {
        let temp = tempfile::tempdir().unwrap();
        let traversal = temp.path().join("traversal.bin");
        archive_with(&traversal, &[("../escape.log", b"x")], &[]);
        assert!(matches!(
            ingest(&traversal, &Config::default()),
            Err(AppError::UnsafeArchive(_))
        ));

        let size_root = tempfile::tempdir().unwrap();
        let oversized = size_root.path().join("upload.bin");
        archive_with(&oversized, &[("large.log", b"12345")], &[]);
        let config = Config {
            max_file_bytes: 4,
            ..Default::default()
        };
        assert!(matches!(
            ingest(&oversized, &config),
            Err(AppError::UnsafeArchive(_))
        ));

        let malformed_root = tempfile::tempdir().unwrap();
        let malformed = malformed_root.path().join("upload.bin");
        File::create(&malformed)
            .unwrap()
            .write_all(b"PK\x03\x04broken")
            .unwrap();
        assert!(matches!(
            ingest(&malformed, &Config::default()),
            Err(AppError::UnsafeArchive(_))
        ));
    }

    #[test]
    fn high_ratio_unsupported_etl_is_quarantined_without_expansion() {
        let payload = vec![0_u8; 1_048_576];
        let mut filler = vec![0_u8; 128 * 1024];
        OsRng.fill_bytes(&mut filler);
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("upload.bin");
        archive_with(
            &archive,
            &[
                ("trace.etl", payload.as_slice()),
                ("bounded.bin", filler.as_slice()),
            ],
            &[],
        );
        let report = ingest(&archive, &Config::default()).unwrap();
        assert_eq!(report.artifacts.len(), 3);
        let etl = report
            .artifacts
            .iter()
            .find(|artifact| artifact.detected_type == "etl-unsupported")
            .unwrap();
        assert!(!etl.object_path.exists());

        let rejected_root = tempfile::tempdir().unwrap();
        let rejected = rejected_root.path().join("upload.bin");
        archive_with(&rejected, &[("compressible.log", payload.as_slice())], &[]);
        assert!(matches!(
            ingest(&rejected, &Config::default()),
            Err(AppError::UnsafeArchive(_))
        ));
    }

    #[test]
    fn small_sparse_evtx_is_accepted_without_weakening_other_ratio_checks() {
        let mut sparse_evtx = vec![0_u8; 69_632];
        sparse_evtx[..8].copy_from_slice(b"ElfFile\0");
        let mut filler = vec![0_u8; 128 * 1024];
        OsRng.fill_bytes(&mut filler);
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("upload.bin");
        archive_with(
            &archive,
            &[
                ("sparse.evtx", sparse_evtx.as_slice()),
                ("bounded.bin", filler.as_slice()),
            ],
            &[],
        );
        let report = ingest(&archive, &Config::default()).unwrap();
        assert!(
            report
                .artifacts
                .iter()
                .any(|artifact| artifact.detected_type == "evtx")
        );

        let rejected_root = tempfile::tempdir().unwrap();
        let rejected = rejected_root.path().join("upload.bin");
        archive_with(
            &rejected,
            &[("compressible.log", sparse_evtx.as_slice())],
            &[],
        );
        assert!(matches!(
            ingest(&rejected, &Config::default()),
            Err(AppError::UnsafeArchive(_))
        ));
    }
}
