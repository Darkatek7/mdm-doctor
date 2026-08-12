use std::time::{Duration, Instant};

use mdm_doctor::{db, models::TimelineQuery};
use rusqlite::params;
use serde::Serialize;
use tempfile::tempdir;

const DEFAULT_EVENTS: usize = 1_000_000;
const MAX_INSERT_TIME: Duration = Duration::from_secs(180);
const MAX_PAGE_TIME: Duration = Duration::from_secs(2);
const MAX_SEARCH_TIME: Duration = Duration::from_secs(5);
const MAX_RSS_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Serialize)]
struct ResultRow {
    events: usize,
    insertion_seconds: f64,
    cursor_row: usize,
    page_milliseconds: f64,
    search_milliseconds: f64,
    max_rss_bytes: u64,
    database_bytes: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let events = parse_events()?;
    if events < 500_100 {
        return Err("--events must be at least 500100".into());
    }

    let root = tempdir()?;
    let path = root.path().join(db::DB_FILE);
    let mut conn = db::open(&path)?;
    db::initialize(&conn)?;
    conn.execute(
        "INSERT INTO artifacts(id,parent_id,layer,normalized_path,original_path,object_path,size,sha256,detected_type,parser_status) VALUES ('scale-artifact',NULL,0,'synthetic.log','synthetic.log','objects/synthetic',0,'synthetic','log','parsed')",
        [],
    )?;

    let insert_started = Instant::now();
    let tx = conn.transaction()?;
    {
        let mut event = tx.prepare_cached(
            "INSERT INTO events(id,artifact_id,timestamp_utc,provider,component,severity,message,current) VALUES (?1,'scale-artifact',?2,'ScaleProvider','ScaleComponent','info',?3,1)",
        )?;
        for index in 0..events {
            let sequence = index + 1;
            let id = format!("scale-{sequence:07}");
            let timestamp = format!(
                "2026-08-11T{:02}:{:02}:{:02}Z",
                (index / 3600) % 24,
                (index / 60) % 60,
                index % 60
            );
            let message = if index % 10_000 == 0 {
                "benchmark enrollment checkpoint"
            } else {
                "benchmark timeline event"
            };
            event.execute(params![id, timestamp, message])?;
        }
    }
    tx.commit()?;
    db::finalize_event_index(&conn)?;
    let insertion = insert_started.elapsed();

    let cursor_row = 500_000;
    let page_started = Instant::now();
    let page = db::timeline(&conn, &query(cursor_row, None), 100, 500)?;
    let page_time = page_started.elapsed();

    let search_started = Instant::now();
    let search = db::timeline(
        &conn,
        &query(cursor_row, Some("enrollment checkpoint".into())),
        100,
        500,
    )?;
    let search_time = search_started.elapsed();
    let rss = max_rss_bytes();
    let database_bytes = std::fs::metadata(&path)?.len();

    if page.items.len() != 100 || page.total_estimate != events as u64 {
        return Err("cursor pagination returned an unexpected result".into());
    }
    if search.items.is_empty() {
        return Err("FTS benchmark returned no checkpoint rows".into());
    }
    if insertion > MAX_INSERT_TIME {
        return Err(format!("event indexing exceeded {MAX_INSERT_TIME:?}").into());
    }
    if page_time > MAX_PAGE_TIME {
        return Err(format!("cursor page exceeded {MAX_PAGE_TIME:?}").into());
    }
    if search_time > MAX_SEARCH_TIME {
        return Err(format!("FTS page exceeded {MAX_SEARCH_TIME:?}").into());
    }
    if rss > MAX_RSS_BYTES {
        return Err(format!("maximum RSS exceeded {MAX_RSS_BYTES} bytes").into());
    }

    println!(
        "{}",
        serde_json::to_string(&ResultRow {
            events,
            insertion_seconds: insertion.as_secs_f64(),
            cursor_row,
            page_milliseconds: page_time.as_secs_f64() * 1000.0,
            search_milliseconds: search_time.as_secs_f64() * 1000.0,
            max_rss_bytes: rss,
            database_bytes,
        })?
    );
    Ok(())
}

fn query(cursor: usize, search: Option<String>) -> TimelineQuery {
    TimelineQuery {
        cursor: Some(cursor as u64),
        limit: Some(100),
        search,
        severity: None,
        source: None,
        provider: None,
        component: None,
        session_id: None,
        since: None,
        temporal_scope: None,
    }
}

fn parse_events() -> Result<usize, Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let Some(flag) = args.next() else {
        return Ok(DEFAULT_EVENTS);
    };
    if flag != "--events" {
        return Err("usage: scale_benchmark [--events COUNT]".into());
    }
    let value = args.next().ok_or("missing --events value")?.parse()?;
    if args.next().is_some() {
        return Err("usage: scale_benchmark [--events COUNT]".into());
    }
    Ok(value)
}

#[cfg(unix)]
fn max_rss_bytes() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage initializes the provided rusage structure on success.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return 0;
    }
    // SAFETY: the successful getrusage call initialized the structure.
    let rss = unsafe { usage.assume_init() }.ru_maxrss.max(0) as u64;
    if cfg!(target_os = "macos") {
        rss
    } else {
        rss.saturating_mul(1024)
    }
}

#[cfg(not(unix))]
fn max_rss_bytes() -> u64 {
    0
}
