//! `hse seeknow-import` — import SeekNow NDJSON records into the local
//! `seeknow_au_cache` corpus.
//!
//! Each input line is expected to be a raw JSON object (the `record_json`
//! blob as stored or exported by `seeknow_harvest`/`seeknow_export`).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};
use serde_json::Value;

use crate::core::error::{Error, Result};

const BATCH: usize = 1_000;

/// Arguments for `hse seeknow-import`.
pub struct SeeknowImportArgs {
    /// Path to NDJSON file (use `"-"` for stdin).
    pub path: String,
    /// Count rows without writing to DB.
    pub dry_run: bool,
}

// ── Schema (identical to seeknow_harvest.rs — CREATE TABLE IF NOT EXISTS) ─────

fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         CREATE TABLE IF NOT EXISTS seeknow_au_cache (
             id           TEXT PRIMARY KEY,
             field        TEXT NOT NULL,
             query_value  TEXT NOT NULL,
             record_json  TEXT NOT NULL,
             inserted_at  TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS seeknow_au_field ON seeknow_au_cache (field, query_value);
         CREATE TABLE IF NOT EXISTS seeknow_harvest_progress (
             checkpoint_key TEXT PRIMARY KEY,
             rows_inserted  INTEGER NOT NULL DEFAULT 0,
             completed_at   TEXT NOT NULL
         );",
    )
    .map_err(|e| Error::Other(format!("DB schema: {e}")))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn stable_hash_id(line: &str) -> String {
    let mut h = DefaultHasher::new();
    line.hash(&mut h);
    format!("import-{:016x}", h.finish())
}

fn now_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    epoch_to_iso(secs)
}

fn epoch_to_iso(epoch: u64) -> String {
    let secs_per_min: u64 = 60;
    let secs_per_hour: u64 = 3_600;
    let secs_per_day: u64 = 86_400;

    let days = epoch / secs_per_day;
    let rem = epoch % secs_per_day;
    let hh = rem / secs_per_hour;
    let mm = (rem % secs_per_hour) / secs_per_min;
    let ss = rem % secs_per_min;

    let z: i64 = days as i64 + 719_468;
    let era: i64 = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe: i64 = z - era * 146_097;
    let yoe: i64 = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y: i64 = yoe + era * 400;
    let doy: i64 = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp: i64 = (5 * doy + 2) / 153;
    let d: i64 = doy - (153 * mp + 2) / 5 + 1;
    let m: i64 = mp + if mp < 10 { 3 } else { -9 };
    let y: i64 = y + if m <= 2 { 1 } else { 0 };

    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

// ── Row extraction ────────────────────────────────────────────────────────────

struct NdjsonRow {
    id: String,
    field: String,
    query_value: String,
    record_json: String,
    inserted_at: String,
}

fn extract_row(line: &str, now: &str) -> Option<NdjsonRow> {
    let rec: Value = serde_json::from_str(line)
        .map_err(|e| {
            eprintln!("[seeknow-import] skip invalid JSON: {e}");
        })
        .ok()?;

    let id = rec["id"]
        .as_str()
        .map(|s| s.to_string())
        .unwrap_or_else(|| stable_hash_id(line));

    let field = rec["field"]
        .as_str()
        .or_else(|| rec["type"].as_str())
        .unwrap_or("import")
        .to_string();

    let query_value = rec["query_value"]
        .as_str()
        .or_else(|| rec["value"].as_str())
        .unwrap_or("")
        .to_string();

    Some(NdjsonRow {
        id,
        field,
        query_value,
        record_json: line.to_string(),
        inserted_at: now.to_string(),
    })
}

// ── Flush batch ───────────────────────────────────────────────────────────────

fn flush_batch(conn: &mut Connection, batch: &mut Vec<NdjsonRow>) -> Result<usize> {
    let tx = conn
        .transaction()
        .map_err(|e| Error::Other(format!("begin tx: {e}")))?;
    for row in batch.iter() {
        tx.execute(
            "INSERT OR IGNORE INTO seeknow_au_cache
                 (id, field, query_value, record_json, inserted_at)
             VALUES (?1,?2,?3,?4,?5)",
            params![
                row.id,
                row.field,
                row.query_value,
                row.record_json,
                row.inserted_at,
            ],
        )
        .map_err(|e| Error::Other(format!("insert: {e}")))?;
    }
    let n = batch.len();
    tx.commit()
        .map_err(|e| Error::Other(format!("commit: {e}")))?;
    batch.clear();
    Ok(n)
}

// ── Main command ──────────────────────────────────────────────────────────────

pub fn cmd_seeknow_import(args: SeeknowImportArgs) -> Result<()> {
    let reader: Box<dyn BufRead> = if args.path == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        let f = std::fs::File::open(&args.path)
            .map_err(|e| Error::Other(format!("open {}: {e}", args.path)))?;
        Box::new(BufReader::new(f))
    };

    if args.dry_run {
        let mut count: usize = 0;
        for line_res in reader.lines() {
            let line = line_res.map_err(|e| Error::Other(e.to_string()))?;
            let line = line.trim_end_matches('\r').to_string();
            if line.is_empty() {
                continue;
            }
            if extract_row(&line, "").is_some() {
                count += 1;
            }
        }
        println!("[seeknow-import] dry-run: {count} rows parsed (not written)");
        return Ok(());
    }

    let db_path = crate::default_db_path();
    let mut conn = Connection::open(&db_path)
        .map_err(|e| Error::Other(format!("cannot open DB at {db_path:?}: {e}")))?;
    ensure_schema(&conn)?;

    let now = now_iso8601();
    let mut imported: usize = 0;
    let mut batch: Vec<NdjsonRow> = Vec::with_capacity(BATCH);

    for line_res in reader.lines() {
        let line = line_res.map_err(|e| Error::Other(e.to_string()))?;
        let line = line.trim_end_matches('\r').to_string();
        if line.is_empty() {
            continue;
        }
        if let Some(row) = extract_row(&line, &now) {
            batch.push(row);
            if batch.len() >= BATCH {
                imported += flush_batch(&mut conn, &mut batch)?;
            }
        }
    }

    if !batch.is_empty() {
        imported += flush_batch(&mut conn, &mut batch)?;
    }

    println!("[seeknow-import] {imported} rows imported.");
    Ok(())
}
