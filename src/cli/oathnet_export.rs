//! `hse oathnet-export` — export the local oathnet_au_cache corpus in
//! OathNet's native JSON format, suitable for re-import or use in any
//! tool that accepts OathNet API response data.
//!
//! Output is NDJSON (one JSON object per line) or a JSON array depending
//! on --format. The record_json field is emitted verbatim — nothing is
//! re-encoded or translated, preserving 100% of the original data.

use std::io::Write;

use rusqlite::{Connection, OpenFlags};

use crate::core::error::{Error, Result};

pub struct OathnetExportArgs {
    /// "ndjson" (default) or "json-array"
    pub format: String,
    /// Write to file (default: stdout)
    pub output: Option<String>,
    /// Filter by surface: "breach" or "stealer"
    pub surface: Option<String>,
    /// Filter by field: "email", "domain", "phone", etc.
    pub field: Option<String>,
    /// Max records (0 = all)
    pub limit: u64,
}

pub fn cmd_oathnet_export(args: OathnetExportArgs) -> Result<()> {
    let db_path = crate::default_db_path();
    let conn = Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| Error::Other(e.to_string()))?;

    // Check table exists.
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='oathnet_au_cache'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if !table_exists {
        eprintln!(
            "[oathnet-export] oathnet_au_cache table not found. Run hse oathnet-harvest first."
        );
        return Ok(());
    }

    let mut writer: Box<dyn Write> = match &args.output {
        Some(path) => Box::new(std::io::BufWriter::new(
            std::fs::File::create(path)
                .map_err(|e| Error::Other(format!("cannot create {path}: {e}")))?,
        )),
        None => Box::new(std::io::BufWriter::new(std::io::stdout())),
    };

    run_export(&conn, &args, &mut writer)
}

fn build_query(surface: Option<&str>, field: Option<&str>, limit: u64) -> String {
    let mut sql = String::from("SELECT record_json FROM oathnet_au_cache WHERE 1=1");
    if surface.is_some() {
        sql.push_str(" AND surface = ?1");
    }
    if field.is_some() {
        if surface.is_some() {
            sql.push_str(" AND field = ?2");
        } else {
            sql.push_str(" AND field = ?1");
        }
    }
    sql.push_str(" ORDER BY rowid");
    if limit > 0 {
        sql.push_str(&format!(" LIMIT {limit}"));
    }
    sql
}

fn run_export<W: Write>(conn: &Connection, args: &OathnetExportArgs, w: &mut W) -> Result<()> {
    let sql = build_query(args.surface.as_deref(), args.field.as_deref(), args.limit);

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| Error::Other(e.to_string()))?;

    let as_json_array = args.format == "json-array";

    let emit = |row: &rusqlite::Row<'_>| -> rusqlite::Result<String> { row.get(0) };

    let rows: Vec<String> = match (args.surface.as_deref(), args.field.as_deref()) {
        (Some(s), Some(f)) => stmt
            .query_map(rusqlite::params![s, f], emit)
            .map_err(|e| Error::Other(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect(),
        (Some(s), None) => stmt
            .query_map(rusqlite::params![s], emit)
            .map_err(|e| Error::Other(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect(),
        (None, Some(f)) => stmt
            .query_map(rusqlite::params![f], emit)
            .map_err(|e| Error::Other(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect(),
        (None, None) => stmt
            .query_map([], emit)
            .map_err(|e| Error::Other(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect(),
    };

    if as_json_array {
        writeln!(w, "[").map_err(io_err)?;
        let last = rows.len().saturating_sub(1);
        for (i, record_json) in rows.iter().enumerate() {
            if i < last {
                writeln!(w, "  {record_json},").map_err(io_err)?;
            } else {
                writeln!(w, "  {record_json}").map_err(io_err)?;
            }
        }
        writeln!(w, "]").map_err(io_err)?;
    } else {
        for record_json in &rows {
            writeln!(w, "{record_json}").map_err(io_err)?;
        }
    }

    w.flush().map_err(io_err)?;
    Ok(())
}

fn io_err(e: std::io::Error) -> Error {
    Error::Other(e.to_string())
}
