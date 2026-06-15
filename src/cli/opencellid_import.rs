//! `hse opencellid-import` — import an OpenCelliD `cell_towers.csv` file into
//! the local `opencellid_au` corpus.
//!
//! Format: `radio,mcc,net,area,cell,unit,lon,lat,range,samples,changeable,created,updated,averageSignal`
//! (first line is the header, which is skipped).

use std::io::{BufRead, BufReader};

use rusqlite::{Connection, params};

use crate::core::error::{Error, Result};

const BATCH: usize = 10_000;

/// Arguments for `hse opencellid-import`.
pub struct OpencellidImportArgs {
    /// Path to `cell_towers.csv` (use `"-"` for stdin).
    pub path: String,
    /// Count rows without writing to DB.
    pub dry_run: bool,
}

// ── Schema (identical to opencellid_harvest.rs — CREATE TABLE IF NOT EXISTS) ──

fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         CREATE TABLE IF NOT EXISTS opencellid_au (
             radio      TEXT NOT NULL,
             mcc        INTEGER NOT NULL,
             mnc        INTEGER NOT NULL,
             lac        INTEGER NOT NULL,
             cid        INTEGER NOT NULL,
             lat        REAL NOT NULL,
             lon        REAL NOT NULL,
             range_m    INTEGER,
             samples    INTEGER,
             changeable INTEGER,
             created    INTEGER,
             updated    INTEGER,
             avg_signal INTEGER,
             PRIMARY KEY (radio, mcc, mnc, lac, cid)
         );
         CREATE INDEX IF NOT EXISTS opencellid_au_geo ON opencellid_au (lat, lon);
         CREATE TABLE IF NOT EXISTS opencellid_harvest_meta (
             key   TEXT PRIMARY KEY,
             value TEXT NOT NULL
         );",
    )
    .map_err(|e| Error::Other(format!("DB schema: {e}")))
}

// ── Parsed row ────────────────────────────────────────────────────────────────

struct CellRow {
    radio: String,
    mcc: i64,
    mnc: i64,
    lac: i64,
    cid: i64,
    lon: f64,
    lat: f64,
    range_m: Option<i64>,
    samples: Option<i64>,
    changeable: i64,
    created: i64,
    updated: i64,
    avg_signal: Option<i64>,
}

fn parse_row(line: &str) -> Option<CellRow> {
    let f: Vec<&str> = line.split(',').collect();
    if f.len() < 14 {
        return None;
    }

    let radio = f[0].trim().to_string();
    let mcc: i64 = f[1].trim().parse().ok()?;
    let mnc: i64 = f[2].trim().parse().ok()?;
    let lac: i64 = f[3].trim().parse().ok()?;
    let cid: i64 = f[4].trim().parse().ok()?;
    // field 5 = unit — discard
    let lon: f64 = f[6].trim().parse().ok()?;
    let lat: f64 = f[7].trim().parse().ok()?;
    let range_raw: i64 = f[8].trim().parse().unwrap_or(0);
    let samples_raw: i64 = f[9].trim().parse().unwrap_or(0);
    let changeable: i64 = f[10].trim().parse().unwrap_or(0);
    let created: i64 = f[11].trim().parse().unwrap_or(0);
    let updated: i64 = f[12].trim().parse().unwrap_or(0);
    let avg_signal_raw: i64 = f[13].trim().parse().unwrap_or(0);

    Some(CellRow {
        radio,
        mcc,
        mnc,
        lac,
        cid,
        lon,
        lat,
        range_m: if range_raw == 0 {
            None
        } else {
            Some(range_raw)
        },
        samples: if samples_raw == 0 {
            None
        } else {
            Some(samples_raw)
        },
        changeable,
        created,
        updated,
        avg_signal: if avg_signal_raw == 0 {
            None
        } else {
            Some(avg_signal_raw)
        },
    })
}

// ── Flush a batch ─────────────────────────────────────────────────────────────

fn flush_batch(conn: &mut Connection, batch: &mut Vec<CellRow>) -> Result<usize> {
    let tx = conn
        .transaction()
        .map_err(|e| Error::Other(format!("begin tx: {e}")))?;
    for row in batch.iter() {
        tx.execute(
            "INSERT OR REPLACE INTO opencellid_au
                 (radio, mcc, mnc, lac, cid, lat, lon, range_m, samples,
                  changeable, created, updated, avg_signal)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                row.radio,
                row.mcc,
                row.mnc,
                row.lac,
                row.cid,
                row.lat,
                row.lon,
                row.range_m,
                row.samples,
                row.changeable,
                row.created,
                row.updated,
                row.avg_signal,
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

pub fn cmd_opencellid_import(args: OpencellidImportArgs) -> Result<()> {
    let reader: Box<dyn BufRead> = if args.path == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        let f = std::fs::File::open(&args.path)
            .map_err(|e| Error::Other(format!("open {}: {e}", args.path)))?;
        Box::new(BufReader::new(f))
    };

    let mut lines = reader.lines();

    // Skip the header line.
    match lines.next() {
        Some(Ok(_)) => {}
        Some(Err(e)) => return Err(Error::Other(format!("read header: {e}"))),
        None => return Err(Error::Other("empty file".into())),
    }

    if args.dry_run {
        let mut count: usize = 0;
        for line_res in lines {
            let line = line_res.map_err(|e| Error::Other(e.to_string()))?;
            let line = line.trim_end_matches('\r').to_string();
            if line.is_empty() {
                continue;
            }
            if parse_row(&line).is_some() {
                count += 1;
            }
        }
        println!("[opencellid-import] dry-run: {count} rows parsed (not written)");
        return Ok(());
    }

    let db_path = crate::default_db_path();
    let mut conn = Connection::open(&db_path)
        .map_err(|e| Error::Other(format!("cannot open DB at {db_path:?}: {e}")))?;
    ensure_schema(&conn)?;

    let mut imported: usize = 0;
    let mut batch: Vec<CellRow> = Vec::with_capacity(BATCH);

    for line_res in lines {
        let line = line_res.map_err(|e| Error::Other(e.to_string()))?;
        let line = line.trim_end_matches('\r').to_string();
        if line.is_empty() {
            continue;
        }
        if let Some(row) = parse_row(&line) {
            batch.push(row);
            if batch.len() >= BATCH {
                imported += flush_batch(&mut conn, &mut batch)?;
            }
        }
    }

    if !batch.is_empty() {
        imported += flush_batch(&mut conn, &mut batch)?;
    }

    println!("[opencellid-import] {imported} rows imported.");
    Ok(())
}
