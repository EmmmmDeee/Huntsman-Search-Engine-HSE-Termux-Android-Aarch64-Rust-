//! Local OpenCelliD cell-tower SQLite database.
//!
//! Lives at `~/.huntsman/cell_towers.db`, separate from the scan DB.
//! Written by `hse cells import`; read by the `cell_local` module.

use std::path::PathBuf;

use rusqlite::{Connection, params};

// ── Public path helper ──────────────────────────────────────────────────────

/// Path to the cell towers DB file: `$HOME/.huntsman/cell_towers.db`.
/// Falls back to `./.huntsman/cell_towers.db` when `$HOME` is unset (see
/// [`crate::util::paths::huntsman_dir`] — the layout stays together under
/// `.huntsman` rather than scattering a bare file into the CWD).
#[must_use]
pub fn cell_db_path() -> PathBuf {
    crate::util::paths::data_file("cell_towers.db")
}

// ── Connection helpers ──────────────────────────────────────────────────────

/// Open (or create) the cell towers DB for read-write access.
pub fn open_rw() -> rusqlite::Result<Connection> {
    let path = cell_db_path();
    let conn = Connection::open(path)?;
    init_schema(&conn)?;
    Ok(conn)
}

/// Open the cell towers DB read-only.
///
/// Returns `Err` when the file does not exist (DB not populated yet).
pub fn open_ro() -> rusqlite::Result<Connection> {
    let path = cell_db_path();
    if !path.exists() {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN),
            Some("cell_towers.db not found — run `hse cells import` first".into()),
        ));
    }
    Connection::open(path)
}

// ── Schema ──────────────────────────────────────────────────────────────────

/// Create the cell tower schema in an open connection.
///
/// Uses `IF NOT EXISTS` so it is safe to call on an existing DB.
pub fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;

         CREATE TABLE IF NOT EXISTS cells (
             radio      TEXT    NOT NULL,
             mcc        INTEGER NOT NULL,
             mnc        INTEGER NOT NULL,
             lac        INTEGER NOT NULL,
             cid        INTEGER NOT NULL,
             lon        REAL    NOT NULL,
             lat        REAL    NOT NULL,
             range_m    INTEGER NOT NULL DEFAULT 0,
             samples    INTEGER NOT NULL DEFAULT 0,
             avg_signal INTEGER NOT NULL DEFAULT 0,
             PRIMARY KEY (mcc, mnc, lac, cid)
         );
         CREATE INDEX IF NOT EXISTS idx_cells_geo ON cells (lat, lon);
         CREATE INDEX IF NOT EXISTS idx_cells_mcc ON cells (mcc);

         CREATE TABLE IF NOT EXISTS cell_imports (
             id          INTEGER PRIMARY KEY AUTOINCREMENT,
             imported_at INTEGER NOT NULL,
             mcc         INTEGER,
             source_file TEXT    NOT NULL DEFAULT '',
             row_count   INTEGER NOT NULL,
             duration_ms INTEGER NOT NULL
         );",
    )
}

// ── Data types ───────────────────────────────────────────────────────────────

/// One cell-tower row from the cells table.
#[derive(Clone, Debug)]
pub struct CellRow {
    pub radio: String,
    pub mcc: i64,
    pub mnc: i64,
    pub lac: i64,
    pub cid: i64,
    pub lon: f64,
    pub lat: f64,
    pub range_m: i64,
    pub samples: i64,
    pub avg_signal: i64,
}

/// Metadata about a completed import.
#[derive(Debug)]
pub struct ImportRecord {
    pub imported_at: i64,
    pub mcc: Option<i64>,
    pub source_file: String,
    pub row_count: u64,
    pub duration_ms: u64,
}

// ── Write helpers ─────────────────────────────────────────────────────────────

/// Insert a batch of [`CellRow`] records using `INSERT OR REPLACE`.
///
/// Wraps the entire batch in a single transaction for performance.
/// Returns the number of rows inserted or replaced.
pub fn insert_batch(conn: &Connection, batch: &[CellRow]) -> rusqlite::Result<usize> {
    if batch.is_empty() {
        return Ok(0);
    }
    let tx = conn.unchecked_transaction()?;
    let mut count = 0usize;
    {
        let mut stmt = tx.prepare_cached(
            "INSERT OR REPLACE INTO cells
             (radio, mcc, mnc, lac, cid, lon, lat, range_m, samples, avg_signal)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )?;
        for row in batch {
            stmt.execute(params![
                row.radio,
                row.mcc,
                row.mnc,
                row.lac,
                row.cid,
                row.lon,
                row.lat,
                row.range_m,
                row.samples,
                row.avg_signal,
            ])?;
            count += 1;
        }
    }
    tx.commit()?;
    Ok(count)
}

// ── Read helpers ──────────────────────────────────────────────────────────────

/// Query towers within a geographic bounding box.
///
/// Returns up to `limit` rows ordered by `(lat, lon)`.
pub fn query_bbox(
    conn: &Connection,
    lat_min: f64,
    lon_min: f64,
    lat_max: f64,
    lon_max: f64,
    limit: usize,
) -> rusqlite::Result<Vec<CellRow>> {
    let mut stmt = conn.prepare_cached(
        "SELECT radio, mcc, mnc, lac, cid, lon, lat, range_m, samples, avg_signal
         FROM cells
         WHERE lat BETWEEN ?1 AND ?2
           AND lon BETWEEN ?3 AND ?4
         ORDER BY lat, lon
         LIMIT ?5",
    )?;
    let rows = stmt.query_map(
        params![lat_min, lat_max, lon_min, lon_max, limit as i64],
        |r| {
            Ok(CellRow {
                radio: r.get(0)?,
                mcc: r.get(1)?,
                mnc: r.get(2)?,
                lac: r.get(3)?,
                cid: r.get(4)?,
                lon: r.get(5)?,
                lat: r.get(6)?,
                range_m: r.get(7)?,
                samples: r.get(8)?,
                avg_signal: r.get(9)?,
            })
        },
    )?;
    rows.collect()
}

/// Total number of rows in the `cells` table.
pub fn total_count(conn: &Connection) -> rusqlite::Result<u64> {
    conn.query_row("SELECT COUNT(*) FROM cells", [], |r| r.get::<_, i64>(0))
        .map(|n| n as u64)
}

/// Row counts grouped by MCC, sorted descending by count.
pub fn count_by_mcc(conn: &Connection) -> rusqlite::Result<Vec<(i64, u64)>> {
    let mut stmt =
        conn.prepare("SELECT mcc, COUNT(*) AS cnt FROM cells GROUP BY mcc ORDER BY cnt DESC")?;
    let rows = stmt.query_map([], |r| {
        let mcc: i64 = r.get(0)?;
        let cnt: i64 = r.get(1)?;
        Ok((mcc, cnt as u64))
    })?;
    rows.collect()
}

// ── Import history ─────────────────────────────────────────────────────────────

/// Record a completed import in `cell_imports`.
pub fn record_import(
    conn: &Connection,
    mcc: Option<i64>,
    source: &str,
    rows: u64,
    duration_ms: u64,
) -> rusqlite::Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    conn.execute(
        "INSERT INTO cell_imports (imported_at, mcc, source_file, row_count, duration_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![now, mcc, source, rows as i64, duration_ms as i64],
    )?;
    Ok(())
}

/// A local cell-tower import is considered **stale** once this many days have
/// elapsed since the last import. OpenCelliD's public dataset changes as
/// towers are added/decommissioned, and this project has no auto-resync —
/// `hse cells import` is a manual trigger only (`SOLUTION_TREE` §4a's
/// "cell_local auto-sync" gap notes no scheduler exists yet) — so a database
/// that has gone quiet for 6+ months is a genuine "consider refreshing"
/// signal for the operator, not noise.
pub const STALE_THRESHOLD_DAYS: u32 = 180;

/// Whether an import at `imported_at` (unix seconds) is stale as of `now_unix`.
/// Pure so it is unit-testable without a live DB or a wall-clock dependency.
#[must_use]
pub fn is_stale(imported_at: i64, now_unix: i64) -> bool {
    now_unix.saturating_sub(imported_at) > i64::from(STALE_THRESHOLD_DAYS) * 86_400
}

/// The most recent import record, if any.
pub fn last_import(conn: &Connection) -> rusqlite::Result<Option<ImportRecord>> {
    let result = conn.query_row(
        "SELECT imported_at, mcc, source_file, row_count, duration_ms
         FROM cell_imports
         ORDER BY imported_at DESC
         LIMIT 1",
        [],
        |r| {
            Ok(ImportRecord {
                imported_at: r.get(0)?,
                mcc: r.get(1)?,
                source_file: r.get(2)?,
                row_count: r.get::<_, i64>(3)? as u64,
                duration_ms: r.get::<_, i64>(4)? as u64,
            })
        },
    );
    match result {
        Ok(rec) => Ok(Some(rec)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn in_memory_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        init_schema(&conn).expect("schema");
        conn
    }

    #[test]
    fn cell_db_path_ends_with_db_filename() {
        let p = cell_db_path();
        assert!(
            p.to_string_lossy().ends_with("cell_towers.db"),
            "unexpected path: {p:?}"
        );
    }

    #[test]
    fn insert_and_query_bbox_round_trip() {
        let conn = in_memory_conn();
        let batch = vec![
            CellRow {
                radio: "LTE".into(),
                mcc: 505,
                mnc: 1,
                lac: 100,
                cid: 200,
                lon: 153.021,
                lat: -27.471,
                range_m: 500,
                samples: 10,
                avg_signal: -80,
            },
            CellRow {
                radio: "GSM".into(),
                mcc: 505,
                mnc: 2,
                lac: 101,
                cid: 201,
                lon: 153.031,
                lat: -27.461,
                range_m: 1000,
                samples: 5,
                avg_signal: -90,
            },
        ];
        let inserted = insert_batch(&conn, &batch).expect("insert");
        assert_eq!(inserted, 2);

        let results = query_bbox(&conn, -27.48, 153.01, -27.45, 153.04, 50).expect("query");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].radio, "LTE");
        assert_eq!(results[1].radio, "GSM");
    }

    #[test]
    fn insert_or_replace_updates_existing() {
        let conn = in_memory_conn();
        let row = CellRow {
            radio: "GSM".into(),
            mcc: 505,
            mnc: 1,
            lac: 10,
            cid: 20,
            lon: 153.0,
            lat: -27.47,
            range_m: 500,
            samples: 1,
            avg_signal: -85,
        };
        insert_batch(&conn, &[row]).expect("first insert");

        let updated = CellRow {
            radio: "LTE".into(),
            mcc: 505,
            mnc: 1,
            lac: 10,
            cid: 20,
            lon: 153.0,
            lat: -27.47,
            range_m: 300,
            samples: 99,
            avg_signal: -70,
        };
        insert_batch(&conn, &[updated]).expect("replace");

        let count = total_count(&conn).expect("count");
        assert_eq!(count, 1, "INSERT OR REPLACE must not duplicate rows");
        let rows = query_bbox(&conn, -27.48, 152.99, -27.46, 153.01, 10).expect("query");
        assert_eq!(rows[0].radio, "LTE");
        assert_eq!(rows[0].samples, 99);
    }

    #[test]
    fn total_count_empty_db_is_zero() {
        let conn = in_memory_conn();
        assert_eq!(total_count(&conn).expect("count"), 0);
    }

    #[test]
    fn count_by_mcc_groups_correctly() {
        let conn = in_memory_conn();
        let batch = vec![
            CellRow {
                radio: "LTE".into(),
                mcc: 505,
                mnc: 1,
                lac: 1,
                cid: 1,
                lon: 0.0,
                lat: 0.1,
                range_m: 0,
                samples: 0,
                avg_signal: 0,
            },
            CellRow {
                radio: "LTE".into(),
                mcc: 505,
                mnc: 2,
                lac: 1,
                cid: 2,
                lon: 0.0,
                lat: 0.2,
                range_m: 0,
                samples: 0,
                avg_signal: 0,
            },
            CellRow {
                radio: "GSM".into(),
                mcc: 310,
                mnc: 1,
                lac: 1,
                cid: 3,
                lon: 0.0,
                lat: 0.3,
                range_m: 0,
                samples: 0,
                avg_signal: 0,
            },
        ];
        insert_batch(&conn, &batch).expect("insert");
        let by_mcc = count_by_mcc(&conn).expect("count_by_mcc");
        // 505 has 2 entries, 310 has 1 — sorted desc
        assert_eq!(by_mcc[0], (505, 2));
        assert_eq!(by_mcc[1], (310, 1));
    }

    #[test]
    fn is_stale_true_past_the_threshold_false_before_it() {
        let now: i64 = 1_800_000_000;
        let just_under = now - i64::from(STALE_THRESHOLD_DAYS) * 86_400 + 1;
        let just_over = now - i64::from(STALE_THRESHOLD_DAYS) * 86_400 - 1;
        assert!(!is_stale(just_under, now), "not yet stale");
        assert!(is_stale(just_over, now), "past the threshold");
        assert!(!is_stale(now, now), "a fresh import is never stale");
    }

    #[test]
    fn record_and_retrieve_import_metadata() {
        let conn = in_memory_conn();
        assert!(last_import(&conn).expect("last_import none").is_none());

        record_import(&conn, Some(505), "test.csv.gz", 12345, 3000).expect("record");
        let rec = last_import(&conn).expect("last_import").expect("some");
        assert_eq!(rec.mcc, Some(505));
        assert_eq!(rec.source_file, "test.csv.gz");
        assert_eq!(rec.row_count, 12345);
        assert_eq!(rec.duration_ms, 3000);
        assert!(rec.imported_at > 0);
    }

    #[test]
    fn query_bbox_respects_limit() {
        let conn = in_memory_conn();
        let batch: Vec<CellRow> = (0..10i64)
            .map(|i| CellRow {
                radio: "LTE".into(),
                mcc: 505,
                mnc: i,
                lac: i,
                cid: i,
                lon: 153.0 + (i as f64) * 0.001,
                lat: -27.47,
                range_m: 100,
                samples: 1,
                avg_signal: -80,
            })
            .collect();
        insert_batch(&conn, &batch).expect("insert");
        let results = query_bbox(&conn, -27.48, 152.99, -27.46, 153.02, 3).expect("query");
        assert_eq!(results.len(), 3);
    }
}
