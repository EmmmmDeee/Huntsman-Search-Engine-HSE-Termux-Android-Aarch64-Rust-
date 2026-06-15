//! `hse opencellid-harvest` — download the Australian OpenCelliD cell tower
//! bulk export (MCC=505) into a local SQLite table for offline `cell_intel`
//! lookups.
//!
//! The bulk download URL is:
//! `https://opencellid.org/downloads/cell_towers.csv.gz?token=<key>&mcc=505`
//!
//! The CSV format (after decompressing) is:
//! `radio,mcc,net,area,cell,unit,lon,lat,range,samples,changeable,created,updated,averageSignal`
//!
//! A local lookup is wired into `cell_intel` via `query_opencellid_local` so
//! that on-device scans skip the API entirely when the corpus is populated.

use std::io::Read;
use std::time::Duration;

use rusqlite::{Connection, params};

use crate::core::error::{Error, Result};

const SRC: &str = "opencellid_harvest";
const BULK_URL: &str = "https://opencellid.org/downloads/cell_towers.csv.gz";
const MIN_ROWS_POPULATED: i64 = 100_000;

pub struct OpencellidHarvestArgs {
    pub dry_run: bool,
    pub update: bool,
    pub force: bool,
}

pub async fn cmd_opencellid_harvest(args: OpencellidHarvestArgs) -> Result<()> {
    let key = std::env::var("HUNTSMAN_OPENCELLID_KEY")
        .ok()
        .filter(|k| !k.is_empty())
        .ok_or_else(|| {
            Error::Other(
                "HUNTSMAN_OPENCELLID_KEY is not set. \
                 Register free at https://opencellid.org/register.php \
                 then run: hse set-key HUNTSMAN_OPENCELLID_KEY <your-key>"
                    .into(),
            )
        })?;

    let db_path = crate::default_db_path();
    crate::cli::harvest_util::check_disk_space(db_path.as_str(), 200)?;
    let mut conn = Connection::open(&db_path)
        .map_err(|e| Error::Other(format!("cannot open DB at {db_path:?}: {e}")))?;

    ensure_schema(&conn)?;

    // Guard: skip if already populated unless --update or --force.
    if !args.force && !args.dry_run {
        let existing: i64 = conn
            .query_row("SELECT COUNT(*) FROM opencellid_au", [], |r| r.get(0))
            .unwrap_or(0);
        if existing >= MIN_ROWS_POPULATED && !args.update {
            eprintln!(
                "[{SRC}] Table already has {existing} rows. \
                 Use --update (if sparse) or --force to re-download."
            );
            return Ok(());
        }
        if existing >= MIN_ROWS_POPULATED && args.update {
            eprintln!(
                "[{SRC}] Table has {existing} rows (≥{MIN_ROWS_POPULATED}). \
                 Already populated — nothing to do. Use --force to re-download."
            );
            return Ok(());
        }
    }

    let url = format!("{BULK_URL}?token={key}&mcc=505");
    eprintln!(
        "[{SRC}] Downloading AU cell tower export (MCC=505){}…",
        if args.dry_run { " (DRY RUN)" } else { "" },
    );

    let bytes = download_with_retry(&url).await?;
    eprintln!(
        "[{SRC}] Downloaded {:.1} MB compressed",
        bytes.len() as f64 / 1_048_576.0
    );

    // Decompress.
    let csv_bytes = decompress_gz(&bytes)?;
    eprintln!(
        "[{SRC}] Decompressed to {:.1} MB",
        csv_bytes.len() as f64 / 1_048_576.0
    );

    let csv_str =
        std::str::from_utf8(&csv_bytes).map_err(|e| Error::Other(format!("CSV encoding: {e}")))?;

    if args.dry_run {
        let preview: Vec<&str> = csv_str.lines().take(6).collect();
        eprintln!("[{SRC}] Sample rows:");
        for line in &preview {
            eprintln!("  {line}");
        }
        return Ok(());
    }

    let inserted = import_csv(&mut conn, csv_str)?;
    eprintln!("[{SRC}] Inserted {inserted} rows into opencellid_au.");

    // Record the download timestamp.
    let now = simple_now();
    conn.execute(
        "INSERT OR REPLACE INTO opencellid_harvest_meta (key, value) VALUES ('last_download', ?1)",
        params![now],
    )
    .ok();

    eprintln!("[{SRC}] Complete.");
    Ok(())
}

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

async fn download_with_retry(url: &str) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300)) // large file
        .build()
        .map_err(|e| Error::Other(e.to_string()))?;

    let mut backoff = 2u64;
    for attempt in 0u8..4 {
        match client.get(url).send().await {
            Err(e) if attempt < 3 => {
                eprintln!("[{SRC}] Network error (retry {attempt}): {e}");
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(60);
                continue;
            }
            Err(e) => return Err(Error::Other(e.to_string())),
            Ok(r) if r.status().as_u16() == 401 => {
                return Err(Error::Other(
                    "OpenCelliD: invalid API key (401). \
                     Check HUNTSMAN_OPENCELLID_KEY."
                        .into(),
                ));
            }
            Ok(r) if !r.status().is_success() => {
                return Err(Error::Other(format!("OpenCelliD HTTP {}", r.status())));
            }
            Ok(r) => {
                let bytes = r.bytes().await.map_err(|e| Error::Other(e.to_string()))?;
                return Ok(bytes.to_vec());
            }
        }
    }
    Err(Error::Other(
        "OpenCelliD download failed after retries".into(),
    ))
}

fn decompress_gz(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut out = Vec::with_capacity(data.len() * 8);
    decoder
        .read_to_end(&mut out)
        .map_err(|e| Error::Other(format!("gzip decompress: {e}")))?;
    Ok(out)
}

fn import_csv(conn: &mut Connection, csv: &str) -> Result<u64> {
    let mut lines = csv.lines();

    // Skip header.
    let _header = lines.next();

    let tx = conn
        .transaction()
        .map_err(|e| Error::Other(e.to_string()))?;

    let mut inserted = 0u64;
    let mut batch = 0u64;

    for line in lines {
        // CSV format: radio,mcc,net,area,cell,unit,lon,lat,range,samples,changeable,created,updated,averageSignal
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() < 14 {
            continue;
        }

        let radio = cols[0];
        let mcc: i64 = match cols[1].trim().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let mnc: i64 = match cols[2].trim().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let lac: i64 = match cols[3].trim().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let cid: i64 = match cols[4].trim().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        // col[5] = unit (ignored)
        let lon: f64 = match cols[6].trim().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let lat: f64 = match cols[7].trim().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let range: Option<i64> = cols[8].trim().parse().ok();
        let samples: Option<i64> = cols[9].trim().parse().ok();
        let changeable: Option<i64> = cols[10].trim().parse().ok();
        let created: Option<i64> = cols[11].trim().parse().ok();
        let updated: Option<i64> = cols[12].trim().parse().ok();
        let avg_signal: Option<i64> = cols[13].trim().parse().ok();

        // Guard: skip rows outside the AU bounding box.
        if !(-44.5..=-9.5).contains(&lat) || !(112.0..=155.0).contains(&lon) {
            continue;
        }

        let n = tx
            .execute(
                "INSERT OR IGNORE INTO opencellid_au \
                 (radio,mcc,mnc,lac,cid,lat,lon,range_m,samples,changeable,created,updated,avg_signal) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![radio, mcc, mnc, lac, cid, lat, lon, range, samples, changeable, created, updated, avg_signal],
            )
            .map_err(|e| Error::Other(e.to_string()))?;

        inserted += n as u64;
        batch += 1;
        if batch.is_multiple_of(10_000) {
            eprint!("\r[{SRC}] {inserted} rows inserted…    ");
        }
    }

    eprintln!();
    tx.commit().map_err(|e| Error::Other(e.to_string()))?;
    Ok(inserted)
}

fn simple_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let sec = secs % 60;
    let min = (secs / 60) % 60;
    let hour = (secs / 3600) % 24;
    let days = secs / 86400;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let n = if is_leap(year) { 366 } else { 365 };
        if days < n {
            break;
        }
        days -= n;
        year += 1;
    }
    let months: [u64; 12] = [
        31,
        if is_leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u64;
    for m in months {
        if days < m {
            break;
        }
        days -= m;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}
