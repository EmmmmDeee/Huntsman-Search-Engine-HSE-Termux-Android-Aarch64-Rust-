//! `hse cells` — local OpenCelliD cell-tower database management.
//!
//! Subcommands:
//!   - `status`             — show tower count, MCC breakdown, last import time
//!   - `import --file PATH` — import a local CSV or CSV.GZ file
//!   - `import --country CODE` — attempt download from OpenCelliD, then import
//!   - `clear [--yes]`      — truncate the cells table

#[cfg(test)]
mod tests;

use std::io::{BufRead, BufReader, Read};
use std::time::Instant;

use clap::Subcommand;

use crate::{
    core::error::{Error, Result},
    util::cell_db::{self, CellRow},
};

/// Hard cap on the COMPRESSED OpenCelliD download (4 GiB) — generous headroom
/// over the real ~1-2 GB `.csv.gz`, so a spoofed/compromised host can't stream
/// until the device's disk fills.
const MAX_DOWNLOAD_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Hard cap on the DECOMPRESSED stream (16 GiB) — far above the real ~3 GB CSV,
/// but finite, so a gzip bomb can't expand without bound during import.
const MAX_DECOMPRESSED_BYTES: u64 = 16 * 1024 * 1024 * 1024;

// ── CLI struct ──────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum CellsAction {
    /// Show database statistics: total towers, MCC breakdown, last import.
    Status,

    /// Import cell tower data into the local database.
    Import {
        /// Local CSV or CSV.GZ file to import.
        #[arg(long)]
        file: Option<String>,

        /// Country code or MCC to download: "AU" (MCC 505), "world", or a raw
        /// MCC integer (e.g. "505"). Requires an OpenCelliD API key.
        #[arg(long)]
        country: Option<String>,

        /// OpenCelliD API key override (default: HUNTSMAN_OPENCELLID_KEY env var).
        #[arg(long)]
        key: Option<String>,
    },

    /// Truncate the cells table (permanently deletes all tower data).
    Clear {
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
}

// ── Entry point ─────────────────────────────────────────────────────────────

pub async fn cmd_cells(action: CellsAction) -> Result<()> {
    match action {
        CellsAction::Status => cmd_status(),
        CellsAction::Import { file, country, key } => cmd_import(file, country, key).await,
        CellsAction::Clear { yes } => cmd_clear(yes),
    }
}

// ── status ──────────────────────────────────────────────────────────────────

fn cmd_status() -> Result<()> {
    let conn = match cell_db::open_ro() {
        Ok(c) => c,
        Err(_) => {
            println!("Cell tower database: not populated.");
            println!(
                "Run `hse cells import --country AU` or `hse cells import --file <path>` to import data."
            );
            return Ok(());
        }
    };

    let total = cell_db::total_count(&conn).map_err(|e| Error::Other(e.to_string()))?;
    println!("Cell tower database: {total} towers");
    println!("Path: {}", cell_db::cell_db_path().display());

    let by_mcc = cell_db::count_by_mcc(&conn).map_err(|e| Error::Other(e.to_string()))?;
    if !by_mcc.is_empty() {
        println!("\n{}", mcc_header_line(by_mcc.len()));
        for (mcc, count) in by_mcc.iter().take(10) {
            println!("  MCC {mcc}: {count} towers");
        }
    }

    if let Some(rec) = cell_db::last_import(&conn).map_err(|e| Error::Other(e.to_string()))? {
        let age_secs = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64)
            .saturating_sub(rec.imported_at);
        let age_str = format_age(age_secs as u64);
        println!("\nLast import:");
        println!("  File:     {}", rec.source_file);
        println!("  Rows:     {}", rec.row_count);
        if let Some(mcc) = rec.mcc {
            println!("  MCC:      {mcc}");
        }
        println!("  Duration: {}ms", rec.duration_ms);
        println!("  Age:      {age_str}");
    } else {
        println!("\nNo import history.");
    }

    Ok(())
}

fn format_age(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

/// The "By MCC" header line for `hse cells status`. States the true total MCC
/// count whenever the printed breakdown is truncated to the top 10 by tower
/// count, so "(top 10)" can never read as "there are only 10" when there are
/// more — a plain "By MCC:" when the full list already fits.
fn mcc_header_line(total_mcc_count: usize) -> String {
    if total_mcc_count > 10 {
        format!("By MCC (top 10 of {total_mcc_count}):")
    } else {
        "By MCC:".to_string()
    }
}

// ── import ───────────────────────────────────────────────────────────────────

/// The OpenCelliD filename for a `--country`/API `country` value: the
/// special "world" dataset, or `OCID_cells_mcc<N>.csv.gz` for a resolved or
/// raw MCC. Pure so both the CLI and the API import handler build the exact
/// same filename from the exact same input, and so it's unit-testable
/// without a network call.
pub(crate) fn opencellid_filename(country: &str, mcc: Option<i64>) -> String {
    if country.eq_ignore_ascii_case("world") {
        "cell_towers.csv.gz".to_string()
    } else {
        let m = mcc.map_or_else(|| country.to_string(), |m| m.to_string());
        format!("OCID_cells_mcc{m}.csv.gz")
    }
}

/// The OpenCelliD download URL for a resolved `filename` + API key. Pure —
/// shared by the CLI and the API import handler.
pub(crate) fn opencellid_download_url(filename: &str, api_key: &str) -> String {
    format!(
        "https://opencellid.org/downloads/?token={api_key}&sourceFilter=ocid&type=full&file={filename}"
    )
}

async fn cmd_import(
    file: Option<String>,
    country: Option<String>,
    key_override: Option<String>,
) -> Result<()> {
    match (file, country) {
        (Some(path), _) => import_from_file_off_runtime(path, None).await,
        (None, Some(ref country)) => {
            let mcc = mcc_for_country(country);

            if country.eq_ignore_ascii_case("world") {
                eprintln!("Warning: the 'world' dataset is ~1-2 GB. This will take a while.");
            }

            // Resolve API key
            let api_key = key_override
                .or_else(|| std::env::var("HUNTSMAN_OPENCELLID_KEY").ok())
                .ok_or_else(|| {
                    Error::Other(
                        "No OpenCelliD API key. Pass --key KEY or set HUNTSMAN_OPENCELLID_KEY"
                            .to_string(),
                    )
                })?;

            let filename = opencellid_filename(country, mcc);
            let url = opencellid_download_url(&filename, &api_key);

            println!("Attempting to download: {filename}");
            match download_and_import(&url, &filename, mcc).await {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("Download failed: {e}");
                    eprintln!();
                    eprintln!(
                        "Download manually from https://opencellid.org/downloads/ (login required)"
                    );
                    eprintln!("and run: hse cells import --file ~/Download/{filename}");
                }
            }
            Ok(())
        }
        (None, None) => Err(Error::Other(
            "Specify --file PATH or --country CODE (e.g. --country AU)".to_string(),
        )),
    }
}

/// Download an OpenCelliD extract and import it. Shared by `hse cells import
/// --country` and `POST /api/v1/cells/import` (`api::cells_handlers`) — the
/// one place this network+import sequence is implemented.
pub(crate) async fn download_and_import(url: &str, filename: &str, mcc: Option<i64>) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| Error::Other(e.to_string()))?;

    let resp = client
        .get(url)
        .send()
        .await
        // `.without_url()` STRIPS the request URL from the reqwest error before it
        // is stringified — the OpenCelliD download URL carries the operator's paid
        // API key as `token=<HUNTSMAN_OPENCELLID_KEY>`, and reqwest's Display
        // re-emits the full URL (`… for url (…?token=…)`). Without this the key
        // would land in `CellsImportPhase::Error`, which the ungated
        // `GET /cells/status` `import_error` field serves verbatim. Mirrors the
        // crate's own leak-proof `From<reqwest::Error>` (core::error).
        .map_err(|e| Error::Other(format!("HTTP request failed: {}", e.without_url())))?;

    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    let is_data = status.is_success()
        && (content_type.contains("gzip")
            || content_type.contains("csv")
            || content_type.contains("octet")
            || content_type.contains("zip"));

    if !is_data {
        return Err(Error::Other(format!(
            "Unexpected response: HTTP {status}, Content-Type: {content_type}"
        )));
    }

    // Stream the body to a temp file in bounded chunks. A plain `resp.bytes()`
    // buffered the whole (self-described 1-2 GB) download into RAM — an OOM on a
    // phone — and was uncapped, so a spoofed/compromised `opencellid.org` could
    // stream until the device died. Chunked write + a hard byte cap fixes both.
    let tmp = tempfile_path();
    {
        use futures::StreamExt as _;
        use tokio::io::AsyncWriteExt;
        let mut f = tokio::fs::File::create(&tmp)
            .await
            .map_err(|e| Error::Other(format!("Temp file create: {e}")))?;
        let mut stream = resp.bytes_stream();
        let mut total: u64 = 0;
        while let Some(chunk) = stream.next().await {
            // Strip the key-bearing URL from the streaming error too (see the
            // `.without_url()` note on the initial send above).
            let chunk =
                chunk.map_err(|e| Error::Other(format!("Download error: {}", e.without_url())))?;
            total += chunk.len() as u64;
            if total > MAX_DOWNLOAD_BYTES {
                let _ = tokio::fs::remove_file(&tmp).await;
                return Err(Error::Other(format!(
                    "download exceeds the {MAX_DOWNLOAD_BYTES}-byte cap — refusing (host may be compromised)"
                )));
            }
            f.write_all(&chunk)
                .await
                .map_err(|e| Error::Other(format!("Temp file write: {e}")))?;
        }
    }

    // Preserves the previous fallback: a temp path that is not valid UTF-8
    // degrades to `filename` rather than failing the import outright.
    let import_path = tmp.to_str().unwrap_or(filename).to_string();
    let result = import_from_file_off_runtime(import_path, mcc).await;
    let _ = tokio::fs::remove_file(&tmp).await;
    result
}

fn tempfile_path() -> std::path::PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    std::env::temp_dir().join(format!("hse_cells_{ts}.csv.gz"))
}

// ── file import ───────────────────────────────────────────────────────────────

/// The ONLY path async code may take into [`import_from_file`].
///
/// [`import_from_file`] is CPU- and IO-bound to a degree that makes running it
/// on a tokio worker a real stall, not a theoretical one: it opens a SQLite
/// write connection and parses a gzip CSV bounded only by
/// [`MAX_DECOMPRESSED_BYTES`] (16 GiB), inserting every row. The runtime is
/// deliberately sized at 2 worker threads for low-power Termux devices
/// (`WORKER_THREADS` in `main.rs`), and `POST /api/v1/cells/import` reaches
/// this through `api::cells_handlers` → [`download_and_import`] — so a single
/// web-triggered OpenCelliD import previously blocked *half* the server's
/// executor for the duration of a multi-gigabyte parse. The streaming download
/// directly above it was already correctly async (`tokio::fs` +
/// `AsyncWriteExt`); only the import was synchronous.
///
/// Keeping [`import_from_file`] private and routing both async callers through
/// this wrapper means the blocking version cannot be reached from async code
/// by accident. A panic inside the import surfaces as a normal `Err` here
/// rather than unwinding a worker thread.
async fn import_from_file_off_runtime(path: String, mcc_hint: Option<i64>) -> Result<()> {
    tokio::task::spawn_blocking(move || import_from_file(&path, mcc_hint))
        .await
        .map_err(|e| Error::Other(format!("cell-tower import task failed: {e}")))?
}

fn import_from_file(path: &str, mcc_hint: Option<i64>) -> Result<()> {
    let p = std::path::Path::new(path);
    if !p.exists() {
        return Err(Error::Other(format!("File not found: {path}")));
    }

    let is_gz = path.ends_with(".gz");

    let conn = cell_db::open_rw().map_err(|e| Error::Other(e.to_string()))?;

    let start = Instant::now();
    let file = std::fs::File::open(p).map_err(|e| Error::Other(e.to_string()))?;

    let total_rows = if is_gz {
        // Cap the DECOMPRESSED stream: a gzip bomb (tiny `.gz` → petabytes) from a
        // spoofed host would otherwise fill the disk during import. `Read::take`
        // bounds it; the limit is far above the real OpenCelliD CSV (~3 GB).
        import_reader(
            BufReader::new(flate2::read::GzDecoder::new(file).take(MAX_DECOMPRESSED_BYTES)),
            &conn,
        )?
    } else {
        import_reader(BufReader::new(file), &conn)?
    };

    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64();
    let rate = if secs > 0.0 {
        (total_rows as f64 / secs) as u64
    } else {
        0
    };

    println!("Done: {total_rows} rows imported in {secs:.1}s ({rate} rows/sec)");

    let filename = p.file_name().and_then(|n| n.to_str()).unwrap_or(path);

    cell_db::record_import(
        &conn,
        mcc_hint,
        filename,
        total_rows as u64,
        elapsed.as_millis() as u64,
    )
    .map_err(|e| Error::Other(e.to_string()))?;

    Ok(())
}

fn import_reader<R: std::io::Read>(
    reader: BufReader<R>,
    conn: &rusqlite::Connection,
) -> Result<usize> {
    const BATCH_SIZE: usize = 50_000;

    let mut batch: Vec<CellRow> = Vec::with_capacity(BATCH_SIZE);
    let mut total = 0usize;
    let mut first_line = true;

    for line in reader.lines() {
        let line = line.map_err(|e| Error::Other(e.to_string()))?;

        // Skip header
        if first_line {
            first_line = false;
            if line.starts_with("radio") || line.starts_with("Radio") {
                continue;
            }
        }

        if let Some(row) = parse_csv_line(&line) {
            batch.push(row);
            if batch.len() >= BATCH_SIZE {
                let inserted =
                    cell_db::insert_batch(conn, &batch).map_err(|e| Error::Other(e.to_string()))?;
                total += inserted;
                println!("=> Importing: {total} rows...");
                batch.clear();
            }
        }
    }

    // Final partial batch
    if !batch.is_empty() {
        let inserted =
            cell_db::insert_batch(conn, &batch).map_err(|e| Error::Other(e.to_string()))?;
        total += inserted;
    }

    Ok(total)
}

// ── clear ────────────────────────────────────────────────────────────────────

/// What a clear actually reclaimed, so the operator is told the truth rather
/// than a bare "cleared".
///
/// On the primary target — Termux on Android, no root, frequently short of
/// storage — the whole reason to run `hse cells clear` is to get the space back
/// from a multi-gigabyte OpenCellID import. Reporting only success hid whether
/// that happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClearReport {
    /// Rows removed from `cells` (the tower table; `cell_imports` is a small
    /// ledger and its count is not separately interesting).
    pub rows_deleted: usize,
    /// Size of `cell_towers.db` before the clear, in bytes.
    pub bytes_before: u64,
    /// Size after. Equal to `bytes_before` when the vacuum could not run.
    pub bytes_after: u64,
    /// `None` when the vacuum succeeded. `Some(reason)` when it did not — the
    /// rows are still gone, but the file kept its size.
    pub vacuum_error: Option<String>,
}

impl ClearReport {
    /// Bytes actually returned to the filesystem. Saturating: a concurrent
    /// writer growing the file must not underflow this into a huge number.
    pub fn bytes_reclaimed(&self) -> u64 {
        self.bytes_before.saturating_sub(self.bytes_after)
    }
}

/// Truncate the `cells`/`cell_imports` tables and return the freed pages to the
/// filesystem. Shared by `hse cells clear` (after its own interactive
/// confirmation) and `POST /api/v1/cells/clear` (which requires an explicit
/// `{"confirm": true}` body instead — there is no stdin to prompt over HTTP).
///
/// `DELETE` alone does not shrink a SQLite database: the freed pages go on the
/// internal freelist and the file keeps its size on disk. A cleared multi-GB
/// OpenCellID import therefore reclaimed **nothing**, which is the opposite of
/// what an operator runs this command for on a storage-constrained phone. The
/// `VACUUM` rewrites the database without the freelist, so the space actually
/// comes back.
///
/// The vacuum is **not** allowed to fail the operation. It needs scratch space
/// roughly the size of the database, so on the very device most likely to need
/// it, it is also the most likely to hit `SQLITE_FULL`. By then the rows are
/// already gone and the clear has succeeded; failing here would report a
/// successful deletion as an error and invite the operator to run it again. The
/// failure is instead carried in [`ClearReport::vacuum_error`] and surfaced by
/// both callers, so it is reported rather than swallowed.
pub(crate) fn clear_cells_db() -> Result<ClearReport> {
    let path = cell_db::cell_db_path();
    let conn = cell_db::open_rw().map_err(|e| Error::Other(e.to_string()))?;
    clear_in(&conn, &path)
}

/// The clear itself, against an explicit connection and file.
///
/// Split from [`clear_cells_db`] so the reclaim behaviour can be tested against
/// a dedicated database. Under `cfg(test)` `cell_db_path()` resolves to one
/// per-process temp location shared by every test, so a test driving the global
/// path would race any sibling touching the cell DB — and the property under
/// test here (the file physically shrinks) needs a database it exclusively owns
/// and has grown to a known size.
fn clear_in(conn: &rusqlite::Connection, path: &std::path::Path) -> Result<ClearReport> {
    // The database occupies its main file PLUS the write-ahead log, and a
    // freshly-vacuumed DB can hold most of its bytes in the WAL. Counting only
    // the main file would let this report space as reclaimed while the WAL
    // still held it.
    let size_of = |p: &std::path::Path| -> u64 {
        let main = std::fs::metadata(p).map_or(0, |m| m.len());
        let wal = std::fs::metadata(p.with_extension("db-wal")).map_or(0, |m| m.len());
        main + wal
    };
    let bytes_before = size_of(path);

    let rows_deleted = conn
        .execute("DELETE FROM cells", [])
        .map_err(|e| Error::Other(e.to_string()))?;
    conn.execute("DELETE FROM cell_imports", [])
        .map_err(|e| Error::Other(e.to_string()))?;

    // VACUUM cannot run inside a transaction; `execute` on this plain
    // connection is not in one.
    //
    // The checkpoint is not optional. `cell_db::init_schema` opens this
    // database in WAL mode, and under WAL a VACUUM rebuilds the database into
    // the write-ahead log — the main file is NOT truncated until the WAL is
    // checkpointed back into it. Vacuuming alone therefore reclaimed exactly
    // zero bytes on disk, which is the original defect wearing a different hat.
    // `TRUNCATE` folds the WAL in and then truncates it to zero length, so both
    // files end up at their true post-clear size.
    let vacuum_error = conn
        .execute("VACUUM", [])
        .err()
        .map(|e| e.to_string())
        .or_else(|| {
            conn.pragma_update(None, "wal_checkpoint", "TRUNCATE")
                .err()
                .map(|e| format!("vacuum succeeded but the WAL checkpoint failed: {e}"))
        });

    // Re-stat after the vacuum and checkpoint, not before, so the number
    // reported is what the filesystem actually shows.
    let bytes_after = size_of(path);

    Ok(ClearReport {
        rows_deleted,
        bytes_before,
        bytes_after,
        vacuum_error,
    })
}

fn cmd_clear(yes: bool) -> Result<()> {
    if !yes {
        print!("This will delete all tower data. Type 'yes' to confirm: ");
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| Error::Other(e.to_string()))?;
        if input.trim() != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    let report = clear_cells_db()?;
    println!(
        "Cell tower database cleared: {} tower rows removed.",
        report.rows_deleted
    );
    match &report.vacuum_error {
        None => println!(
            "Reclaimed {} ({} → {}).",
            human_bytes(report.bytes_reclaimed()),
            human_bytes(report.bytes_before),
            human_bytes(report.bytes_after),
        ),
        // Named explicitly rather than silently leaving the file at its old
        // size: on a phone that is the difference between "I got my storage
        // back" and "I did not, and I do not know why".
        Some(reason) => println!(
            "Rows are gone, but the {} file could not be shrunk: {reason}\n\
             Free some space and re-run `hse cells clear` to reclaim it.",
            human_bytes(report.bytes_after),
        ),
    }
    Ok(())
}

/// Render a byte count for an operator: `1.4 GB`, `812.0 MB`, `0 B`.
///
/// Local to this module and deliberately small — the cells CLI is the only
/// place that needs it, and the crate has no other byte-formatting helper to
/// reuse or extend.
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if n < 1024 {
        return format!("{n} B");
    }
    #[allow(clippy::cast_precision_loss)] // display only; precision is irrelevant here
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit + 1 < UNITS.len() {
        v /= 1024.0;
        unit += 1;
    }
    format!("{v:.1} {}", UNITS[unit])
}

// ── CSV parsing ───────────────────────────────────────────────────────────────

/// Parse one line of the OpenCelliD CSV format.
///
/// Expected columns (0-indexed):
/// 0=radio, 1=mcc, 2=net(mnc), 3=area(lac), 4=cell(cid), 5=unit(skip),
/// 6=lon, 7=lat, 8=range, 9=samples, 10=changeable(skip), 11=created(skip),
/// 12=updated(skip), 13=averageSignal
pub(crate) fn parse_csv_line(line: &str) -> Option<CellRow> {
    let cols: Vec<&str> = line.splitn(15, ',').collect();
    if cols.len() < 14 {
        return None;
    }

    // Skip header row
    let radio = cols[0].trim();
    if radio.eq_ignore_ascii_case("radio") {
        return None;
    }
    // Also skip if first column starts with non-alphabetic (safety guard)
    if radio.is_empty() {
        return None;
    }

    let mcc: i64 = cols[1].trim().parse().ok()?;
    let mnc: i64 = cols[2].trim().parse().ok()?;
    let lac: i64 = cols[3].trim().parse().ok()?;
    let cid: i64 = cols[4].trim().parse().ok()?;
    // col 5 = unit (skip)
    let lon: f64 = cols[6].trim().parse().ok()?;
    let lat: f64 = cols[7].trim().parse().ok()?;
    let range_m: i64 = cols[8].trim().parse().unwrap_or(0);
    let samples: i64 = cols[9].trim().parse().unwrap_or(0);
    // cols 10-12 skip
    let avg_signal: i64 = cols[13].trim().parse().unwrap_or(0);

    // Basic sanity: valid lat/lon range
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }

    Some(CellRow {
        radio: radio.to_string(),
        mcc,
        mnc,
        lac,
        cid,
        lon,
        lat,
        range_m,
        samples,
        avg_signal,
    })
}

/// Resolve a country code string to an MCC integer (returns `None` for "world").
///
/// Accepts: "AU" / "au" → 505, a raw MCC integer string, or "world" → None.
pub(crate) fn mcc_for_country(country: &str) -> Option<i64> {
    let upper = country.trim().to_uppercase();
    if upper == "WORLD" {
        return None;
    }
    // Two-letter ISO 3166-1 alpha-2 → MCC lookup (partial; AU is the primary target)
    match upper.as_str() {
        "AU" => Some(505),
        "NZ" => Some(530),
        "US" => Some(310),
        "CA" => Some(302),
        "GB" | "UK" => Some(234),
        "DE" => Some(262),
        "FR" => Some(208),
        "JP" => Some(440),
        "CN" => Some(460),
        "IN" => Some(404),
        _ => {
            // Try raw MCC integer
            upper.parse().ok()
        }
    }
}
