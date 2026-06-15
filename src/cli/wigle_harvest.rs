//! `hse wigle-harvest` — resumable bulk WiGLE downloader for Australia.
//!
//! Tiles the Australian bounding box (lat −44 → −10, lon 113 → 154) in
//! configurable degree steps, pages the WiGLE `/api/v2/network/search`
//! endpoint with cursor-based pagination, and bulk-inserts results into a
//! local SQLite table `wigle_au`. Completed tiles are checkpointed in
//! `wigle_harvest_tiles` so interrupted runs resume from the last completed
//! tile rather than restarting from scratch.

use std::time::Duration;

use reqwest::Client;
use rusqlite::Connection;
use serde::Deserialize;
use tokio::time::sleep;

use crate::core::error::{Error, Result};
use crate::util::keys::{WIGLE_DEFAULT_TOKEN, WIGLE_DEFAULT_USER};

// ── Australia bounding box ────────────────────────────────────────────────────
const AU_LAT_MIN: f64 = -44.0;
const AU_LAT_MAX: f64 = -10.0;
const AU_LON_MIN: f64 = 113.0;
const AU_LON_MAX: f64 = 154.0;

// ── WiGLE API ─────────────────────────────────────────────────────────────────
const WIGLE_BASE: &str = "https://api.wigle.net/api/v2/network/search";
const RESULTS_PER_PAGE: u32 = 1000;

// ── Rate / backoff ─────────────────────────────────────────────────────────────
const BACKOFF_BASE_SECS: u64 = 2;
const BACKOFF_CAP_SECS: u64 = 120;

/// Arguments for the `wigle-harvest` command.
pub struct WigleHarvestArgs {
    /// Print plan only; make no requests and write nothing to the DB.
    pub dry_run: bool,
    /// Requests per second (WiGLE free-tier safe default: 1.0).
    pub rate: f64,
    /// Tile step in degrees (default 0.5 ≈ ~55 km tiles).
    pub step: f64,
    /// Network kinds to harvest (e.g. `["wifi"]`).
    pub kinds: Vec<String>,
}

// ── WiGLE response types ──────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
struct WigleResponse {
    results: Vec<WigleNetwork>,
    #[serde(rename = "searchAfter")]
    search_after: Option<String>,
}

#[derive(Deserialize, Debug)]
struct WigleNetwork {
    netid: String,
    ssid: Option<String>,
    trilat: f64,
    trilong: f64,
    accuracy: Option<f64>,
    lastupdt: Option<String>,
    channel: Option<i64>,
    encryption: Option<String>,
}

// ── DB schema ────────────────────────────────────────────────────────────────

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS wigle_au (
    netid       TEXT PRIMARY KEY,
    kind        TEXT NOT NULL DEFAULT 'wifi',
    ssid        TEXT,
    lat         REAL NOT NULL,
    lon         REAL NOT NULL,
    accuracy    INTEGER,
    last_seen   TEXT,
    channel     INTEGER,
    encryption  TEXT,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS wigle_au_geo  ON wigle_au (lat, lon);
CREATE INDEX IF NOT EXISTS wigle_au_ssid ON wigle_au (ssid);

CREATE TABLE IF NOT EXISTS wigle_harvest_tiles (
    tile_key       TEXT PRIMARY KEY,
    rows_inserted  INTEGER NOT NULL DEFAULT 0,
    completed_at   TEXT NOT NULL
);
";

fn open_db(path: &str) -> Result<Connection> {
    let conn = Connection::open(path).map_err(|e| Error::Other(e.to_string()))?;
    conn.execute_batch(SCHEMA)
        .map_err(|e| Error::Other(e.to_string()))?;
    Ok(conn)
}

fn tile_done(conn: &Connection, tile_key: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM wigle_harvest_tiles WHERE tile_key = ?1",
        rusqlite::params![tile_key],
        |_| Ok(()),
    )
    .is_ok()
}

fn mark_tile_done(conn: &Connection, tile_key: &str, rows: u64) -> Result<()> {
    let now = chrono_now();
    conn.execute(
        "INSERT OR REPLACE INTO wigle_harvest_tiles (tile_key, rows_inserted, completed_at) \
         VALUES (?1, ?2, ?3)",
        rusqlite::params![tile_key, rows as i64, now],
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    Ok(())
}

fn insert_page(conn: &mut Connection, kind: &str, networks: &[WigleNetwork]) -> Result<u64> {
    let now = chrono_now();
    let tx = conn
        .transaction()
        .map_err(|e| Error::Other(e.to_string()))?;
    let mut stmt = tx
        .prepare_cached(
            "INSERT OR IGNORE INTO wigle_au \
             (netid, kind, ssid, lat, lon, accuracy, last_seen, channel, encryption, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .map_err(|e| Error::Other(e.to_string()))?;
    let mut inserted = 0u64;
    for n in networks {
        let rows = stmt
            .execute(rusqlite::params![
                n.netid,
                kind,
                n.ssid,
                n.trilat,
                n.trilong,
                n.accuracy.map(|a| a as i64),
                n.lastupdt,
                n.channel,
                n.encryption,
                now,
            ])
            .map_err(|e| Error::Other(e.to_string()))?;
        inserted += rows as u64;
    }
    drop(stmt);
    tx.commit().map_err(|e| Error::Other(e.to_string()))?;
    Ok(inserted)
}

fn chrono_now() -> String {
    // RFC 3339 UTC without chrono dependency — use std SystemTime.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (y, mo, d, h, mi, s) = epoch_to_ymd_hms(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Minimal epoch → (Y, M, D, H, Min, S) decomposition (no chrono).
fn epoch_to_ymd_hms(mut secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let s = (secs % 60) as u32;
    secs /= 60;
    let min = (secs % 60) as u32;
    secs /= 60;
    let h = (secs % 24) as u32;
    secs /= 24;
    let mut days = secs as u32;
    let mut y = 1970u32;
    loop {
        let dy = if is_leap(y) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        y += 1;
    }
    let months = if is_leap(y) {
        [31u32, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31u32, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut mo = 1u32;
    for dm in months {
        if days < dm {
            break;
        }
        days -= dm;
        mo += 1;
    }
    (y, mo, days + 1, h, min, s)
}

fn is_leap(y: u32) -> bool {
    y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400))
}

// ── Tile grid helper ──────────────────────────────────────────────────────────

/// Generate all (lat_lo, lon_lo) tile corners for the AU bounding box.
fn generate_tiles(step: f64) -> Vec<(f64, f64)> {
    let mut tiles = Vec::new();
    let mut lat = AU_LAT_MIN;
    while lat < AU_LAT_MAX {
        let mut lon = AU_LON_MIN;
        while lon < AU_LON_MAX {
            tiles.push((lat, lon));
            lon += step;
        }
        lat += step;
    }
    tiles
}

fn tile_key(lat: f64, lon: f64, kind: &str) -> String {
    format!("{:.4}:{:.4}:{kind}", lat, lon)
}

// ── HTTP client ───────────────────────────────────────────────────────────────

fn build_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| Error::Other(e.to_string()))
}

/// Parameters for a single WiGLE tile page fetch.
struct PageRequest<'a> {
    client: &'a Client,
    user: &'a str,
    token: &'a str,
    lat1: f64,
    lat2: f64,
    lon1: f64,
    lon2: f64,
    kind: &'a str,
    search_after: Option<&'a str>,
}

/// Fetch one page of WiGLE results; returns `(networks, search_after)`.
/// Handles 429 with exponential backoff; other non-200 → `Err`.
async fn fetch_page(p: PageRequest<'_>) -> Result<(Vec<WigleNetwork>, Option<String>)> {
    let mut backoff = BACKOFF_BASE_SECS;
    loop {
        let mut req = p
            .client
            .get(WIGLE_BASE)
            .basic_auth(p.user, Some(p.token))
            .query(&[
                ("latrange1", p.lat1.to_string()),
                ("latrange2", p.lat2.to_string()),
                ("longrange1", p.lon1.to_string()),
                ("longrange2", p.lon2.to_string()),
                ("onlymine", "false".to_string()),
                ("freenet", "false".to_string()),
                ("paynet", "false".to_string()),
                ("resultsPerPage", RESULTS_PER_PAGE.to_string()),
                ("type", p.kind.to_string()),
            ]);
        if let Some(cursor) = p.search_after {
            req = req.query(&[("searchAfter", cursor)]);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| Error::Other(format!("WiGLE request error: {e}")))?;

        let status = resp.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let wait = backoff.min(BACKOFF_CAP_SECS);
            eprintln!("[wigle-harvest] 429 — backing off {wait}s");
            sleep(Duration::from_secs(wait)).await;
            backoff = (backoff * 2).min(BACKOFF_CAP_SECS);
            continue;
        }
        if !status.is_success() {
            return Err(Error::Other(format!(
                "WiGLE HTTP {status} for tile lat={lat1}..{lat2} lon={lon1}..{lon2}",
                lat1 = p.lat1,
                lat2 = p.lat2,
                lon1 = p.lon1,
                lon2 = p.lon2,
            )));
        }
        let body: WigleResponse = resp
            .json()
            .await
            .map_err(|e| Error::Other(format!("WiGLE JSON parse error: {e}")))?;
        return Ok((body.results, body.search_after));
    }
}

// ── Main command ──────────────────────────────────────────────────────────────

/// Run `hse wigle-harvest`.
pub async fn cmd_wigle_harvest(args: WigleHarvestArgs) -> Result<()> {
    let WigleHarvestArgs {
        dry_run,
        rate,
        step,
        kinds,
    } = args;

    // Clamp step to a sane minimum to avoid near-infinite loops.
    let step = step.max(0.01);
    let interval_ms = if rate > 0.0 {
        ((1.0 / rate) * 1000.0) as u64
    } else {
        1000
    };

    let tiles = generate_tiles(step);
    let total_tiles = tiles.len();
    let kind_count = kinds.len().max(1);
    let total_work = total_tiles * kind_count;

    eprintln!(
        "[wigle-harvest] AU bounding box: lat {AU_LAT_MIN}..{AU_LAT_MAX}, \
         lon {AU_LON_MIN}..{AU_LON_MAX}, step={step}°"
    );
    eprintln!(
        "[wigle-harvest] tiles={total_tiles}, kinds={}, total={total_work}",
        kinds.join(",")
    );
    eprintln!(
        "[wigle-harvest] estimated rows (worst case): ≤{} at {RESULTS_PER_PAGE}/tile",
        total_work as u64 * RESULTS_PER_PAGE as u64
    );

    if dry_run {
        println!(
            "dry-run: {total_tiles} tiles × {} kind(s) = {total_work} requests (first page each)",
            kinds.len()
        );
        println!(
            "estimated max rows: {}",
            total_work as u64 * RESULTS_PER_PAGE as u64
        );
        return Ok(());
    }

    // Resolve credentials: env vars first, then built-in defaults.
    let user =
        std::env::var("HUNTSMAN_WIGLE_USER").unwrap_or_else(|_| WIGLE_DEFAULT_USER.to_string());
    let token =
        std::env::var("HUNTSMAN_WIGLE_TOKEN").unwrap_or_else(|_| WIGLE_DEFAULT_TOKEN.to_string());

    let db_path = crate::default_db_path();
    let mut conn = open_db(&db_path)?;
    let client = build_client()?;

    let mut work_idx = 0usize;
    for (lat_lo, lon_lo) in &tiles {
        let lat_lo = *lat_lo;
        let lon_lo = *lon_lo;
        let lat_hi = (lat_lo + step).min(AU_LAT_MAX);
        let lon_hi = (lon_lo + step).min(AU_LON_MAX);

        for kind in &kinds {
            work_idx += 1;
            let key = tile_key(lat_lo, lon_lo, kind);

            if tile_done(&conn, &key) {
                eprintln!(
                    "[tile {work_idx}/{total_work}] {lat_lo:.3}/{lon_lo:.3} kind={kind} \
                     — already done, skipping"
                );
                continue;
            }

            let mut pages = 0u32;
            let mut tile_rows = 0u64;
            let mut cursor: Option<String> = None;

            loop {
                // Rate limiting: sleep before every request except the very first.
                if pages > 0 || work_idx > 1 {
                    sleep(Duration::from_millis(interval_ms)).await;
                }

                let result = fetch_page(PageRequest {
                    client: &client,
                    user: &user,
                    token: &token,
                    lat1: lat_lo,
                    lat2: lat_hi,
                    lon1: lon_lo,
                    lon2: lon_hi,
                    kind,
                    search_after: cursor.as_deref(),
                })
                .await;

                match result {
                    Err(e) => {
                        eprintln!(
                            "[tile {work_idx}/{total_work}] {lat_lo:.3}/{lon_lo:.3} kind={kind} \
                             — ERROR: {e}; skipping tile"
                        );
                        break;
                    }
                    Ok((networks, next_cursor)) => {
                        let count = networks.len();
                        pages += 1;

                        let inserted = insert_page(&mut conn, kind, &networks)?;
                        tile_rows += inserted;

                        eprintln!(
                            "[tile {work_idx}/{total_work}] {lat_lo:.3}/{lon_lo:.3} kind={kind} \
                             pages={pages} rows={tile_rows} (+{inserted} this page)"
                        );

                        let is_last = count < RESULTS_PER_PAGE as usize || next_cursor.is_none();
                        cursor = next_cursor;

                        if is_last {
                            break;
                        }
                    }
                }
            }

            // Checkpoint (even if the tile errored, so we don't retry indefinitely).
            mark_tile_done(&conn, &key, tile_rows)?;
        }
    }

    eprintln!("[wigle-harvest] complete.");
    Ok(())
}
