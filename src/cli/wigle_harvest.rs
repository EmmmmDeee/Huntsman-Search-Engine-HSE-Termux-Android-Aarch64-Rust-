//! `hse wigle-harvest` — resumable bulk WiGLE downloader for Australia.
//!
//! Tiles the Australian bounding box (lat −44 → −10, lon 113 → 154) in
//! configurable degree steps, pages the WiGLE `/api/v2/network/search`
//! endpoint with cursor-based pagination, and bulk-inserts results into a
//! local SQLite table `wigle_au`. Every field returned by the WiGLE API is
//! stored — nothing is discarded. Completed tiles are checkpointed in
//! `wigle_harvest_tiles` so interrupted runs resume from the last completed
//! tile. On re-encounter, existing rows are updated with the latest position
//! and metadata while `first_seen` is preserved.

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

/// Full WiGLE network record — every field the API returns is captured.
#[derive(Deserialize, Debug)]
struct WigleNetwork {
    /// BSSID (Wi-Fi), cell ID string, or Bluetooth MAC.
    netid: String,
    /// Human-readable network name (SSID for Wi-Fi, cell name for towers).
    ssid: Option<String>,
    /// Best-estimate latitude from WiGLE trilat.
    trilat: f64,
    /// Best-estimate longitude from WiGLE trilat.
    trilong: f64,
    /// Horizontal accuracy of the trilat estimate (metres).
    accuracy: Option<f64>,
    /// ISO-8601 timestamp of last sighting in WiGLE's database.
    lastupdt: Option<String>,
    /// First time ever seen in WiGLE's database.
    firsttime: Option<String>,
    /// Last time a contributor submitted an observation.
    lasttime: Option<String>,
    /// Wi-Fi channel (1–14 for 2.4 GHz, 36–165 for 5 GHz).
    channel: Option<i64>,
    /// WiGLE encryption label: "WEP", "WPA", "WPA2", "WPA3", "Unknown", "None".
    encryption: Option<String>,
    /// Country code stored by WiGLE.
    country: Option<String>,
    /// State / region / territory.
    region: Option<String>,
    /// City name from reverse-geocoding.
    city: Option<String>,
    /// Road / street name.
    road: Option<String>,
    /// House / building number.
    housenumber: Option<String>,
    /// Postal code.
    postalcode: Option<String>,
    /// Altitude of best position fix (metres, ellipsoid height).
    posalt: Option<f64>,
    /// Beacon interval (ms, Wi-Fi only).
    bcninterval: Option<i64>,
    /// Whether DHCP was detected on the network.
    dhcp: Option<String>,
    /// Whether WiGLE classifies this as a free/open community network.
    freenet: Option<bool>,
    /// Whether WiGLE classifies this as a pay/captive-portal network.
    paynet: Option<bool>,
    /// Whether the submitting user found the network (vs. pre-existing).
    userfound: Option<bool>,
    /// Original network type tag from submitter.
    otype: Option<String>,
    /// Alternate frequency (MHz, Wi-Fi 5/6 dual-band APs).
    altfreq: Option<i64>,
    /// Quality-of-service class (WiGLE internal).
    qos: Option<i64>,
    /// Mobile carrier name (for cell tower records).
    carrier: Option<String>,
    /// Network name / carrier alias.
    name: Option<String>,
    /// Raw WEP flag (pre-encryption field, legacy).
    wep: Option<String>,
    /// Robust security network / PMF capabilities (OUI-level, where available).
    rcois: Option<String>,
    /// Router vendor string if detected.
    #[serde(rename = "routerbrands")]
    router_brands: Option<String>,
    /// Attribution tag (e.g., import batch label).
    attribution: Option<String>,
    /// GPS device identifier that captured the best fix.
    gpsid: Option<String>,
    /// WiGLE internal transaction ID for the best contributing observation.
    transid: Option<String>,
}

// ── DB schema ─────────────────────────────────────────────────────────────────

const SCHEMA: &str = "
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS wigle_au (
    -- Identity
    netid           TEXT PRIMARY KEY,    -- BSSID / cell-id / BT MAC
    kind            TEXT NOT NULL,       -- 'wifi' | 'cell' | 'bluetooth' | 'wimax'
    ssid            TEXT,
    name            TEXT,                -- cell name / AP friendly name
    wep             TEXT,                -- legacy WEP flag
    encryption      TEXT,                -- 'WEP'|'WPA'|'WPA2'|'WPA3'|'None'|'Unknown'
    channel         INTEGER,
    altfreq         INTEGER,             -- secondary frequency MHz (dual-band)
    bcninterval     INTEGER,             -- beacon interval ms
    freenet         INTEGER,             -- 0/1
    paynet          INTEGER,             -- 0/1
    dhcp            TEXT,
    qos             INTEGER,
    carrier         TEXT,                -- mobile carrier (cell records)
    rcois           TEXT,                -- RSN/OUI capability string
    router_brands   TEXT,
    -- Position
    lat             REAL NOT NULL,
    lon             REAL NOT NULL,
    posalt          REAL,
    accuracy        REAL,                -- metres
    -- Timestamps (all ISO-8601 strings as WiGLE sends them)
    first_seen      TEXT,                -- firsttime from WiGLE; never overwritten
    last_seen       TEXT,                -- lasttime from WiGLE
    last_updated    TEXT,                -- lastupdt from WiGLE (record change)
    -- Reverse-geocoded address components
    country         TEXT DEFAULT 'AU',
    region          TEXT,
    city            TEXT,
    road            TEXT,
    housenumber     TEXT,
    postalcode      TEXT,
    -- WiGLE provenance
    otype           TEXT,
    transid         TEXT,
    attribution     TEXT,
    gpsid           TEXT,
    userfound       INTEGER,             -- 0/1
    -- Harvest bookkeeping
    harvested_at    TEXT NOT NULL,       -- when we wrote this row (UTC ISO-8601)
    harvest_count   INTEGER NOT NULL DEFAULT 1  -- times re-observed across harvests
);

CREATE INDEX IF NOT EXISTS wigle_au_geo      ON wigle_au (lat, lon);
CREATE INDEX IF NOT EXISTS wigle_au_ssid     ON wigle_au (ssid);
CREATE INDEX IF NOT EXISTS wigle_au_region   ON wigle_au (region, city);
CREATE INDEX IF NOT EXISTS wigle_au_kind     ON wigle_au (kind);
CREATE INDEX IF NOT EXISTS wigle_au_postal   ON wigle_au (postalcode);

CREATE TABLE IF NOT EXISTS wigle_harvest_tiles (
    tile_key        TEXT PRIMARY KEY,
    rows_upserted   INTEGER NOT NULL DEFAULT 0,
    completed_at    TEXT NOT NULL
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
        "INSERT OR REPLACE INTO wigle_harvest_tiles (tile_key, rows_upserted, completed_at) \
         VALUES (?1, ?2, ?3)",
        rusqlite::params![tile_key, rows as i64, now],
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    Ok(())
}

/// Upsert a page of networks. Existing rows keep their `first_seen` and have
/// `harvest_count` incremented; position and all metadata are updated from
/// the freshest WiGLE data.
fn upsert_page(conn: &mut Connection, kind: &str, networks: &[WigleNetwork]) -> Result<u64> {
    let now = chrono_now();
    let tx = conn
        .transaction()
        .map_err(|e| Error::Other(e.to_string()))?;

    let mut stmt = tx
        .prepare_cached(
            "INSERT INTO wigle_au (
                netid, kind, ssid, name, wep, encryption, channel, altfreq, bcninterval,
                freenet, paynet, dhcp, qos, carrier, rcois, router_brands,
                lat, lon, posalt, accuracy,
                first_seen, last_seen, last_updated,
                country, region, city, road, housenumber, postalcode,
                otype, transid, attribution, gpsid, userfound,
                harvested_at, harvest_count
            ) VALUES (
                ?1,?2,?3,?4,?5,?6,?7,?8,?9,
                ?10,?11,?12,?13,?14,?15,?16,
                ?17,?18,?19,?20,
                ?21,?22,?23,
                ?24,?25,?26,?27,?28,?29,
                ?30,?31,?32,?33,?34,
                ?35, 1
            )
            ON CONFLICT(netid) DO UPDATE SET
                ssid          = excluded.ssid,
                name          = excluded.name,
                wep           = excluded.wep,
                encryption    = excluded.encryption,
                channel       = excluded.channel,
                altfreq       = excluded.altfreq,
                bcninterval   = excluded.bcninterval,
                freenet       = excluded.freenet,
                paynet        = excluded.paynet,
                dhcp          = excluded.dhcp,
                qos           = excluded.qos,
                carrier       = excluded.carrier,
                rcois         = excluded.rcois,
                router_brands = excluded.router_brands,
                lat           = excluded.lat,
                lon           = excluded.lon,
                posalt        = excluded.posalt,
                accuracy      = excluded.accuracy,
                first_seen    = COALESCE(wigle_au.first_seen, excluded.first_seen),
                last_seen     = excluded.last_seen,
                last_updated  = excluded.last_updated,
                country       = excluded.country,
                region        = excluded.region,
                city          = excluded.city,
                road          = excluded.road,
                housenumber   = excluded.housenumber,
                postalcode    = excluded.postalcode,
                otype         = excluded.otype,
                transid       = excluded.transid,
                attribution   = excluded.attribution,
                gpsid         = excluded.gpsid,
                userfound     = excluded.userfound,
                harvested_at  = excluded.harvested_at,
                harvest_count = wigle_au.harvest_count + 1",
        )
        .map_err(|e| Error::Other(e.to_string()))?;

    let mut affected = 0u64;
    for n in networks {
        let rows = stmt
            .execute(rusqlite::params![
                n.netid,
                kind,
                n.ssid,
                n.name,
                n.wep,
                n.encryption,
                n.channel,
                n.altfreq,
                n.bcninterval,
                n.freenet.map(|b| b as i64),
                n.paynet.map(|b| b as i64),
                n.dhcp,
                n.qos,
                n.carrier,
                n.rcois,
                n.router_brands,
                n.trilat,
                n.trilong,
                n.posalt,
                n.accuracy,
                n.firsttime,
                n.lasttime,
                n.lastupdt,
                n.country.as_deref().unwrap_or("AU"),
                n.region,
                n.city,
                n.road,
                n.housenumber,
                n.postalcode,
                n.otype,
                n.transid,
                n.attribution,
                n.gpsid,
                n.userfound.map(|b| b as i64),
                now,
            ])
            .map_err(|e| Error::Other(e.to_string()))?;
        affected += rows as u64;
    }
    drop(stmt);
    tx.commit().map_err(|e| Error::Other(e.to_string()))?;
    Ok(affected)
}

fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (y, mo, d, h, mi, s) = epoch_to_ymd_hms(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

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

/// Fetch one page; returns `(networks, search_after)`.
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

                        let upserted = upsert_page(&mut conn, kind, &networks)?;
                        tile_rows += upserted;

                        eprintln!(
                            "[tile {work_idx}/{total_work}] {lat_lo:.3}/{lon_lo:.3} kind={kind} \
                             pages={pages} rows={tile_rows} (+{upserted} this page)"
                        );

                        let is_last = count < RESULTS_PER_PAGE as usize || next_cursor.is_none();
                        cursor = next_cursor;

                        if is_last {
                            break;
                        }
                    }
                }
            }

            mark_tile_done(&conn, &key, tile_rows)?;
        }
    }

    eprintln!("[wigle-harvest] complete.");
    Ok(())
}
