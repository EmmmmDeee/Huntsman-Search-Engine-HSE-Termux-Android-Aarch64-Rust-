//! `hse wigle-import` — import a WiGLE CSV file into the local wigle_au corpus.
//!
//! Accepts WiGLE CSV v1.4 format (the format produced by hse wigle-export
//! and by WiGLE's own export). On duplicate netid, updates position and
//! metadata while preserving first_seen and incrementing harvest_count.

use std::io::{BufRead, BufReader, Read};

use rusqlite::Connection;

use crate::core::error::{Error, Result};

/// Arguments for `hse wigle-import`.
pub struct WigleImportArgs {
    /// Path to WiGLE CSV file to import (use "-" for stdin).
    pub path: String,
    /// Print row count without writing to DB.
    pub dry_run: bool,
}

// ── DB schema (same as wigle_harvest.rs — CREATE TABLE IF NOT EXISTS is safe) ──

const SCHEMA: &str = "
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS wigle_au (
    -- Identity
    netid           TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,
    ssid            TEXT,
    name            TEXT,
    wep             TEXT,
    encryption      TEXT,
    channel         INTEGER,
    altfreq         INTEGER,
    bcninterval     INTEGER,
    freenet         INTEGER,
    paynet          INTEGER,
    dhcp            TEXT,
    qos             INTEGER,
    carrier         TEXT,
    rcois           TEXT,
    router_brands   TEXT,
    -- Position
    lat             REAL NOT NULL,
    lon             REAL NOT NULL,
    posalt          REAL,
    accuracy        REAL,
    -- Timestamps
    first_seen      TEXT,
    last_seen       TEXT,
    last_updated    TEXT,
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
    userfound       INTEGER,
    -- Harvest bookkeeping
    harvested_at    TEXT NOT NULL,
    harvest_count   INTEGER NOT NULL DEFAULT 1
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

// ── Minimal RFC 4180 CSV parser ───────────────────────────────────────────────

/// Parse one CSV line per RFC 4180.
///
/// Handles fields wrapped in `"..."` with `""` for embedded double-quotes.
/// Returns a `Vec<String>` of the unquoted field values.
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut chars = line.chars().peekable();

    loop {
        // Start of a field.
        if chars.peek() == Some(&'"') {
            // Quoted field.
            chars.next(); // consume opening quote
            let mut field = String::new();
            loop {
                match chars.next() {
                    None => break,
                    Some('"') => {
                        if chars.peek() == Some(&'"') {
                            // Escaped double-quote.
                            chars.next();
                            field.push('"');
                        } else {
                            // Closing quote.
                            break;
                        }
                    }
                    Some(c) => field.push(c),
                }
            }
            fields.push(field);
            // Consume separator or end.
            match chars.next() {
                Some(',') => {}
                _ => break,
            }
        } else {
            // Unquoted field — read until comma or end.
            let mut field = String::new();
            loop {
                match chars.peek() {
                    None | Some(&',') => break,
                    _ => field.push(chars.next().unwrap()),
                }
            }
            fields.push(field);
            match chars.next() {
                Some(',') => {}
                _ => break,
            }
        }
    }

    fields
}

// ── AuthMode → encryption label ───────────────────────────────────────────────

/// Parse WiGLE `AuthMode` bracket notation into a simple encryption label.
///
/// Examples: `[WPA2-PSK-CCMP][ESS]` → `"WPA2"`, `[ESS]` → `"None"`.
fn parse_auth_mode(auth: &str) -> String {
    if auth.contains("WPA3") {
        "WPA3".to_string()
    } else if auth.contains("WPA2") {
        "WPA2".to_string()
    } else if auth.contains("WPA") {
        "WPA".to_string()
    } else if auth.contains("WEP") {
        "WEP".to_string()
    } else {
        "None".to_string()
    }
}

// ── Timestamp conversion ──────────────────────────────────────────────────────

/// Convert `YYYY-MM-DD HH:MM:SS` → `YYYY-MM-DDTHH:MM:SSZ`.
fn wigle_ts_to_iso(ts: &str) -> String {
    let t = ts.trim();
    if t.len() == 19 && t.chars().nth(10) == Some(' ') {
        format!("{}T{}Z", &t[..10], &t[11..])
    } else {
        t.to_string()
    }
}

// ── Type mapping ──────────────────────────────────────────────────────────────

fn csv_type_to_kind(t: &str) -> &str {
    match t.trim().to_ascii_uppercase().as_str() {
        "WIFI" => "wifi",
        "CELL" => "cell",
        "BT" | "BLUETOOTH" => "bluetooth",
        "WIMAX" => "wimax",
        _ => "wifi",
    }
}

// ── Main command ──────────────────────────────────────────────────────────────

pub fn cmd_wigle_import(args: WigleImportArgs) -> Result<()> {
    // Read all input into a string so we can handle both file and stdin.
    let raw: String = if args.path == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| Error::Other(format!("stdin read: {e}")))?;
        buf
    } else {
        std::fs::read_to_string(&args.path)
            .map_err(|e| Error::Other(format!("read {}: {e}", args.path)))?
    };

    let reader = BufReader::new(raw.as_bytes());
    let mut lines = reader.lines();

    // Line 1: WiGLE metadata header — skip.
    lines
        .next()
        .ok_or_else(|| Error::Other("empty file".to_string()))?
        .map_err(|e| Error::Other(e.to_string()))?;

    // Line 2: column headers.
    let header_line = lines
        .next()
        .ok_or_else(|| Error::Other("missing column header line".to_string()))?
        .map_err(|e| Error::Other(e.to_string()))?;
    let header_fields = parse_csv_line(&header_line);

    // Build column index map.
    let col: std::collections::HashMap<&str, usize> = header_fields
        .iter()
        .enumerate()
        .map(|(i, name)| (name.as_str(), i))
        .collect();

    macro_rules! get_col {
        ($name:expr) => {
            col.get($name)
                .copied()
                .ok_or_else(|| Error::Other(format!("missing column: {}", $name)))
        };
    }

    let idx_mac = get_col!("MAC")?;
    let idx_ssid = get_col!("SSID")?;
    let idx_auth = get_col!("AuthMode")?;
    let idx_first = get_col!("FirstSeen")?;
    let idx_channel = get_col!("Channel")?;
    let idx_lat = get_col!("CurrentLatitude")?;
    let idx_lon = get_col!("CurrentLongitude")?;
    let idx_alt = get_col!("AltitudeMeters")?;
    let idx_acc = get_col!("AccuracyMeters")?;
    let idx_type = get_col!("Type")?;

    // Parse all data rows first.
    struct Row {
        netid: String,
        ssid: String,
        encryption: String,
        first_seen: String,
        channel: Option<i64>,
        lat: f64,
        lon: f64,
        posalt: Option<f64>,
        accuracy: Option<f64>,
        kind: String,
    }

    let mut rows: Vec<Row> = Vec::new();
    for line_res in lines {
        let line = line_res.map_err(|e| Error::Other(e.to_string()))?;
        let line = line.trim_end_matches('\r').to_string();
        if line.is_empty() {
            continue;
        }
        let fields = parse_csv_line(&line);
        if fields.len() <= idx_type {
            continue;
        }

        let get = |i: usize| fields.get(i).map(|s| s.as_str()).unwrap_or("");

        let netid = get(idx_mac).to_string();
        if netid.is_empty() {
            continue;
        }

        let lat: f64 = get(idx_lat).parse().unwrap_or(0.0);
        let lon: f64 = get(idx_lon).parse().unwrap_or(0.0);

        rows.push(Row {
            netid,
            ssid: get(idx_ssid).to_string(),
            encryption: parse_auth_mode(get(idx_auth)),
            first_seen: wigle_ts_to_iso(get(idx_first)),
            channel: get(idx_channel).parse::<i64>().ok(),
            lat,
            lon,
            posalt: get(idx_alt).parse::<f64>().ok(),
            accuracy: get(idx_acc).parse::<f64>().ok(),
            kind: csv_type_to_kind(get(idx_type)).to_string(),
        });
    }

    if args.dry_run {
        println!("dry-run: {} rows parsed (not written)", rows.len());
        return Ok(());
    }

    let db_path = crate::default_db_path();
    let conn = open_db(&db_path)?;

    let now = chrono_now();
    let mut upserted: usize = 0;

    for row in &rows {
        conn.execute(
            "INSERT INTO wigle_au (
                netid, kind, ssid, encryption, channel, lat, lon, posalt, accuracy,
                first_seen, last_seen, country, harvested_at, harvest_count
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, 'AU', ?11, 1)
            ON CONFLICT(netid) DO UPDATE SET
                kind          = excluded.kind,
                ssid          = excluded.ssid,
                encryption    = excluded.encryption,
                channel       = excluded.channel,
                lat           = excluded.lat,
                lon           = excluded.lon,
                posalt        = excluded.posalt,
                accuracy      = excluded.accuracy,
                last_seen     = excluded.last_seen,
                harvested_at  = excluded.harvested_at,
                harvest_count = harvest_count + 1",
            rusqlite::params![
                row.netid,
                row.kind,
                if row.ssid.is_empty() {
                    None
                } else {
                    Some(row.ssid.as_str())
                },
                row.encryption,
                row.channel,
                row.lat,
                row.lon,
                row.posalt,
                row.accuracy,
                if row.first_seen.is_empty() {
                    None
                } else {
                    Some(row.first_seen.as_str())
                },
                now,
            ],
        )
        .map_err(|e| Error::Other(format!("upsert {}: {e}", row.netid)))?;
        upserted += 1;
    }

    println!("wigle-import: {} rows upserted into wigle_au", upserted);
    Ok(())
}

fn chrono_now() -> String {
    // Produce a UTC ISO-8601 timestamp without pulling in chrono.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    epoch_to_stix_ts(secs)
}

/// Convert unix epoch seconds to an ISO-8601 UTC timestamp string.
/// Duplicated from `export::renderers` (private module) to keep wigle_import self-contained.
fn epoch_to_stix_ts(epoch: u64) -> String {
    let secs_per_min: u64 = 60;
    let secs_per_hour: u64 = 3600;
    let secs_per_day: u64 = 86400;

    let days = epoch / secs_per_day;
    let rem = epoch % secs_per_day;
    let hh = rem / secs_per_hour;
    let mm = (rem % secs_per_hour) / secs_per_min;
    let ss = rem % secs_per_min;

    let z: i64 = days as i64 + 719468;
    let era: i64 = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe: i64 = z - era * 146097;
    let yoe: i64 = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y: i64 = yoe + era * 400;
    let doy: i64 = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp: i64 = (5 * doy + 2) / 153;
    let d: i64 = doy - (153 * mp + 2) / 5 + 1;
    let m: i64 = mp + if mp < 10 { 3 } else { -9 };
    let y: i64 = y + if m <= 2 { 1 } else { 0 };

    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}
