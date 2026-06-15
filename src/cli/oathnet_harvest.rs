//! `hse oathnet-harvest` — bulk-pull all Australian OathNet breach & stealer
//! records into a local SQLite cache for offline-first lookups.
//!
//! Strategy (two complementary sweeps):
//!
//! 1. **Domain-anchored** — queries `domain:` for every known Australian
//!    ISP / freemail domain.  Captures any `@au-domain` address regardless
//!    of username.
//!
//! 2. **Phone-prefix** — Australian mobile prefixes `04xx` subdivided to
//!    four-digit level (`0400`–`0499`), plus `+614xx` E.164 forms and
//!    the eight two-digit landline area codes.
//!
//! Each page is bulk-inserted into `oathnet_au_cache`.  A checkpoint table
//! lets interrupted runs resume without re-querying completed items.

use std::collections::HashSet;
use std::time::Duration;

use rusqlite::{Connection, params};
use serde_json::Value;
use tokio::time::sleep;

use crate::core::error::{Error, Result};
use crate::util::oathnet::paths;

const SRC: &str = "oathnet_harvest";

/// AU-specific domains to sweep, ordered from high-signal to freemail.
static AU_DOMAINS: &[&str] = &[
    // ISP / telco
    "bigpond.com",
    "bigpond.net.au",
    "optusnet.com.au",
    "iinet.net.au",
    "westnet.com.au",
    "internode.on.net",
    "aapt.net.au",
    "dodo.com.au",
    "tpg.com.au",
    "adam.com.au",
    "exetel.com.au",
    "spin.net.au",
    "bordernet.com.au",
    "chariot.net.au",
    "eftel.com.au",
    // Common .au TLD patterns
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "gov.au",
    "id.au",
    "asn.au",
    "csiro.au",
    // AU freemail
    "icloud.com",
    "me.com",
    "mac.com",
    // Global freemail commonly used in AU (lowest priority)
    "gmail.com",
    "hotmail.com",
    "outlook.com",
    "yahoo.com",
    "live.com",
];

const FREEMAIL_START: usize = 18; // index of "icloud.com" — everything from here is freemail

/// Australian phone query prefixes for the phone-prefix sweep.
fn au_phone_queries() -> Vec<String> {
    let mut out = Vec::with_capacity(204);
    for suffix in 0u32..=99 {
        out.push(format!("04{suffix:02}"));
        out.push(format!("+614{suffix:02}"));
    }
    for code in ["02", "03", "07", "08"] {
        out.push(code.to_string());
    }
    out
}

pub struct OathnetHarvestArgs {
    pub dry_run: bool,
    pub no_freemail: bool,
    pub phones: bool,
    pub max_queries: usize,
    pub page_size: u32,
    pub surfaces: Vec<String>,
}

pub async fn cmd_oathnet_harvest(args: OathnetHarvestArgs) -> Result<()> {
    let key = std::env::var("HUNTSMAN_OATHNET_KEY")
        .ok()
        .filter(|k| !k.is_empty())
        .ok_or_else(|| {
            Error::Other(
                "HUNTSMAN_OATHNET_KEY is not set. \
                 Register at https://oathnet.com to obtain a key, \
                 then run: hse set-key HUNTSMAN_OATHNET_KEY <your-key>"
                    .into(),
            )
        })?;

    let surface_paths: Vec<&'static str> = args
        .surfaces
        .iter()
        .map(|s| match s.as_str() {
            "stealer" => paths::STEALER,
            _ => paths::BREACH,
        })
        .collect();

    let domain_list: &[&str] = if args.no_freemail {
        &AU_DOMAINS[..FREEMAIL_START]
    } else {
        AU_DOMAINS
    };

    let mut queries: Vec<(&str, String)> = domain_list
        .iter()
        .map(|d| ("domain", d.to_string()))
        .collect();

    if args.phones {
        for ph in au_phone_queries() {
            queries.push(("phone", ph));
        }
    }

    if args.max_queries > 0 {
        queries.truncate(args.max_queries);
    }

    let total_calls = queries.len() * surface_paths.len();
    eprintln!(
        "[{SRC}] Plan: {} queries × {} surface(s) = {} API calls{}",
        queries.len(),
        surface_paths.len(),
        total_calls,
        if args.dry_run { " (DRY RUN)" } else { "" },
    );

    if args.dry_run {
        for (field, val) in queries.iter().take(10) {
            eprintln!("  {field}:{val}");
        }
        if queries.len() > 10 {
            eprintln!("  … and {} more", queries.len() - 10);
        }
        return Ok(());
    }

    let db_path = crate::default_db_path();
    let mut conn = Connection::open(&db_path)
        .map_err(|e| Error::Other(format!("cannot open DB at {db_path:?}: {e}")))?;

    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         CREATE TABLE IF NOT EXISTS oathnet_au_cache (
             id           TEXT PRIMARY KEY,
             field        TEXT NOT NULL,
             query_value  TEXT NOT NULL,
             surface      TEXT NOT NULL,
             record_json  TEXT NOT NULL,
             indexed_at   TEXT,
             inserted_at  TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS oathnet_au_field  ON oathnet_au_cache (field, query_value);
         CREATE INDEX IF NOT EXISTS oathnet_au_source ON oathnet_au_cache (surface);
         CREATE TABLE IF NOT EXISTS oathnet_harvest_progress (
             checkpoint_key TEXT PRIMARY KEY,
             rows_inserted  INTEGER NOT NULL DEFAULT 0,
             completed_at   TEXT NOT NULL
         );",
    )
    .map_err(|e| Error::Other(format!("DB schema: {e}")))?;

    // Load completed checkpoints so we can resume.
    let mut done: HashSet<String> = {
        let mut stmt = conn
            .prepare("SELECT checkpoint_key FROM oathnet_harvest_progress")
            .map_err(|e| Error::Other(e.to_string()))?;
        stmt.query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| Error::Other(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect()
    };
    eprintln!("[{SRC}] {} checkpoints already done, resuming", done.len());

    let mut call_index = done.len();
    let mut total_inserted: u64 = 0;

    'outer: for (field, value) in &queries {
        for surface in &surface_paths {
            let ck = format!("{surface}:{field}:{value}");
            if done.contains(&ck) {
                continue;
            }

            call_index += 1;
            eprint!("[{SRC}] [{call_index}/{total_calls}] {field}:{value} … ");

            match fetch_page(&key, surface, field, value, args.page_size).await {
                Err(e) if e.to_string().contains("quota") => {
                    eprintln!("\nQuota exhausted — stopping harvest. Re-run tomorrow.");
                    break 'outer;
                }
                Err(e) => {
                    eprintln!("WARN: {e} (skipping)");
                }
                Ok(records) => {
                    let n = records.len();
                    let inserted = insert_batch(&mut conn, &records, field, value, surface)
                        .unwrap_or_else(|e| {
                            eprintln!("insert error: {e}");
                            0
                        });
                    total_inserted += inserted;
                    eprintln!("{n} records, {inserted} new");

                    let now = simple_now();
                    conn.execute(
                        "INSERT OR REPLACE INTO oathnet_harvest_progress \
                         (checkpoint_key, rows_inserted, completed_at) VALUES (?1,?2,?3)",
                        params![ck, inserted as i64, now],
                    )
                    .ok();
                    done.insert(ck);
                }
            }

            sleep(Duration::from_millis(1100)).await;
        }
    }

    eprintln!("[{SRC}] Complete. Total new rows: {total_inserted}");
    Ok(())
}

async fn fetch_page(
    key: &str,
    surface: &str,
    field: &str,
    value: &str,
    page_size: u32,
) -> Result<Vec<Value>> {
    let base = std::env::var("HUNTSMAN_OATHNET_BASE")
        .unwrap_or_else(|_| "https://api.oathnet.com".to_string());
    let encoded = crate::util::http::urlencode(value);
    let url = format!(
        "{base}{surface}?{field}%5B%5D={encoded}&page_size={page_size}&sort=indexed_at:desc"
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| Error::Other(e.to_string()))?;

    let mut backoff = 2u64;
    for attempt in 0u8..4 {
        let resp = client
            .get(&url)
            .header("Authorization", format!("Bearer {key}"))
            .header("Accept", "application/json")
            .send()
            .await;

        match resp {
            Err(e) if attempt < 3 => {
                eprintln!("\n  [retry {attempt}] network: {e}");
                sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(120);
                continue;
            }
            Err(e) => return Err(Error::Other(e.to_string())),
            Ok(r) if r.status().as_u16() == 429 => {
                eprintln!("\n  [429] rate-limited, waiting {backoff}s");
                sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(120);
                continue;
            }
            Ok(r) if matches!(r.status().as_u16(), 402 | 403) => {
                return Err(Error::Other("OathNet quota exhausted or forbidden".into()));
            }
            Ok(r) if !r.status().is_success() => {
                return Err(Error::Other(format!("OathNet HTTP {}", r.status())));
            }
            Ok(r) => {
                let body = r.text().await.map_err(|e| Error::Other(e.to_string()))?;
                if body.contains("\"left_today\":0")
                    || body.contains("quota exceeded")
                    || body.contains("Daily quota exceeded")
                {
                    return Err(Error::Other("quota".into()));
                }
                let parsed: Value =
                    serde_json::from_str(&body).map_err(|e| Error::Other(e.to_string()))?;
                let records = parsed
                    .pointer("/data/items")
                    .or_else(|| parsed.pointer("/data"))
                    .or_else(|| parsed.pointer("/items"))
                    .or_else(|| parsed.pointer("/results"))
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                return Ok(records);
            }
        }
    }
    Err(Error::Other("OathNet fetch failed after 4 attempts".into()))
}

fn insert_batch(
    conn: &mut Connection,
    records: &[Value],
    field: &str,
    query_value: &str,
    surface: &str,
) -> Result<u64> {
    let now = simple_now();
    let tx = conn
        .transaction()
        .map_err(|e| Error::Other(e.to_string()))?;
    let mut inserted = 0u64;
    for rec in records {
        let id = rec
            .pointer("/id")
            .or_else(|| rec.pointer("/_id"))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| {
                // Deterministic synthetic ID from content hash.
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut h = DefaultHasher::new();
                rec.to_string().hash(&mut h);
                format!("anon-{field}-{:016x}", h.finish())
            });

        let indexed_at = rec
            .pointer("/indexed_at")
            .or_else(|| rec.pointer("/created_at"))
            .and_then(|v| v.as_str())
            .map(str::to_owned);

        let n = tx
            .execute(
                "INSERT OR IGNORE INTO oathnet_au_cache \
                 (id, field, query_value, surface, record_json, indexed_at, inserted_at) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    id,
                    field,
                    query_value,
                    surface,
                    rec.to_string(),
                    indexed_at,
                    now
                ],
            )
            .map_err(|e| Error::Other(e.to_string()))?;
        inserted += n as u64;
    }
    tx.commit().map_err(|e| Error::Other(e.to_string()))?;
    Ok(inserted)
}

/// Minimal RFC-3339 UTC timestamp without pulling in chrono.
fn simple_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let sec = secs % 60;
    let min = (secs / 60) % 60;
    let hour = (secs / 3600) % 24;
    let days = secs / 86400;
    let (y, mo, d) = epoch_days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

fn epoch_days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let n = if is_leap_year(year) { 366 } else { 365 };
        if days < n {
            break;
        }
        days -= n;
        year += 1;
    }
    let months: [u64; 12] = [
        31,
        if is_leap_year(year) { 29 } else { 28 },
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

fn is_leap_year(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}
