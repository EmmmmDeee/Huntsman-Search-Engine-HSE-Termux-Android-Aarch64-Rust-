//! `hse seeknow-harvest` — pull Australian Seek-Search EU (SeekNow) profiles
//! into a local SQLite cache using ABN-anchored and postcode-anchored sweeps.
//!
//! Two complementary strategies:
//!
//! 1. **ABN-anchored** (`--abn`): queries each ABN/ACN-registered entity name
//!    from a seed list of common Australian registered business names.  The
//!    ASIC bulk export is the ideal seed source; here we use the most common
//!    patterns as a starter set that can be extended via `--seed-file`.
//!
//! 2. **Postcode-anchored** (`--postcodes`): submits each Australian postcode
//!    as a location query with a 10 km radius, paging all results.  Captures
//!    individuals not tied to a registered entity.
//!
//! Linked-entity enrichment (`--depth N`, default 1): each returned profile's
//! employer domain feeds back into the query queue (subject to depth cap and a
//! novelty gate — already-seen values are skipped).
//!
//! Results are stored in `seeknow_au_cache` in the main huntsman DB.

use std::collections::{HashSet, VecDeque};
use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, params};
use serde_json::Value;
use tokio::time::sleep;

use crate::core::error::{Error, Result};

const SRC: &str = "seeknow_harvest";

/// Well-known Australian postcodes covering major population centres.
/// A full list should come from `src/util/postcode_au`; this is the
/// seed set for the harvest starter.
static AU_POSTCODES_SAMPLE: &[&str] = &[
    // Sydney metro
    "2000", "2010", "2020", "2030", "2060", "2100", "2150", "2200", // Melbourne metro
    "3000", "3040", "3121", "3150", "3175", "3200", // Brisbane metro
    "4000", "4051", "4101", "4152", "4178", // Perth metro
    "6000", "6005", "6050", "6100", "6150", // Adelaide metro
    "5000", "5033", "5067", "5107", // Canberra
    "2600", "2601", "2602", "2612", // Darwin
    "0800", "0810", // Hobart
    "7000", "7005", // Gold Coast / Sunshine Coast
    "4215", "4217", "4556", "4575", // Newcastle / Wollongong
    "2300", "2302", "2500", "2502",
];

pub struct SeeknowHarvestArgs {
    pub dry_run: bool,
    pub abn: bool,
    pub postcodes: bool,
    pub depth: u32,
    pub max_queries: usize,
    pub seed_file: Option<String>,
}

pub async fn cmd_seeknow_harvest(args: SeeknowHarvestArgs) -> Result<()> {
    let key = std::env::var("HUNTSMAN_SEEKNOW_KEY")
        .ok()
        .filter(|k| !k.is_empty())
        .ok_or_else(|| {
            Error::Other(
                "HUNTSMAN_SEEKNOW_KEY is not set. \
                 Obtain a key from your Seek-Search EU account, \
                 then run: hse set-key HUNTSMAN_SEEKNOW_KEY <your-key>"
                    .into(),
            )
        })?;

    let base = std::env::var("HUNTSMAN_SEEKNOW_BASE")
        .unwrap_or_else(|_| "https://api.seeknow.com".to_string());

    // Build initial query queue.
    let mut queue: VecDeque<(String, String, u32)> = VecDeque::new(); // (field, value, depth)

    if args.postcodes {
        // Load postcodes from the embedded sample; a --seed-file overrides.
        let postcodes: Vec<String> = if let Some(ref path) = args.seed_file {
            load_lines(path)?
        } else {
            AU_POSTCODES_SAMPLE.iter().map(|s| s.to_string()).collect()
        };
        for pc in postcodes {
            queue.push_back(("postcode".to_string(), pc, 0));
        }
    }

    if args.abn {
        // Seed with common AU company suffixes — real harvesting would read the
        // ASIC bulk export. This set provides a useful starter corpus.
        let abn_seeds: &[&str] = &[
            "Pty Ltd",
            "Pty. Ltd.",
            "Limited",
            "Ltd",
            "Trust",
            "Investments",
            "Holdings",
            "Group",
            "Services",
            "Solutions",
            "Consulting",
            "Construction",
            "Engineering",
            "Technologies",
            "Industries",
        ];
        for seed in abn_seeds {
            queue.push_back(("organisation".to_string(), seed.to_string(), 0));
        }
    }

    if queue.is_empty() {
        eprintln!("[{SRC}] No queries scheduled. Use --postcodes and/or --abn.");
        return Ok(());
    }

    let total_hint = queue.len();
    eprintln!(
        "[{SRC}] Plan: ~{} initial queries (depth≤{}){}",
        total_hint,
        args.depth,
        if args.dry_run { " (DRY RUN)" } else { "" },
    );

    if args.dry_run {
        for (field, val, _) in queue.iter().take(10) {
            eprintln!("  {field}:{val}");
        }
        return Ok(());
    }

    let db_path = crate::default_db_path();
    let mut conn = Connection::open(&db_path)
        .map_err(|e| Error::Other(format!("cannot open DB at {db_path:?}: {e}")))?;

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
    .map_err(|e| Error::Other(format!("DB schema: {e}")))?;

    let mut done: HashSet<String> = {
        let mut stmt = conn
            .prepare("SELECT checkpoint_key FROM seeknow_harvest_progress")
            .map_err(|e| Error::Other(e.to_string()))?;
        stmt.query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| Error::Other(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect()
    };

    let mut seen_values: HashSet<String> = done.iter().cloned().collect();
    let mut total_inserted: u64 = 0;
    let mut call_count = 0usize;

    while let Some((field, value, depth)) = queue.pop_front() {
        if args.max_queries > 0 && call_count >= args.max_queries {
            break;
        }

        let ck = format!("{field}:{value}");
        if done.contains(&ck) {
            continue;
        }

        call_count += 1;
        eprint!("[{SRC}] [{call_count}] {field}:{value} (depth {depth}) … ");

        match fetch_seeknow_page(&key, &base, &field, &value).await {
            Err(e) => {
                eprintln!("WARN: {e}");
            }
            Ok(records) => {
                let n = records.len();

                // Linked-entity enrichment: extract employer domains from profiles.
                if depth < args.depth {
                    for rec in &records {
                        if let Some(domain) = extract_employer_domain(rec) {
                            let new_ck = format!("domain:{domain}");
                            if seen_values.insert(new_ck.clone()) {
                                queue.push_back(("domain".to_string(), domain, depth + 1));
                            }
                        }
                    }
                }

                let inserted = insert_seeknow_batch(&mut conn, &records, &field, &value)
                    .unwrap_or_else(|e| {
                        eprintln!("insert error: {e}");
                        0
                    });
                total_inserted += inserted;
                eprintln!("{n} records, {inserted} new");

                let now = simple_now();
                conn.execute(
                    "INSERT OR REPLACE INTO seeknow_harvest_progress \
                     (checkpoint_key, rows_inserted, completed_at) VALUES (?1,?2,?3)",
                    params![ck, inserted as i64, now],
                )
                .ok();
                done.insert(ck);
            }
        }

        sleep(Duration::from_millis(800)).await;
    }

    eprintln!("[{SRC}] Complete. {call_count} queries, {total_inserted} new rows.");
    Ok(())
}

async fn fetch_seeknow_page(key: &str, base: &str, field: &str, value: &str) -> Result<Vec<Value>> {
    let encoded = crate::util::http::urlencode(value);
    let url = format!("{base}/search?{field}={encoded}&country=AU&limit=100");

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
                sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(120);
                let _ = e;
                continue;
            }
            Err(e) => return Err(Error::Other(e.to_string())),
            Ok(r) if r.status().as_u16() == 429 => {
                sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(120);
                continue;
            }
            Ok(r) if !r.status().is_success() => {
                return Err(Error::Other(format!("SeekNow HTTP {}", r.status())));
            }
            Ok(r) => {
                let body = r.text().await.map_err(|e| Error::Other(e.to_string()))?;
                let parsed: Value =
                    serde_json::from_str(&body).map_err(|e| Error::Other(e.to_string()))?;
                let records = parsed
                    .pointer("/data/results")
                    .or_else(|| parsed.pointer("/results"))
                    .or_else(|| parsed.pointer("/data"))
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                return Ok(records);
            }
        }
    }
    Err(Error::Other("SeekNow fetch failed after retries".into()))
}

fn extract_employer_domain(rec: &Value) -> Option<String> {
    // Try common profile schema paths for employer / company domain.
    let company = rec
        .pointer("/company/domain")
        .or_else(|| rec.pointer("/employer_domain"))
        .or_else(|| rec.pointer("/current_employer/domain"))
        .and_then(|v| v.as_str())?;

    let company = company.trim().to_ascii_lowercase();
    // Skip freemail / generic domains.
    const SKIP: &[&str] = &[
        "gmail.com",
        "hotmail.com",
        "outlook.com",
        "yahoo.com",
        "icloud.com",
        "live.com",
        "me.com",
    ];
    if SKIP.contains(&company.as_str()) || company.is_empty() || !company.contains('.') {
        return None;
    }
    Some(company)
}

fn insert_seeknow_batch(
    conn: &mut Connection,
    records: &[Value],
    field: &str,
    query_value: &str,
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
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut h = DefaultHasher::new();
                rec.to_string().hash(&mut h);
                format!("anon-{field}-{:016x}", h.finish())
            });

        let n = tx
            .execute(
                "INSERT OR IGNORE INTO seeknow_au_cache \
                 (id, field, query_value, record_json, inserted_at) \
                 VALUES (?1,?2,?3,?4,?5)",
                params![id, field, query_value, rec.to_string(), now],
            )
            .map_err(|e| Error::Other(e.to_string()))?;
        inserted += n as u64;
    }
    tx.commit().map_err(|e| Error::Other(e.to_string()))?;
    Ok(inserted)
}

fn load_lines(path: &str) -> Result<Vec<String>> {
    std::fs::read_to_string(Path::new(path))
        .map(|s| {
            s.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_owned)
                .collect()
        })
        .map_err(|e| Error::Other(format!("cannot read {path}: {e}")))
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
    let (y, mo, d) = epoch_days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

fn epoch_days_to_ymd(mut days: u64) -> (u64, u64, u64) {
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
