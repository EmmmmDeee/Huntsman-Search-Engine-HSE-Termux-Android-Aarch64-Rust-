//! `hse self-scan` — run a full scan on the operator's own identity seed and
//! diff results against the previous run.
//!
//! Seed resolution order: `--seed` arg → `HUNTSMAN_SELF_SEED` env → stdin prompt.
//! Each run persists its scan_id in `self_scan_meta`; the next run queries the
//! previous scan's entities from the store and prints a +NEW / ~MOVED / -GONE delta.

use std::collections::HashMap;
use std::io::{BufRead, Write as _};

use rusqlite::{Connection, params};

use crate::core::module::ModuleContext;
use crate::core::scan::{Scan, ScanOptions, Target};
use crate::core::error::{Error, Result};
use crate::util::{keys, uid::scan_id};

use super::{build_runtime, parse_target_kind, split_csv};

const SELF_SEED_ENV: &str = "HUNTSMAN_SELF_SEED";

pub(super) struct SelfScanCmd {
    pub seed: Option<String>,
    pub kind: Option<String>,
    pub delta_only: bool,
    pub modules: Option<String>,
    pub output: String,
}

// ── Persistence helpers ───────────────────────────────────────────────────────

fn db_conn() -> Result<Connection> {
    let path = crate::default_db_path();
    let conn = Connection::open(&path)
        .map_err(|e| Error::Other(format!("cannot open DB: {e}")))?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         CREATE TABLE IF NOT EXISTS self_scan_meta (
             seed_key TEXT PRIMARY KEY,
             last_scan_id TEXT NOT NULL,
             run_at TEXT NOT NULL
         );",
    )
    .map_err(|e| Error::Other(format!("self_scan schema: {e}")))?;
    Ok(conn)
}

fn load_last_scan_id(conn: &Connection, seed_key: &str) -> Option<String> {
    conn.query_row(
        "SELECT last_scan_id FROM self_scan_meta WHERE seed_key = ?1",
        params![seed_key],
        |row| row.get(0),
    )
    .ok()
}

fn save_scan_id(conn: &Connection, seed_key: &str, scan_id: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO self_scan_meta (seed_key, last_scan_id, run_at)
         VALUES (?1, ?2, datetime('now'))
         ON CONFLICT(seed_key) DO UPDATE SET last_scan_id=excluded.last_scan_id, run_at=excluded.run_at",
        params![seed_key, scan_id],
    )
    .map_err(|e| Error::Other(format!("save scan id: {e}")))?;
    Ok(())
}

// ── Delta printer ─────────────────────────────────────────────────────────────

type Snapshot = HashMap<String, (String, String, f64)>;

fn print_delta(prev: &Snapshot, curr: &Snapshot, as_json: bool) {
    let mut new_ents: Vec<(&str, &str, f64)> = Vec::new();
    let mut moved: Vec<(&str, &str, f64, f64)> = Vec::new();
    let mut gone: Vec<(&str, &str, f64)> = Vec::new();

    for (key, (kind, value, conf)) in curr {
        match prev.get(key) {
            None => new_ents.push((kind, value, *conf)),
            Some((_, _, pc)) => {
                if (conf - pc).abs() > 0.001 {
                    moved.push((kind, value, *pc, *conf));
                }
            }
        }
    }
    for (key, (kind, value, conf)) in prev {
        if !curr.contains_key(key) {
            gone.push((kind, value, *conf));
        }
    }

    if as_json {
        let obj = serde_json::json!({
            "type": "self_scan_delta",
            "new": new_ents.iter().map(|(k,v,c)| serde_json::json!({"kind":k,"value":v,"confidence":c})).collect::<Vec<_>>(),
            "moved": moved.iter().map(|(k,v,p,c)| serde_json::json!({"kind":k,"value":v,"prev_confidence":p,"confidence":c})).collect::<Vec<_>>(),
            "gone": gone.iter().map(|(k,v,c)| serde_json::json!({"kind":k,"value":v,"was_confidence":c})).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string(&obj).unwrap_or_default());
        return;
    }

    println!("\n=== SELF-SCAN DELTA ===");
    if new_ents.is_empty() && moved.is_empty() && gone.is_empty() {
        println!("  (no changes since last run)");
    } else {
        for (kind, value, conf) in &new_ents {
            println!("  + NEW    {kind}  {value}  ({conf:.2})");
        }
        for (kind, value, prev_c, conf) in &moved {
            println!("  ~ MOVED  {kind}  {value}  ({prev_c:.2}\u{2192}{conf:.2})");
        }
        for (kind, value, conf) in &gone {
            println!("  - GONE   {kind}  {value}  (was {conf:.2})");
        }
    }
}

// ── Main command ──────────────────────────────────────────────────────────────

pub(super) async fn cmd_self_scan(cmd: SelfScanCmd) -> Result<()> {
    // Resolve seed: arg → env → stdin prompt.
    let seed_value = if let Some(s) = cmd.seed.filter(|s| !s.trim().is_empty()) {
        s
    } else if let Ok(s) = std::env::var(SELF_SEED_ENV) {
        if s.trim().is_empty() {
            return Err(Error::Other(format!(
                "{SELF_SEED_ENV} is set but empty — provide a seed"
            )));
        }
        s
    } else {
        eprint!("Enter your identity seed (email, username, phone, …): ");
        std::io::stderr().flush().ok();
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| Error::Other(format!("stdin: {e}")))?;
        let trimmed = line.trim().to_string();
        if trimmed.is_empty() {
            return Err(Error::Other(
                "no seed provided — use --seed or set HUNTSMAN_SELF_SEED".into(),
            ));
        }
        trimmed
    };

    // Detect target kind.
    let kind_arg = cmd.kind.as_deref().unwrap_or("auto");
    let target_kind = if kind_arg.is_empty() || kind_arg.eq_ignore_ascii_case("auto") {
        let k = crate::core::scan::detect_kind(&seed_value);
        eprintln!("auto-detected kind: {} (override with --kind)", k.canonical_str());
        k
    } else {
        parse_target_kind(kind_arg)?
    };

    let target = Target::new(target_kind, seed_value.clone());
    if let Err(msg) = target.validate() {
        return Err(Error::Other(format!("invalid seed '{seed_value}': {msg}")));
    }

    // Load previous scan ID for delta.
    let db = db_conn()?;
    let seed_key = format!("{}:{}", target_kind.canonical_str(), seed_value);
    let prev_scan_id = load_last_scan_id(&db, &seed_key);

    let scan_options = ScanOptions {
        modules: split_csv(cmd.modules),
        ..Default::default()
    };

    let sid = scan_id(target_kind.canonical_str(), &seed_value);
    let (store, bus, engine) = build_runtime(64)?;

    let scan = Scan::new(sid.clone(), target.clone()).with_options(scan_options);
    let kys = keys::populate_and_load().await;
    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus,
        http: crate::util::http::build_client_with_trace(&sid),
        keys: kys,
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
    };

    let _scan = engine.run(scan, target, ctx).await?;
    let entities = store.entities_for_scan(&sid)?;

    // Persist the new scan_id.
    save_scan_id(&db, &seed_key, &sid)?;

    // Build current snapshot.
    let curr_snapshot: Snapshot = entities
        .iter()
        .map(|e| {
            let key = format!("{}\x1f{}", e.kind, e.value);
            (key, (e.kind.to_string(), e.value.clone(), e.confidence))
        })
        .collect();

    // Compute delta against previous run if available.
    let prev_snapshot: Snapshot = if let Some(prev_sid) = prev_scan_id {
        store
            .entities_for_scan(&prev_sid)
            .unwrap_or_default()
            .iter()
            .map(|e| {
                let key = format!("{}\x1f{}", e.kind, e.value);
                (key, (e.kind.to_string(), e.value.clone(), e.confidence))
            })
            .collect()
    } else {
        eprintln!("(first self-scan run — no previous baseline to diff against)");
        HashMap::new()
    };

    let as_json = cmd.output == "json";

    if !cmd.delta_only {
        // Print the full entity list in the requested format.
        if as_json {
            for e in &entities {
                println!("{}", serde_json::to_string(e).unwrap_or_default());
            }
        } else {
            println!("\n=== SELF-SCAN: {seed_value} ===");
            for e in &entities {
                println!(
                    "  [{:.2}] {}  {}{}",
                    e.confidence,
                    e.kind,
                    e.value,
                    if e.tags.is_empty() {
                        String::new()
                    } else {
                        format!("  ({})", e.tags.join(", "))
                    }
                );
            }
        }
    }

    print_delta(&prev_snapshot, &curr_snapshot, as_json);

    Ok(())
}
