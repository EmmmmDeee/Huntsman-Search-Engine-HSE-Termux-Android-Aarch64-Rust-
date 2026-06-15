//! Persistent API response cache. Every key-gated module checks here before
//! making an HTTP request, saving money and quota on repeat lookups.
//!
//! Backed by a SQLite sidecar file (`api_cache.db`) next to `huntsman.db`.
//! A global singleton is initialised once at process start via [`init`];
//! modules access it with [`global`].

use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use rusqlite::{Connection, params};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::core::entity::unix_now;
use crate::core::error::{Error, Result};

// ── Pricing / TTL tables ─────────────────────────────────────────────────────

/// USD cents charged per live API call for a given module.
/// Used to accumulate the "$ saved" counter when a cache hit skips a call.
pub fn cost_cents(module: &str) -> u64 {
    match module {
        "dehashed" => 500,   // ~$5/search
        "proxycurl" => 5,    // ~$0.05/call
        "seon" => 25,        // ~$0.25/call
        "fullcontact" => 10, // ~$0.10/call
        "hunter_io" => 5,    // free quota ≈ $0.05/search equivalent
        "whoisxml" => 1,     // bulk plan ~$0.01/lookup
        "censys" => 1,
        "virustotal" => 1,
        "abuseipdb" => 1,
        "leakix" => 1,
        "numverify" => 0,
        _ => 0,
    }
}

/// Cache TTL in seconds per module.
pub fn ttl_secs(module: &str) -> u64 {
    match module {
        "dehashed" | "proxycurl" | "fullcontact" | "seon" => 7 * 86_400,
        "numverify" => 30 * 86_400,
        "hunter_io" | "whoisxml" | "censys" => 86_400,
        "virustotal" | "abuseipdb" | "leakix" => 12 * 3_600,
        _ => 3_600,
    }
}

// ── Public types ─────────────────────────────────────────────────────────────

/// A response served from the local cache.
pub struct CachedResponse {
    /// Raw response body (JSON / text) as originally returned by the API.
    pub body: String,
    /// `true` when the cached body differs from the **previous** stored value —
    /// i.e. the API data changed between calls. Always `false` on a plain
    /// cache hit where the stored data is unchanged.
    pub is_novel: bool,
}

/// Aggregate cache performance statistics.
#[derive(Debug, Default, Serialize)]
pub struct CacheStats {
    /// Total cache hits across all modules since the cache DB was created.
    pub total_hits: u64,
    /// Total USD cents saved (sum of `cost_cents(module)` per hit).
    pub total_saved_usd_cents: u64,
    /// Formatted dollar string, e.g. `"$3.42"`.
    pub total_saved_display: String,
    /// Per-module breakdown, sorted by savings descending.
    pub by_module: Vec<ModuleStats>,
}

/// Per-module cache statistics.
#[derive(Debug, Serialize)]
pub struct ModuleStats {
    pub module: String,
    pub hits: u64,
    pub saved_usd_cents: u64,
}

// ── ApiCache ─────────────────────────────────────────────────────────────────

/// Persistent API response cache backed by SQLite.
pub struct ApiCache {
    db: Mutex<Connection>,
}

impl ApiCache {
    /// Open (or create) a persistent cache at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let conn =
            Connection::open(path).map_err(|e| Error::Other(format!("api_cache open: {e}")))?;
        Self::init_schema(&conn)?;
        Ok(Self {
            db: Mutex::new(conn),
        })
    }

    /// In-memory cache — used in tests; never persists to disk.
    pub fn in_memory() -> Self {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        Self::init_schema(&conn).expect("schema");
        Self {
            db: Mutex::new(conn),
        }
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS api_cache (
                 id        INTEGER PRIMARY KEY,
                 module    TEXT    NOT NULL,
                 cache_key TEXT    NOT NULL,
                 body      TEXT    NOT NULL,
                 body_hash TEXT    NOT NULL,
                 cached_at INTEGER NOT NULL,
                 ttl_secs  INTEGER NOT NULL DEFAULT 86400,
                 UNIQUE(module, cache_key)
             );
             CREATE INDEX IF NOT EXISTS api_cache_lookup
                 ON api_cache (module, cache_key);
             CREATE TABLE IF NOT EXISTS api_cache_stats (
                 module          TEXT    PRIMARY KEY,
                 hits            INTEGER NOT NULL DEFAULT 0,
                 saved_usd_cents INTEGER NOT NULL DEFAULT 0
             );",
        )
        .map_err(|e| Error::Other(format!("api_cache schema: {e}")))?;
        Ok(())
    }

    /// Look up a cached response. Returns `None` if absent or TTL-expired.
    /// On a hit the stats counters are incremented automatically.
    pub fn get(&self, module: &str, key: &str) -> Option<CachedResponse> {
        let db = self.db.lock().ok()?;
        let (body, _hash, cached_at, ttl): (String, String, u64, u64) = db
            .query_row(
                "SELECT body, body_hash, cached_at, ttl_secs
                 FROM api_cache WHERE module = ?1 AND cache_key = ?2",
                params![module, key],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)? as u64,
                        r.get::<_, i64>(3)? as u64,
                    ))
                },
            )
            .ok()?;
        if unix_now().saturating_sub(cached_at) > ttl {
            return None; // expired
        }
        let cost = cost_cents(module);
        db.execute(
            "INSERT INTO api_cache_stats (module, hits, saved_usd_cents)
             VALUES (?1, 1, ?2)
             ON CONFLICT(module) DO UPDATE SET
                 hits            = hits + 1,
                 saved_usd_cents = saved_usd_cents + ?2",
            params![module, cost as i64],
        )
        .ok();
        Some(CachedResponse {
            body,
            is_novel: false,
        })
    }

    /// Store a response body.
    ///
    /// Returns `true` (novel) when the body differs from the previous stored
    /// value for this `(module, key)` — the API returned new data since the
    /// last call.
    pub fn put(&self, module: &str, key: &str, body: &str, ttl: u64) -> bool {
        let hash = body_hash(body);
        let now = unix_now() as i64;
        let db = match self.db.lock() {
            Ok(d) => d,
            Err(_) => return true,
        };
        let prior: Option<String> = db
            .query_row(
                "SELECT body_hash FROM api_cache WHERE module = ?1 AND cache_key = ?2",
                params![module, key],
                |r| r.get(0),
            )
            .ok();
        let is_novel = prior.as_deref() != Some(hash.as_str());
        db.execute(
            "INSERT INTO api_cache (module, cache_key, body, body_hash, cached_at, ttl_secs)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(module, cache_key) DO UPDATE SET
                 body      = excluded.body,
                 body_hash = excluded.body_hash,
                 cached_at = excluded.cached_at,
                 ttl_secs  = excluded.ttl_secs",
            params![module, key, body, hash, now, ttl as i64],
        )
        .ok();
        is_novel
    }

    /// Return aggregate cache performance statistics.
    pub fn stats(&self) -> CacheStats {
        let db = match self.db.lock() {
            Ok(d) => d,
            Err(_) => return CacheStats::default(),
        };
        let rows: Vec<ModuleStats> = {
            let mut stmt = match db.prepare(
                "SELECT module, hits, saved_usd_cents
                 FROM api_cache_stats ORDER BY saved_usd_cents DESC",
            ) {
                Ok(s) => s,
                Err(_) => return CacheStats::default(),
            };
            stmt.query_map([], |r| {
                Ok(ModuleStats {
                    module: r.get(0)?,
                    hits: r.get::<_, i64>(1)? as u64,
                    saved_usd_cents: r.get::<_, i64>(2)? as u64,
                })
            })
            .ok()
            .map(|it| it.flatten().collect())
            .unwrap_or_default()
        };
        let total_hits: u64 = rows.iter().map(|r| r.hits).sum();
        let total_cents: u64 = rows.iter().map(|r| r.saved_usd_cents).sum();
        let dollars = total_cents / 100;
        let cents = total_cents % 100;
        CacheStats {
            total_hits,
            total_saved_usd_cents: total_cents,
            total_saved_display: format!("${dollars}.{cents:02}"),
            by_module: rows,
        }
    }
}

fn body_hash(s: &str) -> String {
    let h = Sha256::digest(s.as_bytes());
    hex::encode(h)
}

// ── Global singleton ──────────────────────────────────────────────────────────

static GLOBAL: OnceLock<Arc<ApiCache>> = OnceLock::new();

/// Initialise the global persistent cache. Call once at process start.
/// Subsequent calls are silently ignored.
pub fn init(path: &Path) {
    let cache = match ApiCache::open(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("api_cache: init failed ({e}), using in-memory fallback");
            ApiCache::in_memory()
        }
    };
    GLOBAL.set(Arc::new(cache)).ok();
}

/// Access the global [`ApiCache`]. Falls back to an in-memory instance if
/// [`init`] was never called (e.g. in unit tests).
pub fn global() -> &'static Arc<ApiCache> {
    GLOBAL.get_or_init(|| Arc::new(ApiCache::in_memory()))
}
