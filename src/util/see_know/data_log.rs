//! Local See-Know data-log store — Termux Android aarch64 (no root).
//!
//! Every positive See-Know search result the engine obtains (hooked at the
//! `endpoints` module's cache-put sites, covering POST `/search`, POST
//! `/search/deep`, and every GET endpoint via `get_path`) is appended here as
//! one JSON line, so all "seek" data from the module's existing search flows is
//! retained locally on-device. The store is:
//!
//!   * **Autonomous** — writes happen inline on the existing search path; no
//!     extra call sites, flags, or user action required.
//!   * **Transparent** — newline-delimited JSON (`.jsonl`) the operator can
//!     `cat`/`jq` directly; each record carries endpoint, query, type, an epoch
//!     timestamp, item count, and the raw items verbatim.
//!   * **No-root / Termux-first** — lives under [`super::config::get_results_dir`]
//!     (`~/storage/downloads/.hse/see_know_results/logs`, with `$HOME` and CWD
//!     fallbacks), all reachable without root.
//!   * **Best-effort** — logging never fails a scan: any IO error is swallowed
//!     so a read-only or full filesystem degrades logging, not searching.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Serializes concurrent appends. Multiple scan tasks (up to
/// `config::MAX_CONCURRENT_QUERIES`) may log at once; a single line-append under
/// this lock keeps records intact and non-interleaved.
static WRITE_LOCK: Mutex<()> = Mutex::new(());

/// Basename of the append-only data-log file inside the logs directory.
const LOG_FILE: &str = "seek_searches.jsonl";

/// One persisted See-Know search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchLogRecord {
    /// Epoch milliseconds when the record was written.
    pub timestamp_ms: u128,
    /// API path queried, e.g. `/search` or `/network/email-check`.
    pub endpoint: String,
    /// The query value (as sent to the API).
    pub query: String,
    /// Query type discriminator (`""` = auto-detect), e.g. `email`.
    pub query_type: String,
    /// Number of result items captured.
    pub item_count: usize,
    /// Raw result items exactly as returned by the API.
    pub items: Vec<Value>,
}

/// Aggregate statistics over the on-device log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogStats {
    pub records: usize,
    pub total_items: usize,
    pub endpoints: usize,
}

/// Directory holding the See-Know data logs (created on demand).
#[must_use]
pub fn log_dir() -> PathBuf {
    let dir = super::config::get_results_dir().join("logs");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Absolute path of the append-only log file.
#[must_use]
pub fn log_path() -> PathBuf {
    log_dir().join(LOG_FILE)
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn build_record(endpoint: &str, query: &str, query_type: &str, items: &[Value]) -> SearchLogRecord {
    SearchLogRecord {
        timestamp_ms: now_ms(),
        endpoint: endpoint.to_string(),
        query: query.to_string(),
        query_type: query_type.to_string(),
        item_count: items.len(),
        items: items.to_vec(),
    }
}

/// Append one record to the log file inside `dir`. Best-effort: returns `false`
/// on any serialization/IO error, never panicking.
fn append_record(dir: &Path, record: &SearchLogRecord) -> bool {
    let Ok(mut line) = serde_json::to_string(record) else {
        return false;
    };
    line.push('\n');

    let _guard = WRITE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    match OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(LOG_FILE))
    {
        Ok(mut f) => f.write_all(line.as_bytes()).is_ok(),
        Err(_) => false,
    }
}

/// Read every record from the log file inside `dir` (oldest first). Malformed
/// lines are skipped so a partially-written tail never aborts retrieval.
fn read_all_from(dir: &Path) -> Vec<SearchLogRecord> {
    let Ok(file) = std::fs::File::open(dir.join(LOG_FILE)) else {
        return Vec::new();
    };
    BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<SearchLogRecord>(&l).ok())
        .collect()
}

/// Summary statistics over the log file inside `dir`.
fn stats_from(dir: &Path) -> LogStats {
    let Ok(file) = std::fs::File::open(dir.join(LOG_FILE)) else {
        return LogStats::default();
    };
    let mut endpoints = std::collections::HashSet::new();
    let mut out = LogStats::default();
    for rec in BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<SearchLogRecord>(&l).ok())
    {
        out.records += 1;
        out.total_items += rec.item_count;
        endpoints.insert(rec.endpoint);
    }
    out.endpoints = endpoints.len();
    out
}

/// Persist one search result to the on-device log. Best-effort: returns `false`
/// (never panics) if the record could not be written. Empty result sets are
/// skipped — only data-bearing searches are logged, mirroring the client's
/// positive-only cache.
pub fn log_search(endpoint: &str, query: &str, query_type: &str, items: &[Value]) -> bool {
    if items.is_empty() {
        return false;
    }
    append_record(
        &log_dir(),
        &build_record(endpoint, query, query_type, items),
    )
}

/// Read every persisted record (oldest first). Empty vec if no log exists yet.
#[must_use]
pub fn read_all() -> Vec<SearchLogRecord> {
    read_all_from(&log_dir())
}

/// Summary statistics over the on-device log (records, total items, distinct
/// endpoints).
#[must_use]
pub fn stats() -> LogStats {
    stats_from(&log_dir())
}

/// Per-endpoint count of past positive (data-bearing) records. Because only
/// data-bearing searches are logged, this is a direct historical-yield signal:
/// the live plan orderer boosts endpoints that have produced data for THIS
/// operator before, closing the loop from stored results back into scoring.
/// Empty map if no log exists yet.
#[must_use]
pub fn yield_counts() -> std::collections::HashMap<String, usize> {
    yield_counts_from(&log_dir())
}

fn yield_counts_from(dir: &Path) -> std::collections::HashMap<String, usize> {
    let mut out = std::collections::HashMap::new();
    let Ok(file) = std::fs::File::open(dir.join(LOG_FILE)) else {
        return out;
    };
    for rec in BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<SearchLogRecord>(&l).ok())
    {
        *out.entry(rec.endpoint).or_insert(0) += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Unique throwaway dir per test — no env mutation (the crate denies unsafe,
    // and std::env::set_var is unsafe), no clock/rand (unavailable in some
    // sandboxes): derive from an atomic counter plus the process id.
    fn temp_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("hse_seek_log_{}_{}", std::process::id(), n));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn test_log_and_read_roundtrip() {
        let dir = temp_dir();
        let rec = build_record("/search", "user@example.com", "email", &[json!({"hit": 1})]);
        assert!(append_record(&dir, &rec));
        let all = read_all_from(&dir);
        assert!(
            all.iter()
                .any(|r| r.query == "user@example.com" && r.endpoint == "/search")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_empty_items_not_logged() {
        // Public API skips empty item sets entirely.
        assert!(!log_search("/search", "nobody", "email", &[]));
    }

    #[test]
    fn test_stats_counts() {
        let dir = temp_dir();
        append_record(
            &dir,
            &build_record("/search", "a", "", &[json!({"x": 1}), json!({"x": 2})]),
        );
        append_record(
            &dir,
            &build_record(
                "/network/email-check",
                "b@c.com",
                "email",
                &[json!({"svc": "gh"})],
            ),
        );
        let s = stats_from(&dir);
        assert_eq!(s.records, 2);
        assert_eq!(s.total_items, 3);
        assert_eq!(s.endpoints, 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_yield_counts() {
        let dir = temp_dir();
        append_record(&dir, &build_record("/search", "a", "", &[json!({"x": 1})]));
        append_record(&dir, &build_record("/search", "b", "", &[json!({"x": 2})]));
        append_record(
            &dir,
            &build_record("/discord/user", "123", "", &[json!({"d": 1})]),
        );
        let counts = yield_counts_from(&dir);
        assert_eq!(counts.get("/search"), Some(&2));
        assert_eq!(counts.get("/discord/user"), Some(&1));
        assert_eq!(counts.get("/network/ip"), None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_malformed_lines_skipped() {
        let dir = temp_dir();
        std::fs::write(dir.join(LOG_FILE), "not json\n{\"broken\":\n").unwrap();
        assert_eq!(read_all_from(&dir).len(), 0);
        // A valid record still reads back after the garbage.
        append_record(&dir, &build_record("/search", "ok", "", &[json!({"y": 1})]));
        assert_eq!(read_all_from(&dir).len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }
}
