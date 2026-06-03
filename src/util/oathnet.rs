//! Shared OathNet API client — used by both oathnet_pro module and
//! search_engines enrichment pass. Lives in util/ so any module can
//! call it without violating the "no inter-module imports" invariant.

use std::sync::Mutex;

use serde::Deserialize;
use serde_json::Value;

use crate::core::error::{Error, Result};
use crate::util::budget::QuotaBudget;
use crate::util::curl_client::{AuthScheme, CurlClient};
use crate::util::response_cache::ResponseCache;

// Embedded fallback: single source of truth lives in `util::keys`.
const HARDCODED_KEY: &str = crate::util::keys::OATHNET_DEFAULT_KEY;

pub const KEY_ENV: &str = "HUNTSMAN_OATHNET_KEY";

/// Per-process response cache: deduplicates identical (path, field, value)
/// queries across modules. When oathnet_pro, geo_intel, and search_engines
/// all query `search(BREACH, "email", "x@y.com")` for the same entity,
/// only the first makes the HTTP call; subsequent modules get the cached
/// response. Empirically saves ~60% of OathNet API calls on expansion scans.
///
/// Backed by the shared [`ResponseCache`] primitive (cap 1024).
static RESPONSE_CACHE: ResponseCache<Vec<Value>> = ResponseCache::new(1024);

/// Shared curl-subprocess client. `x-api-key` auth, 12s curl timeout,
/// 15s outer tokio timeout — same calibration as the SeekNow client
/// since both providers' rate-limit responses arrive within this
/// window.
static CLIENT: CurlClient = CurlClient::new("oathnet", AuthScheme::XApiKey, 12, 15_000);

/// Per-scan + per-session quota budget for OathNet API calls.
///
/// Default 4 queries per scan (the OathNet quota is tighter than
/// SeekNow's) with a 30-query session ceiling that prevents
/// radar/live sessions from burning the daily allowance. Both caps
/// are env-tunable via `HUNTSMAN_OATHNET_SCAN_CAP` and
/// `HUNTSMAN_OATHNET_SESSION_CAP`.
static BUDGET: QuotaBudget = QuotaBudget::new(
    "oathnet",
    4,
    30,
    "HUNTSMAN_OATHNET_SCAN_CAP",
    "HUNTSMAN_OATHNET_SESSION_CAP",
);

fn cache_key(path: &str, field: &str, value: &str) -> String {
    format!("{path}:{field}:{}", value.to_lowercase())
}

fn cache_get(key: &str) -> Option<Vec<Value>> {
    RESPONSE_CACHE.get(key)
}

fn cache_put(key: String, items: &[Value]) {
    RESPONSE_CACHE.put(key, items.to_vec());
}

fn budget_remaining() -> bool {
    BUDGET.remaining()
}

fn budget_increment() {
    BUDGET.increment();
}

pub fn is_quota_exhausted() -> bool {
    BUDGET.is_exhausted()
}

/// Snapshot of current per-scan + per-session OathNet budget consumption.
/// Surfaced for diagnostics and `/api/v1/stats` so operators can see
/// how much of the daily allowance has been spent.
pub fn budget_snapshot() -> crate::util::budget::BudgetSnapshot {
    BUDGET.snapshot()
}

/// Reset the per-scan budget counters. Must be called at the start of every
/// scan so that `hse serve` / `hse live` (long-lived processes) get a fresh
/// budget for each scan rather than accumulating across scans.
pub fn reset_budget() {
    BUDGET.reset_scan();
}

fn mark_quota_exhausted() {
    BUDGET.mark_exhausted();
    tracing::warn!("OathNet daily quota exhausted — skipping remaining queries");
}

fn base_url() -> String {
    std::env::var("HUNTSMAN_OATHNET_BASE").unwrap_or_else(|_| "https://oathnet.org/api".to_string())
}

pub fn resolve_key(ctx_key: Option<&str>) -> &str {
    match ctx_key {
        Some(k) if !k.is_empty() => k,
        _ => HARDCODED_KEY,
    }
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    data: Option<Value>,
    #[serde(default)]
    errors: Option<ErrorDetail>,
}

#[derive(Deserialize, Default)]
struct ErrorDetail {
    #[serde(default)]
    status_code: Option<u16>,
}

#[derive(Deserialize)]
struct SearchData {
    #[serde(default)]
    items: Vec<Value>,
}

/// Search a specific OathNet surface (breach, stealer, etc.) by field.
/// Returns the raw item array on success, empty vec on 404/clean miss.
/// Returns empty vec immediately if daily quota is exhausted.
pub async fn search(
    key: &str,
    path: &str,
    field: &str,
    value: &str,
    page_size: u32,
) -> Result<Vec<Value>> {
    let ck = cache_key(path, field, value);
    if let Some(cached) = cache_get(&ck) {
        return Ok(cached);
    }
    if is_quota_exhausted() || !budget_remaining() {
        return Ok(Vec::new());
    }
    budget_increment();
    let encoded = crate::util::http::urlencode(value);
    // sort=indexed_at:desc gives the freshest records first within
    // the page_size cap, maximising data freshness per query.
    let mut url = format!(
        "{}{}?{}%5B%5D={}&page_size={}&sort=indexed_at:desc",
        base_url(),
        path,
        field,
        encoded,
        page_size
    );
    if let Some(sid) = session_id_for(value) {
        url.push_str("&search_id=");
        url.push_str(&crate::util::http::urlencode(&sid));
    }
    let body = CLIENT.get(&url, key).await?;
    // Detect actual quota exhaustion. Earlier check used `body.contains("quota")`
    // which false-positives on legitimate metadata fields like `session_quota`
    // and `recommended_quota`. Match only true exhaustion signals.
    if body.contains("\"left_today\":0")
        || body.contains("limit exceeded")
        || body.contains("Daily quota exceeded")
        || body.contains("quota exceeded")
        || body.contains("\"is_unlimited\":false,\"left_today\":0")
    {
        mark_quota_exhausted();
        return Ok(Vec::new());
    }
    let env: Envelope =
        serde_json::from_str(&body).map_err(|e| Error::module("oathnet", e.to_string()))?;
    if !env.success {
        if env.errors.as_ref().and_then(|e| e.status_code) == Some(404) {
            // Negative-cache the clean miss so subsequent scans of the same
            // dead target don't re-spend an OathNet lookup confirming it's
            // still empty. The cache is per-process so this only affects
            // within-session re-queries.
            cache_put(ck, &[]);
            return Ok(Vec::new());
        }
        if env.errors.as_ref().and_then(|e| e.status_code) == Some(429) {
            mark_quota_exhausted();
            return Ok(Vec::new());
        }
        return Err(Error::module("oathnet", "API returned success=false"));
    }
    let data = match env.data {
        Some(d) => d,
        // Negative-cache empty data envelopes too.
        None => {
            cache_put(ck, &[]);
            return Ok(Vec::new());
        }
    };
    let sd: SearchData =
        serde_json::from_value(data).map_err(|e| Error::module("oathnet", e.to_string()))?;
    cache_put(ck, &sd.items);
    Ok(sd.items)
}

/// Extract a string field from a JSON Value.
pub fn val_str(item: &Value, key: &str) -> Option<String> {
    item.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(std::string::ToString::to_string)
}

/// Extract the first non-empty string from multiple candidate fields.
pub fn val_str_or(item: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| val_str(item, k))
}

/// Count top N database names by frequency.
pub fn top_dbnames(items: &[Value], n: usize) -> Vec<String> {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for item in items {
        if let Some(db) = val_str(item, "dbname") {
            *counts.entry(db).or_default() += 1;
        }
    }
    let mut sorted: Vec<(String, usize)> = counts.into_iter().collect();
    sorted.sort_by_key(|b| std::cmp::Reverse(b.1));
    sorted.into_iter().take(n).map(|(k, _)| k).collect()
}

pub mod paths {
    pub const BREACH: &str = "/service/v2/breach/search";
    pub const STEALER: &str = "/service/v2/stealer/search";
    pub const SESSION_INIT: &str = "/service/search/init";
}

/// Per-scan search session ID. When set, breach and stealer queries for
/// the same target value consume only ONE OathNet lookup instead of two.
/// Sessions are valid for 60 minutes on the OathNet side.
static SEARCH_SESSION: std::sync::LazyLock<Mutex<Option<(String, String)>>> =
    std::sync::LazyLock::new(|| Mutex::new(None));

/// Initialise a search session for `value`. Returns the session ID on
/// success, or None if the init call fails (non-fatal — queries still
/// work without a session, they just cost more quota).
pub async fn init_session(key: &str, value: &str) -> Option<String> {
    if is_quota_exhausted() {
        return None;
    }
    let url = format!("{}{}", base_url(), paths::SESSION_INIT);
    let body = format!(r#"{{"query":"{}"}}"#, value.replace('"', "\\\""));
    // Routed through the shared CurlClient — same UA / Accept /
    // auth-header layout as the GET path, just with a JSON body.
    let text = CLIENT.post_json(&url, key, &body).await.ok()?;
    let parsed: Value = serde_json::from_str(&text).ok()?;
    let sid = parsed
        .pointer("/session/id")
        .or_else(|| parsed.pointer("/data/session/id"))
        .and_then(|v| v.as_str())
        .map(str::to_string)?;
    if let Ok(mut guard) = SEARCH_SESSION.lock() {
        *guard = Some((value.to_lowercase(), sid.clone()));
    }
    tracing::info!(session_id = %sid, query = %value, "OathNet search session initialised");
    Some(sid)
}

/// Return the cached session ID if it matches the given target value.
pub fn session_id_for(value: &str) -> Option<String> {
    SEARCH_SESSION.lock().ok().and_then(|guard| {
        guard.as_ref().and_then(|(q, sid)| {
            if q == &value.to_lowercase() {
                Some(sid.clone())
            } else {
                None
            }
        })
    })
}

// The curl-subprocess transport now lives in `util::curl_client` —
// shared with util::see_know via the per-provider `CLIENT` static
// declared at the top of this file. The `Duration` re-export below
// is no longer needed locally now that the timeout lives inside
// CurlClient.

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolve_key_uses_provided_when_non_empty() {
        assert_eq!(resolve_key(Some("my-key")), "my-key");
    }

    #[test]
    fn resolve_key_falls_back_to_hardcoded_when_none() {
        assert_eq!(resolve_key(None), HARDCODED_KEY);
    }

    #[test]
    fn resolve_key_falls_back_to_hardcoded_when_empty() {
        assert_eq!(resolve_key(Some("")), HARDCODED_KEY);
    }

    #[test]
    fn val_str_extracts_string_field() {
        let v = json!({"name": "alice", "age": 30});
        assert_eq!(val_str(&v, "name"), Some("alice".to_string()));
    }

    #[test]
    fn val_str_returns_none_for_missing_field() {
        let v = json!({"name": "alice"});
        assert_eq!(val_str(&v, "missing"), None);
    }

    #[test]
    fn val_str_returns_none_for_empty_string() {
        let v = json!({"name": ""});
        assert_eq!(val_str(&v, "name"), None);
    }

    #[test]
    fn val_str_returns_none_for_non_string() {
        let v = json!({"count": 42});
        assert_eq!(val_str(&v, "count"), None);
    }

    #[test]
    fn val_str_or_returns_first_match() {
        let v = json!({"email": "a@b.com", "login": "alice"});
        assert_eq!(
            val_str_or(&v, &["missing", "email", "login"]),
            Some("a@b.com".to_string())
        );
    }

    #[test]
    fn val_str_or_returns_none_when_all_missing() {
        let v = json!({"x": 1});
        assert_eq!(val_str_or(&v, &["a", "b", "c"]), None);
    }

    #[test]
    fn top_dbnames_ranks_by_frequency() {
        let items = vec![
            json!({"dbname": "linkedin"}),
            json!({"dbname": "adobe"}),
            json!({"dbname": "linkedin"}),
            json!({"dbname": "adobe"}),
            json!({"dbname": "adobe"}),
            json!({"dbname": "myspace"}),
        ];
        let top = top_dbnames(&items, 2);
        assert_eq!(top[0], "adobe");
        assert_eq!(top[1], "linkedin");
        assert_eq!(top.len(), 2);
    }

    #[test]
    fn top_dbnames_empty_input() {
        assert!(top_dbnames(&[], 5).is_empty());
    }

    #[test]
    fn top_dbnames_skips_items_without_dbname() {
        let items = vec![json!({"other": "val"}), json!({"dbname": "x"})];
        let top = top_dbnames(&items, 10);
        assert_eq!(top, vec!["x"]);
    }

    #[test]
    fn paths_are_non_empty() {
        assert!(!paths::BREACH.is_empty());
        assert!(!paths::STEALER.is_empty());
    }
}
