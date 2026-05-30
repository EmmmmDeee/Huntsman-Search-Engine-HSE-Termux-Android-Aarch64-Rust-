//! Shared SeekNow (see-know.eu) API client — a direct OathNet competitor
//! with its own daily-lookup pool.
//!
//! Endpoint surface (all under `https://see-know.eu/api/v1`):
//!
//!   POST /search                — universal search (auto-detects type)
//!   GET  /stealer               — stealer-log credential search
//!   GET  /breachhub/search      — breach record search
//!   GET  /network/email-check   — email existence + service map
//!   GET  /network/ip            — IP geolocation + ASN
//!   GET  /network/phone         — phone number enrichment
//!   GET  /domain/intel          — domain intel
//!   GET  /domain/whois          — WHOIS data
//!   GET  /discord/user          — Discord user info
//!   GET  /discord/to-roblox     — Discord-Roblox linkage
//!   GET  /gaming/{minecraft,roblox,xbox}
//!   GET  /username/{github,reddit,social,tiktok,twitter,history}
//!   GET  /credits               — remaining daily quota
//!
//! Auth: `Authorization: Bearer <key>`
//!
//! Quota model: 5000 daily lookups on premiumhq plan, resets at midnight UTC.
//! Per-process budget mirrors the OathNet client's pattern.

use serde_json::Value;

use crate::core::error::{Error, Result};
use crate::util::budget::QuotaBudget;
use crate::util::curl_client::{AuthScheme, CurlClient};
use crate::util::response_cache::ResponseCache;

// Re-export the shared snapshot type so external consumers
// (`api::handlers::stats`) keep working through the original path.
pub use crate::util::budget::BudgetSnapshot;

const HARDCODED_KEY: &str = "seek-4b33b63d408dd7149765da4e76384ce91fd9f6df518f9a25";

pub const KEY_ENV: &str = "HUNTSMAN_SEEKNOW_KEY";

/// Per-process response cache backed by the shared
/// [`ResponseCache`] primitive (cap 1024 — sized to comfortably hold
/// every distinct endpoint × query a single scan generates).
static RESPONSE_CACHE: ResponseCache<Vec<Value>> = ResponseCache::new(1024);

/// Shared curl-subprocess client. Bearer auth, 12s curl timeout
/// (matches the legacy `--max-time 12`), 15s outer tokio timeout.
// The name/auto `/search` path has a server-side cap of ~55s and routinely
// responds in 50–60s with real data. The previous 12s curl / 15s outer budget
// guaranteed a timeout-exit (curl 28) on every name search, surfacing as an
// opaque "curl failed" with zero entities. Budget above the cap: 75s curl,
// 78s outer (curl < outer so curl's own exit code is observed), paired with an
// 80s module max_timeout in `modules::see_know`.
static CLIENT: CurlClient = CurlClient::new("seek_now", AuthScheme::Bearer, 75, 78_000);

/// Per-scan + per-session quota budget for SeekNow API calls.
///
/// SeekNow's premiumhq plan grants 5,000 daily lookups. Each scan
/// gets a 24-query envelope (env-tunable via `HUNTSMAN_SEEKNOW_SCAN_CAP`,
/// runtime-overridable via `ScanOptions::seeknow_scan_cap`) so a
/// single seed can dispatch the universal search plus ~10 specialised
/// endpoints across the pivot graph. The 200-query session ceiling
/// (env-tunable via `HUNTSMAN_SEEKNOW_SESSION_CAP`) stops long-running
/// radar/live sessions short of the daily 5,000 ceiling.
static BUDGET: QuotaBudget = QuotaBudget::new(
    "seeknow",
    24,
    200,
    "HUNTSMAN_SEEKNOW_SCAN_CAP",
    "HUNTSMAN_SEEKNOW_SESSION_CAP",
);

/// Install a runtime per-scan cap. `0` clears the override (falls back
/// to env + static default). The engine calls this once at scan start
/// when the operator set `ScanOptions::seeknow_scan_cap`.
pub fn set_scan_cap_override(cap: u32) {
    BUDGET.set_scan_cap_override(cap);
}

/// Cache key combining endpoint path, normalised query, and query
/// type (when applicable). Disambiguates the universal /search path
/// — auto-detect ("") and typed ("email") on the same value previously
/// collided, masking type-specific result variants.
fn cache_key(path: &str, query: &str) -> String {
    format!("{path}:{}", query.to_lowercase())
}

fn typed_cache_key(path: &str, query: &str, query_type: &str) -> String {
    if query_type.is_empty() {
        cache_key(path, query)
    } else {
        format!("{path}#{query_type}:{}", query.to_lowercase())
    }
}

fn cache_get(key: &str) -> Option<Vec<Value>> {
    RESPONSE_CACHE.get(key)
}

fn cache_put(key: String, items: Vec<Value>) {
    RESPONSE_CACHE.put(key, items);
}

/// True if there's room in both the per-scan and per-session budgets.
/// Public so the module layer can short-circuit endpoint plans before
/// allocating per-endpoint futures.
pub fn budget_remaining() -> bool {
    BUDGET.remaining()
}

/// Remaining queries in the per-scan budget. Used by the module-layer
/// planner to decide how many specialised endpoints to dispatch.
pub fn scan_budget_remaining() -> u32 {
    BUDGET.scan_remaining()
}

/// Snapshot of current per-scan + per-session budget consumption.
/// Surfaced for diagnostics (`hse doctor`) and `/api/v1/stats`.
pub fn budget_snapshot() -> BudgetSnapshot {
    BUDGET.snapshot()
}

fn budget_increment() {
    BUDGET.increment();
}

pub fn is_quota_exhausted() -> bool {
    BUDGET.is_exhausted()
}

pub fn reset_budget() {
    BUDGET.reset_scan();
}

fn mark_quota_exhausted() {
    BUDGET.mark_exhausted();
    tracing::warn!("SeekNow daily quota exhausted — skipping remaining queries");
}

fn base_url() -> String {
    std::env::var("HUNTSMAN_SEEKNOW_BASE")
        .unwrap_or_else(|_| "https://see-know.eu/api/v1".to_string())
}

pub fn resolve_key(ctx_key: Option<&str>) -> &str {
    match ctx_key {
        Some(k) if !k.is_empty() => k,
        _ => HARDCODED_KEY,
    }
}

/// Universal search via POST /api/v1/search.
///
/// The `query_type` is one of: email, username, domain, ip, phone,
/// discord_id, steam_id. Pass an empty string for auto-detect.
pub async fn search(key: &str, query: &str, query_type: &str) -> Result<Vec<Value>> {
    // Disambiguated cache key — auto-detect ("") and typed ("email")
    // queries on the same value used to collide, masking the typed
    // variant's specialised result rows.
    let ck = typed_cache_key("search", query, query_type);
    if let Some(cached) = cache_get(&ck) {
        return Ok(cached);
    }
    if is_quota_exhausted() || !budget_remaining() {
        return Ok(Vec::new());
    }
    budget_increment();
    let url = format!("{}/search", base_url());
    let body = if query_type.is_empty() {
        format!(r#"{{"query":"{}"}}"#, escape_json(query))
    } else {
        format!(
            r#"{{"query":"{}","type":"{}"}}"#,
            escape_json(query),
            query_type
        )
    };
    let resp = post_json(&url, key, &body).await?;
    let items = extract_items(&resp);
    cache_put(ck, items.clone());
    Ok(items)
}

/// Steam profile lookup via GET /api/v1/gaming/steam?id=<value>
///
/// Some plans publish gaming/steam alongside roblox/xbox/minecraft;
/// safe to call against arbitrary 17-digit Steam IDs surfaced from
/// breach data.
pub async fn steam_profile(key: &str, steam_id: &str) -> Result<Vec<Value>> {
    get_path(key, "gaming/steam", &[("id", steam_id)]).await
}

/// Credits endpoint — returns the SeekNow account's remaining daily
/// quota. Used by the module layer for proactive tier decisions:
/// callers can skip optional endpoint plans when `remaining < N`.
///
/// Returns `Ok(None)` if the endpoint is missing or the response is
/// not understood — callers should treat that as "quota unknown, keep
/// going" so the budget atomic remains authoritative.
///
/// Does NOT consume any of the per-scan budget — credits-check is
/// considered metadata, not a billable lookup.
pub async fn credits(key: &str) -> Result<Option<u64>> {
    if is_quota_exhausted() {
        return Ok(Some(0));
    }
    let url = format!("{}/credits", base_url());
    let body = match CLIENT.get(&url, key).await {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    let v: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    // Common shapes: { "credits_remaining": N }, { "remaining": N },
    // { "data": { "credits": N } }.
    let remaining = v
        .get("credits_remaining")
        .or_else(|| v.get("remaining"))
        .or_else(|| v.get("credits"))
        .or_else(|| v.pointer("/data/credits_remaining"))
        .or_else(|| v.pointer("/data/credits"))
        .or_else(|| v.pointer("/data/remaining"))
        .and_then(|x| x.as_u64());
    Ok(remaining)
}

// Single-parameter GET endpoints (stealer, breachhub/search, domain/intel,
// network/{ip,phone,email-check}, username/{github,twitter,reddit,tiktok,
// social,history}, gaming/{roblox,xbox,minecraft}, domain/whois) carry no
// behaviour beyond `get_path(path, &[(param, value)])`, so they are dispatched
// table-driven from `EndpointCall::spec` in `modules::see_know` via the shared
// [`get_path`] rather than one near-identical wrapper each.
//
// The two Discord bridges keep named wrappers because the module's pivot
// discovery calls them directly (chasing discovered Discord IDs), not only
// through the endpoint planner.

/// Discord user info — captures region/timezone/connected-accounts via
/// GET /api/v1/discord/user?id=<value>
pub async fn discord_user(key: &str, discord_id: &str) -> Result<Vec<Value>> {
    get_path(key, "discord/user", &[("id", discord_id)]).await
}

/// Discord → Roblox linkage via GET /api/v1/discord/to-roblox?id=<value>
pub async fn discord_to_roblox(key: &str, discord_id: &str) -> Result<Vec<Value>> {
    get_path(key, "discord/to-roblox", &[("id", discord_id)]).await
}

/// Shared single-parameter GET dispatcher for the typed SeekNow endpoints.
/// Public within the crate so `EndpointCall::invoke` can drive every endpoint
/// from its `(label, path, param)` spec table without per-endpoint wrappers.
pub(crate) async fn get_path(key: &str, path: &str, params: &[(&str, &str)]) -> Result<Vec<Value>> {
    let qs = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, crate::util::http::urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let ck = format!("{path}:{qs}");
    if let Some(cached) = cache_get(&ck) {
        return Ok(cached);
    }
    if is_quota_exhausted() || !budget_remaining() {
        return Ok(Vec::new());
    }
    budget_increment();
    let url = format!("{}/{path}?{qs}", base_url());
    let resp = get_json(&url, key).await?;
    let items = extract_items(&resp);
    cache_put(ck, items.clone());
    Ok(items)
}

fn extract_items(v: &Value) -> Vec<Value> {
    // SeekNow returns one of: { data: { items: [...] } }, { results: [...] },
    // { data: {...} } (single object), or a top-level array.
    if let Some(arr) = v.as_array() {
        return arr.clone();
    }
    if let Some(items) = v.pointer("/data/items").and_then(|v| v.as_array()) {
        return items.clone();
    }
    if let Some(results) = v.pointer("/results").and_then(|v| v.as_array()) {
        return results.clone();
    }
    if let Some(data) = v.pointer("/data") {
        // Single-object data — wrap in a one-element vec for uniform handling.
        if data.is_object() {
            return vec![data.clone()];
        }
    }
    Vec::new()
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

async fn get_json(url: &str, key: &str) -> Result<Value> {
    let body = CLIENT.get(url, key).await?;
    parse_response(&body)
}

async fn post_json(url: &str, key: &str, body: &str) -> Result<Value> {
    let resp = CLIENT.post_json(url, key, body).await?;
    parse_response(&resp)
}

fn parse_response(body: &str) -> Result<Value> {
    // Detect quota exhaustion. Per docs the rate-limit error contains
    // "rate limit" or "credits" with a specific exhaustion message.
    if body.contains("\"credits_remaining\":0")
        || body.contains("daily limit reached")
        || body.contains("\"error\":\"rate_limit\"")
        || body.contains("quota_exceeded")
    {
        mark_quota_exhausted();
        return Ok(Value::Null);
    }
    serde_json::from_str(body).map_err(|e| Error::module("seek_now", e.to_string()))
}

// The curl-subprocess transport now lives in `util::curl_client` —
// shared with util::oathnet via the per-provider `CLIENT` static
// declared at the top of this file.

/// Extract a string field from a JSON Value.
pub fn val_str(item: &Value, key: &str) -> Option<String> {
    item.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(std::string::ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn client_timeout_budget_exceeds_name_search_server_cap() {
        // Regression: see-know.eu's name/auto `/search` path has a ~55s server
        // cap and returns real data in 50–60s. A curl budget below that (was
        // 12s) guarantees a timeout-exit on every name search — observed live
        // as an opaque "curl failed" with zero entities. The curl ceiling must
        // exceed the cap, and the outer tokio timeout must exceed the curl
        // ceiling so curl's own exit code (28) is what surfaces.
        const SERVER_CAP_SECS: u64 = 55;
        assert!(
            CLIENT.curl_timeout_secs() > SERVER_CAP_SECS,
            "curl --max-time {}s must exceed the ~{SERVER_CAP_SECS}s name-search cap",
            CLIENT.curl_timeout_secs()
        );
        assert!(
            CLIENT.outer_timeout_ms() > CLIENT.curl_timeout_secs() * 1000,
            "outer timeout ({}ms) must exceed curl timeout ({}s) so curl's exit code is observed",
            CLIENT.outer_timeout_ms(),
            CLIENT.curl_timeout_secs()
        );
    }

    #[test]
    fn resolve_key_uses_provided_when_non_empty() {
        assert_eq!(resolve_key(Some("my-key")), "my-key");
    }

    #[test]
    fn resolve_key_falls_back_to_hardcoded_when_none() {
        assert_eq!(resolve_key(None), HARDCODED_KEY);
    }

    #[test]
    fn resolve_key_falls_back_when_empty() {
        assert_eq!(resolve_key(Some("")), HARDCODED_KEY);
    }

    #[test]
    fn hardcoded_key_has_correct_prefix() {
        assert!(HARDCODED_KEY.starts_with("seek-"));
        assert!(HARDCODED_KEY.len() >= 50);
    }

    #[test]
    fn extract_items_handles_envelope() {
        let v = json!({"data": {"items": [{"id": 1}, {"id": 2}]}});
        assert_eq!(extract_items(&v).len(), 2);
    }

    #[test]
    fn extract_items_handles_results_array() {
        let v = json!({"results": [{"a": 1}]});
        assert_eq!(extract_items(&v).len(), 1);
    }

    #[test]
    fn extract_items_handles_top_level_array() {
        let v = json!([{"a": 1}, {"b": 2}, {"c": 3}]);
        assert_eq!(extract_items(&v).len(), 3);
    }

    #[test]
    fn extract_items_wraps_single_data_object() {
        let v = json!({"data": {"single": "object"}});
        assert_eq!(extract_items(&v).len(), 1);
    }

    #[test]
    fn extract_items_empty_for_unknown_shape() {
        let v = json!({"unrelated": "value"});
        assert!(extract_items(&v).is_empty());
    }

    #[test]
    fn escape_json_handles_quotes_and_backslashes() {
        assert_eq!(escape_json(r#"hello"world"#), r#"hello\"world"#);
        assert_eq!(escape_json(r"path\to\file"), r"path\\to\\file");
    }

    #[test]
    fn typed_cache_key_disambiguates_query_type_from_auto_detect() {
        let auto = typed_cache_key("search", "alice", "");
        let typed = typed_cache_key("search", "alice", "email");
        assert_ne!(
            auto, typed,
            "auto-detect and typed search must NOT share a cache key"
        );
        // Without a type, falls back to the legacy key shape.
        assert_eq!(auto, cache_key("search", "alice"));
        // Typed form includes the type marker.
        assert!(typed.contains("#email"));
    }

    #[test]
    fn scan_budget_remaining_decreases_with_increments() {
        reset_budget();
        let start = scan_budget_remaining();
        budget_increment();
        let after = scan_budget_remaining();
        assert_eq!(
            start,
            after + 1,
            "increment must consume exactly one credit"
        );
        reset_budget();
    }

    #[test]
    fn budget_snapshot_reports_active_caps() {
        reset_budget();
        let snap = budget_snapshot();
        assert_eq!(snap.scan_used, 0);
        assert!(snap.scan_cap >= 1);
        assert!(!snap.quota_exhausted);
        budget_increment();
        let snap2 = budget_snapshot();
        assert_eq!(snap2.scan_used, 1);
        reset_budget();
    }

    #[test]
    fn default_scan_cap_is_higher_than_legacy_eight() {
        // Regression guard for the seek-eu remodel: the legacy cap was
        // 8 lookups, leaving 99.84% of the daily quota unused. The new
        // default must be at least 16.
        reset_budget();
        let cap = budget_snapshot().scan_cap;
        assert!(
            cap >= 16,
            "scan cap dropped to {cap} — must remain ≥ 16 to leverage SeekNow quota"
        );
    }

    #[test]
    fn set_scan_cap_override_replaces_default_until_reset() {
        reset_budget();
        let base = budget_snapshot().scan_cap;
        set_scan_cap_override(80);
        assert_eq!(budget_snapshot().scan_cap, 80);
        reset_budget();
        // After reset, falls back to env / static default again.
        assert_eq!(budget_snapshot().scan_cap, base);
    }

    #[test]
    fn scan_cap_override_zero_falls_back_to_default() {
        reset_budget();
        let base = budget_snapshot().scan_cap;
        set_scan_cap_override(0);
        assert_eq!(
            budget_snapshot().scan_cap,
            base,
            "override of 0 must mean 'use default', not 'cap at zero'"
        );
        reset_budget();
    }

    #[test]
    fn snapshot_reflects_override_cap() {
        reset_budget();
        set_scan_cap_override(99);
        let snap = budget_snapshot();
        assert_eq!(snap.scan_cap, 99);
        reset_budget();
    }

    #[test]
    fn reset_clears_override_too() {
        // Regression guard: reset_scan must clear the cap override so
        // the next scan picks up the env / default cap unless the
        // engine installs a fresh override at scan start.
        reset_budget();
        set_scan_cap_override(99);
        assert_eq!(budget_snapshot().scan_cap, 99);
        reset_budget();
        assert_ne!(
            budget_snapshot().scan_cap,
            99,
            "reset_budget must clear the cap override"
        );
    }
}
