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

use std::sync::Mutex;
use std::time::Duration;

use serde_json::Value;

use crate::core::error::{Error, Result};

const HARDCODED_KEY: &str = "seek-4b33b63d408dd7149765da4e76384ce91fd9f6df518f9a25";

pub const KEY_ENV: &str = "HUNTSMAN_SEEKNOW_KEY";

static QUOTA_EXHAUSTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

static RESPONSE_CACHE: std::sync::LazyLock<Mutex<std::collections::HashMap<String, Vec<Value>>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::with_capacity(256)));

static QUERY_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static SESSION_QUERY_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// SeekNow's premiumhq plan grants 5,000 daily lookups. Each scan now
/// gets a richer per-scan envelope (default 24) so it can dispatch the
/// universal search plus ~10 specialised endpoints across the pivot
/// graph (Email + every discovered Username/Phone/Domain/IP in the
/// scan). The session cap stays at 200 so long-running radar / live
/// sessions stop short of the 5,000/day ceiling.
///
/// Both caps are tunable via `HUNTSMAN_SEEKNOW_SCAN_CAP` and
/// `HUNTSMAN_SEEKNOW_SESSION_CAP` for operators with different plan
/// tiers.
const DEFAULT_MAX_QUERIES_PER_SCAN: u32 = 24;

fn max_queries_per_scan() -> u32 {
    static CAP: std::sync::LazyLock<u32> = std::sync::LazyLock::new(|| {
        std::env::var("HUNTSMAN_SEEKNOW_SCAN_CAP")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&v: &u32| v > 0)
            .unwrap_or(DEFAULT_MAX_QUERIES_PER_SCAN)
    });
    *CAP
}

fn max_queries_per_session() -> u32 {
    static CAP: std::sync::LazyLock<u32> = std::sync::LazyLock::new(|| {
        std::env::var("HUNTSMAN_SEEKNOW_SESSION_CAP")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(200)
    });
    *CAP
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
    RESPONSE_CACHE
        .lock()
        .ok()
        .and_then(|cache| cache.get(key).cloned())
}

fn cache_put(key: String, items: Vec<Value>) {
    if let Ok(mut cache) = RESPONSE_CACHE.lock()
        && cache.len() < 1024
    {
        cache.insert(key, items);
    }
}

/// True if there's room in both the per-scan and per-session budgets.
/// Public so the module layer can short-circuit endpoint plans before
/// allocating per-endpoint futures.
pub fn budget_remaining() -> bool {
    QUERY_COUNT.load(std::sync::atomic::Ordering::Acquire) < max_queries_per_scan()
        && SESSION_QUERY_COUNT.load(std::sync::atomic::Ordering::Acquire)
            < max_queries_per_session()
}

/// Remaining queries in the per-scan budget. Used by the module-layer
/// planner to decide how many specialised endpoints to dispatch.
pub fn scan_budget_remaining() -> u32 {
    let cap = max_queries_per_scan();
    let used = QUERY_COUNT.load(std::sync::atomic::Ordering::Acquire);
    cap.saturating_sub(used)
}

/// Snapshot of current per-scan + per-session budget consumption.
/// Surfaced for diagnostics (`hse doctor`) and tests.
#[derive(Debug, Clone, Copy)]
pub struct BudgetSnapshot {
    pub scan_used: u32,
    pub scan_cap: u32,
    pub session_used: u32,
    pub session_cap: u32,
    pub quota_exhausted: bool,
}

pub fn budget_snapshot() -> BudgetSnapshot {
    BudgetSnapshot {
        scan_used: QUERY_COUNT.load(std::sync::atomic::Ordering::Acquire),
        scan_cap: max_queries_per_scan(),
        session_used: SESSION_QUERY_COUNT.load(std::sync::atomic::Ordering::Acquire),
        session_cap: max_queries_per_session(),
        quota_exhausted: is_quota_exhausted(),
    }
}

fn budget_increment() {
    QUERY_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    SESSION_QUERY_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

pub fn is_quota_exhausted() -> bool {
    QUOTA_EXHAUSTED.load(std::sync::atomic::Ordering::Acquire)
}

pub fn reset_budget() {
    QUERY_COUNT.store(0, std::sync::atomic::Ordering::Release);
    QUOTA_EXHAUSTED.store(false, std::sync::atomic::Ordering::Release);
}

fn mark_quota_exhausted() {
    QUOTA_EXHAUSTED.store(true, std::sync::atomic::Ordering::Release);
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
    let body = match curl_exec(&url, key, None).await {
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

/// Stealer-log search via GET /api/v1/stealer?q=<value>
pub async fn stealer(key: &str, query: &str) -> Result<Vec<Value>> {
    get_path(key, "stealer", &[("q", query)]).await
}

/// Breach record search via GET /api/v1/breachhub/search?q=<value>
pub async fn breachhub(key: &str, query: &str) -> Result<Vec<Value>> {
    get_path(key, "breachhub/search", &[("q", query)]).await
}

/// Domain intel via GET /api/v1/domain/intel?domain=<value>
pub async fn domain_intel(key: &str, domain: &str) -> Result<Vec<Value>> {
    get_path(key, "domain/intel", &[("domain", domain)]).await
}

/// IP enrichment via GET /api/v1/network/ip?ip=<value>
pub async fn ip_info(key: &str, ip: &str) -> Result<Vec<Value>> {
    get_path(key, "network/ip", &[("ip", ip)]).await
}

/// Phone enrichment via GET /api/v1/network/phone?phone=<value>
pub async fn phone_info(key: &str, phone: &str) -> Result<Vec<Value>> {
    get_path(key, "network/phone", &[("phone", phone)]).await
}

/// Email-check via GET /api/v1/network/email-check?email=<value>
pub async fn email_check(key: &str, email: &str) -> Result<Vec<Value>> {
    get_path(key, "network/email-check", &[("email", email)]).await
}

// ── Username-side identity-to-geolocation bridges ───────────────────────
//
// These endpoints turn a username into platform-specific profiles that
// frequently carry location/timezone/bio data, feeding the geo pipeline.

/// GitHub profile lookup via GET /api/v1/username/github?username=<value>
pub async fn github_profile(key: &str, username: &str) -> Result<Vec<Value>> {
    get_path(key, "username/github", &[("username", username)]).await
}

/// Twitter / X profile via GET /api/v1/username/twitter?username=<value>
pub async fn twitter_profile(key: &str, username: &str) -> Result<Vec<Value>> {
    get_path(key, "username/twitter", &[("username", username)]).await
}

/// Reddit profile via GET /api/v1/username/reddit?username=<value>
pub async fn reddit_profile(key: &str, username: &str) -> Result<Vec<Value>> {
    get_path(key, "username/reddit", &[("username", username)]).await
}

/// TikTok profile via GET /api/v1/username/tiktok?username=<value>
pub async fn tiktok_profile(key: &str, username: &str) -> Result<Vec<Value>> {
    get_path(key, "username/tiktok", &[("username", username)]).await
}

/// Cross-platform social hits via GET /api/v1/username/social?username=<value>
pub async fn social_aggregate(key: &str, username: &str) -> Result<Vec<Value>> {
    get_path(key, "username/social", &[("username", username)]).await
}

/// Username change history via GET /api/v1/username/history?username=<value>
pub async fn username_history(key: &str, username: &str) -> Result<Vec<Value>> {
    get_path(key, "username/history", &[("username", username)]).await
}

/// Discord user info — captures region/timezone/connected-accounts via
/// GET /api/v1/discord/user?id=<value>
pub async fn discord_user(key: &str, discord_id: &str) -> Result<Vec<Value>> {
    get_path(key, "discord/user", &[("id", discord_id)]).await
}

/// Discord → Roblox linkage via GET /api/v1/discord/to-roblox?id=<value>
pub async fn discord_to_roblox(key: &str, discord_id: &str) -> Result<Vec<Value>> {
    get_path(key, "discord/to-roblox", &[("id", discord_id)]).await
}

/// Roblox profile via GET /api/v1/gaming/roblox?username=<value>
pub async fn roblox_profile(key: &str, username: &str) -> Result<Vec<Value>> {
    get_path(key, "gaming/roblox", &[("username", username)]).await
}

/// Xbox profile via GET /api/v1/gaming/xbox?gamertag=<value>
pub async fn xbox_profile(key: &str, gamertag: &str) -> Result<Vec<Value>> {
    get_path(key, "gaming/xbox", &[("gamertag", gamertag)]).await
}

/// Minecraft username history via GET /api/v1/gaming/minecraft?username=<value>
pub async fn minecraft_profile(key: &str, username: &str) -> Result<Vec<Value>> {
    get_path(key, "gaming/minecraft", &[("username", username)]).await
}

/// WHOIS via GET /api/v1/domain/whois?domain=<value>
pub async fn whois(key: &str, domain: &str) -> Result<Vec<Value>> {
    get_path(key, "domain/whois", &[("domain", domain)]).await
}

async fn get_path(key: &str, path: &str, params: &[(&str, &str)]) -> Result<Vec<Value>> {
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
    let body = curl_exec(url, key, None).await?;
    parse_response(&body)
}

async fn post_json(url: &str, key: &str, body: &str) -> Result<Value> {
    let resp = curl_exec(url, key, Some(body)).await?;
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

async fn curl_exec(url: &str, key: &str, post_body: Option<&str>) -> Result<String> {
    let secs = 12u64.to_string();
    let header = format!("Authorization: Bearer {key}");
    let mut cmd = tokio::process::Command::new("curl");
    cmd.args([
        "-s",
        "-L",
        "--max-time",
        &secs,
        "-A",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
        "-H",
        &header,
        "-H",
        "Accept: application/json",
    ]);
    if let Some(body) = post_body {
        cmd.args([
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            body,
        ]);
    }
    cmd.args(["--", url]);
    cmd.kill_on_drop(true);

    let output = tokio::time::timeout(Duration::from_millis(15_000), cmd.output())
        .await
        .map_err(|_| Error::module("seek_now", "timeout"))?
        .map_err(|e| Error::module("seek_now", e.to_string()))?;

    if !output.status.success() {
        return Err(Error::module("seek_now", "curl failed"));
    }
    String::from_utf8(output.stdout).map_err(|e| Error::module("seek_now", e.to_string()))
}

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
        assert_eq!(start, after + 1, "increment must consume exactly one credit");
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
        let cap = max_queries_per_scan();
        assert!(
            cap >= 16,
            "scan cap dropped to {cap} — must remain ≥ 16 to leverage SeekNow quota"
        );
    }
}
