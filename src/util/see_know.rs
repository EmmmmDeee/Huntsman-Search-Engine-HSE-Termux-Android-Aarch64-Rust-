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
//! Auth: `X-API-Key: <key>` header (per the see-know.eu spec).
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

// Embedded fallback: the single-source-of-truth default lives in `util::keys`.
const HARDCODED_KEY: &str = crate::util::keys::SEEKNOW_DEFAULT_KEY;

pub const KEY_ENV: &str = "HUNTSMAN_SEEKNOW_KEY";

/// Per-process response cache backed by the shared
/// [`ResponseCache`] primitive (cap 1024 — sized to comfortably hold
/// every distinct endpoint × query a single scan generates).
static RESPONSE_CACHE: ResponseCache<Vec<Value>> = ResponseCache::new(1024);

/// Shared curl-subprocess client. `X-API-Key` auth (per the see-know.eu spec —
/// the server rejects `Authorization: Bearer` with "Missing API key. Use
/// X-API-Key"), 75s curl timeout, 78s outer tokio timeout.
// The name/auto `/search` path has a server-side cap of ~55s and routinely
// responds in 50–60s with real data. The previous 12s curl / 15s outer budget
// guaranteed a timeout-exit (curl 28) on every name search, surfacing as an
// opaque "curl failed" with zero entities. Budget above the cap: 75s curl,
// 78s outer (curl < outer so curl's own exit code is observed), paired with an
// 80s module max_timeout in `modules::see_know`.
static CLIENT: CurlClient = CurlClient::new("seek_now", AuthScheme::XApiKey, 75, 78_000);

/// Per-scan + per-session quota budget for SeekNow API calls.
///
/// SeekNow's premiumhq plan grants 5,000 daily lookups. The operator's
/// standing directive is to use see-know.eu *maximally* — extensively, within
/// reason, on every remotely promising seed — to maximise cross-correlation
/// and the confidence of recursive searching. So each scan gets a 160-query
/// envelope (env-tunable via `HUNTSMAN_SEEKNOW_SCAN_CAP`, runtime-overridable
/// via `ScanOptions::seeknow_scan_cap`). A single Username seed alone plans up
/// to 13 specialised endpoints (social aggregate, github, twitter, reddit,
/// tiktok, history, breachhub, roblox, xbox, minecraft, + discord/steam pivots)
/// on top of the universal `/search`; with depth expansion every discovered
/// username/email/phone/domain consumes its own matrix, so a cap of 160 lets
/// the full 18-endpoint pool fire across ~10 recursively-discovered pivots in
/// one scan — corroborating far more of the graph — while still allowing many
/// full scans before the daily 5,000 ceiling. The cap is refreshed at each
/// expansion-round boundary ([`refresh_round_budget`]) so SeekNow participates
/// in EVERY iteration; the 500-query session ceiling (env-tunable via
/// `HUNTSMAN_SEEKNOW_SESSION_CAP`, hard-clamped to 500 by the engine) bounds the
/// total across all rounds of a deep scan — the "bound everything" invariant for
/// a 4 GB device — while leaving room for ~3 full rounds at the per-round cap.
static BUDGET: QuotaBudget = QuotaBudget::new(
    "seeknow",
    160,
    500,
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
    // Never cache an empty result. SeekNow's name/auto `/search` path
    // intermittently returns `total:0` for records that do exist (server-side
    // cap races); caching that empty would poison every subsequent lookup of
    // the same query for the life of the process. Only positive hits are
    // memoised — a transient miss is always re-queried (bounded by budget).
    if items.is_empty() {
        return;
    }
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

// Test-only now: production reserves atomically via `budget_try_increment`.
#[cfg(test)]
fn budget_increment() {
    BUDGET.increment();
}

/// Atomically reserve one query against the SeekNow budget (see
/// [`crate::util::budget::QuotaBudget::try_increment`]). Replaces the racy
/// `budget_remaining()`-then-`budget_increment()` gate so the concurrent
/// endpoint fan-out can't overspend the per-scan/per-round cap.
fn budget_try_increment() -> bool {
    BUDGET.try_increment()
}

pub fn is_quota_exhausted() -> bool {
    BUDGET.is_exhausted()
}

pub fn reset_budget() {
    BUDGET.reset_scan();
    // Re-test the key each scan: if the operator fixed it (UI Settings /
    // HUNTSMAN_SEEKNOW_KEY) since the last scan, SeekNow recovers immediately;
    // if it's still bad, the first call this scan re-latches (one warning, then
    // the remaining ~160 lookups fast-fail).
    KEY_INVALID.store(false, std::sync::atomic::Ordering::Relaxed);
}

/// Refresh SeekNow's per-round budget at each expansion-round boundary so it is
/// utilised in EVERY iteration of a scan, not just until a wide first round
/// drains the budget. Resets only the per-round counter — the per-session
/// ceiling still bounds total volume across all rounds, the operator's cap
/// override survives, and a latched-invalid key stays latched (we do not
/// re-attempt a dead key every round, unlike the per-scan [`reset_budget`]).
pub fn refresh_round_budget() {
    BUDGET.reset_round();
}

fn mark_quota_exhausted() {
    BUDGET.mark_exhausted();
    tracing::warn!("SeekNow daily quota exhausted — skipping remaining queries");
}

/// Latched once per process when see-know.eu rejects the configured API key.
///
/// curl exits 0 on an HTTP 401 (it got a response), so the shared curl client
/// reports success and the `{"error":"invalid_api_key"}` body parses to zero
/// items — which previously made SeekNow look like it "found nothing" on every
/// seed instead of "the key is bad". This latch makes the failure explicit and
/// fast-fails the remaining ~160 doomed lookups for the rest of the scan. It is
/// cleared by [`reset_budget`] at the start of each scan so a corrected key
/// (UI Settings / `HUNTSMAN_SEEKNOW_KEY`) recovers without a process restart.
static KEY_INVALID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// True once see-know.eu has rejected the key. The diagnostic accessor for
/// `hse doctor` / the selftest to report it as an actionable problem.
pub fn is_key_invalid() -> bool {
    KEY_INVALID.load(std::sync::atomic::Ordering::Relaxed)
}

/// Body signature of a key that cannot retrieve data — so the whole scan should
/// latch and stop spending budget on calls that will all come back empty. Two
/// distinct causes, both terminal for the held key:
///   * an outright auth rejection — `{"error":"invalid_api_key",…}` (wrong key)
///     or "…Missing API key. Use X-API-Key…" (header absent);
///   * a recognised key whose account lacks a paid plan —
///     `{"error":"plan_required",…}` (the live see-know.eu response for a
///     free-tier key). The fix to the auth header alone can't unblock this — the
///     account needs a plan — so we treat it the same: skip and warn once.
///
/// Pure (no globals) so it is unit-testable.
fn is_auth_error(body: &str) -> bool {
    body.contains("invalid_api_key")
        || body.contains("Invalid API key")
        || body.contains("plan_required")
}

fn mark_key_invalid(body: &str) {
    // Emit the actionable guidance exactly once (the false→true transition),
    // naming the actual cause so the operator knows whether to swap the key or
    // upgrade the plan.
    if !KEY_INVALID.swap(true, std::sync::atomic::Ordering::Relaxed) {
        let reason = if body.contains("plan_required") {
            "the account has no paid plan (plan_required) — upgrade at https://see-know.eu/pricing"
        } else {
            "the API key was rejected (invalid_api_key)"
        };
        tracing::warn!(
            "SeekNow (see-know.eu) lookups disabled: {reason}. Set a valid, \
             plan-enabled key via HUNTSMAN_SEEKNOW_KEY or the UI Settings panel."
        );
    }
}

fn base_url() -> String {
    std::env::var("HUNTSMAN_SEEKNOW_BASE")
        .unwrap_or_else(|_| "https://see-know.eu/api/v1".to_string())
}

pub fn resolve_key(ctx_key: Option<&str>) -> &str {
    crate::util::keys::resolve_or_default(ctx_key, HARDCODED_KEY)
}

/// Max records per the see-know.eu Universal Search spec (`limit`, default 100,
/// **max 500**). Requested in full — the standing directive is to use
/// see-know.eu maximally, and one richer response costs the same budget slot as
/// a thin one.
const SEARCH_LIMIT: u32 = 500;

/// Build the `POST /api/v1/search` request body per the see-know.eu spec:
/// `{"query": <q>, "type": <t>?, "limit": <n>}`. An empty `query_type` omits
/// `type` so the server auto-detects. Pure (JSON-escapes `query`) so it is
/// unit-tested.
fn build_search_body(query: &str, query_type: &str, limit: u32) -> String {
    if query_type.is_empty() {
        format!(r#"{{"query":"{}","limit":{}}}"#, escape_json(query), limit)
    } else {
        format!(
            r#"{{"query":"{}","type":"{}","limit":{}}}"#,
            escape_json(query),
            query_type,
            limit
        )
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
    // Atomically reserve a budget slot (replaces the racy
    // remaining()-then-increment() that the concurrent endpoint fan-out could
    // overspend); the key-invalid latch short-circuits before reserving.
    if is_key_invalid() || !budget_try_increment() {
        return Ok(Vec::new());
    }
    let url = format!("{}/search", base_url());
    let body = build_search_body(query, query_type, SEARCH_LIMIT);
    // Human archive label: `search` (auto-detect) or `search-<type>` (typed),
    // with the actual looked-up value — so the saved filename names exactly what
    // was queried.
    let archive_endpoint = if query_type.is_empty() {
        "search".to_string()
    } else {
        format!("search-{query_type}")
    };
    // The name/auto `/search` path intermittently returns `total:0` even when
    // the record exists (server-side cap races). Retry once on a transient
    // empty before giving up. `cache_put` already refuses to memoise an empty
    // result, so a transient miss can never poison later lookups of this query.
    const MAX_ATTEMPTS: u32 = 2;
    let mut last_err = None;
    for attempt in 0..MAX_ATTEMPTS {
        match post_json(&url, key, &body, &archive_endpoint, query).await {
            Ok(resp) => {
                let items = extract_items(&resp);
                if !items.is_empty() {
                    cache_put(ck, items.clone());
                    return Ok(items);
                }
                // Transient empty: not cached. Retry if attempts remain.
            }
            Err(e) => last_err = Some(e),
        }
        if attempt + 1 < MAX_ATTEMPTS {
            tracing::debug!(
                query_type,
                attempt = attempt + 1,
                "see_know /search returned empty or errored — retrying once"
            );
        }
    }
    // Both attempts empty/errored. Surface the error (so the curl exit code
    // reaches the logs) if we have one; otherwise an uncached empty vec.
    match last_err {
        Some(e) => Err(e),
        None => Ok(Vec::new()),
    }
}

/// Steam profile lookup via GET /api/v1/gaming/steam?id=<value>
///
/// Some plans publish gaming/steam alongside roblox/xbox/minecraft;
/// safe to call against arbitrary 17-digit Steam IDs surfaced from
/// breach data.
pub async fn steam_profile(key: &str, steam_id: &str) -> Result<Vec<Value>> {
    get_path(key, "gaming/steam", &[("id", steam_id)]).await
}

// Single-parameter GET endpoints (stealer, breachhub/search, domain/intel,
// network/{ip,phone,email-check}, username/{github,twitter,reddit,tiktok,
// social,history}, gaming/{roblox,xbox,minecraft}, domain/whois) carry no
// behaviour beyond `get_path(path, &[(param, value)])`, so they are dispatched
// table-driven from `EndpointCall::spec` in `modules::see_know::endpoints` via the shared
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
    // Atomically reserve a budget slot (replaces the racy
    // remaining()-then-increment() that the concurrent endpoint fan-out could
    // overspend); the key-invalid latch short-circuits before reserving.
    if is_key_invalid() || !budget_try_increment() {
        return Ok(Vec::new());
    }
    let url = format!("{}/{path}?{qs}", base_url());
    // Human archive label: the endpoint path (e.g. `stealer`,
    // `breachhub/search`) and the actual looked-up value (first query param),
    // so the saved filename names exactly what was queried.
    let archive_query = params.first().map(|(_, v)| *v).unwrap_or("");
    // One retry on a transient transport error — flaky mobile/Termux networks
    // drop GETs, and a single-shot call silently loses that endpoint's data
    // (the live transcripts are full of such drops). The retry reuses the same
    // budget slot, so resilience costs no extra quota. We do NOT retry a
    // successful-but-empty response: most of the 18-endpoint matrix legitimately
    // returns empty for a given seed, and retrying those would double scan
    // wall-time for no gain. `cache_put` already refuses to memoise an empty
    // result, so a genuine miss never poisons a later lookup.
    const MAX_ATTEMPTS: u32 = 2;
    let mut last_err = None;
    for attempt in 0..MAX_ATTEMPTS {
        match get_json(&url, key, path, archive_query).await {
            Ok(resp) => {
                let items = extract_items(&resp);
                cache_put(ck.clone(), items.clone());
                return Ok(items);
            }
            Err(e) => {
                if attempt + 1 < MAX_ATTEMPTS {
                    tracing::debug!(
                        path,
                        attempt = attempt + 1,
                        "see_know GET errored — retrying once"
                    );
                }
                last_err = Some(e);
            }
        }
    }
    match last_err {
        Some(e) => Err(e),
        None => Ok(Vec::new()),
    }
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

async fn get_json(url: &str, key: &str, endpoint: &str, query: &str) -> Result<Value> {
    let body = CLIENT.get(url, key).await?;
    // Retain the paid response verbatim BEFORE parsing/extraction — operator
    // policy: purchased data is kept in absolute completeness until manually
    // deleted (see `util::raw_archive`). `endpoint`/`query` name the saved file
    // so it's obvious what was looked up. Empty bodies are skipped by the archive.
    crate::util::raw_archive::record("see-know", endpoint, query, &body);
    parse_response(&body)
}

async fn post_json(url: &str, key: &str, body: &str, endpoint: &str, query: &str) -> Result<Value> {
    let resp = CLIENT.post_json(url, key, body).await?;
    // Archive the raw paid response verbatim, filed under the queried value.
    crate::util::raw_archive::record("see-know", endpoint, query, &resp);
    parse_response(&resp)
}

fn parse_response(body: &str) -> Result<Value> {
    // Invalid/rejected API key — curl returns the 401 body as "success", so
    // detect it here, latch it, and surface the actionable warning.
    if is_auth_error(body) {
        mark_key_invalid(body);
        return Ok(Value::Null);
    }
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
// Shared JSON helper — single definition in `util::json`, re-exported here so
// existing `crate::util::see_know::val_str` call sites are unchanged.
pub use crate::util::json::val_str;

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
    fn search_body_includes_limit_and_optional_type() {
        // Auto-detect: no `type`, always the spec's max `limit`.
        assert_eq!(
            build_search_body("john@example.com", "", SEARCH_LIMIT),
            r#"{"query":"john@example.com","limit":500}"#
        );
        // Typed query carries `type` too.
        assert_eq!(
            build_search_body("alice", "username", 50),
            r#"{"query":"alice","type":"username","limit":50}"#
        );
        // The query is JSON-escaped (a quote can't break out of the body).
        assert_eq!(
            build_search_body("a\"b", "", 1),
            r#"{"query":"a\"b","limit":1}"#
        );
        // We request the spec maximum (default would be 100).
        assert_eq!(SEARCH_LIMIT, 500);
    }

    #[test]
    fn seeknow_client_uses_x_api_key_per_spec() {
        // Regression guard for the auth header: see-know.eu requires X-API-Key
        // and rejects Authorization: Bearer ("Missing API key. Use X-API-Key").
        assert_eq!(CLIENT.auth_scheme(), AuthScheme::XApiKey);
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
    fn auth_error_envelope_is_detected() {
        // The literal body see-know.eu returns for a rejected key (curl exits 0
        // on a 401, so this is what reaches us). Detecting it is what turns
        // "SeekNow found nothing" into the actionable "the key is invalid".
        assert!(is_auth_error(
            r#"{"error":"invalid_api_key","message":"Invalid API key"}"#
        ));
        assert!(is_auth_error(
            r#"{"error":"invalid_api_key","message":"Missing API key. Use X-API-Key"}"#
        ));
        // A recognised key with no paid plan is also terminal — latch + skip.
        // (This is the live see-know.eu response observed for the bundled key.)
        assert!(is_auth_error(
            r#"{"error":"plan_required","message":"API access requires a paid plan. Upgrade at https://see-know.eu/pricing"}"#
        ));
        // A normal (empty or populated) result is NOT an auth error.
        assert!(!is_auth_error(r#"{"data":{"items":[]}}"#));
        assert!(!is_auth_error(r#"{"results":[{"email":"a@b.com"}]}"#));
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
    fn empty_results_are_never_cached_but_non_empty_are() {
        // Regression for the transient-empty poisoning bug: cache_put() must
        // refuse an empty result so a transient `total:0` cannot poison later
        // lookups of the same query, while a real hit is memoised.
        let empty_key = typed_cache_key("search", "transient-empty-probe", "name");
        cache_put(empty_key.clone(), Vec::new());
        assert!(
            cache_get(&empty_key).is_none(),
            "an empty result must not be served from cache (would poison retries)"
        );

        let hit_key = typed_cache_key("search", "real-hit-probe", "name");
        cache_put(
            hit_key.clone(),
            vec![serde_json::json!({"email": "x@y.com"})],
        );
        assert_eq!(
            cache_get(&hit_key).map(|v| v.len()),
            Some(1),
            "a non-empty result must be cached and retrievable"
        );
    }

    // Serialises the tests that touch the shared `BUDGET` global (scan-cap
    // override + budget counters). `cargo test` runs tests in parallel, so
    // without this they interleave `reset_budget()` / `set_scan_cap_override()`
    // and clobber each other — a real CI flake: a concurrent `reset_budget`
    // cleared an override mid-test, so `scan_cap` read the default (160)
    // instead of the value just set (80). parking_lot::Mutex never poisons if
    // a test panics while holding it.
    static BUDGET_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[test]
    fn scan_budget_remaining_decreases_with_increments() {
        let _guard = BUDGET_TEST_LOCK.lock();
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
        let _guard = BUDGET_TEST_LOCK.lock();
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
        // Regression guard for the operator's "use see-know.eu extensively"
        // directive. The legacy cap was 8 lookups (99.84% of quota unused);
        // it was raised to 120 and then to 160 so the full endpoint matrix
        // fires across ~10 recursively-discovered pivots per round. Lock the
        // floor at 120 so coverage can't silently regress below "extensive"
        // (the per-round cap; the per-session ceiling is separate, now 500).
        let _guard = BUDGET_TEST_LOCK.lock();
        reset_budget();
        let cap = budget_snapshot().scan_cap;
        assert!(
            (120..=200).contains(&cap),
            "scan cap {cap} outside the extensive-use band [120, 200]"
        );
    }

    #[test]
    fn set_scan_cap_override_replaces_default_until_reset() {
        let _guard = BUDGET_TEST_LOCK.lock();
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
        let _guard = BUDGET_TEST_LOCK.lock();
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
        let _guard = BUDGET_TEST_LOCK.lock();
        reset_budget();
        set_scan_cap_override(99);
        let snap = budget_snapshot();
        assert_eq!(snap.scan_cap, 99);
        reset_budget();
    }

    #[test]
    fn reset_clears_override_too() {
        let _guard = BUDGET_TEST_LOCK.lock();
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
