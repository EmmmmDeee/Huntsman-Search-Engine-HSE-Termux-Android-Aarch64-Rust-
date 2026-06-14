//! Public API endpoint functions for the SeekNow (see-know.eu) service.

use serde_json::Value;

use crate::core::error::Result;

use super::budget::{budget_try_increment, is_key_invalid};
use super::client::{base_url, cache_get, cache_put, get_json, post_json, typed_cache_key};

/// Max records per the see-know.eu Universal Search spec (`limit`, default 100,
/// **max 500**). Requested in full — the standing directive is to use
/// see-know.eu maximally, and one richer response costs the same budget slot as
/// a thin one.
pub(super) const SEARCH_LIMIT: u32 = 500;

/// Build the `POST /api/v1/search` request body per the see-know.eu spec:
/// `{"query": <q>, "type": <t>?, "limit": <n>}`. An empty `query_type` omits
/// `type` so the server auto-detects. Pure (JSON-escapes `query`) so it is
/// unit-tested.
pub(super) fn build_search_body(query: &str, query_type: &str, limit: u32) -> String {
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

/// Steam profile lookup via `GET /api/v1/gaming/steam?id=<value>`
///
/// Some plans publish gaming/steam alongside roblox/xbox/minecraft;
/// safe to call against arbitrary 17-digit Steam IDs surfaced from
/// breach data.
pub async fn steam_profile(key: &str, steam_id: &str) -> Result<Vec<Value>> {
    get_path(key, "gaming/steam", &[("id", steam_id)]).await
}

// Single-parameter GET endpoints (domain/intel,
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
/// `GET /api/v1/discord/user?id=<value>`
pub async fn discord_user(key: &str, discord_id: &str) -> Result<Vec<Value>> {
    get_path(key, "discord/user", &[("id", discord_id)]).await
}

/// Discord → Roblox linkage via `GET /api/v1/discord/to-roblox?id=<value>`
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

pub(super) fn extract_items(v: &Value) -> Vec<Value> {
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

pub(super) fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
