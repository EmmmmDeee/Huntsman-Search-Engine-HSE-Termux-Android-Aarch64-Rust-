//! Public API endpoint functions for the SeekNow (see-know.eu) service.

use serde_json::Value;

use crate::core::error::{Error, Result};
use crate::util::backoff::BackoffPolicy;

use super::budget::{budget_try_increment, is_key_invalid};
use super::client::{base_url, cache_get, cache_put, get_json, post_json, typed_cache_key};

/// Retry pacing for a transient see-know.eu rate-limit response
/// (`Error::RateLimited`, distinct from true quota exhaustion — see
/// `client::Terminal::RateLimited`'s doc comment). 3 attempts (the initial
/// call plus 2 retries), doubling 2s → 4s, capped at 8s, jittered so several
/// concurrently-dispatched endpoint calls that all get rate-limited at once
/// don't all retry in lockstep. These are the same figures a prior,
/// never-wired `RETRY_STRATEGY` constant in `orchestration.rs` already
/// specified — reused here now that they have a real, live call site.
const RATE_LIMIT_BACKOFF: BackoffPolicy = BackoffPolicy::new(3, 2_000, 8_000, true);

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
    // Two independent, differently-paced retry classes share this loop:
    //  - a transient EMPTY result (server-side cap race on the name/auto path)
    //    → retry once immediately, no delay. `cache_put` already refuses to
    //    memoise an empty result, so a transient miss can never poison later
    //    lookups of this query.
    //  - a transient RATE-LIMIT response (`Error::RateLimited`, distinct from
    //    true quota exhaustion — see `client::Terminal::RateLimited`) → retry
    //    with exponential backoff (`RATE_LIMIT_BACKOFF`) instead of giving up
    //    immediately, which is what happened before this was diagnosed: a
    //    burst throttle used to latch the shared budget and silently abandon
    //    SeekNow for the rest of the scan.
    const EMPTY_RETRY_ATTEMPTS: u32 = 2;
    let mut attempt = 0u32;
    loop {
        match post_json(&url, key, &body, &archive_endpoint, query).await {
            Ok(resp) => {
                let items = extract_items(&resp);
                if !items.is_empty() {
                    cache_put(ck, items.clone());
                    return Ok(items);
                }
                attempt += 1;
                if attempt >= EMPTY_RETRY_ATTEMPTS {
                    // Every attempt came back empty — an uncached genuine miss.
                    return Ok(Vec::new());
                }
                tracing::debug!(
                    query_type,
                    attempt,
                    "see_know /search returned empty — retrying once"
                );
            }
            Err(Error::RateLimited(msg)) => {
                if !RATE_LIMIT_BACKOFF.should_retry(attempt) {
                    return Err(Error::RateLimited(msg));
                }
                let delay = RATE_LIMIT_BACKOFF.delay(attempt);
                tracing::debug!(
                    query_type,
                    attempt = attempt + 1,
                    delay_ms = delay.as_millis() as u64,
                    "see_know /search rate-limited — backing off"
                );
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
            Err(e) => {
                attempt += 1;
                if attempt >= EMPTY_RETRY_ATTEMPTS {
                    return Err(e);
                }
                tracing::debug!(
                    query_type,
                    attempt,
                    "see_know /search errored — retrying once"
                );
            }
        }
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
    let archive_query = params.first().map_or("", |(_, v)| *v);
    // One retry on a transient transport error — flaky mobile/Termux networks
    // drop GETs, and a single-shot call silently loses that endpoint's data
    // (the live transcripts are full of such drops). The retry reuses the same
    // budget slot, so resilience costs no extra quota. We do NOT retry a
    // successful-but-empty response: most of the 18-endpoint matrix legitimately
    // returns empty for a given seed, and retrying those would double scan
    // wall-time for no gain. `cache_put` already refuses to memoise an empty
    // result, so a genuine miss never poisons a later lookup.
    //
    // A `RateLimited` error is paced separately (`RATE_LIMIT_BACKOFF`,
    // distinct from true quota exhaustion — see `client::Terminal::
    // RateLimited`): previously this response was classified identically to
    // exhausted credits, latching the shared budget and silently abandoning
    // SeekNow for every remaining endpoint call in the scan with zero
    // backoff or retry.
    const TRANSPORT_RETRY_ATTEMPTS: u32 = 2;
    let mut attempt = 0u32;
    loop {
        match get_json(&url, key, path, archive_query).await {
            Ok(resp) => {
                let items = extract_items(&resp);
                cache_put(ck.clone(), items.clone());
                return Ok(items);
            }
            Err(Error::RateLimited(msg)) => {
                if !RATE_LIMIT_BACKOFF.should_retry(attempt) {
                    return Err(Error::RateLimited(msg));
                }
                let delay = RATE_LIMIT_BACKOFF.delay(attempt);
                tracing::debug!(
                    path,
                    attempt = attempt + 1,
                    delay_ms = delay.as_millis() as u64,
                    "see_know GET rate-limited — backing off"
                );
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
            Err(e) => {
                attempt += 1;
                if attempt >= TRANSPORT_RETRY_ATTEMPTS {
                    return Err(e);
                }
                tracing::debug!(path, attempt, "see_know GET errored — retrying once");
            }
        }
    }
}

pub(super) fn extract_items(v: &Value) -> Vec<Value> {
    // SeekNow returns one of: { data: { items: [...] } }, { results: [...] },
    // { data: {...} } (single object), a top-level array, or — for the stealer
    // endpoint — { results: 0, victims: [ { log_id, credentials: [...] } ] }.
    if let Some(arr) = v.as_array() {
        return arr.clone();
    }
    if let Some(items) = v.pointer("/data/items").and_then(|v| v.as_array()) {
        return items.clone();
    }
    if let Some(results) = v.pointer("/results").and_then(|v| v.as_array()) {
        return results.clone();
    }
    // Stealer-log shape. The scalar `results` count is routinely `0` even when
    // `victims` carries data (so the array branch above falls through), and the
    // leaked credentials are nested a level down — `victims[].credentials[]`.
    // Reading only the flat shapes dropped 100% of stealer credentials. Flatten
    // them into standalone items so the extractor sees each leaked login.
    if let Some(victims) = v.pointer("/victims").and_then(|v| v.as_array()) {
        return flatten_victims(victims);
    }
    if let Some(data) = v.pointer("/data") {
        // Single-object data — wrap in a one-element vec for uniform handling.
        if data.is_object() {
            return vec![data.clone()];
        }
    }
    Vec::new()
}

/// Flatten SeekNow's stealer `victims[].credentials[]` nesting into standalone
/// credential items.
///
/// Each victim is one infected host (one stealer log). Its scalar context
/// (`log_id`, any host/system/`ip` fields) is inherited by every credential it
/// leaked, so the flattened item carries both the login (`username`/`password`)
/// and the host provenance — and the existing field extractor handles it
/// unchanged. A victim with no `credentials` array still surfaces as one item
/// so host-level intel is never lost. Nested non-credential structures are not
/// inherited (the extractor reads scalar fields).
fn flatten_victims(victims: &[Value]) -> Vec<Value> {
    let mut items = Vec::new();
    for victim in victims {
        let Some(vobj) = victim.as_object() else {
            continue;
        };
        let base: serde_json::Map<String, Value> = vobj
            .iter()
            .filter(|(k, val)| k.as_str() != "credentials" && (val.is_string() || val.is_number()))
            .map(|(k, val)| (k.clone(), val.clone()))
            .collect();
        match vobj.get("credentials").and_then(|c| c.as_array()) {
            Some(creds) if !creds.is_empty() => {
                for cred in creds {
                    let mut item = base.clone();
                    if let Some(cobj) = cred.as_object() {
                        for (k, val) in cobj {
                            item.insert(k.clone(), val.clone());
                        }
                    }
                    items.push(Value::Object(item));
                }
            }
            // A victim with no credentials still carries host-level intelligence.
            _ => items.push(Value::Object(base)),
        }
    }
    items
}

/// Query the remaining daily quota from `GET /api/v1/credits`.
///
/// Returns `(credits_remaining, daily_limit)`. `daily_limit` is `None` if
/// the response does not carry it (some plan tiers omit it). The call does
/// NOT consume a budget slot — it is a meta-query used to scale the scan cap
/// dynamically to the operator's actual plan, not a data lookup.
///
/// Handles several observed response shapes:
/// ```json
/// {"credits_remaining": 4200, "daily_limit": 5000, "plan": "…"}
/// {"data": {"credits_remaining": 4200, "daily_limit": 5000}}
/// {"remaining": 4200, "total": 5000}
/// {"credits": {"remaining": 4200, "daily": 5000}}
/// ```
pub async fn query_credits(key: &str) -> Option<(u32, Option<u32>)> {
    let url = format!("{}/credits", base_url());
    // Direct HTTP call — no budget gate, no archive (meta-query, not paid data).
    let body = super::client::CLIENT.get(&url, key).await.ok()?;
    let v: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    // Walk candidate shapes to find (remaining, daily_limit).
    let root = if let Some(d) = v.get("data") { d } else { &v };
    let inner = root.get("credits").unwrap_or(root);

    let remaining = inner
        .get("credits_remaining")
        .or_else(|| inner.get("remaining"))
        .and_then(serde_json::Value::as_u64)? as u32;

    let daily_limit = inner
        .get("daily_limit")
        .or_else(|| inner.get("total"))
        .or_else(|| inner.get("daily"))
        .and_then(serde_json::Value::as_u64)
        .map(|v| v as u32);

    Some((remaining, daily_limit))
}

/// Escape `s` for embedding inside a JSON string literal — the two body-builder
/// call sites add the surrounding quotes, so this returns the interior only.
/// Delegates to `serde_json` so backslash, quote AND the control bytes (`\n`,
/// `\r`, `\t`, other `< 0x20`) that are illegal raw in a JSON string are all
/// escaped; the hand-rolled version escaped only `\` and `"`, so a query
/// carrying a newline/tab produced invalid JSON. `to_string()` on a JSON string
/// `Value` yields `"…"`; strip the wrapping ASCII quotes to keep the contract.
pub(super) fn escape_json(s: &str) -> String {
    let quoted = serde_json::Value::String(s.to_owned()).to_string();
    quoted[1..quoted.len() - 1].to_owned()
}
