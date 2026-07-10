//! Public API endpoint functions for the SeekNow (see-know.icu) service.

use serde_json::Value;

use crate::core::error::Result;

use super::budget::{budget_try_increment, is_key_invalid};
use super::client::{base_url, cache_get, cache_put, get_json, post_json, typed_cache_key};

/// Max records per the see-know.icu Universal Search spec (`limit`, default 100,
/// **max 500**). Requested in full — the standing directive is to use
/// see-know.icu maximally, and one richer response costs the same budget slot as
/// a thin one.
pub(super) const SEARCH_LIMIT: u32 = 500;

/// Build the `POST /api/v1/search` request body per the see-know.icu spec:
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

/// The outcome of a universal `/search`: the extracted records plus the server's
/// own corpus counters from the response envelope
/// (`breach_count`/`stealer_count`/`external_count`/`total`).
///
/// The counters are the authoritative corpus size; `items.len()` is only what
/// was returned under the `SEARCH_LIMIT` (500) cap, so `server_total` can exceed
/// it and reveals that results were truncated — the single most useful piece of
/// scan metadata the response carries, which was previously parsed and discarded.
///
/// The counters are `None` on a CACHE HIT (the response cache stores only the
/// record array, not the envelope), so a caller MUST fall back to `items.len()`
/// when a counter is `None` — never treat `None` as zero.
#[derive(Debug, Default, Clone)]
pub struct SearchOutcome {
    pub items: Vec<Value>,
    pub breach_count: Option<u64>,
    pub stealer_count: Option<u64>,
    pub external_count: Option<u64>,
    pub server_total: Option<u64>,
}

/// Universal search via POST /api/v1/search.
///
/// The `query_type` is one of: email, username, domain, ip, phone,
/// discord_id, steam_id. Pass an empty string for auto-detect.
pub async fn search(key: &str, query: &str, query_type: &str) -> Result<SearchOutcome> {
    // Disambiguated cache key — auto-detect ("") and typed ("email")
    // queries on the same value used to collide, masking the typed
    // variant's specialised result rows.
    let ck = typed_cache_key("search", query, query_type);
    if let Some(cached) = cache_get(&ck) {
        // Cache stores only the records; counters are unavailable on a hit.
        return Ok(SearchOutcome {
            items: cached,
            ..Default::default()
        });
    }
    // Atomically reserve a budget slot (replaces the racy
    // remaining()-then-increment() that the concurrent endpoint fan-out could
    // overspend); the key-invalid latch short-circuits before reserving.
    if is_key_invalid() || !budget_try_increment() {
        return Ok(SearchOutcome::default());
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
                    // Read the envelope counters BEFORE returning — top-level per
                    // the live shape, with a `/data` fallback for a wrapped body.
                    let count = |k: &str| {
                        resp.get(k)
                            .and_then(Value::as_u64)
                            .or_else(|| resp.pointer(&format!("/data/{k}")).and_then(Value::as_u64))
                    };
                    return Ok(SearchOutcome {
                        breach_count: count("breach_count"),
                        stealer_count: count("stealer_count"),
                        external_count: count("external_count"),
                        server_total: count("total"),
                        items,
                    });
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
    // reaches the logs) if we have one; otherwise an uncached empty outcome.
    match last_err {
        Some(e) => Err(e),
        None => Ok(SearchOutcome::default()),
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
    // { data: [...] } (array), { data: { results|victims: [...] } }, { data: {...} }
    // (single object), a top-level array, or — for the stealer endpoint —
    // { results: 0, victims: [ { log_id, credentials: [...] } ] }.
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
    // Data nested under `data` in one of the collection shapes. These probe INTO
    // the `data` object, so they must precede the single-object wrap below (a
    // `{data:{results:[…]}}` payload is a collection, not one record). Order among
    // them is safe: a normal `data:{scalars}` object matches none of these.
    // Without these, `{data:[…]}` fell through every branch (100% loss) and
    // `{data:{results:[…]}}` was wrapped as one opaque object — degrading a
    // future/array-shaped endpoint (e.g. `username/history`) to zero yield.
    if let Some(arr) = v.pointer("/data").and_then(|v| v.as_array()) {
        return arr.clone();
    }
    if let Some(items) = v.pointer("/data/results").and_then(|v| v.as_array()) {
        return items.clone();
    }
    if let Some(victims) = v.pointer("/data/victims").and_then(|v| v.as_array()) {
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
/// {"plan":"enterprise","credits_remaining":15000,"credits_daily_limit":15000,"credits_used_today":0}
/// {"credits_remaining": 4200, "daily_limit": 5000, "plan": "…"}
/// {"data": {"credits_remaining": 4200, "daily_limit": 5000}}
/// {"remaining": 4200, "total": 5000}
/// {"credits": {"remaining": 4200, "daily": 5000}}
/// ```
///
/// The live see-know.icu enterprise response is the FIRST shape:
/// `credits_daily_limit` (not `daily_limit`). Reading only `daily_limit`/`total`/
/// `daily` returned `None` for the daily cap, so
/// [`super::budget::scale_scan_cap_from_daily`] never saw the real 15k/day
/// ceiling and the scan cap fell back to the floor.
pub async fn query_credits(key: &str) -> Option<(u32, Option<u32>)> {
    let url = format!("{}/credits", base_url());
    // Direct HTTP call — no budget gate, no archive (meta-query, not paid data).
    let body = super::client::CLIENT.get(&url, key).await.ok()?;
    let v: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    parse_credits(&v)
}

/// A `/credits` meter coerced to `u32`, tolerant of number-serialization drift:
/// a bare JSON number, a stringified number (`"15000"`), or a float
/// (`15000.0`). `u32::try_from` cleanly rejects an out-of-range value rather than
/// silently truncating with `as`. Mirrors the numeric-string tolerance
/// `geo::parse_coord` already applies elsewhere — the same provider serializes
/// numbers inconsistently, and this is the one call that governs paid-budget
/// scaling, so a stringified meter must not collapse the whole parse to `None`
/// (which pins the scan cap at the floor).
fn credit_as_u32(v: &serde_json::Value) -> Option<u32> {
    let n = v
        .as_u64()
        .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
        .or_else(|| v.as_f64().map(|f| f as u64))?;
    u32::try_from(n).ok()
}

/// Pure extractor for `(credits_remaining, daily_limit)` from a `/credits`
/// response body, split out so the multi-shape field-walk is unit-testable
/// without a live call. `daily_limit` is `None` when the response omits it.
pub(super) fn parse_credits(v: &serde_json::Value) -> Option<(u32, Option<u32>)> {
    // Walk candidate shapes to find (remaining, daily_limit).
    let root = if let Some(d) = v.get("data") { d } else { v };
    let inner = root.get("credits").unwrap_or(root);

    let remaining = inner
        .get("credits_remaining")
        .or_else(|| inner.get("remaining"))
        .and_then(credit_as_u32)?;

    let daily_limit = inner
        .get("credits_daily_limit")
        .or_else(|| inner.get("daily_limit"))
        .or_else(|| inner.get("total"))
        .or_else(|| inner.get("daily"))
        .and_then(credit_as_u32);

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
