//! Public API endpoint functions for the SeekNow (see-know.ru) service.

use serde_json::Value;

use crate::core::error::{Error, Result};
use crate::util::backoff::BackoffPolicy;

use super::budget::{budget_try_increment, is_key_invalid, mark_key_invalid};
use super::client::{
    cache_get, cache_put, get_json_with_fallback, get_raw_with_fallback, is_auth_error,
    post_json_with_fallback, typed_cache_key,
};
use super::enterprise_config::ENTERPRISE;

/// Retry pacing for a transient see-know.ru rate-limit response
/// (`Error::RateLimited`, distinct from true quota exhaustion — see
/// `client::Terminal::RateLimited`'s doc comment). [`ENTERPRISE`]`.max_retries`
/// attempts (the initial call plus 2 retries), doubling 2s → 4s, capped at
/// 8s, jittered so several concurrently-dispatched endpoint calls that all
/// get rate-limited at once don't all retry in lockstep. These are the same
/// figures a prior, never-wired `RETRY_STRATEGY` constant in
/// `orchestration.rs` already specified — reused here now that they have a
/// real, live call site.
const RATE_LIMIT_BACKOFF: BackoffPolicy =
    BackoffPolicy::new(ENTERPRISE.max_retries, 2_000, 8_000, true);

/// The delay a retry loop paced by [`RATE_LIMIT_BACKOFF`] should sleep before
/// its next attempt, or `None` once the policy's attempt budget is spent (the
/// caller should then return the terminal error). Shared by every retry loop
/// in this module that paces a transient failure through that one policy.
fn backoff_delay(attempt: u32) -> Option<std::time::Duration> {
    RATE_LIMIT_BACKOFF
        .should_retry(attempt)
        .then(|| RATE_LIMIT_BACKOFF.delay(attempt))
}

/// Max records per the see-know.ru Universal Search spec (`limit`, default 100,
/// **max 500**). Requested in full — the standing directive is to use
/// see-know.ru maximally, and one richer response costs the same budget slot as
/// a thin one.
pub(super) const SEARCH_LIMIT: u32 = 500;

/// Build the `POST /api/v1/search` request body per the see-know.ru spec:
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

/// Universal search via `POST /api/v1/search`.
///
/// The `query_type` is one of: email, username, domain, ip, phone,
/// discord_id, steam_id. Pass an empty string for auto-detect.
pub async fn search(key: &str, query: &str, query_type: &str) -> Result<SearchOutcome> {
    search_impl(key, query, query_type, false).await
}

/// Deep universal search via `POST /api/v1/search/deep` — same cost (1 credit) as
/// [`search`] but with MAX coverage: it additionally queries the slow sources the
/// standard `/search` skips (live-observed ~2× the `external_count` for the same
/// seed), returning `mode:"deep"`. ~40s server-side, within the module's 80s cap.
/// Its result set is a superset of `/search`, so the module uses it as the primary
/// universal query and only falls back to [`search`] when deep yields nothing.
///
/// Callers should reserve this for a confirmed EMPTY [`search`] result: it costs
/// the same credit but roughly 8x the latency, so calling it after a fast HIT
/// would waste both quota and wall-time for zero additional coverage.
pub async fn search_deep(key: &str, query: &str, query_type: &str) -> Result<SearchOutcome> {
    search_impl(key, query, query_type, true).await
}

/// Shared universal-search implementation for the standard (`/search`) and deep
/// (`/search/deep`) variants. `deep` switches the endpoint path, the cache
/// namespace (so a deep hit never masks a standard lookup or vice-versa), and the
/// archive label.
async fn search_impl(
    key: &str,
    query: &str,
    query_type: &str,
    deep: bool,
) -> Result<SearchOutcome> {
    // Distinct cache namespace per variant + per query_type, so auto-detect ("")
    // vs typed ("email") and standard vs deep never collide (which would mask a
    // richer result set behind a thinner cached one).
    let cache_ns = if deep { "search-deep" } else { "search" };
    let ck = typed_cache_key(cache_ns, query, query_type);
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
    let path = if deep { "search/deep" } else { "search" };
    let body = build_search_body(query, query_type, SEARCH_LIMIT);
    // Human archive label: variant + optional `-<type>`, with the actual looked-up
    // value — so the saved filename names exactly what was queried.
    let archive_endpoint = if query_type.is_empty() {
        cache_ns.to_string()
    } else {
        format!("{cache_ns}-{query_type}")
    };
    // Two independent, differently-paced retry classes share this loop:
    //  - a transient EMPTY result on the fast (non-deep) path (server-side cap
    //    race on the name/auto path) → retry once immediately, no delay.
    //    `cache_put` already refuses to memoise an empty result, so a transient
    //    miss can never poison later lookups of this query. The deep path skips
    //    this retry — an already-~40s call retried would double the worst-case
    //    latency for no evidenced benefit (there is no equivalent documented
    //    flakiness for `/search/deep`).
    //  - a transient RATE-LIMIT response (`Error::RateLimited`, distinct from
    //    true quota exhaustion — see `client::Terminal::RateLimited`) → retry
    //    with exponential backoff (`RATE_LIMIT_BACKOFF`) instead of giving up
    //    immediately, which is what happened before this was diagnosed: a
    //    burst throttle used to latch the shared budget and silently abandon
    //    SeekNow for the rest of the scan.
    //  - connection/network errors → retried via domain fallback
    //    (`post_json_with_fallback` tries all known domains before returning error)
    let empty_retry_attempts: u32 = if deep { 1 } else { 2 };
    let mut attempt = 0u32;
    loop {
        match post_json_with_fallback(&format!("/{path}"), key, &body, &archive_endpoint, query)
            .await
        {
            Ok(resp) => {
                let items = extract_items(&resp);
                if !items.is_empty() {
                    super::data_log::log_search(&format!("/{path}"), query, query_type, &items);
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
                attempt += 1;
                if attempt >= empty_retry_attempts {
                    // Every attempt came back empty — an uncached genuine miss.
                    return Ok(SearchOutcome::default());
                }
                tracing::debug!(
                    query_type,
                    deep,
                    attempt,
                    "see_know /{path} returned empty — retrying once"
                );
            }
            Err(Error::RateLimited(msg)) => {
                let Some(delay) = backoff_delay(attempt) else {
                    return Err(Error::RateLimited(msg));
                };
                tracing::debug!(
                    query_type,
                    deep,
                    attempt = attempt + 1,
                    delay_ms = delay.as_millis() as u64,
                    "see_know /{path} rate-limited — backing off"
                );
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
            Err(e) => {
                attempt += 1;
                if attempt > empty_retry_attempts {
                    return Err(e);
                }
                tracing::debug!(
                    query_type,
                    deep,
                    attempt,
                    "see_know /{path} errored — retrying once"
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
    let endpoint_path = format!("/{path}");
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
    // backoff or retry. Connection errors also trigger domain fallback retries.
    let mut attempt = 0u32;
    loop {
        match get_json_with_fallback(&endpoint_path, key, &qs, path, archive_query).await {
            Ok(resp) => {
                let items = extract_items(&resp);
                super::data_log::log_search(&endpoint_path, archive_query, "", &items);
                cache_put(ck.clone(), items.clone());
                return Ok(items);
            }
            // Both transient classes — a burst rate-limit AND a 5xx/no-response
            // (now surfaced as `RateLimited` by `client::classify_status`) — pace
            // through the SAME `RATE_LIMIT_BACKOFF` (bounded by
            // `ENTERPRISE.max_retries`), so the whole retry budget lives in one
            // place instead of the old split policy.
            Err(Error::RateLimited(msg)) => {
                let Some(delay) = backoff_delay(attempt) else {
                    return Err(Error::RateLimited(msg));
                };
                tracing::debug!(
                    path,
                    attempt = attempt + 1,
                    delay_ms = delay.as_millis() as u64,
                    "see_know GET transient (rate-limit/5xx) — backing off"
                );
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
            // A plain transport error (connection drop on a flaky mobile link)
            // now ALSO backs off on that shared budget rather than the old
            // zero-delay double-shot — a genuine drop recovers on a paced retry.
            Err(e) => {
                let Some(delay) = backoff_delay(attempt) else {
                    return Err(e);
                };
                tracing::debug!(
                    path,
                    attempt = attempt + 1,
                    delay_ms = delay.as_millis() as u64,
                    "see_know GET transport error — backing off"
                );
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
        }
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
/// Also the diagnostic probe `hse doctor` uses to catch a dead/rejected key
/// BEFORE a scan discovers it only as SeekNow silently returning nothing:
/// an `invalid_api_key`/`plan_required` response here now latches
/// [`mark_key_invalid`] (previously only the data-bearing `search`/`get_path`
/// calls did this classification — a fresh process that only ever calls
/// `query_credits`, like `hse doctor`, could not detect a dead key at all).
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
/// The live see-know.ru enterprise response is the FIRST shape:
/// `credits_daily_limit` (not `daily_limit`). Reading only `daily_limit`/`total`/
/// `daily` returned `None` for the daily cap, so
/// [`super::budget::scale_scan_cap_from_daily`] never saw the real 15k/day
/// ceiling and the scan cap fell back to the floor.
pub async fn query_credits(key: &str) -> Option<(u32, Option<u32>)> {
    match credits_probe(key).await {
        CreditsProbe::Ok {
            remaining,
            daily_limit,
        } => Some((remaining, daily_limit)),
        _ => None,
    }
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

/// The distinguishable outcomes of the `/credits` diagnostic probe, for
/// `hse doctor`'s SeekNow section. `query_credits` collapses this to `Option`
/// for the budget-scaling / key-harvest callers that only need the number, but
/// a human diagnosing "why is SeekNow returning nothing?" needs the *class* of
/// failure — an unreachable API host (DNS/connect/timeout) is a completely
/// different fix from a rejected key, which is different again from a reachable
/// host returning an unrecognised body. A live Termux scan surfaced exactly
/// this ambiguity: every `see_know` call failed with `[seek_now] curl exited 6`
/// (curl's "could not resolve host"), then the circuit breaker cooled the
/// module down — but `query_credits`'s `.ok()?` discarded the curl detail, so
/// `hse doctor` could only report the catch-all "could not reach SeekNow",
/// giving the operator no signal that the real cause was DNS-level host
/// resolution (commonly carrier/ISP filtering of the domain), not a bad key or
/// an exhausted plan.
#[derive(Debug)]
pub enum CreditsProbe {
    /// The key works and the account has quota.
    Ok {
        remaining: u32,
        daily_limit: Option<u32>,
    },
    /// A classified auth/plan rejection (`invalid_api_key` / `plan_required`).
    /// [`mark_key_invalid`] has been latched.
    InvalidKey,
    /// The API host could not be reached at all — DNS resolution, connection,
    /// or timeout failure. Carries curl's own one-line diagnostic (e.g.
    /// `curl exited 6: curl: (6) Could not resolve host: see-know.ru`) so the
    /// operator sees WHICH host failed and WHY. NOT a dead key — never latches
    /// [`mark_key_invalid`].
    Unreachable(String),
    /// The host answered but the body carried no recognised `credits` field
    /// (schema drift, or a plan whose `/credits` shape this parser doesn't
    /// know). Reachable, so also not a confirmed dead key.
    Unparseable,
}

/// Diagnostic probe of `GET /api/v1/credits`, classifying the outcome for
/// `hse doctor`. Does NOT consume a budget slot. See [`CreditsProbe`] for why
/// the transport-failure case is kept distinct from an auth rejection.
pub async fn credits_probe(key: &str) -> CreditsProbe {
    // Direct HTTP call with multi-domain fallback — no budget gate, no archive
    // (meta-query, not paid data). Tries all known SeekNow domains (the service
    // intentionally rotates domains) before giving up. The transport error is
    // stringified and handed to the pure classifier so the Unreachable / auth /
    // schema branches are all unit-testable without a live round-trip.
    let result = get_raw_with_fallback("/credits", key)
        .await
        .map_err(|e| e.to_string());
    classify_credits_probe(result)
}

/// Pure classification of a `/credits` fetch result into a [`CreditsProbe`].
/// Split from the network call so every branch is unit-tested directly. The
/// auth branch is the only one with a side effect — it latches
/// [`mark_key_invalid`], matching the data-bearing `search`/`get_path` paths —
/// so a confirmed-dead key is caught even when this probe is the first-ever
/// call a process makes (`hse doctor`). Transport failures and unparseable
/// bodies are NOT confirmed dead keys and never latch it.
pub(super) fn classify_credits_probe(result: std::result::Result<String, String>) -> CreditsProbe {
    let body = match result {
        Ok(b) => b,
        // Transport failure (curl non-zero exit): keep the detail so doctor can
        // tell the operator it was DNS / connect / timeout, not a key problem.
        Err(detail) => return CreditsProbe::Unreachable(detail),
    };
    match parse_credits_body(&body) {
        CreditsOutcome::Data {
            remaining,
            daily_limit,
        } => CreditsProbe::Ok {
            remaining,
            daily_limit,
        },
        CreditsOutcome::AuthError => {
            mark_key_invalid(&body);
            CreditsProbe::InvalidKey
        }
        CreditsOutcome::Unparseable => CreditsProbe::Unparseable,
    }
}

/// The three distinguishable outcomes of parsing a raw `/credits` response
/// body. Kept separate from `Option<(u32, Option<u32>)>` specifically so an
/// auth rejection (a REAL, classified "this key is dead" signal) can never
/// be conflated with a merely-unparseable body (network noise, a schema this
/// function doesn't recognise) — the two must not both collapse to a bare
/// `None` the caller can't tell apart, since only the former should latch
/// [`mark_key_invalid`].
pub(super) enum CreditsOutcome {
    Data {
        remaining: u32,
        daily_limit: Option<u32>,
    },
    AuthError,
    Unparseable,
}

/// Parse a raw `/credits` response body. Pure (no network, no global state)
/// so the classification is unit-tested directly, without a live HTTP
/// round-trip.
pub(super) fn parse_credits_body(body: &str) -> CreditsOutcome {
    if is_auth_error(body) {
        return CreditsOutcome::AuthError;
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body.trim()) else {
        return CreditsOutcome::Unparseable;
    };
    // Walk candidate shapes to find (remaining, daily_limit).
    let root = if let Some(d) = v.get("data") { d } else { &v };
    let inner = root.get("credits").unwrap_or(root);

    let Some(remaining) = inner
        .get("credits_remaining")
        .or_else(|| inner.get("remaining"))
        .and_then(credit_as_u32)
    else {
        return CreditsOutcome::Unparseable;
    };

    // `credits_daily_limit` is the live see-know.ru enterprise field name;
    // `daily_limit`/`total`/`daily` cover the other observed response shapes.
    let daily_limit = inner
        .get("credits_daily_limit")
        .or_else(|| inner.get("daily_limit"))
        .or_else(|| inner.get("total"))
        .or_else(|| inner.get("daily"))
        .and_then(credit_as_u32);

    CreditsOutcome::Data {
        remaining,
        daily_limit,
    }
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
