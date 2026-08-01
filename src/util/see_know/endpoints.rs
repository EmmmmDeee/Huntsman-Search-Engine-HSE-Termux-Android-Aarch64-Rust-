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
    //  - connection/network errors → retried via domain fallback
    //    (`post_json_with_fallback` tries all known domains before returning error)
    const EMPTY_RETRY_ATTEMPTS: u32 = 2;
    let mut attempt = 0u32;
    loop {
        match post_json_with_fallback("/search", key, &body, &archive_endpoint, query).await {
            Ok(resp) => {
                let items = extract_items(&resp);
                if !items.is_empty() {
                    super::data_log::log_search("/search", query, query_type, &items);
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

/// Deep search via `POST /api/v1/search/deep` — trawls slower, higher-yield
/// databases beyond the fast index's local-DB/low-latency sources (server cap
/// ~40s per `docs/SEEKNOW_SETUP.md`'s troubleshooting section, vs. `/search`'s
/// ~5s typical for a typed query). Same request contract as [`search`] —
/// identical body shape via [`build_search_body`], same 1-credit cost; the
/// see-know.eu docs list the two endpoints side by side with no differing
/// parameters, only depth of corpus searched (`docs/SEEKNOW_SETUP.md`'s own
/// FAQ: "Fast: Local DB + low-latency sources… Deep: Fast + slower high-yield
/// databases, maximum coverage").
///
/// Callers should reserve this for a confirmed EMPTY [`search`] result: it
/// costs the same credit but roughly 8x the latency, so calling it after a
/// fast HIT would waste both quota and wall-time for zero additional coverage
/// — this was never wired before (`docs/SEEKNOW_SETUP.md`: "HSE always calls
/// fast `/search`, never deep"), the single largest documented, unimplemented
/// coverage gap in the SeekNow integration.
pub async fn search_deep(key: &str, query: &str, query_type: &str) -> Result<Vec<Value>> {
    // Separate cache namespace from `search` (`typed_cache_key` prefixes on
    // `path`) — fast and deep results for the same query never collide, and a
    // deep hit is cached independently so a repeat lookup this scan doesn't
    // re-pay the ~40s latency.
    let ck = typed_cache_key("search_deep", query, query_type);
    if let Some(cached) = cache_get(&ck) {
        return Ok(cached);
    }
    if is_key_invalid() || !budget_try_increment() {
        return Ok(Vec::new());
    }
    let body = build_search_body(query, query_type, SEARCH_LIMIT);
    let archive_endpoint = if query_type.is_empty() {
        "search-deep".to_string()
    } else {
        format!("search-deep-{query_type}")
    };
    // A single attempt on empty — a genuine deep-search miss, unlike fast
    // `/search`'s documented "server-side cap race on the name/auto path"
    // quirk that specifically justifies its own empty-result retry; there is
    // no equivalent documented flakiness for the deep path, and retrying an
    // already-~40s call would double the worst-case latency for no evidenced
    // benefit. Transport errors and rate-limits ARE still retried/backed-off
    // (mirrors `get_path`'s resilience contract for flaky mobile networks —
    // every other endpoint gets the same protection). Connection errors also
    // trigger domain fallback retries.
    const TRANSPORT_RETRY_ATTEMPTS: u32 = 2;
    let mut attempt = 0u32;
    loop {
        match post_json_with_fallback("/search/deep", key, &body, &archive_endpoint, query).await {
            Ok(resp) => {
                let items = extract_items(&resp);
                if !items.is_empty() {
                    super::data_log::log_search("/search/deep", query, query_type, &items);
                    cache_put(ck, items.clone());
                }
                return Ok(items);
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
                    "see_know /search/deep rate-limited — backing off"
                );
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
            Err(e) => {
                attempt += 1;
                if attempt >= TRANSPORT_RETRY_ATTEMPTS {
                    return Err(e);
                }
                tracing::debug!(
                    query_type,
                    attempt,
                    "see_know /search/deep errored — retrying once"
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
                if !RATE_LIMIT_BACKOFF.should_retry(attempt) {
                    return Err(Error::RateLimited(msg));
                }
                let delay = RATE_LIMIT_BACKOFF.delay(attempt);
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
                if !RATE_LIMIT_BACKOFF.should_retry(attempt) {
                    return Err(e);
                }
                let delay = RATE_LIMIT_BACKOFF.delay(attempt);
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
/// Also the diagnostic probe `hse doctor` uses to catch a dead/rejected key
/// BEFORE a scan discovers it only as SeekNow silently returning nothing:
/// an `invalid_api_key`/`plan_required` response here now latches
/// [`mark_key_invalid`] (previously only the data-bearing `search`/`get_path`
/// calls did this classification — a fresh process that only ever calls
/// `query_credits`, like `hse doctor`, could not detect a dead key at all).
///
/// Handles several observed response shapes:
/// ```json
/// {"credits_remaining": 4200, "daily_limit": 5000, "plan": "…"}
/// {"data": {"credits_remaining": 4200, "daily_limit": 5000}}
/// {"remaining": 4200, "total": 5000}
/// {"credits": {"remaining": 4200, "daily": 5000}}
/// ```
pub async fn query_credits(key: &str) -> Option<(u32, Option<u32>)> {
    match credits_probe(key).await {
        CreditsProbe::Ok {
            remaining,
            daily_limit,
        } => Some((remaining, daily_limit)),
        _ => None,
    }
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
    /// `curl exited 6: curl: (6) Could not resolve host: see-know.eu`) so the
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
        .and_then(serde_json::Value::as_u64)
    else {
        return CreditsOutcome::Unparseable;
    };

    let daily_limit = inner
        .get("daily_limit")
        .or_else(|| inner.get("total"))
        .or_else(|| inner.get("daily"))
        .and_then(serde_json::Value::as_u64)
        .map(|v| v as u32);

    CreditsOutcome::Data {
        remaining: remaining as u32,
        daily_limit,
    }
}

/// The distinguishable outcomes of the `/status` diagnostic probe, for `hse
/// doctor`'s SeekNow section — mirrors [`CreditsProbe`]'s shape and reasoning
/// exactly (see its doc for why transport, auth, and schema-drift failures
/// are kept as distinct variants a caller can tell apart). Unlike `/credits`,
/// no live `/status` response body has been captured against the real API —
/// `docs/SEEKNOW_SETUP.md` describes it only as showing "snusbase, leakcheck,
/// intelx, breachhub, etc. status" with no worked example — so `Ok` carries
/// the parsed object verbatim rather than a strongly-typed per-source shape
/// this code has no evidence for.
#[derive(Debug)]
pub enum StatusProbe {
    /// The host answered with a JSON object (top-level, or unwrapped from a
    /// `data` envelope) — carried verbatim for the caller to render.
    Ok(Value),
    /// A classified auth/plan rejection (`invalid_api_key` / `plan_required`).
    /// [`mark_key_invalid`] has been latched.
    InvalidKey,
    /// The API host could not be reached at all — DNS resolution, connection,
    /// or timeout failure. Carries curl's own diagnostic, same as
    /// [`CreditsProbe::Unreachable`]. NOT a dead key — never latches
    /// [`mark_key_invalid`].
    Unreachable(String),
    /// The host answered but the body wasn't a JSON object (schema drift, or
    /// a plan whose `/status` shape differs from what's documented).
    Unparseable,
}

/// Diagnostic probe of `GET /api/v1/status`, classifying the outcome for
/// `hse doctor`. Does NOT consume a budget slot (a free meta-query, like
/// [`credits_probe`]) and carries no entities to extract, so — like
/// `/credits` — it is never part of a per-target dispatch plan; it exists
/// solely so an operator can see upstream source health before a scan spends
/// budget against a data source that's already down.
pub async fn status_probe(key: &str) -> StatusProbe {
    let result = get_raw_with_fallback("/status", key)
        .await
        .map_err(|e| e.to_string());
    classify_status_probe(result)
}

/// Pure classification of a `/status` fetch result into a [`StatusProbe`].
/// Split from the network call so every branch is unit-tested directly,
/// mirroring [`classify_credits_probe`].
pub(super) fn classify_status_probe(result: std::result::Result<String, String>) -> StatusProbe {
    let body = match result {
        Ok(b) => b,
        // Transport failure (curl non-zero exit): keep the detail so doctor
        // can tell the operator it was DNS / connect / timeout, not a key
        // problem — same reasoning as `classify_credits_probe`.
        Err(detail) => return StatusProbe::Unreachable(detail),
    };
    if is_auth_error(&body) {
        mark_key_invalid(&body);
        return StatusProbe::InvalidKey;
    }
    let Ok(v) = serde_json::from_str::<Value>(body.trim()) else {
        return StatusProbe::Unparseable;
    };
    // Unwrap a `{"data": {...}}` envelope, mirroring `parse_credits_body`'s
    // root-selection — the same envelope shape `/credits` uses on some plans.
    let root = v.get("data").cloned().unwrap_or(v);
    if root.is_object() {
        StatusProbe::Ok(root)
    } else {
        StatusProbe::Unparseable
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
