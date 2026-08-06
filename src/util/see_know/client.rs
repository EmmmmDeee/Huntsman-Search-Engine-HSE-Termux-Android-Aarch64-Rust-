//! HTTP client, response cache, API key helpers, and low-level JSON I/O for
//! the SeekNow (see-know.eu) API.

use serde_json::Value;

use crate::core::error::{Error, Result};
use crate::util::curl_client::{AuthScheme, CurlClient};
use crate::util::response_cache::ResponseCache;

use super::budget::{mark_key_invalid, mark_quota_exhausted};
use super::enterprise_config::ENTERPRISE;

// Embedded fallback: the single-source-of-truth default lives in `util::keys`.
const HARDCODED_KEY: &str = crate::util::keys::SEEKNOW_DEFAULT_KEY;

/// Per-process response cache backed by the shared
/// [`ResponseCache`] primitive (cap [`ENTERPRISE`]`.cache_size` — sized to
/// comfortably hold every distinct endpoint × query a single scan
/// generates).
pub(super) static RESPONSE_CACHE: ResponseCache<Vec<Value>> =
    ResponseCache::new(ENTERPRISE.cache_size);

/// Shared curl-subprocess client. `X-API-Key` auth (per the see-know.eu spec —
/// the server rejects `Authorization: Bearer` with "Missing API key. Use
/// X-API-Key"), [`ENTERPRISE`]`.curl_timeout_secs` curl timeout,
/// `.tokio_timeout_millis` outer tokio timeout.
// The name/auto `/search` path has a server-side cap of ~55s and routinely
// responds in 50–60s with real data. The previous 12s curl / 15s outer budget
// guaranteed a timeout-exit (curl 28) on every name search, surfacing as an
// opaque "curl failed" with zero entities. Budget above the cap: 75s curl,
// 78s outer (curl < outer so curl's own exit code is observed), paired with an
// 80s module max_timeout in `modules::see_know`.
pub(super) static CLIENT: CurlClient = CurlClient::new(
    "seek_now",
    AuthScheme::XApiKey,
    ENTERPRISE.curl_timeout_secs,
    ENTERPRISE.tokio_timeout_millis,
);

/// Tighter-budgeted client for the FAST single-parameter GET endpoints
/// (`network/*`, `gaming/*`, `username/*`, `domain/*`, `discord/*`) — used by
/// [`get_json_with_fallback`]. Those answer in ~2–5 s, so they must not inherit [`CLIENT`]'s
/// wide 75 s ceiling (sized for the slow `/search` name path): a single hung GET
/// would otherwise burn up to 75 s of the module's per-scan timeout budget before
/// failing. `POST /search`/`/search/deep` keep the wide [`CLIENT`].
pub(super) static CLIENT_FAST: CurlClient = CurlClient::new(
    "seek_now",
    AuthScheme::XApiKey,
    ENTERPRISE.get_timeout_secs,
    ENTERPRISE.get_tokio_timeout_millis,
);

/// Cache key combining endpoint path, normalised query, and query
/// type (when applicable). Disambiguates the universal /search path
/// — auto-detect ("") and typed ("email") on the same value previously
/// collided, masking type-specific result variants.
pub(super) fn cache_key(path: &str, query: &str) -> String {
    format!("{path}:{}", query.to_lowercase())
}

pub(super) fn typed_cache_key(path: &str, query: &str, query_type: &str) -> String {
    if query_type.is_empty() {
        cache_key(path, query)
    } else {
        format!("{path}#{query_type}:{}", query.to_lowercase())
    }
}

pub(super) fn cache_get(key: &str) -> Option<Vec<Value>> {
    RESPONSE_CACHE.get(key)
}

pub(super) fn cache_put(key: String, items: Vec<Value>) {
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

/// The built-in primary endpoint absent any `HUNTSMAN_SEEKNOW_BASE` override.
/// Shared with [`all_base_urls`] so its "is an override actually active" check
/// can never drift from the literal `base_url` resolves against.
const DEFAULT_BASE: &str = "https://see-know.ru/api/v1";

pub fn base_url() -> String {
    // Default promoted (2026-07-29) to `.ru` — the operator-designated primary
    // endpoint SeekNow is currently using. Prior history: default started on
    // `.icu` (sandbox-confirmed reachable T2.83, 2026-07-13), was corrected to
    // `.eu` (2026-07-14) after a real device's DNS resolver failed to resolve
    // `.icu` (`curl exited 6`) while `.eu` succeeded, then to `.xyz`
    // (2026-07-21). `.xyz`, `.eu` and `.icu` remain fallbacks in
    // [`all_base_urls`] so a transient `.ru` outage still exhausts every known
    // domain before the scan surfaces a connection error — UNLESS the operator
    // has set an override, see that function's doc.
    // Vet the operator's override: refuse non-https / private-host redirects and
    // WARN on a divergent host, so a key-bearing request can't be silently
    // redirected to a look-alike or an internal address.
    crate::util::endpoint_override::resolve("HUNTSMAN_SEEKNOW_BASE", DEFAULT_BASE)
}

/// All SeekNow base URLs to try, in order. The service intentionally rotates
/// domains, so with NO operator override active, fallback attempts exhaustively
/// try all known public domains before surfacing a network/connection error,
/// letting the scan continue despite transient domain availability. Auth errors
/// (invalid key, plan required) are NOT retried across domains — if the key is
/// invalid on one, it's invalid on all.
///
/// An ACCEPTED `HUNTSMAN_SEEKNOW_BASE` override — [`base_url`] resolving to
/// anything other than [`DEFAULT_BASE`] — takes exclusive effect instead:
/// no public-domain fallback is appended. Previously every fallback attempt
/// still ran even with an override set, so a transient hiccup on the
/// operator's chosen endpoint silently sent the same key-bearing,
/// PII-bearing request on to see-know.eu/.icu/.ru — hosts the operator did not
/// choose, defeating the override's own purpose (see `endpoint_override`'s
/// doc comment on why a redirect must never be silent). It also actively
/// worked against the override's most-recommended use: `hse doctor` tells an
/// operator on a carrier that DNS-filters the public domains to point this
/// override at a reachable proxy — falling back to the direct domains from
/// there just reproduces the exact resolution failure the override exists
/// to route around. A rejected/unsafe override (`endpoint_override::resolve`
/// already WARNs and substitutes [`DEFAULT_BASE`]) is indistinguishable here
/// from no override at all, so it correctly still gets full rotation.
pub(super) fn all_base_urls() -> Vec<String> {
    base_urls_for(base_url())
}

/// [`all_base_urls`] split on the already-resolved primary URL, so the
/// override-exclusivity policy is unit-testable against a literal instead of
/// the real `HUNTSMAN_SEEKNOW_BASE` environment variable (which tests must
/// not mutate — `std::env::set_var` is `unsafe`, denied crate-wide).
pub(super) fn base_urls_for(primary: String) -> Vec<String> {
    if primary != DEFAULT_BASE {
        return vec![primary];
    }

    let mut urls = vec![primary];
    let fallbacks = [
        "https://see-know.xyz/api/v1",
        "https://see-know.eu/api/v1",
        "https://see-know.icu/api/v1",
    ];
    for fallback in &fallbacks {
        if !urls.contains(&fallback.to_string()) {
            urls.push(fallback.to_string());
        }
    }
    urls
}

/// The SeekNow API key to use for a request: the per-scan context key `ctx_key`
/// when the operator supplied one, otherwise the built-in default
/// ([`crate::util::keys::resolve_or_default`]). Mirrors `oathnet::resolve_key`.
#[must_use]
pub fn resolve_key(ctx_key: Option<&str>) -> &str {
    crate::util::keys::resolve_or_default(ctx_key, HARDCODED_KEY)
}

/// A stable, human-identifiable fingerprint of the SeekNow API key used for a
/// request, so EVERY derived entity records exactly which key/origin returned
/// it. Provider-prefixed head + short tail uniquely identifies the key (an
/// operator running several keys can tell which one produced a finding) without
/// scattering the full secret across the persisted entity store. Pure, so the
/// format is unit-testable.
///
/// The prefix is the domain-agnostic `"see-know"` label, not any one of the
/// three rotating domains ([`all_base_urls`]) — a request served by a fallback
/// domain still carries the same fingerprint, and the label never goes stale
/// when the primary domain changes (see the `provider` evidence attribute
/// fix this mirrors, in `see_know::extract`).
#[must_use]
pub fn key_fingerprint(key: &str) -> String {
    // Shared implementation in `util::key_fingerprint`; this fixes see-know's
    // label and truncation widths (show ≤18-byte keys whole, else 13…6).
    crate::util::key_fingerprint::fingerprint("see-know", key, 18, 13, 6)
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
pub(super) fn is_auth_error(body: &str) -> bool {
    body.contains("invalid_api_key")
        || body.contains("Invalid API key")
        || body.contains("plan_required")
}

/// A terminal condition that should stop the scan from spending more budget on
/// the held key — split so the caller latches the right global.
enum Terminal {
    /// The key itself is rejected (`invalid_api_key` / `plan_required`).
    Auth,
    /// The key is fine but its quota/credits are spent for the rest of the
    /// day — retrying can't help until the next billing period, so this
    /// latches [`mark_quota_exhausted`] and the scan gives up on SeekNow.
    Quota,
    /// A transient burst-rate-limit (`{"error":"rate_limit"}`) — DISTINCT
    /// from [`Terminal::Quota`]: the key still has credits, the request was
    /// simply too fast. Diagnosed as a real bug: this used to be classified
    /// identically to true quota exhaustion, so one 429-shaped response
    /// permanently latched the budget and silently abandoned SeekNow for the
    /// rest of the scan (every remaining endpoint call, often dozens) with
    /// zero backoff or retry. Callers should back off and retry instead.
    RateLimited,
}

/// True when a body signals true daily-quota exhaustion: a zero
/// `credits_remaining` meter (top-level, or nested under `data`) on a body that
/// is NOT a success. A `success:true` body is excluded even at zero credits —
/// it still carries the data of the paid call that spent the last credit, so it
/// must be returned rather than dropped (see the body comment).
fn credits_exhausted(v: &Value) -> bool {
    // A SUCCESSFUL body that merely spent its last credit still carries its
    // data (`success:true, results:[...], credits_remaining:0`). Treating that
    // as exhaustion returned `Ok(Value::Null)` from `parse_response`, silently
    // dropping the results of a paid call — the final successful lookup before
    // the quota ran out lost its answer. True exhaustion is a NON-success body
    // (the 429 / error envelope) reporting zero credits, so only classify the
    // zero-credit meter as terminal when the body is not a success.
    if v.get("success").and_then(Value::as_bool) == Some(true) {
        return false;
    }
    let zero = |o: &Value| o.get("credits_remaining").and_then(Value::as_i64) == Some(0);
    zero(v) || v.get("data").is_some_and(zero)
}

/// Classify a PARSED see-know response for a terminal auth/quota/rate-limit
/// condition, scoped to the top-level `error`/`message` envelope strings and
/// the `credits_remaining` meter. Deliberately does NOT scan the data
/// payload: a breach/stealer record whose captured content happens to
/// contain a marker like `invalid_api_key` (routine in leaked config blobs)
/// must never be mistaken for a provider-level failure — the previous
/// whole-body substring scan did exactly that, silently disabling the
/// provider for the whole scan on a single record.
///
/// `rate_limit` is intentionally its OWN [`Terminal::RateLimited`] variant,
/// not folded into [`Terminal::Quota`]: a burst rate-limit means "the key
/// still has credits, slow down," which is recoverable within the same scan
/// via backoff — unlike true exhaustion (`credits_exhausted` /
/// `quota_exceeded` / `daily limit reached`), which cannot recover until the
/// next billing period.
fn classify_terminal(v: &Value) -> Option<Terminal> {
    let err = v.get("error").and_then(Value::as_str).unwrap_or_default();
    let msg = v.get("message").and_then(Value::as_str).unwrap_or_default();
    if is_auth_error(err) || is_auth_error(msg) {
        return Some(Terminal::Auth);
    }
    if err == "rate_limit" {
        return Some(Terminal::RateLimited);
    }
    if credits_exhausted(v) || err.contains("quota_exceeded") || msg.contains("daily limit reached")
    {
        return Some(Terminal::Quota);
    }
    None
}

pub(super) fn parse_response(body: &str) -> Result<Value> {
    // A non-JSON response body — empty, a whitespace-only 200, an HTML error /
    // challenge / gateway page, or a plain-text message (including a plaintext auth
    // rejection like "Invalid API key") — is "no results", not a module failure. It
    // carries no data payload, so the substring auth check is safe here and still
    // latches a plaintext rejection. Everything else degrades to the `Ok(Value::Null)`
    // sentinel (read as empty by `extract_items`) so a normal empty response never
    // errors the module or trips the circuit breaker.
    let trimmed = body.trim_start();
    if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
        if is_auth_error(body) {
            mark_key_invalid(body);
        } else if !trimmed.is_empty() {
            tracing::debug!(
                preview = %body.chars().take(60).collect::<String>(),
                "see_know: non-JSON response body treated as no results"
            );
        }
        return Ok(Value::Null);
    }
    // A JSON body: parse FIRST, then inspect ONLY the top-level error/quota envelope
    // (never the raw payload) so a breach record whose captured content contains an
    // auth/quota marker cannot disable the provider for the whole scan. A body that
    // looks like JSON but won't parse is genuine schema drift → surfaced as an error.
    let value: Value =
        serde_json::from_str(body).map_err(|e| Error::module("seek_now", e.to_string()))?;
    match classify_terminal(&value) {
        Some(Terminal::Auth) => {
            mark_key_invalid(body);
            Ok(Value::Null)
        }
        Some(Terminal::Quota) => {
            mark_quota_exhausted();
            Ok(Value::Null)
        }
        // Surfaced as an `Err` (not `Ok(Value::Null)`) so the retry loops in
        // `endpoints.rs` can distinguish "back off and retry" from a normal
        // empty result — see `Terminal::RateLimited`'s doc comment for why
        // this must NOT latch `mark_quota_exhausted()`.
        Some(Terminal::RateLimited) => Err(Error::RateLimited(format!(
            "seek_now: {}",
            body.chars().take(120).collect::<String>()
        ))),
        None => Ok(value),
    }
}

/// Route a raw see-know `(body, status)` to either a retryable-transient error
/// or the normal body parse. A 5xx (a one-off gateway/CDN 502/503) or status `0`
/// (curl saw no HTTP response) is returned as [`Error::RateLimited`] so the
/// endpoint retry loops back off and retry it — see-know.eu is the operator's
/// highest-priority paid source, and a one-off upstream 5xx was previously
/// indistinguishable from "no results" (the HTML error page parsed to an empty
/// [`Value::Null`]) and silently lost. A 2xx-empty result and a 4xx JSON body
/// (including the `invalid_api_key`/`plan_required` auth latch) keep their exact
/// [`parse_response`] classification — only the transient class is diverted.
pub(super) fn classify_status(body: &str, status: u16) -> Result<Value> {
    if status == 0 || (500..600).contains(&status) {
        return Err(Error::RateLimited(format!(
            "seek_now: HTTP {status} transient upstream failure"
        )));
    }
    parse_response(body)
}

/// POST with multi-domain fallback. Tries the primary domain first, then falls back
/// to alternate domains on connection/network errors (not auth errors). Auth errors
/// (invalid key, plan required) are NOT retried across domains — if the key is invalid,
/// no domain will help, so we fail fast and avoid wasting domains.
pub(super) async fn post_json_with_fallback(
    endpoint_path: &str,
    key: &str,
    body: &str,
    endpoint: &str,
    query: &str,
) -> Result<Value> {
    let urls = all_base_urls();
    let mut last_error = None;

    for (idx, base) in urls.iter().enumerate() {
        let url = format!("{base}{endpoint_path}");
        // Route the (body, status) through `classify_status` so a 5xx / status-0
        // transient upstream failure surfaces as `RateLimited` instead of being
        // parsed as an empty "no results" body and silently lost.
        match CLIENT.post_json_with_status(&url, key, body).await {
            Ok((resp, status)) => match classify_status(&resp, status) {
                Ok(value) => {
                    crate::util::raw_archive::record("see-know", endpoint, query, &resp);
                    return Ok(value);
                }
                // Transient upstream failure — a rotated domain may answer.
                Err(e @ Error::RateLimited(_)) => {
                    if idx < urls.len() - 1 {
                        tracing::debug!(
                            domain = base,
                            endpoint = endpoint_path,
                            "see_know POST transient (5xx/rate-limit) — trying next domain"
                        );
                    }
                    last_error = Some(e);
                }
                // Auth / body classification is identical on every domain — terminal.
                Err(e) => return Err(e),
            },
            Err(e) => {
                let err_str = e.to_string();
                // Auth errors are terminal — no point trying other domains.
                if err_str.contains("401")
                    || err_str.contains("Unauthorized")
                    || err_str.contains("invalid") && err_str.to_lowercase().contains("key")
                {
                    return Err(e);
                }
                // For other errors (connection, DNS, timeout), try the next domain.
                if idx < urls.len() - 1 {
                    tracing::debug!(
                        domain = base,
                        endpoint = endpoint_path,
                        "see_know POST failed — trying next domain"
                    );
                }
                last_error = Some(e);
            }
        }
    }

    // Exhausted all domains; return the last error.
    Err(last_error.unwrap_or_else(|| Error::module("see_know", "all domains exhausted")))
}

/// GET with multi-domain fallback. Tries the primary domain first, then falls back
/// to alternate domains on connection/network errors (not auth errors).
pub(super) async fn get_json_with_fallback(
    endpoint_path: &str,
    key: &str,
    query_str: &str,
    endpoint: &str,
    query_value: &str,
) -> Result<Value> {
    let urls = all_base_urls();
    let mut last_error = None;

    for (idx, base) in urls.iter().enumerate() {
        let url = format!("{base}{endpoint_path}?{query_str}");
        // The fast GET endpoints use the tighter-budgeted CLIENT_FAST (see its
        // doc), and route the (body, status) through `classify_status` so a 5xx
        // / status-0 transient upstream failure is surfaced as `RateLimited`
        // rather than parsed as an empty "no results" body.
        match CLIENT_FAST.get_with_status(&url, key).await {
            Ok((body, status)) => match classify_status(&body, status) {
                Ok(value) => {
                    crate::util::raw_archive::record("see-know", endpoint, query_value, &body);
                    return Ok(value);
                }
                // A 5xx / status-0 / upstream rate-limit is transient — the
                // service rotates domains, so a rotated host may still answer.
                // Remember it and try the next domain; if all are exhausted the
                // caller's backoff loop retries the whole fallback.
                Err(e @ Error::RateLimited(_)) => {
                    if idx < urls.len() - 1 {
                        tracing::debug!(
                            domain = base,
                            endpoint = endpoint_path,
                            "see_know GET transient (5xx/rate-limit) — trying next domain"
                        );
                    }
                    last_error = Some(e);
                }
                // Auth / body classification (invalid key, plan required) is
                // identical on every domain — terminal, don't waste the rotation.
                Err(e) => return Err(e),
            },
            Err(e) => {
                let err_str = e.to_string();
                // Auth errors are terminal — no point trying other domains.
                if err_str.contains("401")
                    || err_str.contains("Unauthorized")
                    || err_str.contains("invalid") && err_str.to_lowercase().contains("key")
                {
                    return Err(e);
                }
                // For other errors (connection, DNS, timeout), try the next domain.
                if idx < urls.len() - 1 {
                    tracing::debug!(
                        domain = base,
                        endpoint = endpoint_path,
                        "see_know GET failed — trying next domain"
                    );
                }
                last_error = Some(e);
            }
        }
    }

    // Exhausted all domains; return the last error.
    Err(last_error.unwrap_or_else(|| Error::module("see_know", "all domains exhausted")))
}

/// Raw GET with multi-domain fallback (no parsing/archiving). Used for meta-queries
/// like `/credits` that don't consume budget and shouldn't be archived.
///
/// Routes through [`CLIENT_FAST`], not the wide `/search`-sized [`CLIENT`]: its
/// only caller (`credits_probe`) is a parameter-free metadata GET answering in
/// low single-digit seconds, same shape as the other [`CLIENT_FAST`] endpoints
/// — not the ~55s-worst-case name search [`CLIENT`] is budgeted for. Before this
/// fix a single unreachable domain could burn the full 78s `CLIENT` outer
/// timeout (curl's own 75s `--max-time` plus headroom — see [`CLIENT`]'s doc)
/// per domain: up to ~234s across all 3 fallback domains before `hse doctor`
/// or scan-start's budget-scaling probe got an answer.
pub(super) async fn get_raw_with_fallback(endpoint_path: &str, key: &str) -> Result<String> {
    let urls = all_base_urls();
    let mut last_error = None;

    for (idx, base) in urls.iter().enumerate() {
        let url = format!("{base}{endpoint_path}");
        match CLIENT_FAST.get(&url, key).await {
            Ok(body) => return Ok(body),
            Err(e) => {
                let err_str = e.to_string();
                // Auth errors are terminal — no point trying other domains.
                if err_str.contains("401")
                    || err_str.contains("Unauthorized")
                    || err_str.contains("invalid") && err_str.to_lowercase().contains("key")
                {
                    return Err(e);
                }
                // For other errors (connection, DNS, timeout), try the next domain.
                if idx < urls.len() - 1 {
                    tracing::debug!(
                        domain = base,
                        endpoint = endpoint_path,
                        "see_know raw GET failed — trying next domain"
                    );
                }
                last_error = Some(e);
            }
        }
    }

    // Exhausted all domains; return the last error.
    Err(last_error.unwrap_or_else(|| Error::module("see_know", "all domains exhausted")))
}

/// Expose the hardcoded default key so tests can assert on it.
#[cfg(test)]
pub(super) const HARDCODED_KEY_FOR_TESTS: &str = HARDCODED_KEY;
