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

pub fn base_url() -> String {
    // Default promoted (2026-07-21) to `.xyz` — the operator-designated primary
    // endpoint. Prior history: default started on `.icu` (sandbox-confirmed
    // reachable T2.83, 2026-07-13), was corrected to `.eu` (2026-07-14) after a
    // real device's DNS resolver failed to resolve `.icu` (`curl exited 6`) while
    // `.eu` succeeded on the same client machinery — `.icu`-TLD domains are
    // commonly caught by carrier/ISP DNS-level abuse filtering, a failure mode a
    // sandboxed reachability probe cannot see. `.eu` and `.icu` remain first and
    // second fallback in [`all_base_urls`] so a transient `.xyz` outage still
    // exhausts every known domain before the scan surfaces a connection error.
    // Vet the operator's override: refuse non-https / private-host redirects and
    // WARN on a divergent host, so a key-bearing request can't be silently
    // redirected to a look-alike or an internal address.
    crate::util::endpoint_override::resolve("HUNTSMAN_SEEKNOW_BASE", "https://see-know.xyz/api/v1")
}

/// All SeekNow base URLs in fallback order. The service intentionally rotates
/// domains; fallback attempts exhaustively try all known domains before surfacing
/// a network/connection error, allowing the scan to continue despite transient
/// domain availability. Auth errors (invalid key, plan required) are NOT retried
/// across domains — if the key is invalid on one, it's invalid on all.
pub(super) fn all_base_urls() -> Vec<String> {
    let primary = base_url();
    let mut urls = vec![primary.clone()];

    // Add secondary/fallback domains only if they're different from the primary
    // (e.g., if HUNTSMAN_SEEKNOW_BASE override is set to one of these, we skip dupes).
    let fallbacks = ["https://see-know.eu/api/v1", "https://see-know.icu/api/v1"];
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
    let k = key.trim();
    if k.is_empty() {
        return "see-know:(no key)".to_string();
    }
    if k.len() <= 18 {
        return format!("see-know:{k}");
    }
    let head: String = k.chars().take(13).collect();
    let tail: String = {
        let mut t: Vec<char> = k.chars().rev().take(6).collect();
        t.reverse();
        t.into_iter().collect()
    };
    format!("see-know:{head}\u{2026}{tail}")
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

/// True if either `credits_remaining` meter (top-level, or nested under `data`)
/// reads exactly 0 — the JSON-scoped quota signal.
fn credits_exhausted(v: &Value) -> bool {
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
