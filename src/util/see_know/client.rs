//! HTTP client, response cache, API key helpers, and low-level JSON I/O for
//! the SeekNow (see-know.icu) API.

use serde_json::Value;

use crate::core::error::{Error, Result};
use crate::util::curl_client::{AuthScheme, CurlClient};
use crate::util::response_cache::ResponseCache;

use super::budget::{mark_key_invalid, mark_quota_exhausted};

// Embedded fallback: the single-source-of-truth default lives in `util::keys`.
const HARDCODED_KEY: &str = crate::util::keys::SEEKNOW_DEFAULT_KEY;

/// Per-process response cache backed by the shared
/// [`ResponseCache`] primitive (cap 1024 — sized to comfortably hold
/// every distinct endpoint × query a single scan generates).
pub(super) static RESPONSE_CACHE: ResponseCache<Vec<Value>> = ResponseCache::new(1024);

/// Shared curl-subprocess client. `X-API-Key` auth (per the see-know.icu spec —
/// the server rejects `Authorization: Bearer` with "Missing API key. Use
/// X-API-Key"), 75s curl timeout, 78s outer tokio timeout.
// The name/auto `/search` path has a server-side cap of ~55s and routinely
// responds in 50–60s with real data. The previous 12s curl / 15s outer budget
// guaranteed a timeout-exit (curl 28) on every name search, surfacing as an
// opaque "curl failed" with zero entities. Budget above the cap: 75s curl,
// 78s outer (curl < outer so curl's own exit code is observed), paired with an
// 80s module max_timeout in `modules::see_know`.
pub(super) static CLIENT: CurlClient = CurlClient::new("seek_now", AuthScheme::XApiKey, 75, 78_000);

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

pub(super) fn base_url() -> String {
    // Hardcoded to official .icu endpoint (official domain as of 2026).
    // Vet the operator's override: refuse non-https / private-host redirects and
    // WARN on a divergent host, so a key-bearing request can't be silently
    // redirected to a look-alike or an internal address.
    crate::util::endpoint_override::resolve("HUNTSMAN_SEEKNOW_BASE", "https://see-know.icu/api/v1")
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
#[must_use]
pub fn key_fingerprint(key: &str) -> String {
    let k = key.trim();
    if k.is_empty() {
        return "see-know.icu:(no key)".to_string();
    }
    if k.len() <= 18 {
        return format!("see-know.icu:{k}");
    }
    let head: String = k.chars().take(13).collect();
    let tail: String = {
        let mut t: Vec<char> = k.chars().rev().take(6).collect();
        t.reverse();
        t.into_iter().collect()
    };
    format!("see-know.icu:{head}\u{2026}{tail}")
}

/// Body signature of a key that cannot retrieve data — so the whole scan should
/// latch and stop spending budget on calls that will all come back empty. Two
/// distinct causes, both terminal for the held key:
///   * an outright auth rejection — `{"error":"invalid_api_key",…}` (wrong key)
///     or "…Missing API key. Use X-API-Key…" (header absent);
///   * a recognised key whose account lacks a paid plan —
///     `{"error":"plan_required",…}` (the live see-know.icu response for a
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
    /// The key is fine but its quota/credits are spent.
    Quota,
}

/// True if either `credits_remaining` meter (top-level, or nested under `data`)
/// reads exactly 0 — the JSON-scoped quota signal.
fn credits_exhausted(v: &Value) -> bool {
    let zero = |o: &Value| o.get("credits_remaining").and_then(Value::as_i64) == Some(0);
    zero(v) || v.get("data").is_some_and(zero)
}

/// Classify a PARSED see-know response for a terminal auth/quota condition,
/// scoped to the top-level `error`/`message` envelope strings and the
/// `credits_remaining` meter. Deliberately does NOT scan the data payload: a
/// breach/stealer record whose captured content happens to contain a marker like
/// `invalid_api_key` (routine in leaked config blobs) must never be mistaken for a
/// provider-level failure — the previous whole-body substring scan did exactly
/// that, silently disabling the provider for the whole scan on a single record.
fn classify_terminal(v: &Value) -> Option<Terminal> {
    let err = v.get("error").and_then(Value::as_str).unwrap_or_default();
    let msg = v.get("message").and_then(Value::as_str).unwrap_or_default();
    if is_auth_error(err) || is_auth_error(msg) {
        return Some(Terminal::Auth);
    }
    if credits_exhausted(v)
        || err == "rate_limit"
        || err.contains("quota_exceeded")
        || msg.contains("daily limit reached")
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
        None => Ok(value),
    }
}

pub(super) async fn get_json(url: &str, key: &str, endpoint: &str, query: &str) -> Result<Value> {
    let body = CLIENT.get(url, key).await?;
    // Retain the paid response verbatim BEFORE parsing/extraction — operator
    // policy: purchased data is kept in absolute completeness until manually
    // deleted (see `util::raw_archive`). `endpoint`/`query` name the saved file
    // so it's obvious what was looked up. Empty bodies are skipped by the archive.
    crate::util::raw_archive::record("see-know", endpoint, query, &body);
    parse_response(&body)
}

pub(super) async fn post_json(
    url: &str,
    key: &str,
    body: &str,
    endpoint: &str,
    query: &str,
) -> Result<Value> {
    let resp = CLIENT.post_json(url, key, body).await?;
    // Archive the raw paid response verbatim, filed under the queried value.
    crate::util::raw_archive::record("see-know", endpoint, query, &resp);
    parse_response(&resp)
}

/// Expose the hardcoded default key so tests can assert on it.
#[cfg(test)]
pub(super) const HARDCODED_KEY_FOR_TESTS: &str = HARDCODED_KEY;
