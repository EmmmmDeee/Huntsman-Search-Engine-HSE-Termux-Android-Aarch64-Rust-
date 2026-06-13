//! HTTP client, response cache, API key helpers, and low-level JSON I/O for
//! the SeekNow (see-know.eu) API.

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

/// Shared curl-subprocess client. `X-API-Key` auth (per the see-know.eu spec —
/// the server rejects `Authorization: Bearer` with "Missing API key. Use
/// X-API-Key"), 75s curl timeout, 78s outer tokio timeout.
// The name/auto `/search` path has a server-side cap of ~55s and routinely
// responds in 50–60s with real data. The previous 12s curl / 15s outer budget
// guaranteed a timeout-exit (curl 28) on every name search, surfacing as an
// opaque "curl failed" with zero entities. Budget above the cap: 75s curl,
// 78s outer (curl < outer so curl's own exit code is observed), paired with an
// 80s module max_timeout in `modules::see_know`.
pub(super) static CLIENT: CurlClient =
    CurlClient::new("seek_now", AuthScheme::XApiKey, 75, 78_000);

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
    std::env::var("HUNTSMAN_SEEKNOW_BASE")
        .unwrap_or_else(|_| "https://see-know.eu/api/v1".to_string())
}

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
        return "see-know.eu:(no key)".to_string();
    }
    if k.len() <= 18 {
        return format!("see-know.eu:{k}");
    }
    let head: String = k.chars().take(13).collect();
    let tail: String = {
        let mut t: Vec<char> = k.chars().rev().take(6).collect();
        t.reverse();
        t.into_iter().collect()
    };
    format!("see-know.eu:{head}\u{2026}{tail}")
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

pub(super) fn parse_response(body: &str) -> Result<Value> {
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
