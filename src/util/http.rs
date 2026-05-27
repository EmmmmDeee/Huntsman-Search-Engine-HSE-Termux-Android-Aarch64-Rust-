//! Shared HTTP client builder. Rustls-only — no native TLS, no openssl,
//! no native deps at all.
//!
//! No client-level total timeout is set: the engine wraps every
//! `Module::process()` call in `tokio::time::timeout(...)` (see
//! `src/core/engine/dispatch.rs`), capped at whichever of the user
//! override (`ScanOptions::module_timeout_ms`) or each module's
//! `max_timeout_ms()` is larger. A blanket client-level cap of
//! `MODULE_TIMEOUT_MS = 3 s` previously short-circuited every module
//! that declared a larger budget (whois 8 s, wigle 12 s, and other
//! multi-stage network modules) — at least one module has an explicit
//! unit test asserting `max_timeout_ms() > MODULE_TIMEOUT_MS`,
//! proving that the override was expected to apply.
//!
//! A short `connect_timeout` is still set so that attempts to reach
//! firewalled or otherwise-unresponsive hosts fail fast and free up
//! the engine's concurrency slot, instead of consuming the module's
//! full budget waiting on the OS-level TCP connect.

use std::time::Duration;

use serde::de::DeserializeOwned;

use crate::core::error::{Error, Result};

/// Fail-fast TCP connect budget. Independent of each module's total
/// `max_timeout_ms()`. Five seconds is generous on slow mobile links
/// while still preventing a wedged peer from holding a concurrency
/// slot for the module's entire (often double-digit) total budget.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Build a fresh reqwest client. Cheap to call per scan.
///
/// User-Agent uses the conventional `name/version (+url)` form. Bare
/// short UAs like `HSE/0.8.0` are frequently rejected by anti-bot WAFs
/// (HudsonRock's cavalier API among them — observed returning HTTP 400
/// on Termux). The `+https://` contact link is the format recommended
/// by RFC 7231 §5.5.3 and accepted by most rate-limiters.
///
/// No client-level total timeout — see module docstring. A short
/// `connect_timeout` is set so unreachable hosts fail fast.
pub fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .pool_max_idle_per_host(5)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Duration::from_secs(15))
        .user_agent(concat!(
            "huntsman-search-engine/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-)"
        ))
        .build()
        .expect("reqwest client build failed")
}

/// Read up to 200 characters of a non-success response body, trim, and
/// return a single-line string safe to embed in an error message.
///
/// Returns `"<empty>"` when the body is empty, `"<unreadable>"` if the
/// body couldn't be decoded. Consumes the response.
///
/// Use this everywhere a module returns `Error::module(name, "HTTP …")`
/// so the user sees the upstream's actual error payload rather than a
/// bare status code.
pub async fn error_snippet(resp: reqwest::Response) -> String {
    match resp.text().await {
        Ok(body) => {
            scan_for_api_keys(&body);
            let trimmed = body.trim();
            if trimmed.is_empty() {
                "<empty>".to_string()
            } else {
                trimmed
                    .replace(['\n', '\r'], " ")
                    .chars()
                    .take(200)
                    .collect()
            }
        }
        Err(_) => "<unreadable>".to_string(),
    }
}

/// GET `url` and deserialise the JSON body as `T`. Errors on any
/// non-2xx, including 404.
///
/// Use from modules whose upstream never returns 404-as-"no result"
/// — e.g. `ip-api.com` always returns 200 with a `status` field;
/// `crt.sh` always returns 200 with a (possibly empty) JSON array.
/// For modules where 404 means "not found, no findings" (HudsonRock,
/// Gravatar, AlienVault OTX, XposedOrNot, BGPView), use
/// [`fetch_json_or_404`] instead.
///
/// The `module` parameter is the stable module name string — embedded
/// in every error so the operator sees which module failed without
/// reading SSE event metadata.
pub async fn fetch_json<T: DeserializeOwned>(
    client: &reqwest::Client,
    module: &'static str,
    url: &str,
) -> Result<T> {
    match fetch_json_inner(client, module, url, false).await? {
        Some(data) => Ok(data),
        None => Err(Error::module(module, format!("request failed for {url}"))),
    }
}

/// Like [`fetch_json`] but maps `404 Not Found` to `Ok(None)` — the
/// idiomatic "upstream says we don't know about this target" signal.
/// Every other non-2xx still becomes an `Error::module(...)` so 429
/// rate-limits and 5xx outages stay visible.
///
/// Use from modules whose upstream uses 404 as a positive "clean" /
/// "not in our dataset" signal (HudsonRock, Gravatar, AlienVault OTX,
/// XposedOrNot, BGPView).
pub async fn fetch_json_or_404<T: DeserializeOwned>(
    client: &reqwest::Client,
    module: &'static str,
    url: &str,
) -> Result<Option<T>> {
    fetch_json_inner(client, module, url, true).await
}

async fn fetch_json_inner<T: DeserializeOwned>(
    client: &reqwest::Client,
    module: &'static str,
    url: &str,
    map_404_to_none: bool,
) -> Result<Option<T>> {
    match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status();
            if map_404_to_none && status.as_u16() == 404 {
                return Ok(None);
            }
            if !status.is_success() {
                return Err(Error::module(
                    module,
                    format!("HTTP {status}: {}", error_snippet(resp).await),
                ));
            }
            let text = resp
                .text()
                .await
                .map_err(|e| Error::module(module, e.to_string()))?;
            scan_for_api_keys(&text);
            let data = serde_json::from_str::<T>(&text)
                .map_err(|e| Error::module(module, e.to_string()))?;
            Ok(Some(data))
        }
        Err(_) => Ok(super::curl::fetch_json::<T>(url, crate::MODULE_TIMEOUT_MS).await),
    }
}

/// Parse the `Retry-After` header from a response, returning the number
/// of seconds to wait. Falls back to `default_secs` if absent or
/// unparseable. Capped at 120s to prevent infinite waits.
pub fn retry_after_secs(headers: &reqwest::header::HeaderMap, default_secs: u64) -> u64 {
    headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(default_secs)
        .min(120)
}

/// Handle a non-success HTTP response for keyed modules. Returns:
/// - `Ok(true)` if the caller should retry (429 with retries remaining)
/// - `Ok(false)` if the response is a permanent failure (report + stop)
/// - The function sleeps on 429 before returning Ok(true).
///
/// `retries_left`: mutable counter, decremented on 429.
/// `module`: stable module name for report_key_exhausted.
/// `key`: the API key value being used.
/// `ctx`: module context for key exhaustion reporting.
pub async fn handle_keyed_error(
    status: u16,
    headers: &reqwest::header::HeaderMap,
    retries_left: &mut u8,
    module: &str,
    key: &str,
    ctx: &crate::core::module::ModuleContext,
) -> bool {
    match status {
        429 if *retries_left > 0 => {
            *retries_left -= 1;
            ctx.report_key_exhausted(module, key, 429);
            let secs = retry_after_secs(headers, 8);
            tracing::warn!(
                module,
                "429 rate-limited on key …{}, retrying in {secs}s ({} left)",
                &key[key.len().saturating_sub(4)..],
                retries_left
            );
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            true
        }
        429 => {
            ctx.report_key_exhausted(module, key, 429);
            false
        }
        401 | 403 => {
            ctx.report_key_exhausted(module, key, status);
            false
        }
        _ => false,
    }
}

/// Keyed GET: fetch JSON from a URL that requires an API key header.
/// Handles 401/403/429 uniformly via report_key_exhausted, maps 404
/// to Ok(None). Consolidates the error handling pattern duplicated
/// across 8+ keyed modules.
pub async fn fetch_keyed_json<T: DeserializeOwned>(
    ctx: &crate::core::module::ModuleContext,
    module: &'static str,
    url: &str,
    key_env: &str,
    header_name: &str,
) -> Result<Option<T>> {
    let key = ctx.key(key_env)?;
    let resp = ctx
        .http
        .get(url)
        .header(header_name, key)
        .send()
        .await
        .map_err(|e| Error::module(module, e.to_string()))?;

    let status = resp.status();
    if status.as_u16() == 404 {
        return Ok(None);
    }
    if !status.is_success() {
        if matches!(status.as_u16(), 401 | 403 | 429) {
            ctx.report_key_exhausted(module, key, status.as_u16());
        }
        return Err(Error::module(
            module,
            format!("HTTP {status}: {}", error_snippet(resp).await),
        ));
    }
    let text = resp
        .text()
        .await
        .map_err(|e| Error::module(module, e.to_string()))?;
    scan_for_api_keys(&text);
    let data =
        serde_json::from_str::<T>(&text).map_err(|e| Error::module(module, e.to_string()))?;
    Ok(Some(data))
}

/// Percent-encode a single URL path or query-string component using the
/// `application/x-www-form-urlencoded` serialiser. Equivalent to:
///
/// ```ignore
/// url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
/// ```
///
/// but extracted because five modules had this verbatim helper repeated.
pub fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Parse a reqwest Response as JSON while scanning the raw body for API
/// keys. Drop-in replacement for `resp.json::<T>().await` that ensures
/// no response body bypasses the key scanner.
pub async fn json_scanned<T: DeserializeOwned>(
    resp: reqwest::Response,
    module: &str,
) -> std::result::Result<T, String> {
    let text = resp.text().await.map_err(|e| format!("{module}: {e}"))?;
    scan_for_api_keys(&text);
    serde_json::from_str(&text).map_err(|e| format!("{module}: {e}"))
}

/// Scan arbitrary text for API key patterns and store any discoveries
/// in the global key pool. Call on any raw text that passes through the
/// system — HTTP response bodies, WHOIS output, certificate fields, etc.
pub fn scan_for_api_keys(text: &str) {
    scan_for_api_keys_with_source(text, "http_response");
}

pub fn scan_for_api_keys_with_source(text: &str, source: &str) {
    use crate::modules::oathnet_pro::key_harvest::identify_api_key;
    let pool = crate::util::key_pool::global_pool();
    let now = crate::core::entity::unix_now();
    for word in text.split(|c: char| {
        c.is_whitespace()
            || c == '"'
            || c == '\''
            || c == '`'
            || c == '>'
            || c == '<'
            || c == '='
            || c == ';'
    }) {
        let t = word.trim();
        if t.len() >= 16
            && t.len() <= 200
            && let Some((service, key_val)) = identify_api_key(t)
        {
            let mut entry = crate::util::key_pool::KeyEntry::new(key_val);
            entry.status = crate::util::key_pool::KeyStatus::Untested;
            entry.discovered_at = Some(now);
            entry.discovered_by = Some(source.to_string());
            pool.add(service, entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_client_succeeds() {
        let _c = build_client();
    }

    #[test]
    fn urlencode_plain_passthrough() {
        assert_eq!(urlencode("hello"), "hello");
    }

    #[test]
    fn urlencode_spaces_become_plus() {
        assert_eq!(urlencode("hello world"), "hello+world");
    }

    #[test]
    fn urlencode_special_chars() {
        assert_eq!(urlencode("a@b.com"), "a%40b.com");
    }

    #[test]
    fn urlencode_unicode() {
        let encoded = urlencode("café");
        assert!(encoded.contains('%'));
        assert!(!encoded.contains("é"));
    }

    #[test]
    fn urlencode_empty() {
        assert_eq!(urlencode(""), "");
    }

    #[test]
    fn urlencode_slashes_and_ampersands() {
        let encoded = urlencode("a/b&c=d");
        assert!(encoded.contains("%2F"));
        assert!(encoded.contains("%26"));
        assert!(encoded.contains("%3D"));
    }
}
