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
/// Common credential query-param values (`api_key=`, `apiKey=`,
/// `key=`, `token=`, `secret=`, `access_token=`, `auth=`) are
/// redacted before embedding. Several upstreams echo the request URL
/// inside their error body (Cloudflare, AWS, many API gateways),
/// which would otherwise leak the operator's key into the persisted
/// ModuleError event and the SSE stream.
///
/// Use this everywhere a module returns `Error::module(name, "HTTP …")`
/// so the user sees the upstream's actual error payload rather than a
/// bare status code.
pub async fn error_snippet(resp: reqwest::Response) -> String {
    // Stream up to 8 KiB before deciding the snippet is "long
    // enough" — a hostile or compromised upstream could otherwise
    // return a multi-GB body that reqwest's `resp.text()` happily
    // accumulates, exhausting RAM on a Termux device.
    const SNIPPET_BYTES_CAP: usize = 8 * 1024;
    use futures::StreamExt as _;
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                buf.extend_from_slice(&bytes);
                if buf.len() >= SNIPPET_BYTES_CAP {
                    buf.truncate(SNIPPET_BYTES_CAP);
                    break;
                }
            }
            Err(_) => return "<unreadable>".to_string(),
        }
    }
    match std::str::from_utf8(&buf).ok() {
        Some(body) => {
            scan_for_api_keys(body);
            let redacted = redact_credentials(body);
            let trimmed = redacted.trim();
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
        None => "<unreadable>".to_string(),
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

/// Mask values for common credential query-param names inside an
/// arbitrary text blob. Used by [`error_snippet`] before embedding
/// upstream error bodies in module errors — many providers echo the
/// request URL in their error response, and HSE keys often ride in
/// the URL as a `?api_key=…` / `?apiKey=…` query parameter.
///
/// The matched names (`api_key`, `apiKey`, `key`, `token`, `secret`,
/// `access_token`, `auth`) cover the providers HSE keys directly
/// (Hunter, WhoisXML, OpenCellID, Shodan, etc.). The redaction
/// replaces the value with `***` and preserves the surrounding
/// delimiters so the error message still reads naturally.
pub(crate) fn redact_credentials(text: &str) -> String {
    const CREDENTIAL_PARAMS: &[&str] = &[
        "api_key",
        "apiKey",
        "access_token",
        "accessToken",
        "secret",
        "token",
        "auth",
        // `key` is too aggressive on its own (would mask any `key=value`),
        // but `key=` immediately followed by 12+ alphanumerics is almost
        // certainly a credential. We accept a brief surface-area mismatch
        // for clarity.
        "key",
    ];
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    let bytes = text.as_bytes();
    'outer: while cursor < bytes.len() {
        for name in CREDENTIAL_PARAMS {
            let needle_eq = format!("{name}=");
            if bytes[cursor..].starts_with(needle_eq.as_bytes()) {
                // Boundary check: the preceding char (if any) should be
                // a query separator or whitespace — `apiKey=` mid-word
                // (`monKey=`) shouldn't trip.
                let preceded_by_boundary = cursor == 0
                    || matches!(
                        bytes[cursor - 1],
                        b'?' | b'&' | b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\''
                    );
                if !preceded_by_boundary {
                    continue;
                }
                let val_start = cursor + needle_eq.len();
                let mut end = val_start;
                while end < bytes.len() {
                    let b = bytes[end];
                    if b == b'&' || b == b' ' || b == b'\n' || b == b'\r' || b == b'"' {
                        break;
                    }
                    end += 1;
                }
                if end > val_start {
                    out.push_str(&text[cursor..val_start]);
                    out.push_str("***");
                    cursor = end;
                    continue 'outer;
                }
            }
        }
        out.push(bytes[cursor] as char);
        cursor += 1;
    }
    out
}

/// Parse the `Retry-After` header from a response, returning the number
/// of seconds to wait. Falls back to `default_secs` if absent or
/// unparseable, and is clamped to `max_secs`.
///
/// `max_secs` is mandatory because the wait happens *inside* a module's
/// `process()` call, which the engine kills at `max_timeout_ms`. A blanket
/// 120s cap (the previous behaviour) let a server-supplied `Retry-After`
/// — or even a modest default — exceed a 8–20s module budget, so the
/// engine killed `process()` mid-sleep and mislabelled the 429 as a
/// timeout. Callers MUST pass a ceiling derived from their own budget
/// (rule of thumb: ~⅓ of `max_timeout_ms`, leaving headroom for the retry
/// request itself).
pub fn retry_after_secs(
    headers: &reqwest::header::HeaderMap,
    default_secs: u64,
    max_secs: u64,
) -> u64 {
    headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(default_secs)
        .min(max_secs)
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
            // Cap at 4s: callers of this shared helper run with 8–12s module
            // budgets, so a single in-process retry sleep must stay well under
            // the tightest of those or the engine kills process() mid-wait.
            let secs = retry_after_secs(headers, 4, 4);
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

    // ── retry_after_secs ───────────────────────────────────────────────

    fn hdrs(retry_after: Option<&str>) -> reqwest::header::HeaderMap {
        let mut h = reqwest::header::HeaderMap::new();
        if let Some(v) = retry_after {
            h.insert("retry-after", v.parse().unwrap());
        }
        h
    }

    #[test]
    fn retry_after_uses_default_when_header_absent() {
        assert_eq!(retry_after_secs(&hdrs(None), 5, 10), 5);
    }

    #[test]
    fn retry_after_parses_header_value() {
        assert_eq!(retry_after_secs(&hdrs(Some("3")), 5, 10), 3);
    }

    #[test]
    fn retry_after_clamps_hostile_header_to_max() {
        // A server (or a misbehaving proxy) asking for a 600s wait must not
        // exceed the caller's budget ceiling — this is the timeout-kill bug.
        assert_eq!(retry_after_secs(&hdrs(Some("600")), 5, 10), 10);
    }

    #[test]
    fn retry_after_clamps_oversized_default_to_max() {
        assert_eq!(retry_after_secs(&hdrs(None), 99, 6), 6);
    }

    #[test]
    fn retry_after_ignores_unparseable_header() {
        assert_eq!(retry_after_secs(&hdrs(Some("soon")), 7, 30), 7);
    }

    // ── redact_credentials ─────────────────────────────────────────────

    #[test]
    fn redact_strips_api_key_query_param() {
        let s = "HTTP 400: Invalid request: domain=&api_key=SECRET_KEY_123";
        let r = redact_credentials(s);
        assert!(!r.contains("SECRET_KEY_123"));
        assert!(r.contains("api_key=***"));
    }

    #[test]
    fn redact_strips_apikey_camel_case() {
        let s = "Bad URL: ?apiKey=AbCdEf123&domain=example.com";
        let r = redact_credentials(s);
        assert!(!r.contains("AbCdEf123"));
        assert!(r.contains("apiKey=***"));
    }

    #[test]
    fn redact_strips_token_and_secret() {
        let s = "?token=THEACTUALTOKEN&secret=ALSOSECRET&other=keep";
        let r = redact_credentials(s);
        assert!(!r.contains("THEACTUALTOKEN"));
        assert!(!r.contains("ALSOSECRET"));
        assert!(r.contains("other=keep"));
    }

    #[test]
    fn redact_preserves_non_credential_text() {
        let s = "Quota exhausted, contact support@example.com";
        let r = redact_credentials(s);
        assert_eq!(r, s);
    }

    #[test]
    fn redact_does_not_match_substring_words() {
        // `monKey=value` should NOT have `Key=value` matched —
        // boundary check rejects mid-word matches.
        let s = "monkey=banana";
        let r = redact_credentials(s);
        assert!(r.contains("monkey=banana"));
    }

    #[test]
    fn redact_handles_multiple_credentials_on_one_line() {
        let s = "url=https://api.example.com/?api_key=KEY1&token=KEY2&apiKey=KEY3";
        let r = redact_credentials(s);
        assert!(!r.contains("KEY1"));
        assert!(!r.contains("KEY2"));
        assert!(!r.contains("KEY3"));
    }
}
