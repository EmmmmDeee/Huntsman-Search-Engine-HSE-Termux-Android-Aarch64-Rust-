//! HTTP fetch helpers, body reading, JSON decode, and keyed-API error handling.

use serde::de::DeserializeOwned;

use crate::core::error::{Error, Result};

use super::keys::scan_for_api_keys;
use super::redact::redact_credentials;

/// Read up to 200 characters of a non-success response body, trim, and
/// return a single-line string safe to embed in an error message.
///
/// Returns `"<empty>"` when the body is empty, `"<unreadable>"` on a transport
/// error while streaming the body. Consumes the response.
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
    // Lossy decode: the 8 KiB cap can fall mid-multibyte-char, which strict
    // `from_utf8` would reject and report as "<unreadable>" even for a perfectly
    // readable body. We only need a human-facing snippet, so replace the (at most
    // one) split char rather than discard the whole message.
    let body = String::from_utf8_lossy(&buf);
    scan_for_api_keys(&body);
    let redacted = redact_credentials(&body);
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

/// Read a response body but stop after `cap` bytes. A hostile or misconfigured
/// upstream could otherwise return a multi-MB/GB body that `resp.text()`
/// accumulates whole, exhausting RAM on a low-memory Termux device — a real
/// risk under the username_search 32-way probe fan-out. Returns lossy UTF-8 of
/// what was read (sufficient for substring/needle checks), or `None` on a
/// transport error.
pub async fn read_body_capped(resp: reqwest::Response, cap: usize) -> Option<String> {
    use futures::StreamExt as _;
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                buf.extend_from_slice(&bytes);
                if buf.len() >= cap {
                    buf.truncate(cap);
                    break;
                }
            }
            Err(_) => return None,
        }
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Upper bound on a JSON response body we will buffer. `resp.text()` accumulates
/// the whole body, so a hostile or misconfigured upstream returning a multi-GB
/// payload would OOM a Termux device — the same threat `read_body_capped` /
/// `error_snippet` already guard, but the JSON paths did not. 32 MiB is far above
/// any legitimate OSINT JSON response (even a large `crt.sh` certificate list).
pub(super) const JSON_BODY_CAP: usize = 32 * 1024 * 1024;

/// Stream a response body into a String, refusing to buffer more than
/// [`JSON_BODY_CAP`] bytes — the JSON-path equivalent of [`read_body_capped`].
/// Errors (rather than truncating) past the cap, since a half-read JSON body
/// can't be parsed anyway. Lossy UTF-8 so an odd-charset body still yields a
/// parseable string instead of failing outright.
pub(super) async fn read_json_text(resp: reqwest::Response, module: &str) -> Result<String> {
    use futures::StreamExt as _;
    // Capture the request URL before the body stream consumes `resp`, so the
    // raw archive can key this response by what was queried.
    let url = resp.url().to_string();
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.map_err(|e| Error::module(module, redact_credentials(&e.to_string())))?;
        if buf.len() + bytes.len() > JSON_BODY_CAP {
            return Err(Error::module(
                module,
                format!(
                    "response body exceeds the {JSON_BODY_CAP}-byte cap — refusing to buffer \
                     (oversized or hostile upstream)"
                ),
            ));
        }
        buf.extend_from_slice(&bytes);
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    // Universal raw retention: every module's JSON response is archived verbatim
    // here — the single chokepoint shared by fetch_json, fetch_json_or_404,
    // fetch_keyed_json and json_scanned — so the full dossier's RAW SOURCE
    // RECORDS section is complete for ANY scan, not only the breach pools.
    crate::util::raw_archive::record_http(module, &url, &text);
    Ok(text)
}

/// Last up-to-4 *characters* of a key for log lines — char-boundary-safe.
/// Keys can be harvested from arbitrary upstream text (`scan_for_api_keys`), so
/// a byte-index slice (`&key[key.len()-4..]`) would panic when those 4 trailing
/// bytes land mid-UTF-8-sequence.
pub(super) fn key_tail(key: &str) -> String {
    let mut tail: Vec<char> = key.chars().rev().take(4).collect();
    tail.reverse();
    tail.into_iter().collect()
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
        None => Err(Error::module(
            module,
            format!("request failed for {}", redact_credentials(url)),
        )),
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
            Ok(Some(decode_scanned_json(resp, module).await?))
        }
        Err(transport) => {
            // reqwest transport failure → one curl fallback attempt. curl
            // collapses every outcome (404, non-zero exit, parse failure) to
            // `None`, so a `None` here means the fallback ALSO failed — surface
            // that as an error rather than `Ok(None)`, which `fetch_json_or_404`
            // callers would read as a definitive "not found", silently masking a
            // network outage as a clean, empty result.
            match super::super::curl::fetch_json::<T>(url, crate::MODULE_TIMEOUT_MS).await {
                Some(data) => Ok(Some(data)),
                None => Err(Error::module(
                    module,
                    format!(
                        "transport error ({}) and curl fallback failed for {}",
                        redact_credentials(&transport.to_string()),
                        redact_credentials(url)
                    ),
                )),
            }
        }
    }
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
                key_tail(key),
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

/// HTTP status codes that indicate an API-key problem: unauthorized (401),
/// forbidden (403), or rate-limited / quota-exhausted (429). The single source
/// of the "which response codes count against a key" classification, shared by
/// [`note_keyed_error`] and matched (with per-code actions) by
/// [`handle_keyed_error`].
#[must_use]
pub fn is_keyed_error_status(code: u16) -> bool {
    matches!(code, 401 | 403 | 429)
}

/// Mark `key` exhausted (so the key pool / rotation can react) when `code` is a
/// key-problem status per [`is_keyed_error_status`]; a no-op otherwise.
///
/// This is the non-retrying counterpart to [`handle_keyed_error`]: it does NOT
/// sleep, back off, or return a retry signal. It centralises the
/// `if 401/403/429 { ctx.report_key_exhausted(..) }` block that many keyed
/// modules — which surface the error immediately rather than retrying — had
/// hand-rolled identically.
pub fn note_keyed_error(
    code: u16,
    module: &str,
    key: &str,
    ctx: &crate::core::module::ModuleContext,
) {
    if is_keyed_error_status(code) {
        ctx.report_key_exhausted(module, key, code);
    }
}

/// Build the uniform `Error::module` for a non-success HTTP response —
/// `"HTTP <status>: <body snippet>"` — consuming `resp` to read a bounded body
/// snippet via [`error_snippet`]. The single source of the HTTP-status error
/// construction that ~20 keyed modules repeated verbatim.
pub async fn http_status_error(module: &str, resp: reqwest::Response) -> Error {
    let status = resp.status();
    let snippet = error_snippet(resp).await;
    Error::module(module, format!("HTTP {status}: {snippet}"))
}

/// Classify a keyed-API response by status — the full post-send operation that
/// the keyed modules repeat. `404` -> `Ok(None)` (a clean "not in this dataset"
/// miss the caller maps to empty findings); any other non-2xx ->
/// [`note_keyed_error`] (so 401/403/429 burn the key) then `Err` via
/// [`http_status_error`]; `2xx` -> `Ok(Some(resp))` for the caller to decode.
///
/// Composes the keyed-error building blocks so the policy — which codes are a
/// miss, which burn a key, which are a hard error — lives in one tested place.
/// Pairs with `let-else`:
///
/// ```ignore
/// let Some(resp) = http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
///     return Ok(ModuleResult::new());
/// };
/// ```
pub async fn keyed_ok_or_404(
    module: &str,
    key: &str,
    ctx: &crate::core::module::ModuleContext,
    resp: reqwest::Response,
) -> Result<Option<reqwest::Response>> {
    let status = resp.status();
    if status.as_u16() == 404 {
        return Ok(None);
    }
    if !status.is_success() {
        note_keyed_error(status.as_u16(), module, key, ctx);
        return Err(http_status_error(module, resp).await);
    }
    Ok(Some(resp))
}

/// Read a success response body as text, scan it for leaked API keys, then
/// decode it as `T`. The read → scan → decode triple every JSON fetch helper
/// performs after a 2xx — single-sourced so the key-harvesting side-effect and
/// the credential-redacted decode error can never drift between call sites.
async fn decode_scanned_json<T: DeserializeOwned>(
    resp: reqwest::Response,
    module: &str,
) -> Result<T> {
    let text = read_json_text(resp, module).await?;
    scan_for_api_keys(&text);
    serde_json::from_str::<T>(&text)
        .map_err(|e| Error::module(module, redact_credentials(&e.to_string())))
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
        .map_err(|e| Error::module(module, redact_credentials(&e.to_string())))?;

    // 404 → miss; 401/403/429 burn the key; other non-2xx → error — the exact
    // policy in `keyed_ok_or_404`, single-sourced rather than re-inlined here.
    let Some(resp) = keyed_ok_or_404(module, key, ctx, resp).await? else {
        return Ok(None);
    };
    Ok(Some(decode_scanned_json(resp, module).await?))
}
