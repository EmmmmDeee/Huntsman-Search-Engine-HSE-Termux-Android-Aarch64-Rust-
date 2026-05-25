//! Shared HTTP client builder. Rustls-only — no native TLS, no openssl,
//! no native deps at all. Default timeout matches `MODULE_TIMEOUT_MS`.

use std::time::Duration;

use serde::de::DeserializeOwned;

use crate::MODULE_TIMEOUT_MS;
use crate::core::error::{Error, Result};

/// Build a fresh reqwest client. Cheap to call per scan.
///
/// User-Agent uses the conventional `name/version (+url)` form. Bare
/// short UAs like `HSE/0.8.0` are frequently rejected by anti-bot WAFs
/// (HudsonRock's cavalier API among them — observed returning HTTP 400
/// on Termux). The `+https://` contact link is the format recommended
/// by RFC 7231 §5.5.3 and accepted by most rate-limiters.
///
/// # Panics
///
/// Panics (via `.expect()`) if the reqwest builder fails. This is
/// intentional: the builder uses only hard-coded, known-good settings
/// (timeouts, pool sizes, a static user-agent) so failure indicates a
/// broken build environment, not a runtime condition worth recovering
/// from. The panic fires at startup before any scan work begins.
pub fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(MODULE_TIMEOUT_MS))
        .connect_timeout(Duration::from_secs(5))
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
            let trimmed = body.trim();
            if trimmed.is_empty() {
                "<empty>".to_string()
            } else {
                // Collapse newlines so the snippet stays a single log line,
                // then truncate at 200 chars to keep events compact.
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
    match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status();
            if !status.is_success() {
                return Err(Error::module(
                    module,
                    format!("HTTP {status}: {}", error_snippet(resp).await),
                ));
            }
            resp.json::<T>()
                .await
                .map_err(|e| Error::module(module, e.to_string()))
        }
        Err(_) => match super::curl::fetch_json::<T>(url, crate::MODULE_TIMEOUT_MS).await {
            Some(data) => Ok(data),
            None => Err(Error::module(
                module,
                format!("request failed for {url} (reqwest + curl)"),
            )),
        },
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
    match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.as_u16() == 404 {
                return Ok(None);
            }
            if !status.is_success() {
                return Err(Error::module(
                    module,
                    format!("HTTP {status}: {}", error_snippet(resp).await),
                ));
            }
            let data = resp
                .json::<T>()
                .await
                .map_err(|e| Error::module(module, e.to_string()))?;
            Ok(Some(data))
        }
        Err(_) => Ok(super::curl::fetch_json::<T>(url, crate::MODULE_TIMEOUT_MS).await),
    }
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
