//! URL encoding/decoding, JSON decode helpers, and `RequestBuilderExt`.

use serde::de::DeserializeOwned;

use crate::core::error::{Error, Result};

use super::fetch::read_json_text;
use super::keys::scan_for_api_keys;

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

/// Decode one `application/x-www-form-urlencoded` component (`%40` → `@`,
/// `+` → space) — the inverse of [`urlencode`]. Used to recover a legible query
/// value from a URL for the raw archive's filenames. Lossy-UTF8 on the decoded
/// bytes so a malformed escape can never panic.
#[must_use]
pub fn urldecode(s: &str) -> String {
    url::form_urlencoded::parse(format!("={s}").as_bytes())
        .next()
        .map_or_else(|| s.to_string(), |(_, v)| v.into_owned())
}

/// Parse a reqwest Response as JSON while scanning the raw body for API
/// keys. Drop-in replacement for `resp.json::<T>().await` that ensures
/// no response body bypasses the key scanner.
pub async fn json_scanned<T: DeserializeOwned>(
    resp: reqwest::Response,
    module: &str,
) -> std::result::Result<T, String> {
    let text = read_json_text(resp, module)
        .await
        .map_err(|e| e.to_string())?;
    scan_for_api_keys(&text);
    serde_json::from_str(&text).map_err(|e| format!("{module}: {e}"))
}

/// Decode a response body as JSON, tagging any decode failure with `module`.
///
/// Routes through [`read_json_text`] so the body is capped at
/// [`super::fetch::JSON_BODY_CAP`] (32 MiB) and retained in the
/// raw-response archive — the same bounds as [`json_scanned`]. The
/// difference: this helper does **not** scan the body for leaked API keys,
/// so it suits endpoints whose responses don't warrant key-hunting (budget
/// telemetry, geo lookups, DNS-over-HTTPS, etc.).
pub async fn json_decode<T: DeserializeOwned>(module: &str, resp: reqwest::Response) -> Result<T> {
    let text = read_json_text(resp, module).await?;
    serde_json::from_str(&text).map_err(|e| Error::module(module, e.to_string()))
}

/// Extension on [`reqwest::RequestBuilder`] that sends the request and maps any
/// transport error to a module-tagged [`Error`], **with the offending URL
/// stripped** ([`reqwest::Error::without_url`]).
///
/// The strip is load-bearing, not cosmetic. A module's request URL routinely
/// carries secrets in its query string — the upstream **API key** (`?apikey=…`)
/// and the **target's PII** (the email / username / name being searched). The
/// bare `e.to_string()` embeds that URL in the error, which then propagates into
/// the downloadable verbose log (`/api/v1/logs`) and the event stream. Stripping
/// it at this single chokepoint protects every caller — present and future — and
/// folds the
/// `.send().await.map_err(|e| Error::module(module, e.without_url().to_string()))`
/// tail that ~40 modules repeated (several still in the bare, *leaking* form).
///
/// The full `source()` cause chain is preserved after stripping, so the logged
/// error reads e.g. `"error sending request: invalid peer certificate:
/// UnknownIssuer"` or `"error sending request: operation timed out"` rather
/// than the useless generic top-level string alone.
///
/// Crate-internal (`pub(crate)`), so the `async fn` carries no public auto-trait
/// caveat: callers invoke it on the concrete `RequestBuilder`, whose future is
/// `Send`, so it composes inside their `async_trait` module methods.
pub(crate) trait RequestBuilderExt {
    async fn send_tagged(self, module: &'static str) -> Result<reqwest::Response>;
}

impl RequestBuilderExt for reqwest::RequestBuilder {
    async fn send_tagged(self, module: &'static str) -> Result<reqwest::Response> {
        self.send()
            .await
            .map_err(|e| Error::module(module, error_cause_chain(e.without_url())))
    }
}

/// Build a single `: `-joined string of the full `std::error::Error::source()`
/// chain, then credential-redact it.
///
/// reqwest's bare `Display` for transport errors is `"error sending request"`
/// — useful only as a category label. The actual fault (TLS verify failure,
/// DNS resolution, proxy CONNECT reject, timeout) lives in the source() chain
/// and was previously discarded by `.to_string()`. This helper appends each
/// cause level so the log reads `"error sending request: operation timed out"`
/// or `"error sending request: invalid peer certificate: UnknownIssuer"`.
fn error_cause_chain(e: impl std::error::Error) -> String {
    use std::fmt::Write;
    let mut msg = e.to_string();
    let mut src = e.source();
    while let Some(cause) = src {
        let _ = write!(msg, ": {cause}");
        src = cause.source();
    }
    super::redact_credentials(&msg)
}
