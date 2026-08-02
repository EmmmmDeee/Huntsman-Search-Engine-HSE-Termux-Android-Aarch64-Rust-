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
    serde_json::from_str(&text)
        .map_err(|e| format!("{module}: {}", describe_json_reason(&text, &e)))
}

/// True if a response body is an HTML document or an anti-bot challenge
/// interstitial rather than JSON. Conservative — only fires on STRUCTURAL
/// HTML/challenge markers (a leading `<!DOCTYPE`/`<html`, or a Cloudflare
/// challenge token), never on JSON that merely mentions these words in a field.
pub(crate) fn is_html_or_challenge(body: &str) -> bool {
    let head = body.trim_start();
    head.starts_with("<!DOCTYPE")
        || head.starts_with("<!doctype")
        || head.starts_with("<html")
        || head.starts_with("<HTML")
        || body.contains("Just a moment")
        || body.contains("challenge-platform")
        || body.contains("Attention Required")
        || body.contains("__cf_chl_")
}

/// A clear, PII-safe reason a response body failed to parse as JSON (no module
/// prefix — the caller adds its own) — so a module logs "empty response" or "HTML
/// page / anti-bot challenge" instead of the raw serde `expected value at line 1
/// column 1`. Deliberately does NOT echo a malformed-JSON body (it may hold
/// partial data); the HTML/empty classifications carry the diagnostic without any
/// body content. Pure.
fn describe_json_reason(text: &str, err: &serde_json::Error) -> String {
    let head = text.trim_start();
    if head.is_empty() {
        "empty response body (expected JSON)".to_string()
    } else if is_html_or_challenge(head) {
        "non-JSON response — HTML page or anti-bot challenge (not API data)".to_string()
    } else {
        err.to_string()
    }
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
    serde_json::from_str(&text).map_err(|e| Error::module(module, describe_json_reason(&text, &e)))
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

#[cfg(test)]
mod url_json_tests {
    use super::{describe_json_reason, is_html_or_challenge};

    #[test]
    fn is_html_or_challenge_flags_pages_not_json() {
        assert!(is_html_or_challenge("<!DOCTYPE html><html><head>"));
        assert!(is_html_or_challenge("  <html lang=\"en\">"));
        assert!(is_html_or_challenge(
            "<div id=\"challenge-platform\">Just a moment...</div>"
        ));
        assert!(is_html_or_challenge("Attention Required! | Cloudflare"));
        // Real JSON is not a page — even if a field mentions html/cloudflare.
        assert!(!is_html_or_challenge(
            r#"{"note":"served via cloudflare <html>"}"#
        ));
        assert!(!is_html_or_challenge("[]"));
    }

    #[test]
    fn describe_json_reason_names_the_failure_class() {
        let err = serde_json::from_str::<serde_json::Value>("").unwrap_err();
        assert_eq!(
            describe_json_reason("", &err),
            "empty response body (expected JSON)"
        );
        let html = "<!DOCTYPE html><html><title>Just a moment...</title>";
        let herr = serde_json::from_str::<serde_json::Value>(html).unwrap_err();
        assert!(
            describe_json_reason(html, &herr).contains("HTML page or anti-bot challenge"),
            "got: {}",
            describe_json_reason(html, &herr)
        );
        // Genuinely malformed JSON keeps the raw serde message (no body echoed).
        let bad = r#"{"a":"#;
        let berr = serde_json::from_str::<serde_json::Value>(bad).unwrap_err();
        let msg = describe_json_reason(bad, &berr);
        assert!(
            !msg.contains("HTML"),
            "malformed JSON is not an HTML page: {msg}"
        );
        assert!(
            !msg.contains(bad),
            "must not echo the (possibly-partial-data) body"
        );
    }
}
