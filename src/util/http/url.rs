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
///
/// Fails the way [`json_decode`] fails: the bounded read's own error passes
/// through, and a body that will not decode is [`json_body_error`] — the typed
/// `Error::BotChallenge` for an anti-bot page served where JSON was expected,
/// otherwise `Error::Module` with the shape-drift message, credentials
/// redacted. Until 2026-09-15 this helper returned a bare `String` that every
/// caller wrapped as `Error::module`, so a wall behind any of its thirty-odd
/// call sites read as a module fault, and its message was the one JSON path
/// that never ran `redact_credentials`.
pub async fn json_scanned<T: DeserializeOwned>(resp: reqwest::Response, module: &str) -> Result<T> {
    let text = read_json_text(resp, module).await?;
    scan_for_api_keys(&text);
    serde_json::from_str(&text).map_err(|e| json_body_error(module, &text, &e))
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
    serde_json::from_str(&text).map_err(|e| json_body_error(module, &text, &e))
}

/// The message for a body that would not decode as the JSON a module asked
/// for. The three decode helpers used to report serde's own words — `expected
/// value at line 1 column 1` — which say nothing about *what* arrived. That
/// matters for classification: a provider that answers `200 text/html` with its
/// error template, a bot-challenge interstitial, or a login page is an
/// **upstream error page**, not parser drift, and the two call for opposite
/// repairs. So a body that reads as an HTML document (leading comments
/// skipped — WiFiDB's template opens with a licence comment) is named as one,
/// with its `<title>` quoted so the operator and the weekly sweep see the
/// provider's own words — `Error | Vistumbler WiFiDB` (observed 2026-09-15)
/// instead of a column number. Anything else keeps serde's message, with a
/// short prefix of the body so a shape change is legible. Pure.
pub fn json_failure(body: &str, err: &serde_json::Error) -> String {
    let head = skip_leading_html_comments(body);
    if crate::util::html::looks_like_document(head) {
        let title = crate::util::html::title(head).unwrap_or_else(|| {
            crate::util::html::collapse_whitespace(&crate::util::html::strip_html(head))
                .chars()
                .take(120)
                .collect()
        });
        return format!(
            "provider answered an HTML page where JSON was expected — an error page, \
             interstitial or login page, not the data (title: {title:?}); serde: {err}"
        );
    }
    let sample: String = body.trim_start().chars().take(80).collect();
    format!("{err} (body starts: {sample:?})")
}

/// The typed error for a body that would not decode as the JSON a module asked
/// for. An anti-bot challenge / WAF block page served with a 2xx — some edges
/// answer a challenge as `200 text/html` — is
/// [`Error::BotChallenge`]: the provider refusing this client, which dispatch
/// benches under its own reason and the capability probe reports as `blocked`
/// rather than as a failure or an outage. Anything else is [`Error::Module`]
/// carrying [`json_failure`]'s message. Credential-looking query values an
/// upstream echoes into its body are redacted in both.
pub(super) fn json_body_error(module: &str, body: &str, err: &serde_json::Error) -> Error {
    let message = super::redact_credentials(&json_failure(body, err));
    if crate::util::html::is_challenge_page(body) {
        return Error::BotChallenge(format!("{module}: {message}"));
    }
    Error::module(module, message)
}

/// `body` with any leading `<!-- … -->` comment blocks (and whitespace) removed,
/// so a document that opens with a comment still reads as a document.
fn skip_leading_html_comments(body: &str) -> &str {
    let mut s = body.trim_start();
    while let Some(rest) = s.strip_prefix("<!--") {
        match rest.find("-->") {
            Some(i) => s = rest[i + 3..].trim_start(),
            None => return s,
        }
    }
    s
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
            .map_err(|e| Error::module(module, transport_error_message(e)))
    }
}

/// A reqwest error as text an operator may see: the request URL **stripped**
/// ([`reqwest::Error::without_url`]), the `source()` cause chain kept, the
/// whole credential-redacted ([`super::redact_credentials`]).
///
/// For a reqwest error that leaves the process — a module error
/// ([`RequestBuilderExt::send_tagged`]) or an HTTP error body a handler answers
/// with (the map tile proxy's `502`, `api::tiles`). reqwest's own `Display`
/// appends ` for url (<full request URL>)` whenever the error carries one — and
/// its documentation warns that the URL may hold an API key in the query — so a
/// bare `{e}` publishes whatever the URL carries: an operator's tile key
/// (`?apikey=…`), a module's key, the target being searched (REQ-CRED-003).
/// Stripping here, not at each site, means a caller that renders through this
/// cannot forget it. (Older sites that strip inline — `core::error`'s
/// `From<reqwest::Error>`, `app::cells`, `core::webhook` — drop the cause
/// chain instead.)
pub(crate) fn transport_error_message(e: reqwest::Error) -> String {
    error_cause_chain(e.without_url())
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
