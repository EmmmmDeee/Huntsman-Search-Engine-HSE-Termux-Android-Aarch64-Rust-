//! Shared WiGLE API plumbing.
//!
//! The `wigle` and `wifi_intel` modules both query WiGLE's authenticated
//! `network/detail` endpoint with the same basic-auth, URL shape and — most
//! importantly — the same rate-limit / auth-failure classification. That status
//! handling (the subtle part: a 429 must surface immediately rather than sleep
//! past the caller's wall-clock budget) lived in two copies that could drift.
//! This is the single home for it; callers decode the body into their own
//! response type so the helper stays response-shape-agnostic.

use crate::core::error::{Error, Result};
use crate::util::http::RequestBuilderExt;

/// WiGLE API base. Endpoint paths are appended by the URL builders below.
const API_BASE: &str = "https://api.wigle.net/api/v2";

/// Build the `network/detail` URL for a `netid` (BSSID / cell id) and `type`
/// (`"wifi"`, `"cell"`, `"bt"`). The id is percent-encoded.
#[must_use]
pub fn detail_url(netid: &str, kind: &str) -> String {
    let encoded = crate::util::http::urlencode(netid);
    format!("{API_BASE}/network/detail?netid={encoded}&type={kind}")
}

/// Issue an authenticated GET to a WiGLE API `url` and classify the response by
/// WiGLE's conventions, returning the live response for the caller to decode:
///
/// * `429` → rate-limit `Err`, **recorded against the host's circuit breaker**
///   for the backoff the server asked for (see below).
/// * `401` / `403` → auth-failure `Err` naming the credential env vars.
/// * `404` → `Ok(None)` (no such network).
/// * other non-2xx → `Err` carrying a body snippet.
/// * success → `Ok(Some(resp))`.
///
/// ## Why the 429 backoff is recorded rather than slept on
///
/// This helper still does not sleep: its callers query WiGLE in a *loop* (one
/// `network/detail` lookup per observed BSSID) inside a bounded per-module
/// wall-clock budget, and a sleep here would overrun that budget and get the
/// whole result discarded. But the previous code computed the server-requested
/// backoff purely to log it and then threw it away, so nothing anywhere
/// remembered that WiGLE had just refused us. Every later iteration re-asked a
/// server that had already said no: an eight-sweep `hse radar` session was
/// observed issuing eight consecutive 429s roughly 330 ms apart, five from one
/// `wifi_intel` dispatch and three more from a pivot 25 s later, each one
/// logging a 60 s backoff that never happened. That burns the operator's daily
/// WiGLE allowance, the phone's battery and radio, on requests whose answer is
/// already known.
///
/// Recording it against [`crate::util::circuit_breaker`] — the existing
/// process-global per-host gate — fixes that without sleeping anywhere: the
/// first 429 opens the host, and every subsequent call in the loop (and in
/// every other module and concurrent scan sharing `api.wigle.net`)
/// short-circuits with no socket opened until the server's own window elapses.
/// The breaker was already the repository's answer to "a 429 one scan sees
/// backs every other scan off the same host too"; this helper simply was not
/// wired to it, because it hands the live `Response` back to its caller and so
/// bypasses the `util::http` fetch helpers where that wiring lives.
///
/// `src` tags tracing and error context with the calling module's source name.
pub async fn get(
    http: &reqwest::Client,
    user: &str,
    token: &str,
    url: &str,
    src: &'static str,
) -> Result<Option<reqwest::Response>> {
    let host = crate::util::circuit_breaker::host_of(url);
    let now = crate::core::entity::unix_now();
    if let Some(h) = host.as_deref()
        && !crate::util::circuit_breaker::allow_host(h, now)
    {
        // Already refused within the server's own backoff window — do not
        // re-ask. This is the cheap path that the 429 storm above was missing.
        return Err(Error::module(
            src,
            "rate-limited (429) — backing off, request not sent",
        ));
    }

    let resp = http
        .get(url)
        .basic_auth(user, Some(token))
        .header("Accept", "application/json")
        .send_tagged(src)
        .await?;

    let status = resp.status();
    if status.as_u16() == 429 {
        let retry_secs = crate::util::http::retry_after_secs(resp.headers(), 60, 120);
        tracing::warn!(
            "WiGLE 429 — rate-limited, backing off {retry_secs}s (server's own request)"
        );
        if let Some(h) = host.as_deref() {
            crate::util::circuit_breaker::record_rate_limited(h, now, retry_secs);
        }
        return Err(Error::module(src, "rate-limited (429)"));
    }
    // Any definitive answer from WiGLE — including the 404 below and the auth
    // failures after it — proves the host is up, so the breaker closes. Only a
    // 429 or a server fault backs it off.
    if let Some(h) = host.as_deref() {
        if status.is_server_error() {
            crate::util::circuit_breaker::record_failure(h, now);
        } else {
            crate::util::circuit_breaker::record_success(h);
        }
    }
    if status.as_u16() == 404 {
        return Ok(None);
    }
    if status.as_u16() == 401 || status.as_u16() == 403 {
        return Err(Error::module(
            src,
            format!("WiGLE auth failed (HTTP {status}): check HUNTSMAN_WIGLE_USER/TOKEN"),
        ));
    }
    if !status.is_success() {
        return Err(Error::module(
            src,
            format!(
                "WiGLE HTTP {status}: {}",
                crate::util::http::error_snippet(resp).await
            ),
        ));
    }

    Ok(Some(resp))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The point of wiring the breaker in: once WiGLE has 429'd a host, a
    /// later `get` to that same host short-circuits *before* opening a socket,
    /// instead of re-issuing the request the server already refused. This is
    /// the mechanism that collapses the observed run of eight consecutive 429
    /// round-trips in one radar sweep down to one.
    ///
    /// Isolation-safe by construction: it uses a unique, reserved `.invalid`
    /// host (never a shared `127.0.0.1` mock) and pre-opens that host's breaker
    /// directly, so the assertion never races another test and the early return
    /// guarantees no DNS or network is touched.
    #[tokio::test]
    async fn a_rate_limited_host_short_circuits_the_next_get() {
        let host = "wigle-breaker-gate-test.invalid";
        let url = format!("https://{host}/api/v2/network/detail?netid=x&type=wifi");
        // The server asked for a long backoff; well within it, the gate holds.
        crate::util::circuit_breaker::record_rate_limited(
            host,
            crate::core::entity::unix_now(),
            120,
        );

        let err = get(&reqwest::Client::new(), "user", "token", &url, "test_src")
            .await
            .expect_err("a host still inside its 429 backoff must not be requested again");
        // Surfaced as this module's rate-limit error, and — the load-bearing part
        // — reached without a network round-trip (the `.invalid` host is
        // unresolvable, so any real send would fail differently).
        assert!(
            err.to_string().contains("backing off"),
            "must short-circuit via the breaker, not attempt the request: {err}"
        );
    }

    #[test]
    fn detail_url_encodes_netid_and_sets_type() {
        assert_eq!(
            detail_url("AA:BB:CC:DD:EE:FF", "wifi"),
            "https://api.wigle.net/api/v2/network/detail?netid=AA%3ABB%3ACC%3ADD%3AEE%3AFF&type=wifi"
        );
        // type is passed through verbatim for the cell/bt corpora.
        assert!(detail_url("123", "cell").ends_with("netid=123&type=cell"));
    }
}
