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

/// Build the `network/detail` URL for a WiFi/cell `netid` and network `type`.
/// The documented `type` values (`https://api.wigle.net/swagger.json`,
/// retrieved 2026-09-03) are `CDMA` / `GSM` / `LTE` / `WCDMA` / `NR` / `WIFI`;
/// a BSSID lookup passes `"WIFI"`. The id is percent-encoded.
#[must_use]
pub fn detail_url(netid: &str, kind: &str) -> String {
    let encoded = crate::util::http::urlencode(netid);
    format!("{API_BASE}/network/detail?netid={encoded}&type={kind}")
}

/// Build the `bluetooth/detail` URL for a Bluetooth device address — its own
/// documented endpoint (`netid` is its only lookup parameter), NOT
/// `network/detail`, which has no Bluetooth `type`. The id is percent-encoded.
#[must_use]
pub fn bluetooth_detail_url(netid: &str) -> String {
    let encoded = crate::util::http::urlencode(netid);
    format!("{API_BASE}/bluetooth/detail?netid={encoded}")
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
    // The shared pre-send gate: already refused within this endpoint's backoff
    // window → do not re-ask, no socket opened. This is the cheap path the 429
    // storm above was missing. The message is deliberately the shared one: the
    // breaker does not record WHY it opened, so claiming "rate-limited" here
    // would over-state a breaker opened by a 5xx.
    let host = crate::util::http::breaker_gate(src, url)?;

    let resp = http
        .get(url)
        .basic_auth(user, Some(token))
        .header("Accept", "application/json")
        .send_tagged(src)
        .await?;

    // One authority for what a round-trip does to the endpoint's breaker: a 429
    // opens it immediately for the server's own Retry-After window, a 5xx counts
    // toward the failure threshold, and any definitive answer — including the
    // 404 below and the auth failures after it — proves the host is up and
    // closes it. This module used to hand-roll that here, correctly, beside a
    // shared version that got the 429 wrong (REQ-HTTP-005); the shared one is
    // now the correct one and this is the only copy.
    crate::util::http::record_breaker_outcome(host.as_deref(), &resp);

    let status = resp.status();
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
        // Typed, so a 429 reaches the breaker, the doctor and the live sweep as
        // `RateLimited` and a WAF interstitial as `BotChallenge` — never the
        // generic module fault this arm used to build by hand, which is what
        // made a throttled WiGLE read as a dead one (cycle E's rule, unapplied
        // here until REQ-HTTP-005).
        return Err(crate::util::http::http_status_error(src, resp).await);
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
    /// host (never a shared `127.0.0.1` mock) and pre-opens that endpoint's
    /// breaker directly, so the assertion never races another test and the
    /// early return guarantees no DNS or network is touched.
    ///
    /// The key is DERIVED with `endpoint_of`, the same function `get` uses,
    /// rather than written out. It previously hard-coded the bare host, which
    /// duplicated the key construction — so when `REQ-BREAKER-001` added the
    /// port to the key, the seeded breaker and the one `get` consults silently
    /// stopped being the same one and the gate under test never fired. A test
    /// that re-implements the thing it is testing can drift from it.
    #[tokio::test]
    async fn a_rate_limited_host_short_circuits_the_next_get() {
        let url = "https://wigle-breaker-gate-test.invalid/api/v2/network/detail?netid=x&type=wifi";
        let endpoint = crate::util::circuit_breaker::endpoint_of(url)
            .expect("a well-formed https URL keys an endpoint");
        // The server asked for a long backoff; well within it, the gate holds.
        crate::util::circuit_breaker::record_rate_limited(
            &endpoint,
            crate::core::entity::unix_now(),
            120,
        );

        let err = get(&reqwest::Client::new(), "user", "token", url, "test_src")
            .await
            .expect_err("a host still inside its 429 backoff must not be requested again");
        // Surfaced as the SHARED breaker short-circuit, and — the load-bearing
        // part — reached without a network round-trip (the `.invalid` host is
        // unresolvable, so any real send would fail differently).
        //
        // The message is the shared one rather than this module's former
        // "backing off" wording, which over-claimed: the breaker does not
        // record WHY it opened, so a gate opened by a 5xx would have read as a
        // rate limit (REQ-HTTP-005 folded the hand-rolled copy into
        // `util::http::breaker_gate`).
        assert!(
            err.to_string()
                .contains("short-circuited by circuit breaker"),
            "must short-circuit via the breaker, not attempt the request: {err}"
        );
    }

    #[test]
    fn detail_url_encodes_netid_and_sets_type() {
        assert_eq!(
            detail_url("AA:BB:CC:DD:EE:FF", "WIFI"),
            "https://api.wigle.net/api/v2/network/detail?netid=AA%3ABB%3ACC%3ADD%3AEE%3AFF&type=WIFI"
        );
        // A cell type is one of the documented network types, passed verbatim.
        assert!(detail_url("123", "LTE").ends_with("netid=123&type=LTE"));
    }

    #[test]
    fn bluetooth_detail_has_its_own_endpoint_and_no_type() {
        assert_eq!(
            bluetooth_detail_url("DD:EE:FF:00:11:22"),
            "https://api.wigle.net/api/v2/bluetooth/detail?netid=DD%3AEE%3AFF%3A00%3A11%3A22"
        );
    }
}
