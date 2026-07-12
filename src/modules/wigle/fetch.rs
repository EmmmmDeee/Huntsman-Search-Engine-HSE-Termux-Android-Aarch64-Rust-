//! HTTP fetchers for the WiGLE API.

use super::*;

/// WiGLE's signal for "this account's email isn't verified yet": query
/// endpoints answer with HTTP 412 and a `success:false` body rather than a
/// 200 with a thinner result set — live-confirmed 2026-07-11:
/// `{"success":false,"message":"Email is not verified for account. Send
/// verification email on account page: https://wigle.net/account"}`. This is
/// a known, already-documented throttle (surfaced separately by `hse doctor`
/// / `/api/v1/stats`), not a transient failure, so callers should see a
/// clean zero-yield result — same as any other "WiGLE said no" — instead of
/// a `ModuleError`. Also records the fact in the account cache: ground truth
/// learned for free from traffic already being made, without a dedicated
/// `profile/user` poll.
fn account_unverified_response() -> Resp {
    super::account::mark_unverified(crate::core::entity::unix_now());
    Resp {
        success: Some(false),
        result_count: None,
        total_results: None,
        results: Vec::new(),
    }
}

/// Bounded cap for a single post-429 retry sleep. WiGLE's own `Retry-After`
/// can ask for up to 120s (see the `retry_after_secs` call below), far more
/// than fits inside one `process()` call: `max_timeout_ms` is 20s, split
/// across up to four sub-fetches (WiFi bbox, WiFi SSID, cell, Bluetooth) in
/// the same invocation. 4s mirrors the same "cap the server's real hint to
/// the caller's own budget" discipline `util::http::handle_keyed_error`
/// already established for keyed modules — enough to ride out a short burst
/// throttle without starving the other sub-fetches of their share of the
/// module's total budget.
const RATE_LIMIT_RETRY_CAP_SECS: u64 = 4;

/// Send a GET to `url` with WiGLE's Basic-auth scheme, retrying **once** on a
/// 429 using the server's own `Retry-After` value (bounded to
/// [`RATE_LIMIT_RETRY_CAP_SECS`]) before giving up.
///
/// Previously every 429 computed `retry_secs` from the response purely to log
/// it, then discarded it and failed immediately — a real, server-specified
/// cooldown went completely unused. The module-level error that resulted
/// then tripped the shared per-module circuit breaker's flat 600s
/// `RATE_LIMIT_COOLDOWN` regardless of what WiGLE actually asked for,
/// over-throttling the module for far longer than its own rate-limit
/// contract required whenever the real hint was shorter than 600s (WiGLE's
/// documented burst limits reset in well under that). Acting on the real
/// value first — bounded to fit this module's own timeout budget — recovers
/// the common short burst-throttle within the SAME `process()` call instead
/// of losing the rest of the scan's WiGLE coverage to an oversized cooldown.
/// A persistent 429 (the retry ALSO rate-limited) still degrades to the same
/// module-error-and-circuit-breaker path as before — no infinite retrying.
pub(super) async fn get_with_retry(
    http: &reqwest::Client,
    user: &str,
    token: &str,
    url: &str,
) -> crate::core::error::Result<reqwest::Response> {
    use crate::core::error::Error;
    use crate::util::http::RequestBuilderExt;

    let mut attempt = 0u32;
    loop {
        let resp = http
            .get(url)
            .basic_auth(user, Some(token))
            .header("Accept", "application/json")
            .send_tagged(SRC)
            .await?;
        if resp.status().as_u16() != 429 {
            return Ok(resp);
        }
        if attempt >= 1 {
            return Err(Error::RateLimited(format!("{SRC}: rate-limited (429)")));
        }
        let retry_secs =
            crate::util::http::retry_after_secs(resp.headers(), 2, RATE_LIMIT_RETRY_CAP_SECS);
        tracing::warn!(
            "WiGLE 429 — rate-limited, retrying once in {retry_secs}s (server's own \
             Retry-After, capped to fit the module budget)"
        );
        tokio::time::sleep(std::time::Duration::from_secs(retry_secs)).await;
        attempt += 1;
    }
}

/// Classify a completed WiGLE response: `412` (unverified account) maps to a
/// clean empty result, any other non-success is a hard error, and a success
/// is decoded + scanned for leaked keys. Shared tail for every WiGLE search
/// endpoint once [`get_with_retry`] has resolved the 429 question.
async fn classify_and_decode(resp: reqwest::Response) -> crate::core::error::Result<Resp> {
    use crate::core::error::Error;

    if resp.status().as_u16() == 412 {
        return Ok(account_unverified_response());
    }
    if !resp.status().is_success() {
        return Err(crate::util::http::http_status_error(SRC, resp).await);
    }
    crate::util::http::json_scanned(resp, SRC)
        .await
        .map_err(|e| Error::module(SRC, e))
}

/// Default WiFi-only fetch retained for back-compat — delegates to
/// the type-parameterised variant.
pub(super) async fn fetch_wigle(
    http: &reqwest::Client,
    user: &str,
    token: &str,
    lat: f64,
    lon: f64,
    d: f64,
) -> crate::core::error::Result<Resp> {
    fetch_wigle_typed(http, user, token, lat, lon, d, NetworkKind::Wifi).await
}

/// Type-parameterised WiGLE bbox search. `kind=Wifi` is the legacy
/// path; `Cell` and `Bluetooth` exercise the previously-unused
/// observation corpora.
pub(super) async fn fetch_wigle_typed(
    http: &reqwest::Client,
    user: &str,
    token: &str,
    lat: f64,
    lon: f64,
    d: f64,
    kind: NetworkKind,
) -> crate::core::error::Result<Resp> {
    let url = format!(
        "https://api.wigle.net/api/v2/network/search?\
         latrange1={lat_lo:.6}&latrange2={lat_hi:.6}\
         &longrange1={lon_lo:.6}&longrange2={lon_hi:.6}\
         &onlymine=false&freenet=false&paynet=false\
         &resultsPerPage=100&type={kind}",
        lat_lo = lat - d,
        lat_hi = lat + d,
        lon_lo = lon - d,
        lon_hi = lon + d,
        kind = kind.as_str(),
    );

    let resp = get_with_retry(http, user, token, &url).await?;
    classify_and_decode(resp).await
}

/// WiGLE SSID search: every observed network broadcasting `ssid`, each with its
/// trilaterated location. A *unique* SSID (a personalised home/office network
/// name) geolocates the network — and by extension its owner.
pub(super) async fn fetch_wigle_ssid(
    http: &reqwest::Client,
    user: &str,
    token: &str,
    ssid: &str,
) -> crate::core::error::Result<Resp> {
    use crate::util::http::urlencode;

    let url = format!(
        "https://api.wigle.net/api/v2/network/search?\
         ssid={}&onlymine=false&freenet=false&paynet=false&resultsPerPage=100",
        urlencode(ssid)
    );
    let resp = get_with_retry(http, user, token, &url).await?;
    classify_and_decode(resp).await
}

#[derive(serde::Deserialize)]
pub(super) struct DetailResp {
    #[serde(default)]
    pub(super) success: Option<bool>,
    #[serde(default)]
    pub(super) results: Vec<Network>,
}

pub(super) async fn fetch_detail(
    http: &reqwest::Client,
    user: &str,
    token: &str,
    bssid: &str,
    kind: NetworkKind,
) -> Option<DetailResp> {
    // Shared WiGLE auth + status classification; this fetcher swallows every
    // non-success outcome (404/auth/rate-limit/other) into None, as before.
    let url = crate::util::wigle::detail_url(bssid, kind.as_str());
    let resp = crate::util::wigle::get(http, user, token, &url, SRC)
        .await
        .ok()
        .flatten()?;
    crate::util::http::json_scanned::<DetailResp>(resp, SRC)
        .await
        .ok()
}
