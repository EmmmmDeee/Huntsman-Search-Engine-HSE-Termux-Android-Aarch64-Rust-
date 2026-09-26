//! HTTP fetchers for the WiGLE API.

use super::*;

/// WiGLE's signal for "this account's email isn't verified yet": query
/// endpoints answer with HTTP 412 and a `success:false` body rather than a
/// 200 with a thinner result set — live-confirmed 2026-07-11:
/// `{"success":false,"message":"Email is not verified for account. Send
/// verification email on account page: https://wigle.net/account"}`. It is a
/// known account state (surfaced separately by `hse doctor` / `/api/v1/stats`),
/// not a transient fault, so it must not be a `ModuleError` that trips the
/// circuit breaker. It is not an answer about the target either: it used to
/// come back as an empty `success:false` body, which every caller turned into
/// `Ok(empty)`, which coverage records as `CleanNegative` — "WiGLE holds
/// nothing here" for a search WiGLE refused to run (REQ-WIGLE-002). It is the
/// typed `Unavailable` skip. Also records the fact in the account cache:
/// ground truth learned for free from traffic already being made, without a
/// dedicated `profile/user` poll.
fn account_unverified() -> crate::core::error::Error {
    super::account::mark_unverified(crate::core::entity::unix_now());
    crate::core::error::Error::skipped(
        crate::core::event::SkipClass::Unavailable,
        "WiGLE refused this account (HTTP 412) because its email address \
         is not verified, and serves no search results until it is. Verify it at \
         https://wigle.net/account. This is NOT \"nothing found\": WiGLE returned no data",
    )
}

/// A decoded search body WiGLE marked `success:false`: the request reached
/// WiGLE and WiGLE declined to serve it, in its own words (`message`). Not a
/// negative — the search did not run — and not a transport fault the breaker
/// should count, so it is the same typed `Unavailable` skip (REQ-WIGLE-002).
pub(super) fn refused(body: &Resp) -> crate::core::error::Error {
    refused_with_message(body.message.as_deref())
}

/// The `success:false` refusal skip, built from WiGLE's own `message`. Shared by
/// [`refused`] (search bodies) and [`fetch_detail`] (detail bodies) so a declined
/// detail lookup carries the identical typed skip and wording a declined search
/// does — the classification the BSSID path was missing (REQ-WIGLE-002).
pub(super) fn refused_with_message(message: Option<&str>) -> crate::core::error::Error {
    let said = message
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .unwrap_or("no reason given");
    crate::core::error::Error::skipped(
        crate::core::event::SkipClass::Unavailable,
        format!(
            "WiGLE answered success:false ({said}). This is NOT \"nothing found\": the search did not run"
        ),
    )
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

/// Classify a completed WiGLE response: `412` (unverified account) is the
/// typed `Unavailable` skip, any other non-success is a hard error, and a
/// success is decoded + scanned for leaked keys — and a decoded body WiGLE
/// itself marked `success:false` is the same skip, so every caller holds a body
/// that really is an answer (REQ-WIGLE-002). A success ALSO records the account
/// as verified (the symmetric counterpart of the 412 branch below) — see
/// [`super::account::mark_verified`] — so a stale unverified latch from
/// earlier in the process self-corrects the moment traffic proves otherwise.
/// Shared tail for every WiGLE search endpoint once [`get_with_retry`] has
/// resolved the 429 question.
pub(super) async fn classify_and_decode(
    resp: reqwest::Response,
) -> crate::core::error::Result<Resp> {
    if resp.status().as_u16() == 412 {
        return Err(account_unverified());
    }
    if !resp.status().is_success() {
        return Err(crate::util::http::http_status_error(SRC, resp).await);
    }
    super::account::mark_verified(crate::core::entity::unix_now());
    let body: Resp = crate::util::http::json_scanned(resp, SRC).await?;
    if body.success != Some(true) {
        return Err(refused(&body));
    }
    Ok(body)
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

/// Bounding-box search URL for `kind`'s corpus. Pure, so the exact parameter
/// set is unit-tested against the documented one.
///
/// Authoritative source: WiGLE's Swagger, `https://api.wigle.net/swagger.json`
/// (retrieved 2026-09-03). The three corpora are three SEPARATE endpoints —
/// see [`NetworkKind::search_endpoint`] — each documenting `latrange1` /
/// `latrange2` / `longrange1` / `longrange2` and `resultsPerPage`, which is all
/// this sends. `onlymine` ("leave unset for general search") and the WiFi-only
/// `freenet`/`paynet` booleans (default `false`) are left unset rather than
/// sent as `false`, exactly as the spec describes the general search.
///
/// `/api/v2/network/search` has NO `type` parameter. This used to send
/// `?type=cell` / `?type=bluetooth` to it: the server ignored the parameter and
/// returned WiFi rows, which the cell/Bluetooth extractors then labelled as
/// cell-carrier and Bluetooth-beacon intelligence — RULE.md's own cautionary
/// case, still live in the code until this.
pub(super) fn search_bbox_url(kind: NetworkKind, lat: f64, lon: f64, d: f64) -> String {
    format!(
        "{}?latrange1={:.6}&latrange2={:.6}&longrange1={:.6}&longrange2={:.6}&resultsPerPage=100",
        kind.search_endpoint(),
        lat - d,
        lat + d,
        lon - d,
        lon + d,
    )
}

/// WiFi SSID search URL — `ssid` is a documented `/api/v2/network/search`
/// parameter ("Include only networks exactly matching the string network
/// name"). Pure; see [`search_bbox_url`] for the source and parameter policy.
pub(super) fn ssid_search_url(ssid: &str) -> String {
    format!(
        "{}?ssid={}&resultsPerPage=100",
        NetworkKind::Wifi.search_endpoint(),
        crate::util::http::urlencode(ssid)
    )
}

/// Bounding-box search of `kind`'s corpus (WiFi, cell tower or Bluetooth),
/// each against its own documented endpoint — see [`search_bbox_url`].
pub(super) async fn fetch_wigle_typed(
    http: &reqwest::Client,
    user: &str,
    token: &str,
    lat: f64,
    lon: f64,
    d: f64,
    kind: NetworkKind,
) -> crate::core::error::Result<Resp> {
    let url = search_bbox_url(kind, lat, lon, d);
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
    let url = ssid_search_url(ssid);
    let resp = get_with_retry(http, user, token, &url).await?;
    classify_and_decode(resp).await
}

#[derive(serde::Deserialize)]
pub(super) struct DetailResp {
    #[serde(default)]
    pub(super) success: Option<bool>,
    #[serde(default)]
    pub(super) results: Vec<Network>,
    /// WiGLE's own explanation on a `success:false` detail body (e.g. the
    /// email-unverified text). Carried so a declined detail lookup reports the
    /// same worded skip a declined search does (REQ-WIGLE-002).
    #[serde(default)]
    pub(super) message: Option<String>,
}

/// Fetch one device address's detail record from `kind`'s corpus. `Ok(None)`
/// is the genuine WiGLE "no such network" answer (a 404, per
/// [`crate::util::wigle::get_answer`]). Every non-absence outcome propagates as
/// `Err` instead of collapsing into the same `None`, so the caller can tell a
/// real outage from a confirmed absence — and, crucially, the detail path is now
/// classified by the SAME conventions the search path is (REQ-WIGLE-002):
///
/// * a 412 is the account-unverified skip — it latches the account state for
///   `hse doctor` (via [`account_unverified`]) exactly as the search path does,
///   instead of the hard, un-latched HTTP error `util::wigle::get` turned it
///   into;
/// * a decoded body WiGLE marked `success:false` is the [`refused`] skip
///   carrying WiGLE's own `message`, instead of an `Ok(_)` the caller read as a
///   miss and coverage recorded as a clean negative.
///
/// Per the Swagger (see [`search_bbox_url`]): a WiFi BSSID is looked up on
/// `/api/v2/network/detail?netid=…&type=WIFI`, a Bluetooth address on its own
/// `/api/v2/bluetooth/detail?netid=…`. There is no address-keyed cell lookup —
/// a cell tower is identified by operator/LAC/CID, never by a MAC — so
/// [`NetworkKind::Cell`] is a caller error here, not a silently-empty answer.
pub(super) async fn fetch_detail(
    http: &reqwest::Client,
    user: &str,
    token: &str,
    bssid: &str,
    kind: NetworkKind,
) -> crate::core::error::Result<Option<DetailResp>> {
    let url = match kind {
        NetworkKind::Wifi => crate::util::wigle::detail_url(bssid, "WIFI"),
        NetworkKind::Bluetooth => crate::util::wigle::bluetooth_detail_url(bssid),
        NetworkKind::Cell => {
            return Err(crate::core::error::Error::module(
                SRC,
                "a cell tower has no address-keyed detail lookup (operator/LAC/CID only)",
            ));
        }
    };
    match crate::util::wigle::get_answer(http, user, token, &url, SRC).await? {
        crate::util::wigle::DetailAnswer::Absent => Ok(None),
        crate::util::wigle::DetailAnswer::Unverified => Err(account_unverified()),
        crate::util::wigle::DetailAnswer::Answer(resp) => decode_detail(resp).await,
    }
}

/// Decode a 2xx detail body, applying the same `success:false` classification
/// the search path does: WiGLE answering `success:false` on a detail lookup is
/// the [`refused`] skip carrying its own `message`, never an `Ok(_)` the caller
/// reads as a miss (REQ-WIGLE-002). Split from [`fetch_detail`] so the
/// success/refusal decision is unit-tested against a real `reqwest::Response`.
pub(super) async fn decode_detail(
    resp: reqwest::Response,
) -> crate::core::error::Result<Option<DetailResp>> {
    let body: DetailResp = crate::util::http::json_scanned(resp, SRC).await?;
    if body.success != Some(true) {
        return Err(refused_with_message(body.message.as_deref()));
    }
    Ok(Some(body))
}
