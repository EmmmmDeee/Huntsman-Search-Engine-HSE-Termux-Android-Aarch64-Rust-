//! HTTP fetchers for the WiGLE API.

use super::*;

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
    use crate::core::error::Error;
    use crate::util::http::RequestBuilderExt;

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

    let resp = http
        .get(&url)
        .basic_auth(user, Some(token))
        .header("Accept", "application/json")
        .send_tagged(SRC)
        .await?;

    let status = resp.status();
    if status.as_u16() == 429 {
        let retry_secs = crate::util::http::retry_after_secs(resp.headers(), 60, 120);
        tracing::warn!("WiGLE 429 — rate-limited (server requested {retry_secs}s backoff)");
        return Err(Error::module(SRC, "rate-limited (429)"));
    }
    if !status.is_success() {
        return Err(crate::util::http::http_status_error(SRC, resp).await);
    }

    crate::util::http::json_scanned(resp, SRC)
        .await
        .map_err(|e| Error::module(SRC, e))
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
    let encoded = crate::util::http::urlencode(bssid);
    let url = format!(
        "https://api.wigle.net/api/v2/network/detail?netid={encoded}&type={kind}",
        kind = kind.as_str(),
    );
    let resp = http
        .get(&url)
        .basic_auth(user, Some(token))
        .header("Accept", "application/json")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    crate::util::http::json_scanned::<DetailResp>(resp, SRC)
        .await
        .ok()
}
