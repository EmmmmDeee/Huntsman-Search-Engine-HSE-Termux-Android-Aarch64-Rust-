//! WiGLE detail-API query helper.

use crate::core::error::Result;

use super::SOURCE;
use super::types::{DetailNetwork, DetailResp};

pub(super) async fn query_wigle_detail(
    http: &reqwest::Client,
    user: &str,
    token: &str,
    bssid: &str,
) -> Result<Option<DetailNetwork>> {
    // Shared auth + rate-limit/auth-failure classification lives in util::wigle
    // (the 429 must surface immediately, not sleep past this module's 20 s
    // budget). A 404 there returns Ok(None) — no such network.
    let url = crate::util::wigle::detail_url(bssid, "wifi");
    let Some(resp) = crate::util::wigle::get(http, user, token, &url, SOURCE).await? else {
        return Ok(None);
    };

    let body: DetailResp = crate::util::http::json_decode(SOURCE, resp).await?;
    if body.success != Some(true) {
        return Ok(None);
    }
    Ok(body.results.into_iter().next())
}
