//! WiGLE detail-API query helper.

use crate::core::error::{Error, Result};
use crate::util::http::RequestBuilderExt;
use crate::util::http::error_snippet;

use super::SOURCE;
use super::types::{DetailNetwork, DetailResp};

pub(super) async fn query_wigle_detail(
    http: &reqwest::Client,
    user: &str,
    token: &str,
    bssid: &str,
) -> Result<Option<DetailNetwork>> {
    let encoded = crate::util::http::urlencode(bssid);
    let url = format!("https://api.wigle.net/api/v2/network/detail?netid={encoded}&type=wifi");

    let resp = http
        .get(&url)
        .basic_auth(user, Some(token))
        .header("Accept", "application/json")
        .send_tagged(SOURCE)
        .await?;

    let status = resp.status();
    if status.as_u16() == 429 {
        // Return the rate-limit to the caller immediately. The previous code
        // slept up to 120 s here before returning Err, but this module's 20 s
        // budget (max_timeout_ms) meant the engine killed process() mid-sleep
        // — discarding the entire module result, including the phase-1 AP
        // survey already collected, and mislabelling the 429 as a "timeout".
        // No retry follows this branch, so the sleep bought nothing. The
        // value is logged only (not slept on), so the ceiling just bounds the
        // displayed number.
        let retry_secs = crate::util::http::retry_after_secs(resp.headers(), 60, 120);
        tracing::warn!("WiGLE 429 — rate-limited (server requested {retry_secs}s backoff)");
        return Err(Error::module(SOURCE, "rate-limited (429)"));
    }
    if status.as_u16() == 404 {
        return Ok(None);
    }
    if status.as_u16() == 401 || status.as_u16() == 403 {
        return Err(Error::module(
            SOURCE,
            format!("WiGLE auth failed (HTTP {status}): check HUNTSMAN_WIGLE_USER/TOKEN"),
        ));
    }
    if !status.is_success() {
        return Err(Error::module(
            SOURCE,
            format!("WiGLE HTTP {status}: {}", error_snippet(resp).await),
        ));
    }

    let body: DetailResp = crate::util::http::json_decode(SOURCE, resp).await?;

    if body.success != Some(true) {
        return Ok(None);
    }

    Ok(body.results.into_iter().next())
}
