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
/// * `429` → rate-limit `Err` (logs the server-requested backoff but does **not**
///   sleep — a sleep here would overrun the calling module's wall-clock budget
///   and get the whole result discarded).
/// * `401` / `403` → auth-failure `Err` naming the credential env vars.
/// * `404` → `Ok(None)` (no such network).
/// * other non-2xx → `Err` carrying a body snippet.
/// * success → `Ok(Some(resp))`.
///
/// `src` tags tracing and error context with the calling module's source name.
pub async fn get(
    http: &reqwest::Client,
    user: &str,
    token: &str,
    url: &str,
    src: &'static str,
) -> Result<Option<reqwest::Response>> {
    let resp = http
        .get(url)
        .basic_auth(user, Some(token))
        .header("Accept", "application/json")
        .send_tagged(src)
        .await?;

    let status = resp.status();
    if status.as_u16() == 429 {
        let retry_secs = crate::util::http::retry_after_secs(resp.headers(), 60, 120);
        tracing::warn!("WiGLE 429 — rate-limited (server requested {retry_secs}s backoff)");
        return Err(Error::module(src, "rate-limited (429)"));
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
