//! HTTP fetch helpers for the ABR JSONP API.

use std::time::Duration;

use serde_json::Value;
use tokio::process::Command;

use crate::core::error::{Error, Result};

use super::{BASE_URL, SRC};

pub(super) async fn fetch_abn(guid: &str, abn: &str) -> Result<Option<Value>> {
    let url = format!("{BASE_URL}/AbnDetails.aspx?abn={abn}&callback=cb&guid={guid}");
    fetch_jsonp(&url).await
}

pub(super) async fn fetch_acn(guid: &str, acn: &str) -> Result<Option<Value>> {
    let url = format!("{BASE_URL}/AcnDetails.aspx?acn={acn}&callback=cb&guid={guid}");
    fetch_jsonp(&url).await
}

pub(super) async fn fetch_name(guid: &str, name: &str) -> Result<Option<Value>> {
    let encoded = crate::util::http::urlencode(name);
    let url = format!("{BASE_URL}/MatchingNames.aspx?name={encoded}&callback=cb&guid={guid}");
    fetch_jsonp(&url).await
}

async fn curl_with_status(url: &str, timeout_ms: u64) -> Option<(String, u16)> {
    let secs = (timeout_ms / 1000).max(3).to_string();
    let mut cmd = Command::new("curl");
    cmd.args([
        "-s",
        "--max-time",
        &secs,
        "-A",
        crate::util::curl::UA_MOBILE,
        "-H",
        "Accept: text/html,application/xhtml+xml,application/json",
        "-H",
        "Accept-Language: en-US,en;q=0.9",
        "-w",
        "\n%{http_code}",
        "-L",
        "--",
        url,
    ]);

    if let Ok(proxy) = std::env::var("HUNTSMAN_SEARCH_PROXY")
        && !proxy.is_empty()
    {
        cmd.args(["-x", &proxy]);
    }

    cmd.kill_on_drop(true);

    let output = tokio::time::timeout(Duration::from_millis(timeout_ms + 2000), cmd.output())
        .await
        .ok()?
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let raw = String::from_utf8(output.stdout).ok()?;
    let (body, code_str) = raw.rsplit_once('\n')?;
    let code: u16 = code_str.trim().parse().unwrap_or(0);
    Some((body.to_string(), code))
}

pub(super) fn parse_jsonp_body(body: &str) -> Option<Value> {
    let json_str = body.strip_prefix("cb(").and_then(|s| s.strip_suffix(')'))?;
    serde_json::from_str(json_str).ok()
}

async fn fetch_jsonp(url: &str) -> Result<Option<Value>> {
    let (body, status) = match curl_with_status(url, 10_000).await {
        Some(pair) => pair,
        None => return Ok(None),
    };

    if status == 429 {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let (body, status) = match curl_with_status(url, 10_000).await {
            Some(pair) => pair,
            None => return Ok(None),
        };
        if status == 429 {
            return Err(Error::module(SRC, "rate-limited (429) after retry"));
        }
        if status == 401 || status == 403 {
            return Err(Error::module(
                SRC,
                format!("HTTP {status}: unauthorized or forbidden"),
            ));
        }
        if status >= 400 {
            return Ok(None);
        }
        return Ok(parse_jsonp_body(&body));
    }

    if status == 401 || status == 403 {
        return Err(Error::module(
            SRC,
            format!("HTTP {status}: unauthorized or forbidden"),
        ));
    }

    if status >= 400 {
        return Ok(None);
    }

    Ok(parse_jsonp_body(&body))
}
