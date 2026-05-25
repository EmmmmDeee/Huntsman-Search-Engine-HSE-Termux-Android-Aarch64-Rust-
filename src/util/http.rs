use std::time::Duration;

use serde::de::DeserializeOwned;

use crate::core::error::{Error, Result};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .pool_max_idle_per_host(5)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Duration::from_secs(15))
        .user_agent(concat!(
            "huntsman-search-engine/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-)"
        ))
        .build()
        .expect("reqwest client build failed")
}

pub async fn error_snippet(resp: reqwest::Response) -> String {
    match resp.text().await {
        Ok(body) => {
            let trimmed = body.trim();
            if trimmed.is_empty() {
                "<empty>".to_string()
            } else {
                trimmed
                    .replace(['\n', '\r'], " ")
                    .chars()
                    .take(200)
                    .collect()
            }
        }
        Err(_) => "<unreadable>".to_string(),
    }
}

pub async fn fetch_json<T: DeserializeOwned>(
    client: &reqwest::Client,
    module: &'static str,
    url: &str,
) -> Result<T> {
    match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status();
            if !status.is_success() {
                return Err(Error::module(
                    module,
                    format!("HTTP {status}: {}", error_snippet(resp).await),
                ));
            }
            resp.json::<T>()
                .await
                .map_err(|e| Error::module(module, e.to_string()))
        }
        Err(_) => match super::curl::fetch_json::<T>(url, crate::MODULE_TIMEOUT_MS).await {
            Some(data) => Ok(data),
            None => Err(Error::module(
                module,
                format!("request failed for {url} (reqwest + curl)"),
            )),
        },
    }
}

/// Maps HTTP 404 to `Ok(None)` for upstreams that use 404 as a "not in
/// our dataset" signal. Other non-2xx statuses remain errors.
pub async fn fetch_json_or_404<T: DeserializeOwned>(
    client: &reqwest::Client,
    module: &'static str,
    url: &str,
) -> Result<Option<T>> {
    match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.as_u16() == 404 {
                return Ok(None);
            }
            if !status.is_success() {
                return Err(Error::module(
                    module,
                    format!("HTTP {status}: {}", error_snippet(resp).await),
                ));
            }
            let data = resp
                .json::<T>()
                .await
                .map_err(|e| Error::module(module, e.to_string()))?;
            Ok(Some(data))
        }
        Err(_) => Ok(super::curl::fetch_json::<T>(url, crate::MODULE_TIMEOUT_MS).await),
    }
}

pub fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
