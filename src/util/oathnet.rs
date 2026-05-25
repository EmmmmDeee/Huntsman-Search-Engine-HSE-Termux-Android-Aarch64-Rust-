use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

use crate::core::error::{Error, Result};

const HARDCODED_KEY: &str = "1f8097bdbf7dc68619857861adbc4343ddb490a1d72ae890551409e4b47116f2";

pub const KEY_ENV: &str = "HUNTSMAN_OATHNET_KEY";

fn base_url() -> String {
    std::env::var("HUNTSMAN_OATHNET_BASE").unwrap_or_else(|_| "https://oathnet.org/api".to_string())
}

pub fn resolve_key(ctx_key: Option<&str>) -> &str {
    match ctx_key {
        Some(k) if !k.is_empty() => k,
        _ => HARDCODED_KEY,
    }
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    data: Option<Value>,
    #[serde(default)]
    errors: Option<ErrorDetail>,
}

#[derive(Deserialize, Default)]
struct ErrorDetail {
    #[serde(default)]
    status_code: Option<u16>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct SearchData {
    #[serde(default)]
    items: Vec<Value>,
    #[serde(default)]
    total: Option<u64>,
    #[serde(default, alias = "total_pages")]
    pages: Option<u64>,
    #[serde(default, alias = "current_page")]
    page: Option<u64>,
}

pub async fn search(
    key: &str,
    path: &str,
    field: &str,
    value: &str,
    page_size: u32,
) -> Result<Vec<Value>> {
    let encoded = crate::util::http::urlencode(value);
    let url = format!(
        "{}{}?{}%5B%5D={}&page_size={}",
        base_url(),
        path,
        field,
        encoded,
        page_size
    );
    let body = curl_get(&url, key).await?;
    let env: Envelope =
        serde_json::from_str(&body).map_err(|e| Error::module("oathnet", e.to_string()))?;
    if !env.success {
        if env.errors.as_ref().and_then(|e| e.status_code) == Some(404) {
            return Ok(Vec::new());
        }
        return Err(Error::module("oathnet", "API returned success=false"));
    }
    let data = match env.data {
        Some(d) => d,
        None => return Ok(Vec::new()),
    };
    let sd: SearchData =
        serde_json::from_value(data).map_err(|e| Error::module("oathnet", e.to_string()))?;
    Ok(sd.items)
}

pub async fn search_all_pages(
    key: &str,
    path: &str,
    field: &str,
    value: &str,
    page_size: u32,
    max_pages: u32,
) -> Result<Vec<Value>> {
    let encoded = crate::util::http::urlencode(value);
    let mut all_items: Vec<Value> = Vec::new();
    let mut page = 1u32;

    loop {
        if page > max_pages {
            break;
        }

        let url = format!(
            "{}{}?{}%5B%5D={}&page_size={}&page={}",
            base_url(),
            path,
            field,
            encoded,
            page_size,
            page
        );
        let body = curl_get(&url, key).await?;
        let env: Envelope =
            serde_json::from_str(&body).map_err(|e| Error::module("oathnet", e.to_string()))?;

        if !env.success {
            if env.errors.as_ref().and_then(|e| e.status_code) == Some(404) {
                break;
            }
            if page == 1 {
                return Err(Error::module("oathnet", "API returned success=false"));
            }
            break;
        }

        let data = match env.data {
            Some(d) => d,
            None => break,
        };
        let sd: SearchData =
            serde_json::from_value(data).map_err(|e| Error::module("oathnet", e.to_string()))?;

        let page_count = sd.items.len();
        all_items.extend(sd.items);

        // Stop if this page returned fewer items than requested (last page)
        if (page_count as u32) < page_size {
            break;
        }

        // Stop if we've reached the total reported by the API
        if let Some(total) = sd.total
            && all_items.len() as u64 >= total
        {
            break;
        }

        // Stop if we've reached the total page count
        if let Some(total_pages) = sd.pages
            && page as u64 >= total_pages
        {
            break;
        }

        page += 1;
    }

    Ok(all_items)
}

pub async fn regex_search(
    key: &str,
    path: &str,
    pattern: &str,
    page_size: u32,
) -> Result<Vec<Value>> {
    let encoded = crate::util::http::urlencode(pattern);
    let url = format!(
        "{}{}?q%5B%5D={}&page_size={}&search_type=regex",
        base_url(),
        path,
        encoded,
        page_size
    );
    let body = curl_get(&url, key).await?;
    let env: Envelope =
        serde_json::from_str(&body).map_err(|e| Error::module("oathnet", e.to_string()))?;
    if !env.success {
        if env.errors.as_ref().and_then(|e| e.status_code) == Some(404) {
            return Ok(Vec::new());
        }
        return Err(Error::module("oathnet", "regex search failed"));
    }
    let data = match env.data {
        Some(d) => d,
        None => return Ok(Vec::new()),
    };
    let sd: SearchData =
        serde_json::from_value(data).map_err(|e| Error::module("oathnet", e.to_string()))?;
    Ok(sd.items)
}

pub async fn field_regex_search(
    key: &str,
    path: &str,
    field: &str,
    pattern: &str,
    page_size: u32,
) -> Result<Vec<Value>> {
    let encoded = crate::util::http::urlencode(pattern);
    let url = format!(
        "{}{}?{}%5B%5D={}&page_size={}&search_type=regex",
        base_url(),
        path,
        field,
        encoded,
        page_size
    );
    let body = curl_get(&url, key).await?;
    let env: Envelope =
        serde_json::from_str(&body).map_err(|e| Error::module("oathnet", e.to_string()))?;
    if !env.success {
        if env.errors.as_ref().and_then(|e| e.status_code) == Some(404) {
            return Ok(Vec::new());
        }
        return Err(Error::module("oathnet", "field regex search failed"));
    }
    let data = match env.data {
        Some(d) => d,
        None => return Ok(Vec::new()),
    };
    let sd: SearchData =
        serde_json::from_value(data).map_err(|e| Error::module("oathnet", e.to_string()))?;
    Ok(sd.items)
}

pub async fn regex_search_all_pages(
    key: &str,
    path: &str,
    pattern: &str,
    page_size: u32,
    max_pages: u32,
) -> Result<Vec<Value>> {
    let encoded = crate::util::http::urlencode(pattern);
    let mut all_items: Vec<Value> = Vec::new();
    let mut page = 1u32;

    loop {
        if page > max_pages {
            break;
        }

        let url = format!(
            "{}{}?q%5B%5D={}&page_size={}&search_type=regex&page={}",
            base_url(),
            path,
            encoded,
            page_size,
            page
        );
        let body = curl_get(&url, key).await?;
        let env: Envelope =
            serde_json::from_str(&body).map_err(|e| Error::module("oathnet", e.to_string()))?;

        if !env.success {
            if env.errors.as_ref().and_then(|e| e.status_code) == Some(404) {
                break;
            }
            if page == 1 {
                return Err(Error::module("oathnet", "regex search failed"));
            }
            break;
        }

        let data = match env.data {
            Some(d) => d,
            None => break,
        };
        let sd: SearchData =
            serde_json::from_value(data).map_err(|e| Error::module("oathnet", e.to_string()))?;

        let page_count = sd.items.len();
        all_items.extend(sd.items);

        if (page_count as u32) < page_size {
            break;
        }
        if let Some(total) = sd.total
            && all_items.len() as u64 >= total
        {
            break;
        }

        page += 1;
    }

    Ok(all_items)
}

pub async fn field_regex_search_all(
    key: &str,
    path: &str,
    field: &str,
    pattern: &str,
    page_size: u32,
    max_pages: u32,
) -> Result<Vec<Value>> {
    let encoded = crate::util::http::urlencode(pattern);
    let mut all_items: Vec<Value> = Vec::new();
    let mut page = 1u32;

    loop {
        if page > max_pages {
            break;
        }

        let url = format!(
            "{}{}?{}%5B%5D={}&page_size={}&search_type=regex&page={}",
            base_url(),
            path,
            field,
            encoded,
            page_size,
            page
        );
        let body = curl_get(&url, key).await?;
        let env: Envelope =
            serde_json::from_str(&body).map_err(|e| Error::module("oathnet", e.to_string()))?;

        if !env.success {
            if page == 1 && env.errors.as_ref().and_then(|e| e.status_code) != Some(404) {
                return Err(Error::module("oathnet", "field regex search failed"));
            }
            break;
        }

        let data = match env.data {
            Some(d) => d,
            None => break,
        };
        let sd: SearchData =
            serde_json::from_value(data).map_err(|e| Error::module("oathnet", e.to_string()))?;

        let page_count = sd.items.len();
        all_items.extend(sd.items);

        if (page_count as u32) < page_size {
            break;
        }
        if let Some(total) = sd.total
            && all_items.len() as u64 >= total
        {
            break;
        }

        page += 1;
    }

    Ok(all_items)
}

pub async fn osint(key: &str, path: &str, param: &str, value: &str) -> Result<Value> {
    let encoded = crate::util::http::urlencode(value);
    let url = format!("{}{}?{}={}", base_url(), path, param, encoded);
    let body = curl_get(&url, key).await?;
    let env: Envelope =
        serde_json::from_str(&body).map_err(|e| Error::module("oathnet", e.to_string()))?;
    if !env.success {
        return Err(Error::module("oathnet", "OSINT lookup failed"));
    }
    Ok(env.data.unwrap_or(Value::Null))
}

pub async fn osint_opt(key: &str, path: &str, param: &str, value: &str) -> Result<Option<Value>> {
    let encoded = crate::util::http::urlencode(value);
    let url = format!("{}{}?{}={}", base_url(), path, param, encoded);
    let body = match curl_get(&url, key).await {
        Ok(b) => b,
        Err(_) => return Ok(None),
    };
    let env: Envelope = match serde_json::from_str(&body) {
        Ok(e) => e,
        Err(_) => return Ok(None),
    };
    if !env.success {
        return Ok(None);
    }
    Ok(env.data)
}

#[allow(clippy::too_many_arguments)]
pub async fn search_cached(
    key: &str,
    path: &str,
    field: &str,
    value: &str,
    page_size: u32,
    store: &crate::storage::store::Store,
    scan_id: &str,
    cache_hours: u32,
) -> Result<Vec<Value>> {
    // Check cache first
    if cache_hours > 0
        && let Some(cached) = store
            .cached_response("oathnet_pro", path, field, value, cache_hours)
            .ok()
            .flatten()
        && let Ok(items) = serde_json::from_str::<Vec<Value>>(&cached)
    {
        return Ok(items);
    }

    // Cache miss — make the API call
    let items = search(key, path, field, value, page_size).await?;

    // Store the response
    let response_json = serde_json::to_string(&items).unwrap_or_default();
    let _ = store.cache_api_response(
        "oathnet_pro",
        path,
        field,
        value,
        &response_json,
        items.len(),
        scan_id,
        cache_hours,
    );

    Ok(items)
}

#[allow(clippy::too_many_arguments)]
pub async fn search_all_cached(
    key: &str,
    path: &str,
    field: &str,
    value: &str,
    page_size: u32,
    max_pages: u32,
    store: &crate::storage::store::Store,
    scan_id: &str,
    cache_hours: u32,
) -> Result<Vec<Value>> {
    if cache_hours > 0
        && let Some(cached) = store
            .cached_response("oathnet_pro", path, field, value, cache_hours)
            .ok()
            .flatten()
        && let Ok(items) = serde_json::from_str::<Vec<Value>>(&cached)
        && !items.is_empty()
    {
        return Ok(items);
    }

    let items = search_all_pages(key, path, field, value, page_size, max_pages).await?;

    let response_json = serde_json::to_string(&items).unwrap_or_default();
    let _ = store.cache_api_response(
        "oathnet_pro",
        path,
        field,
        value,
        &response_json,
        items.len(),
        scan_id,
        cache_hours,
    );

    Ok(items)
}

pub async fn osint_cached(
    key: &str,
    path: &str,
    param: &str,
    value: &str,
    store: &crate::storage::store::Store,
    scan_id: &str,
    cache_hours: u32,
) -> Result<Value> {
    if cache_hours > 0
        && let Some(cached) = store
            .cached_response("oathnet_pro", path, param, value, cache_hours)
            .ok()
            .flatten()
        && let Ok(data) = serde_json::from_str::<Value>(&cached)
    {
        return Ok(data);
    }

    let data = osint(key, path, param, value).await?;

    let response_json = data.to_string();
    let _ = store.cache_api_response(
        "oathnet_pro",
        path,
        param,
        value,
        &response_json,
        1,
        scan_id,
        cache_hours,
    );

    Ok(data)
}

pub async fn osint_opt_cached(
    key: &str,
    path: &str,
    param: &str,
    value: &str,
    store: &crate::storage::store::Store,
    scan_id: &str,
    cache_hours: u32,
) -> Result<Option<Value>> {
    if cache_hours > 0
        && let Some(cached) = store
            .cached_response("oathnet_pro", path, param, value, cache_hours)
            .ok()
            .flatten()
        && let Ok(data) = serde_json::from_str::<Value>(&cached)
    {
        return Ok(Some(data));
    }

    let data = osint_opt(key, path, param, value).await?;

    if let Some(ref d) = data {
        let response_json = d.to_string();
        let _ = store.cache_api_response(
            "oathnet_pro",
            path,
            param,
            value,
            &response_json,
            1,
            scan_id,
            cache_hours,
        );
    }

    Ok(data)
}

pub fn val_str(item: &Value, key: &str) -> Option<String> {
    item.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

pub fn val_str_or(item: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| val_str(item, k))
}

pub fn val_i64(item: &Value, key: &str) -> Option<i64> {
    item.get(key).and_then(|v| v.as_i64())
}

pub fn val_bool(item: &Value, key: &str) -> Option<bool> {
    item.get(key).and_then(|v| v.as_bool())
}

pub fn val_array_strings(item: &Value, key: &str) -> Vec<String> {
    item.get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

pub fn top_dbnames(items: &[Value], n: usize) -> Vec<String> {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for item in items {
        if let Some(db) = val_str(item, "dbname") {
            *counts.entry(db).or_default() += 1;
        }
    }
    let mut sorted: Vec<(String, usize)> = counts.into_iter().collect();
    sorted.sort_by_key(|b| std::cmp::Reverse(b.1));
    sorted.into_iter().take(n).map(|(k, _)| k).collect()
}

pub mod paths {
    pub const BREACH: &str = "/service/v2/breach/search";
    pub const STEALER: &str = "/service/v2/stealer/search";
    pub const HOLEHE: &str = "/service/holehe";
    pub const IP_INFO: &str = "/service/ip-info";
    pub const GHUNT: &str = "/service/ghunt";
    pub const DISCORD_USER: &str = "/service/discord-userinfo";
    pub const STEAM: &str = "/service/steam";
    pub const XBOX: &str = "/service/xbox";
    pub const ROBLOX: &str = "/service/roblox-userinfo";
    pub const VICTIMS: &str = "/service/v2/victims/search";
    pub const MAIGRET: &str = "/service/maigret";
    pub const PHONE_LOOKUP: &str = "/service/phone-lookup";
}

pub async fn harvest_credentials(key: &str) -> Vec<(String, String, String, String)> {
    let services = [
        "shodan.io",
        "virustotal.com",
        "hunter.io",
        "securitytrails.com",
        "dehashed.com",
        "intelx.io",
        "numverify.com",
        "wigle.net",
        "ipqualityscore.com",
        "leakix.net",
        "haveibeenpwned.com",
    ];

    let mut creds = Vec::new();
    for service in &services {
        if let Ok(items) = search_all_pages(key, paths::STEALER, "q", service, 50, 3).await {
            for item in &items {
                let url = val_str(item, "url").unwrap_or_default();
                let user = val_str(item, "username").unwrap_or_default();
                let pw = val_str(item, "password").unwrap_or_default();
                if !user.is_empty() && !pw.is_empty() {
                    creds.push((service.to_string(), user, pw, url));
                    break;
                }
            }
        }
    }
    creds
}

async fn curl_get(url: &str, key: &str) -> Result<String> {
    if key.bytes().any(|b| b < 0x20) {
        return Err(Error::module(
            "oathnet",
            "API key contains control characters",
        ));
    }
    let secs = 12u64.to_string();
    let header = format!("x-api-key: {key}");
    let mut cmd = tokio::process::Command::new("curl");
    cmd.args([
        "-s",
        "--max-time",
        &secs,
        "-H",
        &header,
        "-H",
        "Accept: application/json",
        "--",
        url,
    ]);
    cmd.kill_on_drop(true);

    let output = tokio::time::timeout(Duration::from_millis(15_000), cmd.output())
        .await
        .map_err(|_| Error::module("oathnet", "timeout"))?
        .map_err(|e| Error::module("oathnet", e.to_string()))?;

    if !output.status.success() {
        return Err(Error::module("oathnet", "curl failed"));
    }
    String::from_utf8(output.stdout).map_err(|e| Error::module("oathnet", e.to_string()))
}
