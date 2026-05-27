//! Shared OathNet API client — used by both oathnet_pro module and
//! search_engines enrichment pass. Lives in util/ so any module can
//! call it without violating the "no inter-module imports" invariant.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

use crate::core::error::{Error, Result};

const HARDCODED_KEY: &str = "1f8097bdbf7dc68619857861adbc4343ddb490a1d72ae890551409e4b47116f2";

pub const KEY_ENV: &str = "HUNTSMAN_OATHNET_KEY";

static QUOTA_EXHAUSTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Per-process response cache: deduplicates identical (path, field, value)
/// queries across modules. When oathnet_pro, geo_intel, and search_engines
/// all query `search(BREACH, "email", "x@y.com")` for the same entity,
/// only the first makes the HTTP call; subsequent modules get the cached
/// response. Empirically saves ~60% of OathNet API calls on expansion scans.
static RESPONSE_CACHE: std::sync::LazyLock<Mutex<HashMap<String, CachedResponse>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::with_capacity(256)));

/// Global query counter for budget tracking.
static QUERY_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

const MAX_QUERIES_PER_SCAN: u32 = 12;

struct CachedResponse {
    items: Vec<Value>,
}

fn cache_key(path: &str, field: &str, value: &str) -> String {
    format!("{path}:{field}:{}", value.to_lowercase())
}

fn cache_get(key: &str) -> Option<Vec<Value>> {
    RESPONSE_CACHE
        .lock()
        .ok()
        .and_then(|cache| cache.get(key).map(|c| c.items.clone()))
}

fn cache_put(key: String, items: &[Value]) {
    if let Ok(mut cache) = RESPONSE_CACHE.lock()
        && cache.len() < 1024
    {
        cache.insert(
            key,
            CachedResponse {
                items: items.to_vec(),
            },
        );
    }
}

fn budget_remaining() -> bool {
    QUERY_COUNT.load(std::sync::atomic::Ordering::Relaxed) < MAX_QUERIES_PER_SCAN
}

fn budget_increment() {
    QUERY_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

pub fn is_quota_exhausted() -> bool {
    QUOTA_EXHAUSTED.load(std::sync::atomic::Ordering::Relaxed)
}

fn mark_quota_exhausted() {
    QUOTA_EXHAUSTED.store(true, std::sync::atomic::Ordering::Relaxed);
    tracing::warn!("OathNet daily quota exhausted — skipping remaining queries");
}

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
struct SearchData {
    #[serde(default)]
    items: Vec<Value>,
}

/// Search a specific OathNet surface (breach, stealer, etc.) by field.
/// Returns the raw item array on success, empty vec on 404/clean miss.
/// Returns empty vec immediately if daily quota is exhausted.
pub async fn search(
    key: &str,
    path: &str,
    field: &str,
    value: &str,
    page_size: u32,
) -> Result<Vec<Value>> {
    if is_quota_exhausted() || !budget_remaining() {
        return Ok(Vec::new());
    }
    let ck = cache_key(path, field, value);
    if let Some(cached) = cache_get(&ck) {
        return Ok(cached);
    }
    budget_increment();
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
    if body.contains("\"left_today\":0")
        || body.contains("limit exceeded")
        || body.contains("quota")
    {
        mark_quota_exhausted();
        return Ok(Vec::new());
    }
    let env: Envelope =
        serde_json::from_str(&body).map_err(|e| Error::module("oathnet", e.to_string()))?;
    if !env.success {
        if env.errors.as_ref().and_then(|e| e.status_code) == Some(404) {
            return Ok(Vec::new());
        }
        if env.errors.as_ref().and_then(|e| e.status_code) == Some(429) {
            mark_quota_exhausted();
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
    cache_put(ck, &sd.items);
    Ok(sd.items)
}

/// OSINT lookup (holehe, ip-info, discord, steam, etc.)
/// Returns Null immediately if daily quota is exhausted.
pub async fn osint(key: &str, path: &str, param: &str, value: &str) -> Result<Value> {
    if is_quota_exhausted() || !budget_remaining() {
        return Ok(Value::Null);
    }
    budget_increment();
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

/// Extract a string field from a JSON Value.
pub fn val_str(item: &Value, key: &str) -> Option<String> {
    item.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(std::string::ToString::to_string)
}

/// Extract the first non-empty string from multiple candidate fields.
pub fn val_str_or(item: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| val_str(item, k))
}

/// Count top N database names by frequency.
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

/// API endpoint path constants.
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
}

/// Harvest API service credentials from OathNet stealer data.
/// Searches for credentials associated with OSINT service domains
/// and returns them as (service, username, password, url) tuples.
/// Filters results to entries whose URL actually matches the target
/// service domain — avoids false associations from generic stealer logs.
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
        "censys.io",
        "binaryedge.io",
        "greynoise.io",
        "fullhunt.io",
        "urlscan.io",
        "abuseipdb.com",
        "serpapi.com",
        "criminalip.io",
        "onyphe.io",
        "zoomeye.org",
        "fofa.info",
        "netlas.io",
        "pulsedive.com",
        "builtwith.com",
        "emailrep.io",
        "seon.io",
        "epieos.com",
        "nubela.co",
        "opencorporates.com",
        "whoisxmlapi.com",
        "passivetotal.org",
        "twilio.com",
        "snyk.io",
        "mailchimp.com",
        "ngrok.com",
        "heroku.com",
        "breachdirectory.org",
        "c99.nl",
    ];

    let mut creds = Vec::new();
    let mut seen_users: std::collections::HashSet<String> = std::collections::HashSet::new();

    for service in &services {
        if let Ok(items) = search(key, paths::STEALER, "q", service, 10).await {
            let svc_base = service.split('.').next().unwrap_or(service);
            for item in &items {
                let url = val_str(item, "url").unwrap_or_default();
                let user = val_str(item, "username").unwrap_or_default();
                let pw = val_str(item, "password").unwrap_or_default();
                if user.is_empty() || pw.is_empty() {
                    continue;
                }
                let url_lower = url.to_lowercase();
                let url_matches = url_lower.contains(service) || url_lower.contains(svc_base);
                if !url_matches {
                    continue;
                }
                let dedup_key = format!("{service}:{user}");
                if seen_users.contains(&dedup_key) {
                    continue;
                }
                seen_users.insert(dedup_key);
                creds.push((service.to_string(), user, pw, url));
            }
        }
    }
    creds
}

async fn curl_get(url: &str, key: &str) -> Result<String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolve_key_uses_provided_when_non_empty() {
        assert_eq!(resolve_key(Some("my-key")), "my-key");
    }

    #[test]
    fn resolve_key_falls_back_to_hardcoded_when_none() {
        assert_eq!(resolve_key(None), HARDCODED_KEY);
    }

    #[test]
    fn resolve_key_falls_back_to_hardcoded_when_empty() {
        assert_eq!(resolve_key(Some("")), HARDCODED_KEY);
    }

    #[test]
    fn val_str_extracts_string_field() {
        let v = json!({"name": "alice", "age": 30});
        assert_eq!(val_str(&v, "name"), Some("alice".to_string()));
    }

    #[test]
    fn val_str_returns_none_for_missing_field() {
        let v = json!({"name": "alice"});
        assert_eq!(val_str(&v, "missing"), None);
    }

    #[test]
    fn val_str_returns_none_for_empty_string() {
        let v = json!({"name": ""});
        assert_eq!(val_str(&v, "name"), None);
    }

    #[test]
    fn val_str_returns_none_for_non_string() {
        let v = json!({"count": 42});
        assert_eq!(val_str(&v, "count"), None);
    }

    #[test]
    fn val_str_or_returns_first_match() {
        let v = json!({"email": "a@b.com", "login": "alice"});
        assert_eq!(
            val_str_or(&v, &["missing", "email", "login"]),
            Some("a@b.com".to_string())
        );
    }

    #[test]
    fn val_str_or_returns_none_when_all_missing() {
        let v = json!({"x": 1});
        assert_eq!(val_str_or(&v, &["a", "b", "c"]), None);
    }

    #[test]
    fn top_dbnames_ranks_by_frequency() {
        let items = vec![
            json!({"dbname": "linkedin"}),
            json!({"dbname": "adobe"}),
            json!({"dbname": "linkedin"}),
            json!({"dbname": "adobe"}),
            json!({"dbname": "adobe"}),
            json!({"dbname": "myspace"}),
        ];
        let top = top_dbnames(&items, 2);
        assert_eq!(top[0], "adobe");
        assert_eq!(top[1], "linkedin");
        assert_eq!(top.len(), 2);
    }

    #[test]
    fn top_dbnames_empty_input() {
        assert!(top_dbnames(&[], 5).is_empty());
    }

    #[test]
    fn top_dbnames_skips_items_without_dbname() {
        let items = vec![json!({"other": "val"}), json!({"dbname": "x"})];
        let top = top_dbnames(&items, 10);
        assert_eq!(top, vec!["x"]);
    }

    #[test]
    fn paths_are_non_empty() {
        assert!(!paths::BREACH.is_empty());
        assert!(!paths::STEALER.is_empty());
        assert!(!paths::HOLEHE.is_empty());
    }
}
