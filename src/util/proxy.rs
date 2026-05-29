//! Live proxy harvester and validator.
//!
//! Discovers free HTTP/SOCKS proxies from public sources, validates
//! them against a test endpoint, and maintains a rotating pool. The
//! pool is stored in memory and refreshed on demand.
//!
//! Compatible with Termux aarch64 — uses curl subprocess for all
//! network calls (no native TLS dependencies).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// A validated proxy entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proxy {
    pub addr: String,
    pub proto: String,
    pub latency_ms: u64,
}

impl Proxy {
    pub fn url(&self) -> String {
        format!("{}://{}", self.proto, self.addr)
    }
}

/// Thread-safe proxy pool with round-robin selection.
pub struct ProxyPool {
    proxies: Mutex<Vec<Proxy>>,
    index: Mutex<usize>,
}

impl Default for ProxyPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyPool {
    pub fn new() -> Self {
        Self {
            proxies: Mutex::new(Vec::new()),
            index: Mutex::new(0),
        }
    }

    pub fn count(&self) -> usize {
        self.proxies.lock().len()
    }

    pub fn next(&self) -> Option<Proxy> {
        let proxies = self.proxies.lock();
        if proxies.is_empty() {
            return None;
        }
        let mut idx = self.index.lock();
        let proxy = proxies[*idx % proxies.len()].clone();
        *idx = idx.wrapping_add(1);
        Some(proxy)
    }

    pub fn replace(&self, new: Vec<Proxy>) {
        let mut proxies = self.proxies.lock();
        *proxies = new;
        *self.index.lock() = 0;
    }
}

/// Harvest proxies from multiple free public sources.
pub async fn harvest() -> Vec<String> {
    let mut raw: Vec<String> = Vec::new();

    // Source 1: proxyscrape.com (text list, one per line)
    if let Some(body) = curl_get(
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=yes&anonymity=all",
    ).await {
        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.contains(':') && trimmed.len() >= 9 {
                raw.push(trimmed.to_string());
            }
        }
    }

    // Source 2: proxy-list.download (text list)
    if let Some(body) =
        curl_get("https://www.proxy-list.download/api/v1/get?type=https&anon=elite").await
    {
        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.contains(':') && trimmed.len() >= 9 {
                raw.push(trimmed.to_string());
            }
        }
    }

    // Source 3: geonode (JSON)
    if let Some(body) = curl_get(
        "https://proxylist.geonode.com/api/proxy-list?limit=50&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps",
    ).await
        && let Ok(val) = serde_json::from_str::<serde_json::Value>(&body)
        && let Some(data) = val.get("data").and_then(|d| d.as_array())
    {
        for item in data {
            let ip = item.get("ip").and_then(|v| v.as_str()).unwrap_or("");
            let port = item.get("port").and_then(|v| v.as_str()).unwrap_or("");
            if !ip.is_empty() && !port.is_empty() {
                raw.push(format!("{ip}:{port}"));
            }
        }
    }

    raw.sort();
    raw.dedup();
    raw
}

/// Validate a proxy by making a test request through it.
/// Returns the proxy with latency if valid, None if dead.
pub async fn validate(addr: &str) -> Option<Proxy> {
    let start = std::time::Instant::now();
    let proxy_url = format!("http://{addr}");

    let secs = 8u64.to_string();
    let mut cmd = tokio::process::Command::new("curl");
    cmd.args([
        "-s",
        "--max-time",
        &secs,
        "-x",
        &proxy_url,
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "--",
        "http://httpbin.org/ip",
    ]);
    cmd.kill_on_drop(true);

    let output = tokio::time::timeout(Duration::from_secs(10), cmd.output())
        .await
        .ok()?
        .ok()?;

    let code = String::from_utf8_lossy(&output.stdout);
    if code.trim() == "200" {
        let latency = start.elapsed().as_millis() as u64;
        Some(Proxy {
            addr: addr.to_string(),
            proto: "http".to_string(),
            latency_ms: latency,
        })
    } else {
        None
    }
}

/// Harvest and validate proxies, returning only live ones sorted by latency.
/// Validates up to `max_validate` candidates in parallel. This is the proxy
/// *retriever*: the one entry point that turns public sources into a usable,
/// fastest-first list. Network-bound (curl); empty `Vec` if nothing validates.
pub async fn retrieve(max_validate: usize) -> Vec<Proxy> {
    let candidates = harvest().await;
    if candidates.is_empty() {
        return Vec::new();
    }

    let to_test: Vec<String> = candidates.into_iter().take(max_validate).collect();
    let mut tasks = Vec::new();
    for addr in to_test {
        tasks.push(tokio::spawn(async move { validate(&addr).await }));
    }

    let mut valid: Vec<Proxy> = Vec::new();
    for task in tasks {
        if let Ok(Some(proxy)) = task.await {
            valid.push(proxy);
        }
    }
    valid.sort_by_key(|p| p.latency_ms);
    valid
}

/// Refresh an in-memory pool from the live retriever.
pub async fn refresh_pool(pool: &Arc<ProxyPool>, max_validate: usize) {
    pool.replace(retrieve(max_validate).await);
}

/// Where the validated pool is persisted between invocations. Each CLI run is a
/// fresh process, so the retriever's output is saved here for later scans/serve
/// to load (`hse proxies refresh` writes it; `HUNTSMAN_PROXY=auto` reads it).
pub fn pool_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".huntsman").join("proxies.json")
}

/// Persist validated proxies (fastest-first) to [`pool_path`] as JSON.
pub fn save_pool(proxies: &[Proxy]) -> std::io::Result<()> {
    let path = pool_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let json = serde_json::to_string_pretty(proxies).unwrap_or_else(|_| "[]".to_string());
    std::fs::write(path, json)
}

/// Load the persisted pool (fastest-first). Empty `Vec` if absent/unreadable.
pub fn load_pool() -> Vec<Proxy> {
    std::fs::read_to_string(pool_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

async fn curl_get(url: &str) -> Option<String> {
    let secs = 10u64.to_string();
    let mut cmd = tokio::process::Command::new("curl");
    cmd.args(["-s", "--max-time", &secs, "-L", "--", url]);
    cmd.kill_on_drop(true);

    let output = tokio::time::timeout(Duration::from_secs(12), cmd.output())
        .await
        .ok()?
        .ok()?;

    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_pool_round_robin() {
        let pool = ProxyPool::new();
        pool.replace(vec![
            Proxy {
                addr: "1.2.3.4:8080".into(),
                proto: "http".into(),
                latency_ms: 100,
            },
            Proxy {
                addr: "5.6.7.8:3128".into(),
                proto: "http".into(),
                latency_ms: 200,
            },
        ]);
        assert_eq!(pool.count(), 2);
        let a = pool.next().unwrap();
        let b = pool.next().unwrap();
        let c = pool.next().unwrap();
        assert_eq!(a.addr, "1.2.3.4:8080");
        assert_eq!(b.addr, "5.6.7.8:3128");
        assert_eq!(c.addr, "1.2.3.4:8080"); // wraps around
    }

    #[test]
    fn proxy_url_format() {
        let p = Proxy {
            addr: "1.2.3.4:8080".into(),
            proto: "http".into(),
            latency_ms: 50,
        };
        assert_eq!(p.url(), "http://1.2.3.4:8080");
    }

    #[test]
    fn pool_json_round_trips() {
        let proxies = vec![
            Proxy {
                addr: "1.2.3.4:8080".into(),
                proto: "http".into(),
                latency_ms: 100,
            },
            Proxy {
                addr: "5.6.7.8:3128".into(),
                proto: "http".into(),
                latency_ms: 200,
            },
        ];
        let json = serde_json::to_string(&proxies).unwrap();
        let back: Vec<Proxy> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].addr, "1.2.3.4:8080");
        assert_eq!(back[0].url(), "http://1.2.3.4:8080");
    }

    #[test]
    fn empty_pool_returns_none() {
        let pool = ProxyPool::new();
        assert!(pool.next().is_none());
    }
}
