//! Live proxy harvester and validator.
//!
//! Discovers free HTTP/SOCKS proxies from public sources, validates them
//! against a test endpoint, and maintains a rotating pool. The pool is stored in
//! memory and refreshed on demand.
//!
//! Termux aarch64 hardening:
//!   * all source fetches go through the hardened `util::curl` fetcher (SSRF
//!     connect-pin, `--proto`/`--proto-redir` limits, `--max-filesize`, lossy
//!     decode) — no second, un-hardened curl path;
//!   * harvested candidates are filtered to PUBLIC numeric endpoints so a
//!     poisoned proxy list can't turn the fetcher into an SSRF vector
//!     (`curl -x 127.0.0.1:… ` / `-x 169.254.169.254:…`);
//!   * proxy validation is concurrency-bounded so a refresh can't spawn dozens
//!     of `curl` processes on a low-power device.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

/// Max proxy validations to run at once. Each spawns a `curl` subprocess, so an
/// unbounded fan-out (one task per candidate) would spawn dozens of processes on
/// a 2-core phone; this caps concurrency while leaving the candidate count to
/// the caller.
const MAX_CONCURRENT_VALIDATIONS: usize = 8;

/// A validated proxy entry.
#[derive(Debug, Clone)]
pub struct Proxy {
    pub addr: String,
    pub proto: &'static str,
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

/// True if `addr` (`host:port`) is a usable PUBLIC proxy endpoint. Drops
/// private / reserved / loopback / link-local hosts, hostnames, and malformed or
/// port-less entries — so a poisoned proxy list can't make the fetcher proxy
/// through a local/internal service (the proxy-side half of the SSRF defence).
fn is_public_proxy(addr: &str) -> bool {
    let Some((host, port)) = addr.rsplit_once(':') else {
        return false;
    };
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.parse::<std::net::IpAddr>()
        .map(|ip| !crate::util::preflight::is_private_addr(ip))
        .unwrap_or(false)
}

/// Collect `host:port`-looking lines from a text proxy list.
fn push_lines(out: &mut Vec<String>, body: &str) {
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.contains(':') && trimmed.len() >= 9 {
            out.push(trimmed.to_string());
        }
    }
}

/// Harvest proxies from multiple free public sources, keeping only public
/// numeric endpoints. All fetches go through the hardened `util::curl` fetcher.
pub async fn harvest() -> Vec<String> {
    let mut raw: Vec<String> = Vec::new();

    // Source 1: proxyscrape.com (text list, one per line)
    if let Some(body) = crate::util::curl::fetch(
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=yes&anonymity=all",
        10_000,
    )
    .await
    {
        push_lines(&mut raw, &body);
    }

    // Source 2: proxy-list.download (text list)
    if let Some(body) = crate::util::curl::fetch(
        "https://www.proxy-list.download/api/v1/get?type=https&anon=elite",
        10_000,
    )
    .await
    {
        push_lines(&mut raw, &body);
    }

    // Source 3: geonode (JSON)
    if let Some(body) = crate::util::curl::fetch(
        "https://proxylist.geonode.com/api/proxy-list?limit=50&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps",
        10_000,
    )
    .await
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

    // SSRF: keep only public numeric endpoints (drop loopback / RFC1918 /
    // link-local-metadata / hostnames a poisoned source might inject).
    raw.retain(|a| is_public_proxy(a));
    raw.sort();
    raw.dedup();
    raw
}

/// Validate a proxy by making a test request through it. Returns the proxy with
/// latency if valid, `None` if dead. Refuses non-public proxy addresses up front
/// (defence in depth, even if a caller passes one directly).
pub async fn validate(addr: &str) -> Option<Proxy> {
    if !is_public_proxy(addr) {
        return None;
    }

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
        // Restrict to HTTP(S) and bound redirects even for the test fetch.
        "--proto",
        "=http,https",
        "--max-redirs",
        "2",
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
        Some(Proxy {
            addr: addr.to_string(),
            proto: "http",
            latency_ms: start.elapsed().as_millis() as u64,
        })
    } else {
        None
    }
}

/// Harvest and validate proxies, returning only live ones. Validates up to
/// `max_validate` candidates, at most [`MAX_CONCURRENT_VALIDATIONS`] at a time so
/// a refresh never spawns dozens of `curl` processes on a phone.
pub async fn refresh_pool(pool: &Arc<ProxyPool>, max_validate: usize) {
    let candidates = harvest().await;
    if candidates.is_empty() {
        return;
    }

    let to_test: Vec<String> = candidates.into_iter().take(max_validate).collect();
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_VALIDATIONS));
    let mut tasks = Vec::with_capacity(to_test.len());

    for addr in to_test {
        let sem = Arc::clone(&sem);
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            validate(&addr).await
        }));
    }

    let mut valid: Vec<Proxy> = Vec::new();
    for task in tasks {
        if let Ok(Some(proxy)) = task.await {
            valid.push(proxy);
        }
    }

    valid.sort_by_key(|p| p.latency_ms);
    pool.replace(valid);
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
