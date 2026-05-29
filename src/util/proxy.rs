//! Live proxy harvester, grader, and validator — the proxy *retriever*.
//!
//! Discovers free HTTP proxies from public sources, validates each against a
//! header-echo endpoint, **grades its anonymity** (elite / anonymous /
//! transparent), captures its **country** where the source provides it, and
//! maintains a fastest-/best-first pool. Higher-yield proxies (elite, low
//! latency) sort first so `HUNTSMAN_PROXY=auto` always grabs the best.
//!
//! Compatible with Termux aarch64 — uses the `curl` subprocess for all network
//! calls (no native TLS dependency in this path).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// Anonymity grade of a proxy, ordered best→worst for "high-yield" selection.
///
/// - **Elite**: the origin server sees only the proxy; no proxy-revealing
///   headers — your identity is fully hidden.
/// - **Anonymous**: the server can tell a proxy is in use (`Via` /
///   `X-Forwarded-For` present) but your real IP is not exposed.
/// - **Transparent**: your real IP leaks (in `X-Forwarded-For` / the origin) —
///   useless, even dangerous, for anti-blocking. Sorted last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Grade {
    Elite,
    Anonymous,
    Transparent,
}

impl Grade {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Elite => "elite",
            Self::Anonymous => "anonymous",
            Self::Transparent => "transparent",
        }
    }
}

/// A validated proxy entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Proxy {
    pub addr: String,
    pub proto: String,
    pub latency_ms: u64,
    /// Anonymity grade; `None` when the echo response couldn't be classified.
    #[serde(default)]
    pub grade: Option<Grade>,
    /// ISO country where the harvest source reported it; `None` otherwise.
    #[serde(default)]
    pub country: Option<String>,
}

impl Proxy {
    pub fn url(&self) -> String {
        format!("{}://{}", self.proto, self.addr)
    }
}

/// A harvested-but-unvalidated candidate, carrying the country the source
/// reported (where available) so it survives validation.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub addr: String,
    pub country: Option<String>,
}

/// Sort key: best anonymity first. `None` (undetermined) sits above the
/// dangerous Transparent grade but below confirmed Elite/Anonymous.
fn grade_rank(g: Option<Grade>) -> u8 {
    match g {
        Some(Grade::Elite) => 0,
        Some(Grade::Anonymous) => 1,
        None => 2,
        Some(Grade::Transparent) => 3,
    }
}

/// Classify anonymity from a header-echo response: the `origin` IP the server
/// saw, the (lowercased) request header keys it received, and our own real
/// public IP (empty if unknown). Pure — unit-tested without the network.
pub fn classify_grade(origin_seen: &str, header_keys_lower: &[String], real_ip: &str) -> Grade {
    // Headers that betray a proxy is in use.
    const REVEALING: &[&str] = &[
        "via",
        "x-forwarded-for",
        "forwarded",
        "x-real-ip",
        "client-ip",
        "proxy-connection",
    ];
    let leaks_real_ip = !real_ip.is_empty() && origin_seen.contains(real_ip);
    let has_proxy_headers = header_keys_lower
        .iter()
        .any(|k| REVEALING.contains(&k.as_str()));

    if leaks_real_ip {
        Grade::Transparent
    } else if has_proxy_headers {
        Grade::Anonymous
    } else {
        Grade::Elite
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

/// Harvest candidate proxies from multiple free public sources, capturing
/// country where the source provides it (geonode does; the text lists don't).
pub async fn harvest() -> Vec<Candidate> {
    let mut raw: Vec<Candidate> = Vec::new();

    // Source 1: proxyscrape.com (text list, one per line)
    if let Some(body) = curl_get(
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=yes&anonymity=all",
    ).await {
        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.contains(':') && trimmed.len() >= 9 {
                raw.push(Candidate { addr: trimmed.to_string(), country: None });
            }
        }
    }

    // Source 2: proxy-list.download (text list, elite-only request)
    if let Some(body) =
        curl_get("https://www.proxy-list.download/api/v1/get?type=https&anon=elite").await
    {
        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.contains(':') && trimmed.len() >= 9 {
                raw.push(Candidate {
                    addr: trimmed.to_string(),
                    country: None,
                });
            }
        }
    }

    // Source 3: geonode (JSON — includes country)
    if let Some(body) = curl_get(
        "https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps",
    ).await
        && let Ok(val) = serde_json::from_str::<serde_json::Value>(&body)
        && let Some(data) = val.get("data").and_then(|d| d.as_array())
    {
        for item in data {
            let ip = item.get("ip").and_then(|v| v.as_str()).unwrap_or("");
            let port = item.get("port").and_then(|v| v.as_str()).unwrap_or("");
            let country = item
                .get("country")
                .and_then(|v| v.as_str())
                .filter(|c| !c.is_empty())
                .map(|c| c.to_uppercase());
            if !ip.is_empty() && !port.is_empty() {
                raw.push(Candidate {
                    addr: format!("{ip}:{port}"),
                    country,
                });
            }
        }
    }

    // Dedup by address, keeping the first occurrence (which may carry country).
    raw.sort_by(|a, b| a.addr.cmp(&b.addr));
    raw.dedup_by(|a, b| a.addr == b.addr);
    raw
}

/// Validate a proxy via a header-echo request, returning it with latency and
/// anonymity grade. `real_ip` is our own public IP (empty if unknown) used to
/// detect transparent proxies. `None` if the proxy is dead.
pub async fn validate(addr: &str, real_ip: &str) -> Option<Proxy> {
    let start = std::time::Instant::now();
    let proxy_url = format!("http://{addr}");
    let (code, body) = curl_through_proxy(&proxy_url, "http://httpbin.org/get").await?;
    if code != 200 {
        return None;
    }
    let latency_ms = start.elapsed().as_millis() as u64;

    // Grade from the echoed origin + header keys (best-effort; None on parse fail).
    let grade = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .map(|v| {
            let origin = v.get("origin").and_then(|o| o.as_str()).unwrap_or("");
            let keys: Vec<String> = v
                .get("headers")
                .and_then(|h| h.as_object())
                .map(|m| m.keys().map(|k| k.to_lowercase()).collect())
                .unwrap_or_default();
            classify_grade(origin, &keys, real_ip)
        });

    Some(Proxy {
        addr: addr.to_string(),
        proto: "http".to_string(),
        latency_ms,
        grade,
        country: None,
    })
}

/// The proxy retriever: harvest → validate → grade, returning live proxies in
/// **high-yield order** (best anonymity first, then lowest latency). Validates
/// up to `max_validate` candidates in parallel. Network-bound; empty `Vec` if
/// nothing validates.
pub async fn retrieve(max_validate: usize) -> Vec<Proxy> {
    let candidates = harvest().await;
    if candidates.is_empty() {
        return Vec::new();
    }
    let real_ip = real_public_ip().await.unwrap_or_default();

    let to_test: Vec<Candidate> = candidates.into_iter().take(max_validate).collect();
    let mut tasks = Vec::new();
    for c in to_test {
        let rip = real_ip.clone();
        tasks.push(tokio::spawn(async move {
            validate(&c.addr, &rip).await.map(|mut p| {
                p.country = c.country;
                p
            })
        }));
    }

    let mut valid: Vec<Proxy> = Vec::new();
    for task in tasks {
        if let Ok(Some(proxy)) = task.await {
            valid.push(proxy);
        }
    }
    sort_high_yield(&mut valid);
    valid
}

/// Order proxies best-first: anonymity grade, then latency.
pub fn sort_high_yield(proxies: &mut [Proxy]) {
    proxies.sort_by(|a, b| {
        grade_rank(a.grade)
            .cmp(&grade_rank(b.grade))
            .then(a.latency_ms.cmp(&b.latency_ms))
    });
}

/// Refresh an in-memory pool from the live retriever.
pub async fn refresh_pool(pool: &Arc<ProxyPool>, max_validate: usize) {
    pool.replace(retrieve(max_validate).await);
}

/// Where the validated pool is persisted between invocations.
pub fn pool_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".huntsman").join("proxies.json")
}

/// Persist validated proxies (best-first) to [`pool_path`] as JSON.
pub fn save_pool(proxies: &[Proxy]) -> std::io::Result<()> {
    let path = pool_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let json = serde_json::to_string_pretty(proxies).unwrap_or_else(|_| "[]".to_string());
    std::fs::write(path, json)
}

/// Load the persisted pool (best-first). Empty `Vec` if absent/unreadable.
pub fn load_pool() -> Vec<Proxy> {
    std::fs::read_to_string(pool_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Fetch our own public IP (direct, no proxy) so transparent proxies can be
/// detected by comparison. `None` if unreachable.
async fn real_public_ip() -> Option<String> {
    let body = curl_get("http://httpbin.org/ip").await?;
    serde_json::from_str::<serde_json::Value>(&body)
        .ok()?
        .get("origin")?
        .as_str()
        .map(|s| s.trim().to_string())
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

/// `curl` a URL through a proxy, returning `(http_code, body)`.
async fn curl_through_proxy(proxy_url: &str, url: &str) -> Option<(u16, String)> {
    let secs = 8u64.to_string();
    let mut cmd = tokio::process::Command::new("curl");
    cmd.args([
        "-s",
        "--max-time",
        &secs,
        "-x",
        proxy_url,
        "-w",
        "\n%{http_code}",
        "--",
        url,
    ]);
    cmd.kill_on_drop(true);

    let output = tokio::time::timeout(Duration::from_secs(10), cmd.output())
        .await
        .ok()?
        .ok()?;
    let s = String::from_utf8_lossy(&output.stdout);
    // Last line is the http_code (from -w); everything before it is the body.
    let (body, code) = s.rsplit_once('\n')?;
    let code: u16 = code.trim().parse().ok()?;
    Some((code, body.to_string()))
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
                ..Default::default()
            },
            Proxy {
                addr: "5.6.7.8:3128".into(),
                proto: "http".into(),
                latency_ms: 200,
                ..Default::default()
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
            ..Default::default()
        };
        assert_eq!(p.url(), "http://1.2.3.4:8080");
    }

    #[test]
    fn empty_pool_returns_none() {
        let pool = ProxyPool::new();
        assert!(pool.next().is_none());
    }

    #[test]
    fn pool_json_round_trips_with_grade_and_country() {
        let proxies = vec![Proxy {
            addr: "1.2.3.4:8080".into(),
            proto: "http".into(),
            latency_ms: 100,
            grade: Some(Grade::Elite),
            country: Some("AU".into()),
        }];
        let json = serde_json::to_string(&proxies).unwrap();
        let back: Vec<Proxy> = serde_json::from_str(&json).unwrap();
        assert_eq!(back[0].grade, Some(Grade::Elite));
        assert_eq!(back[0].country.as_deref(), Some("AU"));
    }

    #[test]
    fn old_pool_json_without_grade_still_loads() {
        // Backward-compat: pools written before grading omit the new fields.
        let json = r#"[{"addr":"1.2.3.4:8080","proto":"http","latency_ms":10}]"#;
        let back: Vec<Proxy> = serde_json::from_str(json).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].grade, None);
        assert_eq!(back[0].country, None);
    }

    #[test]
    fn classify_grade_detects_all_three() {
        // Elite: no revealing headers, origin is not our IP.
        assert_eq!(
            classify_grade(
                "203.0.113.9",
                &["host".into(), "accept".into()],
                "198.51.100.7"
            ),
            Grade::Elite
        );
        // Anonymous: a Via header present but our IP not leaked.
        assert_eq!(
            classify_grade(
                "203.0.113.9",
                &["host".into(), "via".into()],
                "198.51.100.7"
            ),
            Grade::Anonymous
        );
        // Transparent: our real IP appears in the origin the server saw.
        assert_eq!(
            classify_grade(
                "198.51.100.7, 203.0.113.9",
                &["x-forwarded-for".into()],
                "198.51.100.7"
            ),
            Grade::Transparent
        );
    }

    #[test]
    fn high_yield_sort_puts_elite_then_fastest_first() {
        let mut v = vec![
            Proxy {
                addr: "a".into(),
                grade: Some(Grade::Transparent),
                latency_ms: 10,
                ..Default::default()
            },
            Proxy {
                addr: "b".into(),
                grade: Some(Grade::Elite),
                latency_ms: 300,
                ..Default::default()
            },
            Proxy {
                addr: "c".into(),
                grade: Some(Grade::Elite),
                latency_ms: 50,
                ..Default::default()
            },
            Proxy {
                addr: "d".into(),
                grade: Some(Grade::Anonymous),
                latency_ms: 20,
                ..Default::default()
            },
        ];
        sort_high_yield(&mut v);
        let order: Vec<&str> = v.iter().map(|p| p.addr.as_str()).collect();
        assert_eq!(order, ["c", "b", "d", "a"]); // elite(fast), elite(slow), anon, transparent
    }
}
