use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

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

pub async fn harvest() -> Vec<String> {
    let mut raw: Vec<String> = Vec::new();

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
            proto: "http",
            latency_ms: latency,
        })
    } else {
        None
    }
}

pub async fn refresh_pool(pool: &Arc<ProxyPool>, max_validate: usize) {
    let candidates = harvest().await;
    if candidates.is_empty() {
        return;
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
    pool.replace(valid);
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
                proto: "http",
                latency_ms: 100,
            },
            Proxy {
                addr: "5.6.7.8:3128".into(),
                proto: "http",
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
            proto: "http",
            latency_ms: 50,
        };
        assert_eq!(p.url(), "http://1.2.3.4:8080");
    }

    #[test]
    fn empty_pool_returns_none() {
        let pool = ProxyPool::new();
        assert!(pool.next().is_none());
    }
}
