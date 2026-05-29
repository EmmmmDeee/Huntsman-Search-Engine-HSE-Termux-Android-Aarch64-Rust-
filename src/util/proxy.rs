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

/// Infrastructure type of a proxy's IP, by ASN/IP-intelligence. The strongest
/// "high-yield" signal: **residential** and **mobile** egress is far less
/// blocked than **datacenter** (which most free proxies are, and which anti-bot
/// WAFs reject on sight).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyType {
    Mobile,
    Residential,
    Datacenter,
    Unknown,
}

impl ProxyType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mobile => "mobile",
            Self::Residential => "residential",
            Self::Datacenter => "datacenter",
            Self::Unknown => "unknown",
        }
    }
}

/// ASN-org substrings that mark a datacenter/hosting network — used to
/// corroborate (or stand in for) the IP-intelligence `hosting` flag.
const DATACENTER_ORG_HINTS: &[&str] = &[
    "hosting",
    "host",
    "cloud",
    "vps",
    "server",
    "data center",
    "datacenter",
    "colo",
    "dedicated",
    "ovh",
    "amazon",
    "aws",
    "google",
    "microsoft",
    "azure",
    "digitalocean",
    "hetzner",
    "vultr",
    "linode",
    "choopa",
    "m247",
    "leaseweb",
    "contabo",
    "scaleway",
    "oracle",
    "alibaba",
    "tencent",
    "gcore",
];

/// Classify an IP's infrastructure type. The curated `hosting`/`mobile` flags
/// from IP-intelligence are authoritative; when both are false the IP is a
/// residential/business ISP — corroborated against [`DATACENTER_ORG_HINTS`] to
/// catch the rare mislabel. Pure — unit-tested without the network.
pub fn classify_type(hosting: bool, mobile: bool, org: &str) -> ProxyType {
    if mobile {
        ProxyType::Mobile
    } else if hosting {
        ProxyType::Datacenter
    } else {
        let o = org.to_lowercase();
        if DATACENTER_ORG_HINTS.iter().any(|k| o.contains(k)) {
            ProxyType::Datacenter
        } else {
            ProxyType::Residential
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
    /// ISO country (from IP-intelligence, else the harvest source).
    #[serde(default)]
    pub country: Option<String>,
    /// Infrastructure type (datacenter / residential / mobile) by ASN.
    #[serde(default)]
    pub proxy_type: Option<ProxyType>,
    /// ASN org / ISP name, for display and corroboration.
    #[serde(default)]
    pub org: Option<String>,
    /// Unix seconds when this proxy was last confirmed live. Free proxies churn
    /// fast, so the pool's freshness gates whether `auto` should trust it.
    #[serde(default)]
    pub last_validated: u64,
}

/// Pool entries older than this are considered stale (free proxies die fast).
pub const STALE_AFTER_SECS: u64 = 6 * 3600;

/// Re-exported from `util::time` so this module's many `now_secs()` call
/// sites (and the public `proxy::now_secs` path) keep resolving after the
/// helper was hoisted to a shared leaf.
pub use crate::util::time::now_secs;

/// Age in seconds of the freshest proxy in `pool` (how long since the last
/// successful refresh). `None` if the pool is empty or carries no timestamps
/// (e.g. written before freshness tracking).
pub fn pool_age_secs(pool: &[Proxy]) -> Option<u64> {
    let newest = pool.iter().map(|p| p.last_validated).max()?;
    if newest == 0 {
        return None;
    }
    Some(now_secs().saturating_sub(newest))
}

impl Proxy {
    pub fn url(&self) -> String {
        format!("{}://{}", self.proto, self.addr)
    }
}

/// A harvested-but-unvalidated candidate. Carries the wire protocol
/// (`http`/`socks5`/`socks4`), the country the source reported (if any), and a
/// **liveness prior** (higher = source/recency more likely to be live) used to
/// validate the most promising candidates first under a fixed probe budget.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub addr: String,
    pub proto: &'static str,
    pub country: Option<String>,
    pub prior: u8,
}

/// Normalise a source-reported protocol to one we route/validate.
fn map_proto(p: &str) -> &'static str {
    match p.trim().to_lowercase().as_str() {
        "socks5" => "socks5",
        "socks4" => "socks4",
        // "https" in free lists means "supports HTTPS targets", not a TLS proxy.
        _ => "http",
    }
}

/// Liveness-prior score for validation ordering: source/recency prior, boosted
/// when the port is a common proxy port (more likely to be a real, live proxy).
/// Maximises live-proxy yield per probe — the statistically efficient ordering.
fn candidate_score(c: &Candidate) -> u32 {
    let mut s = u32::from(c.prior) * 10;
    if let Some(port) = c
        .addr
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        && matches!(
            port,
            80 | 443 | 1080 | 1085 | 3128 | 4145 | 8000 | 8080 | 8888 | 9050
        )
    {
        s += 5;
    }
    s
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

/// Sort key: least-blocked infrastructure first (mobile < residential <
/// unknown < datacenter) — the "high-yield range" ordering.
fn type_rank(t: Option<ProxyType>) -> u8 {
    match t {
        Some(ProxyType::Mobile) => 0,
        Some(ProxyType::Residential) => 1,
        None | Some(ProxyType::Unknown) => 2,
        Some(ProxyType::Datacenter) => 3,
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

/// Harvest candidate proxies from a **diverse** set of free public sources —
/// HTTP *and* SOCKS4/SOCKS5, including broad community aggregations, so the pool
/// isn't limited to the same few saturated scrape APIs. Candidates carry their
/// protocol, country (where the source reports it), and a liveness prior.
///
/// **Government / military / reserved ranges are dropped here and never probed**
/// (see `preflight::sensitive_range_reason`). We only ingest publicly-listed
/// (advertised-open) proxies — there is intentionally no active scanning of
/// arbitrary IP ranges.
pub async fn harvest() -> Vec<Candidate> {
    let mut raw: Vec<Candidate> = Vec::new();

    // (url, protocol, liveness-prior). Higher prior = source/recency more
    // predictive of a live proxy.
    const TEXT_SOURCES: &[(&str, &str, u8)] = &[
        (
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=yes&anonymity=all",
            "http",
            1,
        ),
        (
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=5000&country=all",
            "socks5",
            2,
        ),
        (
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=5000&country=all",
            "socks4",
            1,
        ),
        (
            "https://www.proxy-list.download/api/v1/get?type=https&anon=elite",
            "http",
            2,
        ),
        (
            "https://www.proxy-list.download/api/v1/get?type=socks5",
            "socks5",
            2,
        ),
        // Broad community aggregations (not the saturated scrape APIs):
        (
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "http",
            1,
        ),
        (
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
            "socks5",
            2,
        ),
        (
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
            "socks4",
            1,
        ),
    ];
    for (url, proto, prior) in TEXT_SOURCES {
        if let Some(body) = curl_get(url).await {
            for line in body.lines() {
                let t = line.trim();
                if t.contains(':') && t.len() >= 9 && !t.contains(' ') {
                    raw.push(Candidate {
                        addr: t.to_string(),
                        proto,
                        country: None,
                        prior: *prior,
                    });
                }
            }
        }
    }

    // geonode (JSON — country + recency + per-proxy protocol). Recency-sorted →
    // highest liveness prior.
    if let Some(body) = curl_get(
        "https://proxylist.geonode.com/api/proxy-list?limit=200&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps%2Csocks4%2Csocks5",
    ).await
        && let Ok(val) = serde_json::from_str::<serde_json::Value>(&body)
        && let Some(data) = val.get("data").and_then(|d| d.as_array())
    {
        for item in data {
            let ip = item.get("ip").and_then(|v| v.as_str()).unwrap_or("");
            let port = item.get("port").and_then(|v| v.as_str()).unwrap_or("");
            if ip.is_empty() || port.is_empty() {
                continue;
            }
            let proto = item
                .get("protocols")
                .and_then(|p| p.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .map(map_proto)
                .unwrap_or("http");
            let country = item
                .get("country")
                .and_then(|v| v.as_str())
                .filter(|c| !c.is_empty())
                .map(str::to_uppercase);
            raw.push(Candidate {
                addr: format!("{ip}:{port}"),
                proto,
                country,
                prior: 3,
            });
        }
    }

    // Dedup by (addr, proto), then DROP any government/reserved range — those
    // are never probed, validated, or routed through.
    raw.sort_by(|a, b| a.addr.cmp(&b.addr).then(a.proto.cmp(b.proto)));
    raw.dedup_by(|a, b| a.addr == b.addr && a.proto == b.proto);
    raw.retain(|c| {
        let ip = c.addr.split(':').next().unwrap_or("");
        crate::util::preflight::sensitive_range_reason(ip).is_none()
    });
    raw
}

/// Validate a proxy via a header-echo request, returning it with latency and
/// anonymity grade. `real_ip` is our own public IP (empty if unknown) used to
/// detect transparent proxies. `None` if the proxy is dead.
pub async fn validate(addr: &str, proto: &str, real_ip: &str) -> Option<Proxy> {
    // Hard guardrail (defence-in-depth): never connect to a sensitive range,
    // even if one slipped past the harvest filter.
    let ip = addr.split(':').next().unwrap_or("");
    if crate::util::preflight::sensitive_range_reason(ip).is_some() {
        return None;
    }
    let start = std::time::Instant::now();
    let proxy_url = format!("{proto}://{addr}");
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
        proto: proto.to_string(),
        latency_ms,
        grade,
        country: None,
        proxy_type: None, // filled by the batched classify step
        org: None,
        last_validated: now_secs(),
    })
}

/// The proxy retriever: harvest → validate → grade, returning live proxies in
/// **high-yield order** (best anonymity first, then lowest latency). Validates
/// up to `max_validate` candidates in parallel. Network-bound; empty `Vec` if
/// nothing validates.
pub async fn retrieve(max_validate: usize) -> Vec<Proxy> {
    let mut candidates = harvest().await;
    if candidates.is_empty() {
        return Vec::new();
    }
    let real_ip = real_public_ip().await.unwrap_or_default();

    // Statistically efficient: validate the highest-liveness-prior candidates
    // first (recency-sorted sources, SOCKS, common ports) so a fixed probe
    // budget yields the most live proxies.
    candidates.sort_by_key(|c| std::cmp::Reverse(candidate_score(c)));
    let to_test: Vec<Candidate> = candidates.into_iter().take(max_validate).collect();
    let mut tasks = Vec::new();
    for c in to_test {
        let rip = real_ip.clone();
        tasks.push(tokio::spawn(async move {
            validate(&c.addr, c.proto, &rip).await.map(|mut p| {
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
    // Determine infrastructure type + authoritative country in one batched
    // IP-intelligence call (best-effort).
    classify_batch(&mut valid).await;
    sort_high_yield(&mut valid);
    valid
}

/// Enrich validated proxies with infrastructure **type** + authoritative
/// **country** + ASN org via one batched IP-intelligence lookup
/// (ip-api.com `/batch`, free, ≤100 IPs per call — so no per-proxy rate-limit).
/// The curated `hosting`/`mobile` flags are the most accurate readily-available
/// type signal. Best-effort: leaves fields untouched on any failure.
async fn classify_batch(proxies: &mut [Proxy]) {
    use std::collections::HashMap;
    if proxies.is_empty() {
        return;
    }
    // ip-result keyed by IP: (countryCode, type, org).
    let mut info: HashMap<String, (Option<String>, ProxyType, Option<String>)> = HashMap::new();
    let ips: Vec<String> = proxies
        .iter()
        .filter_map(|p| p.addr.split(':').next().map(str::to_string))
        .collect();

    for chunk in ips.chunks(100) {
        let Ok(body) = serde_json::to_string(chunk) else {
            continue;
        };
        let url =
            "http://ip-api.com/batch?fields=status,countryCode,as,org,isp,hosting,mobile,query";
        let Some(resp) = curl_post_json(url, &body).await else {
            continue;
        };
        let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&resp) else {
            continue;
        };
        for item in arr {
            if item.get("status").and_then(|s| s.as_str()) != Some("success") {
                continue;
            }
            let Some(ip) = item.get("query").and_then(|v| v.as_str()) else {
                continue;
            };
            let hosting = item
                .get("hosting")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let mobile = item
                .get("mobile")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let org = item
                .get("org")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .or_else(|| item.get("isp").and_then(|v| v.as_str()))
                .or_else(|| item.get("as").and_then(|v| v.as_str()))
                .unwrap_or("")
                .to_string();
            let cc = item
                .get("countryCode")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_uppercase);
            let ty = classify_type(hosting, mobile, &org);
            info.insert(ip.to_string(), (cc, ty, (!org.is_empty()).then_some(org)));
        }
    }

    for p in proxies.iter_mut() {
        if let Some(ip) = p.addr.split(':').next()
            && let Some((cc, ty, org)) = info.get(ip)
        {
            if cc.is_some() {
                p.country = cc.clone(); // ip-api country is authoritative
            }
            p.proxy_type = Some(*ty);
            if p.org.is_none() {
                p.org = org.clone();
            }
        }
    }
}

/// Order proxies best-first: anonymity grade, then infrastructure type
/// (residential/mobile over datacenter), then latency.
pub fn sort_high_yield(proxies: &mut [Proxy]) {
    proxies.sort_by(|a, b| {
        grade_rank(a.grade)
            .cmp(&grade_rank(b.grade))
            .then(type_rank(a.proxy_type).cmp(&type_rank(b.proxy_type)))
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
    let mut pool: Vec<Proxy> = std::fs::read_to_string(pool_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    // Defence-in-depth: never serve a proxy in a government/reserved range,
    // even from a stale or hand-edited pool that predates the harvest filter.
    pool.retain(|p| {
        let ip = p.addr.split(':').next().unwrap_or("");
        crate::util::preflight::sensitive_range_reason(ip).is_none()
    });
    pool
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
    let output = crate::util::curl::run_raw(
        &["--max-time", "10", "-L", "--", url],
        Duration::from_secs(12),
    )
    .await?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

/// POST a JSON `body` to `url` (no proxy), returning the response body.
async fn curl_post_json(url: &str, body: &str) -> Option<String> {
    let output = crate::util::curl::run_raw(
        &[
            "--max-time",
            "12",
            "-H",
            "Content-Type: application/json",
            "-d",
            body,
            "--",
            url,
        ],
        Duration::from_secs(15),
    )
    .await?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

/// `curl` a URL through a proxy, returning `(http_code, body)`.
async fn curl_through_proxy(proxy_url: &str, url: &str) -> Option<(u16, String)> {
    let output = crate::util::curl::run_raw(
        &[
            "--max-time",
            "8",
            "-x",
            proxy_url,
            "-w",
            "\n%{http_code}",
            "--",
            url,
        ],
        Duration::from_secs(10),
    )
    .await?;
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
    fn pool_json_round_trips_with_grade_country_and_type() {
        let proxies = vec![Proxy {
            addr: "1.2.3.4:8080".into(),
            proto: "http".into(),
            latency_ms: 100,
            grade: Some(Grade::Elite),
            country: Some("AU".into()),
            proxy_type: Some(ProxyType::Residential),
            org: Some("Telstra".into()),
            last_validated: 1_700_000_000,
        }];
        let json = serde_json::to_string(&proxies).unwrap();
        let back: Vec<Proxy> = serde_json::from_str(&json).unwrap();
        assert_eq!(back[0].grade, Some(Grade::Elite));
        assert_eq!(back[0].country.as_deref(), Some("AU"));
        assert_eq!(back[0].proxy_type, Some(ProxyType::Residential));
        assert_eq!(back[0].org.as_deref(), Some("Telstra"));
        assert_eq!(back[0].last_validated, 1_700_000_000);
    }

    #[test]
    fn pool_age_reports_freshness() {
        let fresh = vec![Proxy {
            last_validated: now_secs(),
            ..Default::default()
        }];
        assert!(pool_age_secs(&fresh).unwrap() < 5);

        // A pool with no timestamps (pre-freshness JSON) reports None.
        let undated = vec![Proxy::default()];
        assert_eq!(pool_age_secs(&undated), None);
        assert_eq!(pool_age_secs(&[]), None);

        // Old entry → stale.
        let old = vec![Proxy {
            last_validated: now_secs().saturating_sub(STALE_AFTER_SECS + 60),
            ..Default::default()
        }];
        assert!(pool_age_secs(&old).unwrap() > STALE_AFTER_SECS);
    }

    #[test]
    fn classify_type_prefers_flags_then_org_keywords() {
        // Curated flags are authoritative.
        assert_eq!(classify_type(false, true, "Vodafone"), ProxyType::Mobile);
        assert_eq!(
            classify_type(true, false, "Amazon.com"),
            ProxyType::Datacenter
        );
        assert_eq!(classify_type(true, true, "whatever"), ProxyType::Mobile); // mobile wins
        // Neither flag set + ISP org → residential.
        assert_eq!(
            classify_type(false, false, "Telstra Internet"),
            ProxyType::Residential
        );
        // Neither flag but org screams datacenter → corroborated as datacenter.
        assert_eq!(
            classify_type(false, false, "OVH SAS"),
            ProxyType::Datacenter
        );
    }

    #[test]
    fn high_yield_prefers_residential_over_datacenter_at_equal_grade() {
        let mk = |addr: &str, t: ProxyType, lat: u64| Proxy {
            addr: addr.into(),
            grade: Some(Grade::Elite),
            proxy_type: Some(t),
            latency_ms: lat,
            ..Default::default()
        };
        let mut v = vec![
            mk("dc", ProxyType::Datacenter, 10),
            mk("res", ProxyType::Residential, 300),
            mk("mob", ProxyType::Mobile, 500),
        ];
        sort_high_yield(&mut v);
        let order: Vec<&str> = v.iter().map(|p| p.addr.as_str()).collect();
        // Type beats latency at equal anonymity grade: mobile < residential < datacenter.
        assert_eq!(order, ["mob", "res", "dc"]);
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
