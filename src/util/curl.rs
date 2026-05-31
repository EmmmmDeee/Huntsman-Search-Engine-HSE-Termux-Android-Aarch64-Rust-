//! curl subprocess fallback for HTTP fetches.
//!
//! Some environments (cloud containers, sandboxes) block the binary's
//! outbound TLS but allow the system `curl` binary. This module
//! provides a `fetch` function that shells out to `curl` as a fallback
//! when reqwest fails, giving modules a reliable HTTP path.
//!
//! On Termux this is also useful: curl is always installed via `pkg`
//! and uses the system's OpenSSL/certificate store, which is often
//! more permissive than rustls's bundled webpki-roots.

use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// Default mobile Chrome User-Agent (Termux context).
pub const UA_MOBILE: &str = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36";

/// Desktop Chrome User-Agent — some engines (Brave, Ecosia) serve
/// better results to desktop browsers.
pub const UA_DESKTOP: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

/// Firefox User-Agent — useful for Startpage and as a fallback when
/// Chrome UAs trigger bot detection.
pub const UA_FIREFOX: &str =
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";

/// macOS Safari User-Agent — a third fingerprint class that some
/// engines treat more leniently.
pub const UA_SAFARI: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15";

/// All available User-Agent strings for rotation.
pub const UA_POOL: &[&str] = &[UA_MOBILE, UA_DESKTOP, UA_FIREFOX, UA_SAFARI];

/// Pick a UA from the pool by index (wraps around).
pub fn pick_ua(idx: usize) -> &'static str {
    UA_POOL[idx % UA_POOL.len()]
}

/// Internal: run curl with full parameter control.
///
/// When the `HUNTSMAN_SEARCH_PROXY` environment variable is set
/// (e.g. `socks5://127.0.0.1:9050` or `http://user:pass@host:port`),
/// the proxy is passed to curl via `-x`. This enables Tor routing,
/// residential proxy services, or any SOCKS/HTTP proxy chain.
/// Resolve `url`'s host, drop private/reserved IPs, and return curl `--resolve`
/// args pinning host:port to a vetted PUBLIC IP — TOCTOU-safe, since curl then
/// will not re-resolve the initial host. Returns `None` when the host resolves
/// only to private/reserved space (or is unparseable), so the caller refuses
/// the fetch. This is the curl-fallback half of the SSRF defense, mirroring
/// `http::SsrfResolver`; it covers attacker-controlled hosts such as
/// employer_pivot's `https://{discovered_domain}/...`.
async fn ssrf_resolve_pin(url: &str) -> Option<Vec<String>> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port_or_known_default()?;
    let ip = tokio::net::lookup_host((host, port))
        .await
        .ok()?
        .map(|a| a.ip())
        .find(|ip| !crate::util::preflight::is_private_addr(*ip))?;
    Some(vec!["--resolve".to_string(), format!("{host}:{port}:{ip}")])
}

async fn curl_exec(
    url: &str,
    timeout_ms: u64,
    ua: &str,
    post_data: Option<&str>,
) -> Option<String> {
    let secs = (timeout_ms / 1000).max(3).to_string();
    let mut cmd = Command::new("curl");
    cmd.args(["-s", "--max-time", &secs, "-A", ua]);
    cmd.args([
        "-H",
        "Accept: text/html,application/xhtml+xml,application/json",
    ]);
    cmd.args(["-H", "Accept-Language: en-US,en;q=0.9"]);

    if let Some(data) = post_data {
        cmd.args(["-H", "Content-Type: application/x-www-form-urlencoded"]);
        cmd.args(["-d", data]);
    }

    let proxy = std::env::var("HUNTSMAN_SEARCH_PROXY")
        .ok()
        .filter(|p| !p.is_empty());

    if let Some(ref p) = proxy {
        cmd.args(["-x", p]);
    } else {
        // Direct connection: pin curl to a vetted public IP so an
        // attacker-controlled host can't be rebound onto an internal address.
        // (When proxied, the proxy resolves and isolates us, so pinning is both
        // inapplicable and unnecessary.) Refuse the fetch if no public IP.
        match ssrf_resolve_pin(url).await {
            Some(pin) => {
                cmd.args(&pin);
            }
            None => return None,
        }
    }

    cmd.args([
        "--proto",
        "=http,https",
        "--proto-redir",
        "=http,https",
        "--max-redirs",
        "5",
    ]);
    cmd.args(["-L", "--", url]);
    cmd.kill_on_drop(true);

    let output = timeout(Duration::from_millis(timeout_ms + 2000), cmd.output())
        .await
        .ok()?
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let body = String::from_utf8(output.stdout).ok()?;
    super::http::scan_for_api_keys(&body);
    Some(body)
}

/// Fetch a URL via curl subprocess. Returns the response body on
/// success, None on any error (timeout, non-zero exit, missing curl).
pub async fn fetch(url: &str, timeout_ms: u64) -> Option<String> {
    curl_exec(url, timeout_ms, UA_MOBILE, None).await
}

/// Fetch with a specific User-Agent string.
pub async fn fetch_with_ua(url: &str, timeout_ms: u64, ua: &str) -> Option<String> {
    curl_exec(url, timeout_ms, ua, None).await
}

/// POST form data to a URL via curl subprocess. Returns the response body
/// on success, None on any error (timeout, non-zero exit, missing curl).
pub async fn fetch_post(url: &str, data: &str, timeout_ms: u64) -> Option<String> {
    curl_exec(url, timeout_ms, UA_MOBILE, Some(data)).await
}

/// POST form data with a specific User-Agent string.
pub async fn fetch_post_with_ua(
    url: &str,
    data: &str,
    timeout_ms: u64,
    ua: &str,
) -> Option<String> {
    curl_exec(url, timeout_ms, ua, Some(data)).await
}

/// Fetch a URL through a specific proxy (SOCKS5, HTTP, or HTTPS).
/// Proxy format: `socks5://host:port`, `http://user:pass@host:port`, etc.
pub async fn fetch_via_proxy(url: &str, timeout_ms: u64, ua: &str, proxy: &str) -> Option<String> {
    let secs = (timeout_ms / 1000).max(3).to_string();
    let mut cmd = Command::new("curl");
    cmd.args(["-s", "--max-time", &secs, "-A", ua]);
    cmd.args([
        "-H",
        "Accept: text/html,application/xhtml+xml,application/json",
    ]);
    cmd.args(["-H", "Accept-Language: en-US,en;q=0.9"]);
    cmd.args(["-x", proxy]);
    cmd.args([
        "--proto",
        "=http,https",
        "--proto-redir",
        "=http,https",
        "--max-redirs",
        "5",
    ]);
    cmd.args(["-L", "--", url]);
    cmd.kill_on_drop(true);

    let output = timeout(Duration::from_millis(timeout_ms + 2000), cmd.output())
        .await
        .ok()?
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let body = String::from_utf8(output.stdout).ok()?;
    super::http::scan_for_api_keys(&body);
    Some(body)
}

/// Fetch JSON from a URL via curl, deserialise as T.
pub async fn fetch_json<T: serde::de::DeserializeOwned>(url: &str, timeout_ms: u64) -> Option<T> {
    let body = fetch(url, timeout_ms).await?;
    match serde_json::from_str(&body) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::debug!(url = %crate::util::http::redact_credentials(url), error = %e, "curl JSON parse failed ({} bytes)", body.len());
            None
        }
    }
}

/// Fetch with proxy fallback: direct → HUNTSMAN_PROXY env → pool rotation.
/// Returns the response body, or None if all paths fail. Modules that
/// want free proxy rotation call this instead of plain `fetch`.
pub async fn fetch_pooled(
    url: &str,
    timeout_ms: u64,
    ua: &str,
    pool: &super::proxy::ProxyPool,
) -> Option<String> {
    if let Some(body) = fetch_with_ua(url, timeout_ms, ua).await
        && !body.is_empty()
    {
        return Some(body);
    }
    if let Ok(proxy) = std::env::var("HUNTSMAN_PROXY")
        && !proxy.is_empty()
        && let Some(body) = fetch_via_proxy(url, timeout_ms, ua, &proxy).await
    {
        return Some(body);
    }
    if let Some(proxy) = pool.next() {
        fetch_via_proxy(url, timeout_ms, ua, &proxy.url()).await
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fetch_returns_none_for_bad_url() {
        let r = fetch("https://256.256.256.256/nonexistent", 3000).await;
        assert!(r.is_none());
    }

    #[test]
    fn ua_pool_has_four_entries() {
        assert_eq!(UA_POOL.len(), 4);
    }

    #[test]
    fn pick_ua_wraps_around() {
        assert_eq!(pick_ua(0), UA_MOBILE);
        assert_eq!(pick_ua(1), UA_DESKTOP);
        assert_eq!(pick_ua(4), UA_MOBILE);
    }
}
