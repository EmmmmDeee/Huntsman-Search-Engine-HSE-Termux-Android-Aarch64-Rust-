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
async fn curl_exec(
    url: &str,
    timeout_ms: u64,
    ua: &str,
    post_data: Option<&str>,
) -> Option<String> {
    let secs = (timeout_ms / 1000).max(3).to_string();
    let search_proxy = std::env::var("HUNTSMAN_SEARCH_PROXY")
        .ok()
        .filter(|p| !p.is_empty());

    let mut args: Vec<&str> = vec![
        "--max-time",
        secs.as_str(),
        "-A",
        ua,
        "-H",
        "Accept: text/html,application/xhtml+xml,application/json",
        "-H",
        "Accept-Language: en-US,en;q=0.9",
    ];
    if let Some(data) = post_data {
        args.extend([
            "-H",
            "Content-Type: application/x-www-form-urlencoded",
            "-d",
            data,
        ]);
    }
    if let Some(proxy) = search_proxy.as_deref() {
        args.extend(["-x", proxy]);
    }
    args.extend(["-L", "--", url]);

    let output = run_raw(&args, Duration::from_millis(timeout_ms + 2000)).await?;
    if !output.status.success() {
        return None;
    }
    let body = String::from_utf8(output.stdout).ok()?;
    super::http::scan_for_api_keys(&body);
    Some(body)
}

/// Why a low-level curl spawn failed, for callers that need to tell a hard
/// timeout apart from an actual spawn/io error. The typed `curl_client`
/// transport uses this to keep its distinct `"timeout"` vs io-error module
/// log messages; the common `run_raw` path collapses both into `None`.
pub(crate) enum CurlSpawnError {
    /// The outer hard timeout fired before curl exited.
    Timeout,
    /// curl could not be spawned, or collecting its output failed.
    Spawn(std::io::Error),
}

/// The single point where the `curl` subprocess is spawned. Always passes
/// `-s`, sets `kill_on_drop`, and enforces a hard outer timeout so a wedged
/// curl can never hold a concurrency slot. Distinguishes a timeout from a
/// spawn/io failure for callers that report them differently (most callers
/// use the `run_raw` wrapper, which discards that distinction). The caller
/// interprets the exit status / stdout — a `-w %{http_code}` probe needs the
/// body even on a non-2xx. Every curl invocation in the crate routes through
/// here, so subprocess hardening lives in exactly one place.
pub(crate) async fn run_raw_result(
    args: &[&str],
    hard_timeout: Duration,
) -> std::result::Result<std::process::Output, CurlSpawnError> {
    let mut cmd = Command::new("curl");
    cmd.arg("-s");
    cmd.args(args);
    cmd.kill_on_drop(true);
    match timeout(hard_timeout, cmd.output()).await {
        Err(_) => Err(CurlSpawnError::Timeout),
        Ok(Err(e)) => Err(CurlSpawnError::Spawn(e)),
        Ok(Ok(out)) => Ok(out),
    }
}

/// `run_raw_result` reduced to an `Option` — the common case where the caller
/// treats "timed out" and "couldn't spawn" identically and only needs the
/// captured output (or nothing).
pub(crate) async fn run_raw(args: &[&str], hard_timeout: Duration) -> Option<std::process::Output> {
    run_raw_result(args, hard_timeout).await.ok()
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
    let args = [
        "--max-time",
        secs.as_str(),
        "-A",
        ua,
        "-H",
        "Accept: text/html,application/xhtml+xml,application/json",
        "-H",
        "Accept-Language: en-US,en;q=0.9",
        "-x",
        proxy,
        "-L",
        "--",
        url,
    ];
    let output = run_raw(&args, Duration::from_millis(timeout_ms + 2000)).await?;
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
            tracing::debug!(url, error = %e, "curl JSON parse failed ({} bytes)", body.len());
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

/// Fetch `url` through the intelligent per-resource rotator
/// ([`crate::util::proxy::global_router`]).
///
/// `resource` is a stable key (a search-engine name, an API host) so each
/// resource rotates independently and keeps its own cooldowns. Tries up to
/// `max_tries` distinct egress IPs, resting any that fail for this resource —
/// so a per-IP-rate-limited freemium API is spread across the whole validated
/// pool (*N* live proxies ≈ *N×* the free-tier ceiling). Region-matches the
/// egress when `region` (e.g. `HUNTSMAN_REGION`) is given.
///
/// Returns the first non-empty body, or `None` if the pool is empty / every try
/// failed — the caller then falls back to a direct fetch, byte-identical to the
/// pre-rotation path when no proxies are available.
pub async fn fetch_rotating(
    resource: &str,
    url: &str,
    timeout_ms: u64,
    ua: &str,
    region: Option<&str>,
    max_tries: usize,
) -> Option<String> {
    let router = super::proxy::global_router();
    for _ in 0..max_tries {
        let proxy = router.pick(resource, region)?;
        match fetch_via_proxy(url, timeout_ms, ua, &proxy.url()).await {
            Some(body) if !body.is_empty() => {
                router.report_success(resource, &proxy.addr);
                return Some(body);
            }
            // Dead / blocked / empty: rest this egress IP for the resource and
            // rotate on. Short base cooldown; the router backs off repeats.
            _ => router.report_block(resource, &proxy.addr, 60),
        }
    }
    None
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
