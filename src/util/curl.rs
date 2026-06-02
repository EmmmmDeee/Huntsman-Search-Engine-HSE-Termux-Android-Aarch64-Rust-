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

/// Hard ceiling on a curl download, in bytes (32 MiB), passed as
/// `--max-filesize`. Bounds the common (Content-Length-bearing) case of a
/// hostile/misconfigured upstream returning a multi-GB body that `cmd.output()`
/// would otherwise buffer whole and OOM a Termux device. A chunked response
/// without a Content-Length is still bounded in practice by the outer
/// `timeout(... + 2s)` + `kill_on_drop` (a phone's bandwidth × the few-second
/// budget caps the accumulation). Mirrors `http::JSON_BODY_CAP`.
const CURL_MAX_DOWNLOAD_BYTES: &str = "33554432";

// SSRF residual (documented, deliberately accepted in the fallback): `--resolve`
// pins only the *initial* host to a vetted public IP, but `curl -L` re-resolves a
// cross-host 3xx itself, so a redirect to an internal name/IP is not vetted here.
// Fully closing it needs a Rust-side hop-by-hop redirect loop (`--max-redirs 0`
// per hop, re-running `ssrf_resolve_pin` on each `Location`) — disabling
// redirects outright would break the redirecting search engines that depend on
// this path. Mitigated meanwhile by: reqwest (the redirect-vetted primary)
// running first, `--proto-redir =http,https` (no `file://`/`gopher://` hops), and
// `--max-redirs 5`.

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

/// Single curl execution path shared by every public fetch helper (so the
/// hardening — SSRF pin, proto/redirect limits, the `--max-filesize` cap, the
/// header set — lives in exactly one place and can't drift between the direct
/// and proxied variants).
///
/// Proxy precedence: an explicit `proxy_override` (from [`fetch_via_proxy`]) wins,
/// else the `HUNTSMAN_SEARCH_PROXY` env var, else a direct connection pinned to a
/// vetted public IP. When proxied the SSRF pin is skipped (the proxy resolves and
/// isolates us); a direct fetch with no resolvable public IP is refused.
async fn curl_exec(
    url: &str,
    timeout_ms: u64,
    ua: &str,
    post_data: Option<&str>,
    proxy_override: Option<&str>,
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

    let proxy = proxy_override.map(str::to_string).or_else(|| {
        std::env::var("HUNTSMAN_SEARCH_PROXY")
            .ok()
            .filter(|p| !p.is_empty())
    });

    if let Some(ref p) = proxy {
        cmd.args(["-x", p]);
    } else {
        // Direct connection: pin curl to a vetted public IP so an
        // attacker-controlled host can't be rebound onto an internal address.
        // Refuse the fetch if the host has no resolvable public IP.
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
        // Bound the download so a hostile upstream can't OOM the device — see
        // CURL_MAX_DOWNLOAD_BYTES. (Redirect-hop IP vetting is a documented
        // residual — see the SSRF-residual note above the constant.)
        "--max-filesize",
        CURL_MAX_DOWNLOAD_BYTES,
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

    // Lossy: a non-UTF-8 body (ISO-8859-1 HTML, a charset curl didn't transcode)
    // must still yield a usable string rather than being dropped as a failure —
    // matches `http::read_body_capped`.
    let body = String::from_utf8_lossy(&output.stdout).into_owned();
    super::http::scan_for_api_keys(&body);
    Some(body)
}

/// Fetch a URL via curl subprocess. Returns the response body on
/// success, None on any error (timeout, non-zero exit, missing curl).
pub async fn fetch(url: &str, timeout_ms: u64) -> Option<String> {
    curl_exec(url, timeout_ms, UA_MOBILE, None, None).await
}

/// Fetch with a specific User-Agent string.
pub async fn fetch_with_ua(url: &str, timeout_ms: u64, ua: &str) -> Option<String> {
    curl_exec(url, timeout_ms, ua, None, None).await
}

/// POST form data to a URL via curl subprocess. Returns the response body
/// on success, None on any error (timeout, non-zero exit, missing curl).
pub async fn fetch_post(url: &str, data: &str, timeout_ms: u64) -> Option<String> {
    curl_exec(url, timeout_ms, UA_MOBILE, Some(data), None).await
}

/// POST form data with a specific User-Agent string.
pub async fn fetch_post_with_ua(
    url: &str,
    data: &str,
    timeout_ms: u64,
    ua: &str,
) -> Option<String> {
    curl_exec(url, timeout_ms, ua, Some(data), None).await
}

/// Fetch a URL through a specific proxy (SOCKS5, HTTP, or HTTPS).
/// Proxy format: `socks5://host:port`, `http://user:pass@host:port`, etc.
/// Delegates to the shared [`curl_exec`] (proxy path skips the SSRF pin).
pub async fn fetch_via_proxy(url: &str, timeout_ms: u64, ua: &str, proxy: &str) -> Option<String> {
    curl_exec(url, timeout_ms, ua, None, Some(proxy)).await
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

/// Fetch with proxy fallback: a direct attempt (which itself honours
/// `HUNTSMAN_SEARCH_PROXY` inside [`curl_exec`]) → free proxy-pool rotation.
/// Returns the response body, or None if all paths fail. Modules that want free
/// proxy rotation call this instead of plain [`fetch`].
pub async fn fetch_pooled(
    url: &str,
    timeout_ms: u64,
    ua: &str,
    pool: &super::proxy::ProxyPool,
) -> Option<String> {
    // Tier 1 — direct (or via HUNTSMAN_SEARCH_PROXY, applied inside curl_exec).
    if let Some(body) = fetch_with_ua(url, timeout_ms, ua).await
        && !body.is_empty()
    {
        return Some(body);
    }
    // Tier 2 — rotate a free pool proxy. An empty body counts as a miss, the
    // same as the direct tier (previously the proxy tiers leaked an empty
    // `Some("")`). The old `HUNTSMAN_PROXY` env tier is removed: that variable
    // was a typo of `HUNTSMAN_SEARCH_PROXY` (used nowhere else in the codebase),
    // so the tier never fired — and the env-proxy intent is already covered by
    // tier 1.
    if let Some(proxy) = pool.next()
        && let Some(body) = fetch_via_proxy(url, timeout_ms, ua, &proxy.url()).await
        && !body.is_empty()
    {
        return Some(body);
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

    // ── SSRF pin (B8: the security-critical path was untested) ─────────

    #[tokio::test]
    async fn ssrf_pin_refuses_private_and_metadata_hosts() {
        // Literal IPs resolve offline (no DNS query) → deterministic, network-
        // free. Each private/reserved host must yield no pin so the caller
        // refuses the fetch (the curl half of the SSRF defense).
        for u in [
            "http://127.0.0.1/x",
            "http://10.0.0.1/x",
            "http://192.168.1.1/x",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/x",
        ] {
            assert!(
                ssrf_resolve_pin(u).await.is_none(),
                "{u} must be refused as private/reserved"
            );
        }
    }

    #[tokio::test]
    async fn ssrf_pin_allows_public_host_and_pins_it() {
        let pin = ssrf_resolve_pin("http://8.8.8.8/x")
            .await
            .expect("public IP must be pinned");
        assert_eq!(
            pin,
            vec!["--resolve".to_string(), "8.8.8.8:80:8.8.8.8".to_string()]
        );
    }
}
