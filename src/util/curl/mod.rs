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
///
/// `pub(crate)` so the keyed-API curl path (`curl_client`) applies the identical
/// cap — a trusted API endpoint can still return a multi-GB body and OOM the
/// device, so the bound belongs on both curl invocations, single-sourced here.
pub(crate) const CURL_MAX_DOWNLOAD_BYTES: &str = "33554432";

// SSRF residual (documented, deliberately accepted in the fallback): `--resolve`
// pins only the *initial* host to a vetted public IP, but `curl -L` re-resolves a
// cross-host 3xx itself, so a redirect to an internal name/IP is not vetted here.
// Fully closing it needs a Rust-side hop-by-hop redirect loop (`--max-redirs 0`
// per hop, re-running `ssrf_resolve_pin` on each `Location`) — disabling
// redirects outright would break the redirecting search engines that depend on
// this path. Mitigated meanwhile by: reqwest (the redirect-vetted primary)
// running first, `--proto-redir =http,https` (no `file://`/`gopher://` hops), and
// `--max-redirs 5`.

/// Per-fetch hardening flags shared by both curl paths — the free-function
/// [`curl_exec`] and `curl_client::CurlClient::exec`. Restrict the wire protocol
/// to http/https on the initial request (`--proto`) *and* every redirect hop
/// (`--proto-redir`, blocking `file://`/`gopher://`/`dict://` pivots), cap
/// redirects at 5, and bound the download via `--max-filesize` (see
/// [`CURL_MAX_DOWNLOAD_BYTES`]). Single-sourced so the two invocations can never
/// drift apart — each is a security property that must hold on both, or neither.
pub(crate) const FETCH_HARDENING_ARGS: &[&str] = &[
    "--proto",
    "=http,https",
    "--proto-redir",
    "=http,https",
    "--max-redirs",
    "5",
    "--max-filesize",
    CURL_MAX_DOWNLOAD_BYTES,
];

/// Internal: run curl with full parameter control.
///
/// When the `HUNTSMAN_SEARCH_PROXY` environment variable is set
/// (e.g. `socks5://127.0.0.1:9050` or `http://user:pass@host:port`),
/// the proxy is passed to curl via `-x`. This enables Tor routing,
/// residential proxy services, or any SOCKS/HTTP proxy chain.
/// Vet `url`'s host against the private/reserved set and return the curl args
/// that make the fetch SSRF-safe. For a **hostname**, resolves it, drops
/// private/reserved addresses, and returns `--resolve host:port:<public-ip>` so
/// curl will not re-resolve (TOCTOU-safe). For an **IP literal**, curl dials it
/// directly with no DNS lookup, so there is nothing to pin: the literal is
/// checked in-process and accepted with an **empty** arg set. Returns `None`
/// when the host is private/reserved (or unparseable), so the caller refuses the
/// fetch. The curl-fallback half of the SSRF defense, mirroring
/// `http::SsrfResolver`; it covers attacker-controlled hosts such as
/// employer_pivot's `https://{discovered_domain}/...`.
async fn ssrf_resolve_pin(url: &str) -> Option<Vec<String>> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port_or_known_default()?;

    // IP-literal host: curl dials the literal directly — no DNS lookup, so there
    // is no rebinding race and `--resolve` (which only rewrites name lookups)
    // would do nothing. Just vet the literal and emit no pin. `host_str()`
    // brackets IPv6 literals (`[2606:…]`); strip them before the parse, or every
    // IPv6-literal target fails `lookup_host` below (getaddrinfo rejects the
    // brackets) and is wrongly refused — public ones included.
    let bare = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        return (!crate::util::preflight::is_private_addr(ip)).then(Vec::new);
    }

    let ip = tokio::net::lookup_host((host, port))
        .await
        .ok()?
        .map(|a| a.ip())
        .find(|ip| !crate::util::preflight::is_private_addr(*ip))?;
    Some(vec!["--resolve".to_string(), format!("{host}:{port}:{ip}")])
}

/// Pick the next search proxy from `HUNTSMAN_SEARCH_PROXY`. The variable may be
/// a comma-separated list (`socks5://h:1, http://h:2`) which is rotated
/// round-robin across calls so traffic spreads over several egress paths; a
/// single value behaves exactly as before. `None` ⇒ direct connection with
/// SSRF IP-pinning.
fn rotating_search_proxy() -> Option<String> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static IDX: AtomicUsize = AtomicUsize::new(0);
    let raw = std::env::var("HUNTSMAN_SEARCH_PROXY").ok()?;
    let list = crate::util::netrotate::parse_proxy_list(&raw);
    let i = match list.len() {
        0 => return None,
        1 => 0,
        _ => IDX.fetch_add(1, Ordering::Relaxed),
    };
    crate::util::netrotate::select_proxy(&list, i)
}

/// Single curl execution path shared by every public fetch helper (so the
/// hardening — SSRF pin, proto/redirect limits, the `--max-filesize` cap, the
/// header set — lives in exactly one place and can't drift between the direct
/// and proxied variants).
///
/// Proxy precedence: an explicit `proxy_override` (from [`fetch_via_proxy`]) wins,
/// else a rotated entry from the `HUNTSMAN_SEARCH_PROXY` list (see
/// [`rotating_search_proxy`]), else a direct connection pinned to a vetted public
/// IP. When proxied the SSRF pin is skipped (the proxy resolves and isolates us);
/// a direct fetch with no resolvable public IP is refused.
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

    // Override (from the proxy pool) wins; otherwise rotate through the
    // HUNTSMAN_SEARCH_PROXY list (single value behaves as before).
    let proxy = proxy_override
        .map(str::to_string)
        .or_else(rotating_search_proxy);

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

    cmd.args(FETCH_HARDENING_ARGS);
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
    // Archive the raw JSON body before parsing (universal raw retention). The
    // curl path carries no module name, so the URL host is the provider label.
    crate::util::raw_archive::record_http(crate::util::url_util::host_only(url), url, &body);
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

/// Fetch `url` and return `(http_status_code, body)`.
///
/// When `capture_body` is `false` the body is discarded (`-o /dev/null`) and the
/// returned string is empty — use this fast path when the status code alone is
/// sufficient. When `capture_body` is `true` the body is captured (capped at 8 KB
/// via `--max-filesize`) so the caller can apply negative-pattern checks.
///
/// Uses curl's `-w "\n%{http_code}"` sentinel to surface the HTTP status even
/// when the body was truncated by `--max-filesize` (curl exit code 63). Treating
/// exit 63 as a hard failure would suppress real profiles whose pages exceed 8 KB.
/// `timeout_ms` is reserved for future use; the current implementation encodes a
/// 4-second curl `--max-time` internally.
pub async fn fetch_with_status(url: &str, _timeout_ms: u64, capture_body: bool) -> (u16, String) {
    let mut args: Vec<&str> = vec![
        "-s",
        "-w",
        "\n%{http_code}",
        "--max-time",
        "4",
        "-L",
        "-A",
        UA_MOBILE,
    ];

    let filesize_arg;
    if capture_body {
        filesize_arg = "8192";
        args.extend_from_slice(&["--max-filesize", filesize_arg]);
    } else {
        args.extend_from_slice(&["-o", "/dev/null"]);
    }
    args.extend_from_slice(&["--", url]);

    let output = tokio::process::Command::new("curl")
        .args(&args)
        .kill_on_drop(true)
        .output()
        .await;

    match output {
        Ok(o) => {
            let raw = String::from_utf8_lossy(&o.stdout);
            let is_truncated = o.status.code() == Some(63);
            if o.status.success() || is_truncated {
                if capture_body && let Some(nl) = raw.rfind('\n') {
                    let body = raw[..nl].to_string();
                    let code: u16 = raw[nl + 1..].trim().parse().unwrap_or(0);
                    return (code, body);
                }
                let code: u16 = raw.trim().parse().unwrap_or(0);
                (code, String::new())
            } else {
                (0, String::new())
            }
        }
        _ => (0, String::new()),
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
