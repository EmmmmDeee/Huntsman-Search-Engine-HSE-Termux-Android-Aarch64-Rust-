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
///
/// Plus one resilience flag: `--connect-timeout 15` bounds the TCP+TLS CONNECT
/// phase alone. Without it, a stuck connect to an unreachable/blackholed host
/// burns the whole `--max-time` budget (up to 75 s on the SeekNow client) before
/// failing — dozens of dead endpoints in a scan then serialise into minutes of
/// dead air on a flaky Termux link. 15 s is generous enough for a slow mobile or
/// Tor/`HUNTSMAN_SEARCH_PROXY` circuit to establish, while still failing a truly
/// dead host far below the total ceiling. It bounds only connect, so a
/// legitimately slow *response* still gets the full `--max-time`.
pub(crate) const FETCH_HARDENING_ARGS: &[&str] = &[
    "--proto",
    "=http,https",
    "--proto-redir",
    "=http,https",
    "--max-redirs",
    "5",
    "--max-filesize",
    CURL_MAX_DOWNLOAD_BYTES,
    "--connect-timeout",
    "15",
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
///
/// Hostname resolution goes through [`crate::util::http::resolve_public_ips`] —
/// the same rotating-resolver-with-system-fallback strategy `SsrfResolver`
/// applies to every reqwest lookup — rather than a bare `tokio::net::lookup_host`,
/// so a carrier/ISP resolver that filters (or is entirely broken for) this host
/// no longer hard-fails the fetch when `HUNTSMAN_DNS_RESOLVERS` is configured.
async fn ssrf_resolve_pin(url: &str) -> Option<Vec<String>> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port_or_known_default()?;

    // IP-literal host: curl dials the literal directly — no DNS lookup, so there
    // is no rebinding race and `--resolve` (which only rewrites name lookups)
    // would do nothing. Just vet the literal and emit no pin. `host_str()`
    // brackets IPv6 literals (`[2606:…]`); strip them before the parse, or every
    // IPv6-literal target fails resolution below (getaddrinfo rejects the
    // brackets) and is wrongly refused — public ones included.
    let bare = crate::util::preflight::unbracket_host(host);
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        return (!crate::util::preflight::is_private_addr(ip)).then(Vec::new);
    }

    let ip = crate::util::http::resolve_public_ips(host)
        .await
        .ok()?
        .into_iter()
        .next()?;
    Some(vec!["--resolve".to_string(), format!("{host}:{port}:{ip}")])
}

// Proxy selection + per-request failover now lives in the validated
// `crate::util::egress` pool (health-ranked, self-healing) — see `curl_exec`.
// The former stateless round-robin over `HUNTSMAN_SEARCH_PROXY` (which blindly
// dispatched even to proven-dead proxies) was replaced by it.

/// Single curl execution path shared by every public fetch helper (so the
/// hardening — SSRF pin, proto/redirect limits, the `--max-filesize` cap, the
/// header set — lives in exactly one place and can't drift between the direct
/// and proxied variants).
///
/// Proxy precedence: an explicit `proxy_override` (from [`fetch_via_proxy`]) wins,
/// else a health-ranked entry from the validated [`crate::util::egress`] pool
/// with per-request failover, else — only when NO proxy is configured — a direct
/// connection pinned to a vetted public IP. When proxied the SSRF pin is skipped
/// (the proxy resolves and isolates us); a direct fetch with no resolvable public
/// IP is refused; and a configured-but-exhausted pool never silently goes direct.
async fn curl_exec(
    url: &str,
    timeout_ms: u64,
    ua: &str,
    post_data: Option<&str>,
    proxy_override: Option<&str>,
) -> Option<String> {
    let secs = (timeout_ms / 1000).max(3).to_string();

    // An explicit override (from `fetch_via_proxy`) wins — a single attempt, no
    // pool involvement or reporting (the caller chose this exact proxy).
    if let Some(p) = proxy_override {
        return run_curl_once(url, &secs, ua, post_data, timeout_ms, Some(p), None).await;
    }

    // The validated proxy pool with per-request FAILOVER. Try up to
    // MAX_PROXY_FAILOVER healthy proxies, reporting each real outcome so the
    // pool self-heals (a dead proxy accrues failures and drops out of
    // rotation); one dead path never renders the resource unreachable while a
    // healthy peer exists. Selection is health-ranked (see `util::egress`), so a
    // proven-dead proxy is skipped rather than blindly round-robined into.
    //
    // Security invariant: when the operator HAS configured proxies we NEVER fall
    // back to a direct connection on exhaustion — that would leak the real IP
    // the proxy exists to hide. `pool_is_configured` distinguishes "configured
    // but every entry is currently failing" (⇒ give up, return None) from "no
    // proxy configured at all" (⇒ the normal SSRF-pinned direct path below).
    if crate::util::egress::pool_is_configured() {
        let mut tried: Vec<String> = Vec::new();
        while tried.len() < MAX_PROXY_FAILOVER {
            let Some(proxy) = crate::util::egress::next_proxy_excluding(&tried) else {
                break;
            };
            let started = std::time::Instant::now();
            let res =
                run_curl_once(url, &secs, ua, post_data, timeout_ms, Some(&proxy), None).await;
            #[allow(clippy::cast_possible_truncation)]
            let latency = started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
            crate::util::egress::report_proxy(&proxy, res.is_some(), latency);
            if res.is_some() {
                return res;
            }
            tried.push(proxy);
        }
        // Every pooled proxy failed (or none usable) — do NOT leak a direct
        // connection the operator's proxy config exists to prevent.
        return None;
    }

    // No proxy configured: direct connection, pinned to a vetted public IP so an
    // attacker-controlled host can't be rebound onto an internal address. Refuse
    // the fetch if the host has no resolvable public IP.
    match ssrf_resolve_pin(url).await {
        Some(pin) => run_curl_once(url, &secs, ua, post_data, timeout_ms, None, Some(&pin)).await,
        None => None,
    }
}

/// Maximum distinct proxies tried for one fetch before giving up. Bounds the
/// per-request failover so a pool full of dead proxies can't turn one fetch into
/// a long serial retry storm — the health pool + eviction keep this rare.
const MAX_PROXY_FAILOVER: usize = 3;

/// Build and run one hardened `curl` fetch. At most one of `proxy` / `pin` is
/// meaningful: with a `proxy` the SSRF pin is skipped (the proxy resolves and
/// isolates us); with a `pin` (a `--resolve host:port:ip` pair set) the direct
/// connection is locked to a vetted public IP. Shared by the override, pool, and
/// direct paths so the hardening (proto/redirect limits, `--max-filesize` cap,
/// header set, `kill_on_drop`, the outer timeout) lives in ONE place and can't
/// drift between them.
#[allow(clippy::too_many_arguments)]
async fn run_curl_once(
    url: &str,
    secs: &str,
    ua: &str,
    post_data: Option<&str>,
    timeout_ms: u64,
    proxy: Option<&str>,
    pin: Option<&[String]>,
) -> Option<String> {
    let mut cmd = Command::new("curl");
    cmd.args(["-s", "--max-time", secs, "-A", ua]);
    cmd.args([
        "-H",
        "Accept: text/html,application/xhtml+xml,application/json",
    ]);
    cmd.args(["-H", "Accept-Language: en-US,en;q=0.9"]);
    if let Some(data) = post_data {
        cmd.args(["-H", "Content-Type: application/x-www-form-urlencoded"]);
        cmd.args(["-d", data]);
    }
    if let Some(p) = proxy {
        cmd.args(["-x", p]);
    } else if let Some(pin) = pin {
        cmd.args(pin);
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
///
/// # SSRF model
/// This path applies the same protocol/redirect hardening as [`curl_exec`]
/// (`--proto`/`--proto-redir` http/https only, `--max-redirs 5`) but deliberately
/// omits the in-process private-IP `ssrf_resolve_pin`. That is safe **only because
/// of how it is called**: the sole caller (`social_probe`) builds every URL from a
/// hardcoded platform `url_pattern`, substituting user input into the URL *path*
/// only — the host is always a trusted public platform, never attacker-controlled,
/// so there is no rebinding target to pin. Adding a resolve-per-probe to this
/// high-volume status fan-out is not warranted. Any future caller that passes an
/// attacker-controlled host MUST route through [`curl_exec`] (or reqwest), which
/// pin the resolved address against the private/reserved set.
pub async fn fetch_with_status(url: &str, _timeout_ms: u64, capture_body: bool) -> (u16, String) {
    let mut args: Vec<&str> = vec![
        "-s",
        "-w",
        "\n%{http_code}",
        "--max-time",
        "4",
        "-L",
        // Protocol/redirect hardening, mirroring `FETCH_HARDENING_ARGS`: confine
        // the initial request and every redirect hop to http/https (no
        // `file://`/`gopher://`/`dict://` pivots) and bound the redirect chain.
        // `--max-filesize` is set separately below because this path uses a tighter
        // 8 KB body cap than the shared 32 MiB constant.
        "--proto",
        "=http,https",
        "--proto-redir",
        "=http,https",
        "--max-redirs",
        "5",
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
