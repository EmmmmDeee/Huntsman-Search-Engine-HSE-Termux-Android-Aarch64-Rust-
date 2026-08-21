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

// SSRF redirect vetting (the direct fallback path): `--resolve` pins only the
// *initial* host, so letting `curl -L` follow a cross-host 3xx itself would
// re-resolve an internal name/IP UNVETTED — a redirect to `169.254.169.254` or
// `http://internal.corp/` would be fetched. Worse, this path is reached exactly
// when reqwest (the redirect-vetted primary) *refused* such a hop and failed the
// request, so "reqwest runs first" was not the mitigation it appeared to be.
//
// Closed by driving redirects hop-by-hop in Rust instead (see the direct branch
// of `curl_exec`): each hop runs curl with NO `-L`, reads curl's resolved
// `%{redirect_url}`, and re-vets it — `curl_redirect_refused` rejects a
// non-http(s) scheme or a private/reserved IP-literal target outright, and
// `ssrf_resolve_pin` re-resolves+pins a hostname target against the same
// private/reserved set every reqwest lookup uses. A private hop stops the chain
// (fetch refused) rather than being followed. Bounded at
// [`MAX_CURL_REDIRECT_HOPS`]. The proxied path keeps curl's own `-L`: there the
// proxy resolves and isolates every hop, so an operator-internal address is not
// reachable through it. `--proto-redir =http,https` still blocks
// `file://`/`gopher://` hops on both paths as defence in depth.

/// Maximum redirect hops the direct curl path follows before refusing — matches
/// the `--max-redirs 5` that previously bounded curl's own `-L`, now enforced by
/// the Rust-side hop loop that vets each hop.
const MAX_CURL_REDIRECT_HOPS: usize = 5;

/// Decide, from a redirect target URL alone, whether the direct curl path must
/// REFUSE the hop — the fallback-path mirror of reqwest's `redirect_to_private_ip`
/// (`ssrf.rs`). Refuses an unparseable URL, a non-http(s) scheme (no
/// `file://`/`gopher://` pivots), a host-less URL, or a private/reserved
/// IP-literal target (loopback, RFC1918, link-local incl. `169.254.169.254`,
/// ULA, etc., via `to_canonical`-folding `is_private_addr`). A hostname target
/// is NOT refused here: it is re-resolved and pinned at connect by
/// `ssrf_resolve_pin`, which drops private addresses — so a rebinding target
/// cannot slip through by presenting as a name.
fn curl_redirect_refused(next_url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(next_url) else {
        return true;
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return true;
    }
    let Some(host) = parsed.host_str() else {
        return true;
    };
    if host.is_empty() {
        return true;
    }
    let bare = crate::util::preflight::unbracket_host(host);
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        return crate::util::preflight::is_private_addr(ip);
    }
    false
}

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
/// Proxy precedence: a health-ranked entry from the validated
/// [`crate::util::egress`] pool with per-request failover, else — only when NO
/// proxy is configured — a direct connection pinned to a vetted public IP. When
/// proxied the SSRF pin is skipped (the proxy resolves and isolates us); a
/// direct fetch with no resolvable public IP is refused; and a configured-but-
/// exhausted pool never silently goes direct.
async fn curl_exec(
    url: &str,
    timeout_ms: u64,
    ua: &str,
    post_data: Option<&str>,
) -> Option<String> {
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
        // Budget the WHOLE failover loop, not each attempt independently — a
        // fixed deadline, decremented per attempt. Reusing the caller's full
        // `timeout_ms` on every one of up to MAX_PROXY_FAILOVER attempts let a
        // single `curl_exec` call take up to ~3x its budget, silently breaking
        // every caller's deadline contract (the same guarantee
        // `search_engines::fetch::fetch_timeout_ms` documents and relies on).
        // `Instant + Duration` panics on overflow (its `Add` impl is a bare
        // `checked_add(...).expect(...)`), and `timeout_ms` is a parameter on
        // every public fetch helper in this module — a nonsensically large
        // caller value must fail this one fetch, not crash the process.
        let deadline = std::time::Instant::now().checked_add(Duration::from_millis(timeout_ms))?;
        let mut tried: Vec<String> = Vec::new();
        while tried.len() < MAX_PROXY_FAILOVER {
            let remaining_ms = deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_millis() as u64;
            // Not enough budget left for another attempt to have a realistic
            // chance — subprocess spawn + TCP handshake overhead alone would
            // likely consume the remainder. Stop rather than return a request
            // doomed to fail right as the caller's deadline expires.
            if remaining_ms < MIN_PROXY_ATTEMPT_MS {
                break;
            }
            let Some(proxy) = crate::util::egress::next_proxy_excluding(&tried) else {
                break;
            };
            let secs = curl_max_time_arg(remaining_ms);
            let started = std::time::Instant::now();
            // Proxied: curl follows redirects itself (`follow = true`) — the
            // proxy resolves and isolates every hop, so an operator-internal
            // address is not reachable through it.
            let res = run_curl_once(
                url,
                &secs,
                ua,
                post_data,
                remaining_ms,
                Some(&proxy),
                None,
                true,
            )
            .await
            .map(|o| o.body);
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
    // the fetch if the host has no resolvable public IP. Redirects are driven
    // hop-by-hop HERE (not by curl's `-L`) so each 3xx target is re-vetted before
    // it is fetched — closing the fallback redirect-SSRF hole.
    //
    // The whole chain shares ONE deadline (decremented per hop), so a redirect
    // loop cannot multiply the caller's `timeout_ms` by the hop count — the same
    // deadline discipline the proxy-failover loop above uses.
    let mut pin = ssrf_resolve_pin(url).await?;
    let deadline = std::time::Instant::now().checked_add(Duration::from_millis(timeout_ms))?;
    let mut current = url.to_string();
    // The POST body rides only the FIRST request. curl's own `-L` turns a
    // 301/302/303 into a GET (dropping the body); preserving that here keeps the
    // hop-by-hop path behaviourally identical to the `-L` it replaces, and avoids
    // silently re-POSTing a form to a redirect target.
    let mut body = post_data;
    for _hop in 0..=MAX_CURL_REDIRECT_HOPS {
        let remaining_ms = deadline
            .saturating_duration_since(std::time::Instant::now())
            .as_millis() as u64;
        if remaining_ms == 0 {
            return None;
        }
        let secs = curl_max_time_arg(remaining_ms);
        let outcome = run_curl_once(
            &current,
            &secs,
            ua,
            body,
            remaining_ms,
            None,
            Some(&pin),
            false,
        )
        .await?;
        let Some(next) = outcome.next else {
            // Terminal response (no redirect) — this is the body to return.
            return Some(outcome.body);
        };
        // A redirect: vet the resolved target before following it. A non-http(s)
        // scheme or a private/reserved IP-literal is refused outright; a hostname
        // is re-resolved and pinned against the private/reserved set. Either
        // refusal stops the chain rather than fetching an internal resource.
        if curl_redirect_refused(&next) {
            return None;
        }
        pin = ssrf_resolve_pin(&next).await?;
        current = next;
        // Method reverts to GET on the redirect, matching curl's `-L` default.
        body = None;
    }
    // Exceeded the hop bound — refuse rather than follow further.
    None
}

/// Minimum remaining budget (ms) worth attempting another proxy in the
/// failover loop. Below this, subprocess spawn + TCP handshake overhead alone
/// would likely consume the whole remainder.
const MIN_PROXY_ATTEMPT_MS: u64 = 250;

/// Format a millisecond budget as curl's `--max-time` argument. curl accepts
/// fractional seconds (e.g. `"1.500"`), so this honours a sub-second budget
/// precisely instead of rounding it up to a multi-second floor. Floors the
/// numerator at 1ms so the result is never `"0.000"` — curl treats
/// `--max-time 0` as **no limit**, the opposite of what a near-zero budget
/// means here.
fn curl_max_time_arg(timeout_ms: u64) -> String {
    format!("{:.3}", timeout_ms.max(1) as f64 / 1000.0)
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
/// One curl outcome: the response body, and — in hop-by-hop mode — the next-hop
/// URL curl *would* have followed (its resolved-to-absolute `%{redirect_url}`),
/// so the caller can vet it before re-issuing. `next` is always `None` in
/// `follow`-mode (curl already followed) and when the response is terminal.
struct CurlOnce {
    body: String,
    next: Option<String>,
}

/// `follow = true`  → curl follows redirects itself (`-L`), bounded by
/// `--max-redirs`; used ONLY on the proxied path, where the proxy resolves and
/// isolates every hop. `follow = false` → curl does NOT follow; it emits the
/// resolved next-hop URL via `-w %{redirect_url}` (written to STDERR with the
/// `%{stderr}` directive so the body on stdout stays byte-clean), and the caller
/// (`curl_exec`'s direct branch) vets each hop and re-issues. This is what closes
/// the redirect-SSRF hole on the unproxied fallback.
#[allow(clippy::too_many_arguments)]
async fn run_curl_once(
    url: &str,
    secs: &str,
    ua: &str,
    post_data: Option<&str>,
    timeout_ms: u64,
    proxy: Option<&str>,
    pin: Option<&[String]>,
    follow: bool,
) -> Option<CurlOnce> {
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
    if follow {
        cmd.args(["-L"]);
    } else {
        // No `-L`: return the 3xx as-is. `%{stderr}` sends the rest of the
        // write-out (the resolved absolute redirect target, empty when the
        // response is terminal) to STDERR, keeping stdout the pure body.
        cmd.args(["-w", "%{stderr}%{redirect_url}"]);
    }
    cmd.args(["--", url]);
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
    let next = if follow {
        None
    } else {
        let target = String::from_utf8_lossy(&output.stderr);
        let target = target.trim();
        (!target.is_empty()).then(|| target.to_string())
    };
    Some(CurlOnce { body, next })
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

/// POST form data with a specific User-Agent string.
pub async fn fetch_post_with_ua(
    url: &str,
    data: &str,
    timeout_ms: u64,
    ua: &str,
) -> Option<String> {
    curl_exec(url, timeout_ms, ua, Some(data)).await
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
