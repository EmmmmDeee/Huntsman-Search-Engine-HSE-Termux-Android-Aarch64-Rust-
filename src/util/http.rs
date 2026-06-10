//! Shared HTTP client builder. Rustls-only — no native TLS, no openssl,
//! no native deps at all.
//!
//! No client-level total timeout is set: the engine wraps every
//! `Module::process()` call in `tokio::time::timeout(...)` (see
//! `src/core/engine/dispatch.rs`), capped at whichever of the user
//! override (`ScanOptions::module_timeout_ms`) or each module's
//! `max_timeout_ms()` is larger. A blanket client-level cap of
//! `MODULE_TIMEOUT_MS = 3 s` previously short-circuited every module
//! that declared a larger budget (whois 8 s, wigle 12 s, and other
//! multi-stage network modules) — at least one module has an explicit
//! unit test asserting `max_timeout_ms() > MODULE_TIMEOUT_MS`,
//! proving that the override was expected to apply.
//!
//! A short `connect_timeout` is still set so that attempts to reach
//! firewalled or otherwise-unresponsive hosts fail fast and free up
//! the engine's concurrency slot, instead of consuming the module's
//! full budget waiting on the OS-level TCP connect.

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde::de::DeserializeOwned;

use crate::core::error::{Error, Result};

/// Fail-fast TCP connect budget. Independent of each module's total
/// `max_timeout_ms()`. Five seconds is generous on slow mobile links
/// while still preventing a wedged peer from holding a concurrency
/// slot for the module's entire (often double-digit) total budget.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Build a fresh reqwest client. Cheap to call per scan.
///
/// User-Agent uses the conventional `name/version (+url)` form. Bare
/// short UAs like `HSE/0.8.0` are frequently rejected by anti-bot WAFs
/// (HudsonRock's cavalier API among them — observed returning HTTP 400
/// on Termux). The `+https://` contact link is the format recommended
/// by RFC 7231 §5.5.3 and accepted by most rate-limiters.
///
/// No client-level total timeout — see module docstring. A short
/// `connect_timeout` is set so unreachable hosts fail fast.
/// True if a redirect's next-hop `host` must be refused as an SSRF risk — i.e.
/// it is a private/reserved IP literal (cloud-metadata 169.254.169.254,
/// loopback, RFC1918, ULA, …). Hostnames are not judged here (they are resolved
/// at connect time); the engine's `url_host_is_private` gate already rejects
/// private-host *targets*, and this extends the guard to every redirect hop so
/// a public URL can't 3xx us onto an internal address.
///
/// `host` is `Url::host_str()`, which (`url` 2.5) returns IPv6 literals **with**
/// brackets (`[::1]`). The brackets must be stripped before the `IpAddr` parse
/// inside `is_private_ip`, or every IPv6-literal hop (loopback `[::1]`, ULA,
/// link-local, IPv4-mapped metadata `[::ffff:169.254.169.254]`) fails to parse,
/// returns `false`, and is followed — an SSRF bypass. Mirrors the bracket
/// handling in [`crate::util::preflight::url_host_is_private`].
fn redirect_to_private_ip(host: Option<&str>) -> bool {
    host.map(|h| {
        h.strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(h)
    })
    .is_some_and(crate::util::preflight::is_private_ip)
}

/// Drop private/reserved IPs from a resolved address set — the SSRF DNS filter.
fn filter_public(addrs: impl Iterator<Item = std::net::SocketAddr>) -> Vec<std::net::SocketAddr> {
    addrs
        .filter(|a| !crate::util::preflight::is_private_addr(a.ip()))
        .collect()
}

/// reqwest DNS resolver that refuses private/reserved addresses. This is the
/// TOCTOU-safe half of the SSRF defense for **hostname** targets: a discovered
/// hostname that resolves (via DNS rebinding, or an internal name like
/// `intranet`) to an RFC1918 / loopback / link-local / 169.254 metadata address
/// yields **no connectable address**, so the request fails instead of reaching
/// an internal service. reqwest connects only to the addresses returned here, so
/// there is no resolve-then-connect race. Delegates the actual lookup to the
/// system resolver (`getaddrinfo` via `tokio::net::lookup_host`) — no root,
/// Termux-ok.
///
/// IMPORTANT — scope: this resolver is invoked **only for hostnames**. An
/// IP-literal URL (`http://169.254.169.254/`, `http://127.0.0.1/`, `http://[::1]/`)
/// is connected directly by hyper-util *without* a DNS lookup, so it never
/// reaches this filter. IP-literal SSRF is therefore gated separately, before
/// dispatch, by the engine's target check (`core::engine::url_host_is_private` /
/// `util::preflight::should_skip_external_ip`) — not here. The redirect policy in
/// [`build_client`] (`redirect_to_private_ip`) covers private-IP *redirect* hops.
struct SsrfResolver;

/// Build the rotating public-resolver set from `HUNTSMAN_DNS_RESOLVERS`
/// (`cloudflare`/`google`/`quad9`). Returns `None` when unset/empty, so the
/// resolver falls back to the system path and default behaviour is unchanged.
/// A resolver that fails to build is simply skipped — never a hard error.
fn build_rotating_resolvers() -> Option<Vec<hickory_resolver::TokioResolver>> {
    use hickory_resolver::{
        TokioResolver,
        config::{CLOUDFLARE, GOOGLE, LookupIpStrategy, QUAD9, ResolverConfig},
        net::runtime::TokioRuntimeProvider,
    };
    let raw = std::env::var("HUNTSMAN_DNS_RESOLVERS").ok()?;
    let providers = crate::util::netrotate::parse_dns_providers(&raw);
    if providers.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for p in providers {
        let group = match p {
            "cloudflare" => &CLOUDFLARE,
            "google" => &GOOGLE,
            "quad9" => &QUAD9,
            _ => continue,
        };
        let mut builder = TokioResolver::builder_with_config(
            ResolverConfig::udp_and_tcp(group),
            TokioRuntimeProvider::default(),
        );
        {
            // Same fail-fast budget as the shared dns_intel resolver.
            let opts = builder.options_mut();
            opts.timeout = std::time::Duration::from_secs(2);
            opts.attempts = 1;
            opts.ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
        }
        if let Ok(r) = builder.build() {
            out.push(r);
        }
    }
    (!out.is_empty()).then_some(out)
}

/// Lazily-built rotating resolvers (or `None` for the system resolver).
fn rotating_resolvers() -> Option<&'static Vec<hickory_resolver::TokioResolver>> {
    static RESOLVERS: OnceLock<Option<Vec<hickory_resolver::TokioResolver>>> = OnceLock::new();
    RESOLVERS.get_or_init(build_rotating_resolvers).as_ref()
}

impl reqwest::dns::Resolve for SsrfResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let host = name.as_str().to_owned();
            // Opt-in rotating public resolvers (HUNTSMAN_DNS_RESOLVERS): spread
            // lookups across providers, with the same private-IP SSRF filter.
            // Any resolver error degrades gracefully to the system resolver.
            if let Some(resolvers) = rotating_resolvers() {
                static IDX: AtomicUsize = AtomicUsize::new(0);
                let idx = IDX.fetch_add(1, Ordering::Relaxed) % resolvers.len();
                if let Ok(lookup) = resolvers[idx].lookup_ip(host.as_str()).await {
                    let public: Vec<SocketAddr> = lookup
                        .iter()
                        .filter(|ip| !crate::util::preflight::is_private_addr(*ip))
                        .map(|ip| SocketAddr::new(ip, 0))
                        .collect();
                    return Ok(Box::new(public.into_iter()) as reqwest::dns::Addrs);
                }
            }
            let addrs = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let public = filter_public(addrs);
            Ok(Box::new(public.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Shared reqwest configuration (SSRF-guarded DNS, redirect policy, timeouts,
/// pool, UA) used by both the plain and the trace-stamped client builders.
fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .dns_resolver(std::sync::Arc::new(SsrfResolver))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 10 {
                attempt.error("too many redirects")
            } else if redirect_to_private_ip(attempt.url().host_str()) {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .connect_timeout(CONNECT_TIMEOUT)
        .pool_max_idle_per_host(5)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Duration::from_secs(15))
        .user_agent(concat!(
            "huntsman-search-engine/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-)"
        ))
}

pub fn build_client() -> reqwest::Client {
    client_builder()
        .build()
        .expect("reqwest client build failed")
}

/// Like [`build_client`] but stamps every outbound request with a default
/// `x-huntsman-trace: <trace_id>` header. End-to-end traceability across external
/// calls (item #3 of the operator program): the same id the NDJSON scan logs
/// carry in their span chain now rides on the wire, so an outbound request can be
/// matched to its scan in a proxy's or upstream's access log — closing the loop
/// logs → services → external calls. The id is non-secret (the scan id). A header
/// value must be visible ASCII; a non-conforming id falls back to the plain
/// client rather than panicking.
pub fn build_client_with_trace(trace_id: &str) -> reqwest::Client {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(trace_id) {
        headers.insert(HeaderName::from_static("x-huntsman-trace"), value);
    }
    client_builder()
        .default_headers(headers)
        .build()
        .expect("reqwest client build failed")
}

/// Read up to 200 characters of a non-success response body, trim, and
/// return a single-line string safe to embed in an error message.
///
/// Returns `"<empty>"` when the body is empty, `"<unreadable>"` on a transport
/// error while streaming the body. Consumes the response.
///
/// Common credential query-param values (`api_key=`, `apiKey=`,
/// `key=`, `token=`, `secret=`, `access_token=`, `auth=`) are
/// redacted before embedding. Several upstreams echo the request URL
/// inside their error body (Cloudflare, AWS, many API gateways),
/// which would otherwise leak the operator's key into the persisted
/// ModuleError event and the SSE stream.
///
/// Use this everywhere a module returns `Error::module(name, "HTTP …")`
/// so the user sees the upstream's actual error payload rather than a
/// bare status code.
pub async fn error_snippet(resp: reqwest::Response) -> String {
    // Stream up to 8 KiB before deciding the snippet is "long
    // enough" — a hostile or compromised upstream could otherwise
    // return a multi-GB body that reqwest's `resp.text()` happily
    // accumulates, exhausting RAM on a Termux device.
    const SNIPPET_BYTES_CAP: usize = 8 * 1024;
    use futures::StreamExt as _;
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                buf.extend_from_slice(&bytes);
                if buf.len() >= SNIPPET_BYTES_CAP {
                    buf.truncate(SNIPPET_BYTES_CAP);
                    break;
                }
            }
            Err(_) => return "<unreadable>".to_string(),
        }
    }
    // Lossy decode: the 8 KiB cap can fall mid-multibyte-char, which strict
    // `from_utf8` would reject and report as "<unreadable>" even for a perfectly
    // readable body. We only need a human-facing snippet, so replace the (at most
    // one) split char rather than discard the whole message.
    let body = String::from_utf8_lossy(&buf);
    scan_for_api_keys(&body);
    let redacted = redact_credentials(&body);
    let trimmed = redacted.trim();
    if trimmed.is_empty() {
        "<empty>".to_string()
    } else {
        trimmed
            .replace(['\n', '\r'], " ")
            .chars()
            .take(200)
            .collect()
    }
}

/// Read a response body but stop after `cap` bytes. A hostile or misconfigured
/// upstream could otherwise return a multi-MB/GB body that `resp.text()`
/// accumulates whole, exhausting RAM on a low-memory Termux device — a real
/// risk under the username_search 32-way probe fan-out. Returns lossy UTF-8 of
/// what was read (sufficient for substring/needle checks), or `None` on a
/// transport error.
pub async fn read_body_capped(resp: reqwest::Response, cap: usize) -> Option<String> {
    use futures::StreamExt as _;
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                buf.extend_from_slice(&bytes);
                if buf.len() >= cap {
                    buf.truncate(cap);
                    break;
                }
            }
            Err(_) => return None,
        }
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Upper bound on a JSON response body we will buffer. `resp.text()` accumulates
/// the whole body, so a hostile or misconfigured upstream returning a multi-GB
/// payload would OOM a Termux device — the same threat `read_body_capped` /
/// `error_snippet` already guard, but the JSON paths did not. 32 MiB is far above
/// any legitimate OSINT JSON response (even a large `crt.sh` certificate list).
const JSON_BODY_CAP: usize = 32 * 1024 * 1024;

/// Stream a response body into a String, refusing to buffer more than
/// [`JSON_BODY_CAP`] bytes — the JSON-path equivalent of [`read_body_capped`].
/// Errors (rather than truncating) past the cap, since a half-read JSON body
/// can't be parsed anyway. Lossy UTF-8 so an odd-charset body still yields a
/// parseable string instead of failing outright.
async fn read_json_text(resp: reqwest::Response, module: &str) -> Result<String> {
    use futures::StreamExt as _;
    // Capture the request URL before the body stream consumes `resp`, so the
    // raw archive can key this response by what was queried.
    let url = resp.url().to_string();
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.map_err(|e| Error::module(module, redact_credentials(&e.to_string())))?;
        if buf.len() + bytes.len() > JSON_BODY_CAP {
            return Err(Error::module(
                module,
                format!(
                    "response body exceeds the {JSON_BODY_CAP}-byte cap — refusing to buffer \
                     (oversized or hostile upstream)"
                ),
            ));
        }
        buf.extend_from_slice(&bytes);
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    // Universal raw retention: every module's JSON response is archived verbatim
    // here — the single chokepoint shared by fetch_json, fetch_json_or_404,
    // fetch_keyed_json and json_scanned — so the full dossier's RAW SOURCE
    // RECORDS section is complete for ANY scan, not only the breach pools.
    crate::util::raw_archive::record_http(module, &url, &text);
    Ok(text)
}

/// Last up-to-4 *characters* of a key for log lines — char-boundary-safe.
/// Keys can be harvested from arbitrary upstream text (`scan_for_api_keys`), so
/// a byte-index slice (`&key[key.len()-4..]`) would panic when those 4 trailing
/// bytes land mid-UTF-8-sequence.
fn key_tail(key: &str) -> String {
    let mut tail: Vec<char> = key.chars().rev().take(4).collect();
    tail.reverse();
    tail.into_iter().collect()
}

/// GET `url` and deserialise the JSON body as `T`. Errors on any
/// non-2xx, including 404.
///
/// Use from modules whose upstream never returns 404-as-"no result"
/// — e.g. `ip-api.com` always returns 200 with a `status` field;
/// `crt.sh` always returns 200 with a (possibly empty) JSON array.
/// For modules where 404 means "not found, no findings" (HudsonRock,
/// Gravatar, AlienVault OTX, XposedOrNot, BGPView), use
/// [`fetch_json_or_404`] instead.
///
/// The `module` parameter is the stable module name string — embedded
/// in every error so the operator sees which module failed without
/// reading SSE event metadata.
pub async fn fetch_json<T: DeserializeOwned>(
    client: &reqwest::Client,
    module: &'static str,
    url: &str,
) -> Result<T> {
    match fetch_json_inner(client, module, url, false).await? {
        Some(data) => Ok(data),
        None => Err(Error::module(
            module,
            format!("request failed for {}", redact_credentials(url)),
        )),
    }
}

/// Like [`fetch_json`] but maps `404 Not Found` to `Ok(None)` — the
/// idiomatic "upstream says we don't know about this target" signal.
/// Every other non-2xx still becomes an `Error::module(...)` so 429
/// rate-limits and 5xx outages stay visible.
///
/// Use from modules whose upstream uses 404 as a positive "clean" /
/// "not in our dataset" signal (HudsonRock, Gravatar, AlienVault OTX,
/// XposedOrNot, BGPView).
pub async fn fetch_json_or_404<T: DeserializeOwned>(
    client: &reqwest::Client,
    module: &'static str,
    url: &str,
) -> Result<Option<T>> {
    fetch_json_inner(client, module, url, true).await
}

async fn fetch_json_inner<T: DeserializeOwned>(
    client: &reqwest::Client,
    module: &'static str,
    url: &str,
    map_404_to_none: bool,
) -> Result<Option<T>> {
    match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status();
            if map_404_to_none && status.as_u16() == 404 {
                return Ok(None);
            }
            if !status.is_success() {
                return Err(Error::module(
                    module,
                    format!("HTTP {status}: {}", error_snippet(resp).await),
                ));
            }
            let text = read_json_text(resp, module).await?;
            scan_for_api_keys(&text);
            let data = serde_json::from_str::<T>(&text)
                .map_err(|e| Error::module(module, redact_credentials(&e.to_string())))?;
            Ok(Some(data))
        }
        Err(transport) => {
            // reqwest transport failure → one curl fallback attempt. curl
            // collapses every outcome (404, non-zero exit, parse failure) to
            // `None`, so a `None` here means the fallback ALSO failed — surface
            // that as an error rather than `Ok(None)`, which `fetch_json_or_404`
            // callers would read as a definitive "not found", silently masking a
            // network outage as a clean, empty result.
            match super::curl::fetch_json::<T>(url, crate::MODULE_TIMEOUT_MS).await {
                Some(data) => Ok(Some(data)),
                None => Err(Error::module(
                    module,
                    format!(
                        "transport error ({}) and curl fallback failed for {}",
                        redact_credentials(&transport.to_string()),
                        redact_credentials(url)
                    ),
                )),
            }
        }
    }
}

/// Mask values for common credential query-param names inside an
/// arbitrary text blob. Used by [`error_snippet`] before embedding
/// upstream error bodies in module errors — many providers echo the
/// request URL in their error response, and HSE keys often ride in
/// the URL as a `?api_key=…` / `?apiKey=…` query parameter.
///
/// The matched names (`api_key`, `apiKey`, `key`, `token`, `secret`,
/// `access_token`, `auth`) cover the providers HSE keys directly
/// (Hunter, WhoisXML, OpenCellID, Shodan, etc.). The redaction
/// replaces the value with `***` and preserves the surrounding
/// delimiters so the error message still reads naturally.
pub(crate) fn redact_credentials(text: &str) -> String {
    const CREDENTIAL_PARAMS: &[&str] = &[
        "api_key",
        "apiKey",
        "access_token",
        "accessToken",
        "secret",
        "token",
        "auth",
        // `key` deliberately masks ANY `key=<value>` that follows a query
        // boundary (the `preceded_by_boundary` check below stops it tripping on
        // mid-word matches like `monkey=`). We accept over-redacting a benign
        // `?key=…` rather than risk leaking a credential that rides as `?key=…`
        // — over-redaction in an error string is harmless; under-redaction leaks.
        "key",
    ];
    // Build on bytes, not chars: copying one byte at a time into a `String`
    // via `byte as char` would reinterpret every multi-byte UTF-8 sequence as
    // Latin-1 codepoints and mojibake any non-ASCII error text (e.g. a
    // provider's localised message). Each redacted run is bounded by an ASCII
    // delimiter (`name=` … `& \n \r "` / EOF), so copying verbatim byte-runs
    // never splits a char and the assembled buffer is always valid UTF-8.
    let mut out: Vec<u8> = Vec::with_capacity(text.len());
    let mut cursor = 0;
    let bytes = text.as_bytes();
    'outer: while cursor < bytes.len() {
        for name in CREDENTIAL_PARAMS {
            let needle_eq = format!("{name}=");
            if bytes[cursor..].starts_with(needle_eq.as_bytes()) {
                // Boundary check: the preceding char (if any) should be
                // a query separator or whitespace — `apiKey=` mid-word
                // (`monKey=`) shouldn't trip.
                let preceded_by_boundary = cursor == 0
                    || matches!(
                        bytes[cursor - 1],
                        b'?' | b'&' | b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\''
                    );
                if !preceded_by_boundary {
                    continue;
                }
                let val_start = cursor + needle_eq.len();
                let mut end = val_start;
                while end < bytes.len() {
                    let b = bytes[end];
                    if b == b'&' || b == b' ' || b == b'\n' || b == b'\r' || b == b'"' {
                        break;
                    }
                    end += 1;
                }
                if end > val_start {
                    out.extend_from_slice(&bytes[cursor..val_start]);
                    out.extend_from_slice(b"***");
                    cursor = end;
                    continue 'outer;
                }
            }
        }
        out.push(bytes[cursor]);
        cursor += 1;
    }
    // Valid UTF-8 by construction (see above); lossy is a defensive fallback
    // that can't be reached for valid-UTF-8 input.
    let query_masked = String::from_utf8(out)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
    // Second pass: mask any configured secret value appearing VERBATIM. This
    // closes the gap where a key embedded in a URL *path* (e.g. IPQS
    // `/api/json/ip/<KEY>/...`) is echoed back by an upstream error body — the
    // query-param pass above only catches `name=value` shapes, so a path key
    // would otherwise survive into the persisted `events` table and SSE stream.
    redact_literal_secrets(&query_masked, env_secret_values())
}

/// `HUNTSMAN_*` values from the process environment — the operator's configured
/// keys (loaded via dotenvy at startup). Cheap in-memory read, consulted only on
/// the error path.
fn env_secret_values() -> impl Iterator<Item = String> {
    std::env::vars()
        .filter(|(k, _)| k.starts_with("HUNTSMAN_"))
        .map(|(_, v)| v)
}

/// Mask every `secret` wherever it appears in `text`, regardless of position
/// (path, query, header echo, body). Length-gated (>= 8) so short non-secret
/// values aren't touched. Split out from [`redact_credentials`] so it is
/// unit-testable without mutating the process environment (which is `unsafe`
/// under `#![forbid(unsafe_code)]`).
fn redact_literal_secrets(text: &str, secrets: impl Iterator<Item = String>) -> String {
    let mut out = text.to_string();
    for v in secrets {
        if v.len() >= 8 && out.contains(v.as_str()) {
            out = out.replace(v.as_str(), "***");
        }
    }
    out
}

/// Parse the `Retry-After` header from a response, returning the number
/// of seconds to wait. Falls back to `default_secs` if absent or
/// unparseable, and is clamped to `max_secs`.
///
/// `max_secs` is mandatory because the wait happens *inside* a module's
/// `process()` call, which the engine kills at `max_timeout_ms`. A blanket
/// 120s cap (the previous behaviour) let a server-supplied `Retry-After`
/// — or even a modest default — exceed a 8–20s module budget, so the
/// engine killed `process()` mid-sleep and mislabelled the 429 as a
/// timeout. Callers MUST pass a ceiling derived from their own budget
/// (rule of thumb: ~⅓ of `max_timeout_ms`, leaving headroom for the retry
/// request itself).
pub fn retry_after_secs(
    headers: &reqwest::header::HeaderMap,
    default_secs: u64,
    max_secs: u64,
) -> u64 {
    headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(default_secs)
        .min(max_secs)
}

/// Handle a non-success HTTP response for keyed modules. Returns:
/// - `Ok(true)` if the caller should retry (429 with retries remaining)
/// - `Ok(false)` if the response is a permanent failure (report + stop)
/// - The function sleeps on 429 before returning Ok(true).
///
/// `retries_left`: mutable counter, decremented on 429.
/// `module`: stable module name for report_key_exhausted.
/// `key`: the API key value being used.
/// `ctx`: module context for key exhaustion reporting.
pub async fn handle_keyed_error(
    status: u16,
    headers: &reqwest::header::HeaderMap,
    retries_left: &mut u8,
    module: &str,
    key: &str,
    ctx: &crate::core::module::ModuleContext,
) -> bool {
    match status {
        429 if *retries_left > 0 => {
            *retries_left -= 1;
            ctx.report_key_exhausted(module, key, 429);
            // Cap at 4s: callers of this shared helper run with 8–12s module
            // budgets, so a single in-process retry sleep must stay well under
            // the tightest of those or the engine kills process() mid-wait.
            let secs = retry_after_secs(headers, 4, 4);
            tracing::warn!(
                module,
                "429 rate-limited on key …{}, retrying in {secs}s ({} left)",
                key_tail(key),
                retries_left
            );
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            true
        }
        429 => {
            ctx.report_key_exhausted(module, key, 429);
            false
        }
        401 | 403 => {
            ctx.report_key_exhausted(module, key, status);
            false
        }
        _ => false,
    }
}

/// Keyed GET: fetch JSON from a URL that requires an API key header.
/// Handles 401/403/429 uniformly via report_key_exhausted, maps 404
/// to Ok(None). Consolidates the error handling pattern duplicated
/// across 8+ keyed modules.
pub async fn fetch_keyed_json<T: DeserializeOwned>(
    ctx: &crate::core::module::ModuleContext,
    module: &'static str,
    url: &str,
    key_env: &str,
    header_name: &str,
) -> Result<Option<T>> {
    let key = ctx.key(key_env)?;
    let resp = ctx
        .http
        .get(url)
        .header(header_name, key)
        .send()
        .await
        .map_err(|e| Error::module(module, redact_credentials(&e.to_string())))?;

    let status = resp.status();
    if status.as_u16() == 404 {
        return Ok(None);
    }
    if !status.is_success() {
        if matches!(status.as_u16(), 401 | 403 | 429) {
            ctx.report_key_exhausted(module, key, status.as_u16());
        }
        return Err(Error::module(
            module,
            format!("HTTP {status}: {}", error_snippet(resp).await),
        ));
    }
    let text = read_json_text(resp, module).await?;
    scan_for_api_keys(&text);
    let data = serde_json::from_str::<T>(&text)
        .map_err(|e| Error::module(module, redact_credentials(&e.to_string())))?;
    Ok(Some(data))
}

/// Percent-encode a single URL path or query-string component using the
/// `application/x-www-form-urlencoded` serialiser. Equivalent to:
///
/// ```ignore
/// url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
/// ```
///
/// but extracted because five modules had this verbatim helper repeated.
pub fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Decode one `application/x-www-form-urlencoded` component (`%40` → `@`,
/// `+` → space) — the inverse of [`urlencode`]. Used to recover a legible query
/// value from a URL for the raw archive's filenames. Lossy-UTF8 on the decoded
/// bytes so a malformed escape can never panic.
#[must_use]
pub fn urldecode(s: &str) -> String {
    url::form_urlencoded::parse(format!("={s}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| s.to_string())
}

/// Parse a reqwest Response as JSON while scanning the raw body for API
/// keys. Drop-in replacement for `resp.json::<T>().await` that ensures
/// no response body bypasses the key scanner.
pub async fn json_scanned<T: DeserializeOwned>(
    resp: reqwest::Response,
    module: &str,
) -> std::result::Result<T, String> {
    let text = read_json_text(resp, module)
        .await
        .map_err(|e| e.to_string())?;
    scan_for_api_keys(&text);
    serde_json::from_str(&text).map_err(|e| format!("{module}: {e}"))
}

/// Scan arbitrary text for API key patterns and store any discoveries
/// in the global key pool. Call on any raw text that passes through the
/// system — HTTP response bodies, WHOIS output, certificate fields, etc.
pub fn scan_for_api_keys(text: &str) {
    scan_for_api_keys_with_source(text, "http_response");
}

/// Separators that bound a key-candidate token in arbitrary scanned text.
/// No real API key contains any of these, so splitting on them can never
/// break a key — but omitting one corrupts the harvest: without `&`/`?` a
/// query-string echo (`?api_key=AKIA…&b=2`, the most common shape an upstream
/// reflects) tokenised to `AKIA…&b` — which still PASSED the vendor-prefix
/// match (`starts_with` + min-length) and was stored in the pool with the
/// trailing `&b=2` garbage attached: a corrupted key that can never
/// authenticate. `,` similarly bounds CSV-style dump rows.
fn is_key_token_separator(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '"' | '\'' | '`' | '>' | '<' | '=' | ';' | '&' | '?' | ','
        )
}

pub fn scan_for_api_keys_with_source(text: &str, source: &str) {
    use crate::modules::oathnet_pro::key_harvest::identify_api_key;
    let pool = crate::util::key_pool::global_pool();
    let now = crate::core::entity::unix_now();
    for word in text.split(is_key_token_separator) {
        let t = word.trim();
        if t.len() >= 16
            && t.len() <= 200
            && let Some((service, key_val)) = identify_api_key(t)
        {
            let mut entry = crate::util::key_pool::KeyEntry::new(key_val);
            entry.status = crate::util::key_pool::KeyStatus::Untested;
            entry.discovered_at = Some(now);
            entry.discovered_by = Some(source.to_string());
            pool.add(service, entry);
        }
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn traced_client_sends_x_huntsman_trace_header() {
        // Prove the trace id rides on the wire: a minimal TCP server reads the
        // raw request bytes and the header must be present. A literal-IP host
        // skips DNS, so the SSRF resolver isn't involved.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
            req
        });
        let client = build_client_with_trace("scan-abc123");
        let _ = client.get(format!("http://{addr}/")).send().await;
        let req = server.await.unwrap().to_lowercase();
        assert!(
            req.contains("x-huntsman-trace: scan-abc123"),
            "trace header missing; raw request was:\n{req}"
        );
    }

    #[test]
    fn traced_client_builds_and_tolerates_non_ascii_id() {
        // Construction must not panic; a non-ASCII id can't be a header value, so
        // it falls back to a plain (header-less) client rather than crashing.
        let _ = build_client_with_trace("plain-ascii-id");
        let _ = build_client_with_trace("non-ascii-\u{2022}-id");
    }

    #[test]
    fn ssrf_dns_filter_drops_private_and_metadata() {
        let addrs: Vec<std::net::SocketAddr> = [
            "10.0.0.1:80",
            "8.8.8.8:443",
            "169.254.169.254:80",
            "127.0.0.1:80",
            "[::1]:80",
            "[2606:4700:4700::1111]:443",
        ]
        .iter()
        .map(|x| x.parse().unwrap())
        .collect();
        let kept: Vec<String> = super::filter_public(addrs.into_iter())
            .iter()
            .map(|a| a.ip().to_string())
            .collect();
        assert!(kept.contains(&"8.8.8.8".to_string()), "public v4 kept");
        assert!(
            kept.contains(&"2606:4700:4700::1111".to_string()),
            "public v6 kept"
        );
        for blocked in ["10.0.0.1", "169.254.169.254", "127.0.0.1", "::1"] {
            assert!(
                !kept.iter().any(|i| i == blocked),
                "{blocked} must be filtered"
            );
        }
    }

    #[test]
    fn redirect_to_private_ip_blocks_metadata_and_internal() {
        use super::redirect_to_private_ip as blk;
        assert!(
            blk(Some("169.254.169.254")),
            "cloud-metadata IP must be refused"
        );
        assert!(blk(Some("127.0.0.1")));
        assert!(blk(Some("10.0.0.5")));
        assert!(blk(Some("192.168.1.1")));
        assert!(!blk(Some("8.8.8.8")), "public IP follows");
        assert!(
            !blk(Some("example.com")),
            "hostnames resolved at connect, not judged here"
        );
        assert!(!blk(None));

        // IPv6-literal hops arrive bracketed from `Url::host_str()` (url 2.5).
        // Without bracket-stripping these fail to parse and slip through — a
        // public site could 3xx the client onto IPv6 loopback / ULA / the
        // IPv4-mapped cloud-metadata address. Each must be refused.
        assert!(blk(Some("[::1]")), "IPv6 loopback hop must be refused");
        assert!(blk(Some("[fc00::1]")), "ULA hop must be refused");
        assert!(blk(Some("[fe80::1]")), "link-local hop must be refused");
        assert!(
            blk(Some("[::ffff:169.254.169.254]")),
            "IPv4-mapped cloud-metadata hop must be refused"
        );
        assert!(
            blk(Some("[64:ff9b::a9fe:a9fe]")),
            "NAT64-embedded metadata hop must be refused"
        );
        // A public IPv6 hop (bracketed) still follows.
        assert!(
            !blk(Some("[2606:4700:4700::1111]")),
            "public IPv6 hop follows"
        );
    }

    use super::*;

    #[test]
    fn build_client_succeeds() {
        let _c = build_client();
    }

    #[test]
    fn redacts_path_embedded_secret_value() {
        // Regression: a key carried in a URL *path* (IPQS-style) that an upstream
        // echoes in its error body must be masked, even though it is not a
        // `name=value` query param the first pass would catch. Otherwise it is
        // persisted to the events table and streamed over SSE in cleartext.
        let key = "abcd1234efgh5678ijkl"; // realistic key length (>= 8)
        let body = format!("invalid request: /api/json/ip/{key}/1.2.3.4 rejected");
        let masked = redact_literal_secrets(&body, std::iter::once(key.to_string()));
        assert!(
            !masked.contains(key),
            "path-embedded key must be redacted: {masked}"
        );
        assert!(masked.contains("***"));
        // Short values are NOT masked (avoid clobbering benign substrings).
        assert_eq!(
            redact_literal_secrets("xabcx", std::iter::once("abc".to_string())),
            "xabcx"
        );
    }

    #[test]
    fn urlencode_plain_passthrough() {
        assert_eq!(urlencode("hello"), "hello");
    }

    #[test]
    fn urlencode_spaces_become_plus() {
        assert_eq!(urlencode("hello world"), "hello+world");
    }

    #[test]
    fn urlencode_special_chars() {
        assert_eq!(urlencode("a@b.com"), "a%40b.com");
    }

    #[test]
    fn urlencode_unicode() {
        let encoded = urlencode("café");
        assert!(encoded.contains('%'));
        assert!(!encoded.contains("é"));
    }

    #[test]
    fn urlencode_empty() {
        assert_eq!(urlencode(""), "");
    }

    #[test]
    fn urlencode_slashes_and_ampersands() {
        let encoded = urlencode("a/b&c=d");
        assert!(encoded.contains("%2F"));
        assert!(encoded.contains("%26"));
        assert!(encoded.contains("%3D"));
    }

    // ── retry_after_secs ───────────────────────────────────────────────

    fn hdrs(retry_after: Option<&str>) -> reqwest::header::HeaderMap {
        let mut h = reqwest::header::HeaderMap::new();
        if let Some(v) = retry_after {
            h.insert("retry-after", v.parse().unwrap());
        }
        h
    }

    #[test]
    fn retry_after_uses_default_when_header_absent() {
        assert_eq!(retry_after_secs(&hdrs(None), 5, 10), 5);
    }

    #[test]
    fn retry_after_parses_header_value() {
        assert_eq!(retry_after_secs(&hdrs(Some("3")), 5, 10), 3);
    }

    #[test]
    fn retry_after_clamps_hostile_header_to_max() {
        // A server (or a misbehaving proxy) asking for a 600s wait must not
        // exceed the caller's budget ceiling — this is the timeout-kill bug.
        assert_eq!(retry_after_secs(&hdrs(Some("600")), 5, 10), 10);
    }

    #[test]
    fn retry_after_clamps_oversized_default_to_max() {
        assert_eq!(retry_after_secs(&hdrs(None), 99, 6), 6);
    }

    #[test]
    fn retry_after_ignores_unparseable_header() {
        assert_eq!(retry_after_secs(&hdrs(Some("soon")), 7, 30), 7);
    }

    // ── redact_credentials ─────────────────────────────────────────────

    #[test]
    fn redact_strips_api_key_query_param() {
        let s = "HTTP 400: Invalid request: domain=&api_key=SECRET_KEY_123";
        let r = redact_credentials(s);
        assert!(!r.contains("SECRET_KEY_123"));
        assert!(r.contains("api_key=***"));
    }

    #[test]
    fn redact_strips_apikey_camel_case() {
        let s = "Bad URL: ?apiKey=AbCdEf123&domain=example.com";
        let r = redact_credentials(s);
        assert!(!r.contains("AbCdEf123"));
        assert!(r.contains("apiKey=***"));
    }

    #[test]
    fn redact_strips_token_and_secret() {
        let s = "?token=THEACTUALTOKEN&secret=ALSOSECRET&other=keep";
        let r = redact_credentials(s);
        assert!(!r.contains("THEACTUALTOKEN"));
        assert!(!r.contains("ALSOSECRET"));
        assert!(r.contains("other=keep"));
    }

    #[test]
    fn redact_preserves_non_credential_text() {
        let s = "Quota exhausted, contact support@example.com";
        let r = redact_credentials(s);
        assert_eq!(r, s);
    }

    #[test]
    fn redact_does_not_match_substring_words() {
        // `monKey=value` should NOT have `Key=value` matched —
        // boundary check rejects mid-word matches.
        let s = "monkey=banana";
        let r = redact_credentials(s);
        assert!(r.contains("monkey=banana"));
    }

    #[test]
    fn redact_handles_multiple_credentials_on_one_line() {
        let s = "url=https://api.example.com/?api_key=KEY1&token=KEY2&apiKey=KEY3";
        let r = redact_credentials(s);
        assert!(!r.contains("KEY1"));
        assert!(!r.contains("KEY2"));
        assert!(!r.contains("KEY3"));
    }

    #[test]
    fn redact_preserves_non_ascii_text() {
        // Provider error bodies can carry non-ASCII (localised messages, IDN,
        // em-dashes). The credential must still be masked while the surrounding
        // UTF-8 survives intact — a naïve byte→char copy would mojibake it.
        let s = "{\"error\":\"clé API invalide — accès refusé\",\
                 \"url\":\"https://api.x.com/?api_key=SECRET123456&q=café\"}";
        let r = redact_credentials(s);
        // Credential masked.
        assert!(!r.contains("SECRET123456"), "credential must be redacted");
        assert!(r.contains("api_key=***"));
        // Non-ASCII text preserved verbatim (no mojibake).
        assert!(r.contains("clé API invalide — accès refusé"), "got: {r}");
        assert!(r.contains("q=café"), "got: {r}");
        // Result is well-formed UTF-8 (String guarantees this; assert no
        // replacement char leaked from a lossy fallback).
        assert!(!r.contains('\u{FFFD}'), "no replacement chars: {r}");
    }

    // ── key_tail (char-boundary safety, F-C) ───────────────────────────

    #[test]
    fn key_tail_is_char_boundary_safe() {
        assert_eq!(key_tail("abcdef123456"), "3456");
        assert_eq!(key_tail("ab"), "ab");
        assert_eq!(key_tail(""), "");
        // A byte slice of the last 4 BYTES would split these chars and panic;
        // key_tail keeps whole chars and never panics.
        assert_eq!(key_tail("clé"), "clé");
        assert_eq!(key_tail("k😀😀😀😀").chars().count(), 4);
    }

    #[test]
    fn key_scan_tokeniser_bounds_query_string_keys_cleanly() {
        // The most common echo shape an upstream reflects: a key in a URL
        // query string followed by another parameter. The tokeniser must
        // yield the BARE key — without '&'/'?' as separators, the token was
        // `AKIA…&b` which still passed the vendor prefix match and was
        // pooled with trailing garbage (a corrupted, never-authenticating key).
        let body = r#"error at https://api.example.com/v1?api_key=AKIAJK28SLQQV61MNG9X&b=2"#;
        let tokens: Vec<&str> = body.split(super::is_key_token_separator).collect();
        assert!(
            tokens.contains(&"AKIAJK28SLQQV61MNG9X"),
            "bare key must be its own token: {tokens:?}"
        );
        assert!(
            !tokens.iter().any(|t| t.contains('&') || t.contains('?')),
            "no token may carry query separators: {tokens:?}"
        );
        // And the clean token round-trips through the identifier as exactly
        // the key — not key-plus-garbage.
        use crate::modules::oathnet_pro::key_harvest::identify_api_key;
        let (svc, val) = identify_api_key("AKIAJK28SLQQV61MNG9X").expect("real-shape AWS key");
        assert_eq!(svc, "aws");
        assert_eq!(val, "AKIAJK28SLQQV61MNG9X");
        // Why the tokeniser is load-bearing: the identifier's vendor-prefix
        // branch passes its token through VERBATIM (starts_with + min-length),
        // so a `key&garbage` token would be pooled as-is — the corruption the
        // old splitter produced. The tokeniser is the only guard.
        assert!(
            identify_api_key("AKIAJK28SLQQV61MNG9X&b=2").is_some_and(|(_, v)| v.contains('&')),
            "identifier passes tokens through verbatim — the tokeniser must pre-split"
        );
        // CSV-style dump rows split too.
        let csv: Vec<&str> = "AKIAJK28SLQQV61MNG9X,other"
            .split(super::is_key_token_separator)
            .collect();
        assert_eq!(csv, vec!["AKIAJK28SLQQV61MNG9X", "other"]);
    }

    #[test]
    fn redact_over_masks_bare_key_param_after_boundary() {
        // Documented behaviour (F-E): any boundary-preceded `key=…` value is
        // masked, even a benign short one — over-redaction is the safe direction
        // in an error string; under-redaction would leak a `?key=…` credential.
        let r = redact_credentials("?key=sortorder&page=2");
        assert!(r.contains("key=***"), "got: {r}");
        assert!(r.contains("page=2"), "got: {r}");
    }
}
