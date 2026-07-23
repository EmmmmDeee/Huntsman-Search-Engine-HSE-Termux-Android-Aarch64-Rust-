//! Shared curl-subprocess client for paid OSINT API providers.
//!
//! `util::see_know::curl_exec` and `util::oathnet::curl_get` were
//! near-clones — same `Mozilla/5.0 (Linux; Android 14; Pixel 8) ...`
//! UA, same `Accept: application/json` header, same 12s `--max-time`
//! arg, same 15s outer `tokio::time::timeout`, same `cmd.kill_on_drop`
//! pattern. The only meaningful difference was the auth header
//! (`Authorization: Bearer` vs `x-api-key`) and whether the call
//! also supports POST.
//!
//! `CurlClient` captures that common shape so each provider declares
//! a single `static CLIENT: CurlClient = CurlClient::new(...)` and
//! calls `client.get(url, key)` / `client.post_json(url, key, body)`.
//!
//! Why curl subprocess at all (vs `reqwest`):
//!   - The paid OSINT providers fingerprint Cloudflare / CDN
//!     challenges off the User-Agent header and TLS fingerprint.
//!     A mobile-Chrome UA on curl matches the operator's expected
//!     browser fingerprint more closely than rustls + reqwest's
//!     default UA.
//!   - Termux ships curl as part of the standard pkg set; one less
//!     thing to link against on minimal aarch64 builds.
//!
//! Self-healing DNS: because every request goes through the system
//! resolver, a Termux device whose carrier/ISP resolver *filters* a
//! provider domain sees `curl: (6) Could not resolve host` even though
//! the host is reachable. [`CurlClient::exec`] retries such a failure
//! ONCE through a DoH (DNS-over-HTTPS) resolver (`curl --doh-url`), which
//! resolves over HTTPS and bypasses the broken/filtering local resolver.
//! Only the already-failed resolution path pays the extra call; every
//! success path is byte-identical to before. Operator override:
//! `HUNTSMAN_DOH_URL` (set to `off`/`none`/empty to disable).

use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

use crate::core::error::{Error, Result};

/// Default User-Agent for paid OSINT API calls. Mobile Chrome on
/// Android 14 — matches what an operator's Termux-launched browser
/// would send, which is what the providers' CDN fingerprinting
/// expects.
const DEFAULT_UA: &str = crate::util::curl::UA_MOBILE;

/// Static curl flags every [`CurlClient`] request carries, independent of the
/// per-call timeout / auth / body.
///
/// `--compressed` is the potentiation: it advertises `Accept-Encoding`
/// (gzip/br/zstd, whatever the local libcurl was built with) and curl
/// transparently decompresses the response, so the body the caller receives is
/// byte-for-byte identical while the on-wire transfer for a paid API's JSON
/// (SeekNow breach dumps, OathNet records) shrinks ~4× — measured live, a RIPE
/// JSON body went 4743→1138 bytes. On a metered Termux mobile link that is a
/// direct data-cost and latency win on every paid call, and it never changes
/// the archived bytes or the parsed entities.
///
/// Deliberately NOT folded into the general [`crate::util::curl::FETCH_HARDENING_ARGS`]
/// SSRF fetch path: THAT path fetches attacker-influenceable hosts (web crawl,
/// scan-target URLs), where `--max-filesize` bounds the *compressed* transfer,
/// so a malicious server could ship a small compressed body that decompresses
/// past the intended memory cap (a decompression-bomb vector). A [`CurlClient`]
/// only ever targets a hardcoded, trusted paid-provider API base, so that risk
/// does not apply here — which is exactly why compression is enabled on this
/// transport and only this transport.
const CLIENT_BASE_ARGS: &[&str] = &["-s", "-S", "-L", "--compressed"];

/// curl exit code for "Could not resolve host" — the DNS-resolution failure the
/// DoH fallback is designed to self-heal. Named so the retry condition in
/// [`CurlClient::exec`] reads intent rather than a bare magic number.
const CURL_EXIT_COULD_NOT_RESOLVE: i32 = 6;

/// Default DoH resolver for the reachability fallback — Cloudflare's RFC 8484
/// endpoint, addressed by its **literal IP** rather than `cloudflare-dns.com`.
/// Used when the system resolver fails (curl exit 6) and no operator override
/// is set. HTTPS-based, so a filtering/broken local resolver is bypassed.
///
/// The IP literal matters: reaching this URL at all still requires resolving
/// ITS host first, and a hostname here would need the very same (possibly
/// totally broken, not just filtering one provider) system resolver the DoH
/// fallback exists to route around — a chicken-and-egg bootstrap gap that a
/// `cloudflare-dns.com` URL never closes. `1.1.1.1` needs no lookup at all
/// (curl dials the literal directly), and Cloudflare's DoH certificate is
/// issued with `1.1.1.1`/`1.0.0.1` as literal-IP Subject Alternative Names
/// specifically to support this bootstrap pattern, so TLS validation still
/// succeeds.
const DEFAULT_DOH_URL: &str = "https://1.1.1.1/dns-query";

/// Env var by which an operator overrides (or disables) the DoH fallback.
const DOH_ENV: &str = "HUNTSMAN_DOH_URL";

/// How a provider's API key is presented on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthScheme {
    /// `Authorization: Bearer <key>`.
    Bearer,
    /// `x-api-key: <key>` — used by OathNet and SeekNow (see-know.eu).
    XApiKey,
    /// No auth header. Useful for endpoints that don't require a key
    /// (rare for paid APIs but present for some public sub-paths).
    None,
}

impl AuthScheme {
    fn header_line(self, key: &str) -> Option<String> {
        match self {
            Self::Bearer => Some(format!("Authorization: Bearer {key}")),
            Self::XApiKey => Some(format!("x-api-key: {key}")),
            Self::None => None,
        }
    }
}

/// Shared curl-subprocess HTTP client.
///
/// Declare as a `static` per-provider — every method takes `&self`
/// and the struct is `Send + Sync` (only contains plain integers
/// and `&'static str`/`AuthScheme` data).
pub struct CurlClient {
    /// Provider name (`"seek_now"`, `"oathnet"`) used in error
    /// messages so the `Module::process` failure log says which API
    /// timed out.
    module: &'static str,

    /// Auth header shape — applied to every `get` / `post_json`
    /// call when the caller supplies a non-empty key.
    auth: AuthScheme,

    /// `--max-time N` passed to curl. Bounds curl's own retry +
    /// connect waits.
    curl_timeout_secs: u64,

    /// Outer `tokio::time::timeout` — slightly longer than the curl
    /// timeout so we observe curl's own timeout-exit rather than
    /// killing it mid-write.
    outer_timeout_ms: u64,
}

impl CurlClient {
    /// `const fn` constructor so callers can declare a per-module
    /// `static CLIENT: CurlClient = CurlClient::new(...)`.
    ///
    /// `outer_timeout_ms` SHOULD be ≥ `curl_timeout_secs * 1000`
    /// so curl's own exit code (28 = operation timed out) is what
    /// we see, rather than tokio aborting the process mid-flight.
    pub const fn new(
        module: &'static str,
        auth: AuthScheme,
        curl_timeout_secs: u64,
        outer_timeout_ms: u64,
    ) -> Self {
        Self {
            module,
            auth,
            curl_timeout_secs,
            outer_timeout_ms,
        }
    }

    /// curl `--max-time` ceiling in seconds. Exposed so per-module tests can
    /// assert the budget sits above a known slow upstream's response time.
    #[cfg(test)]
    pub(crate) const fn curl_timeout_secs(&self) -> u64 {
        self.curl_timeout_secs
    }

    /// The configured auth scheme. Exposed so per-module tests can assert the
    /// header matches the provider's spec (e.g. SeekNow requires `X-API-Key`).
    #[cfg(test)]
    pub(crate) const fn auth_scheme(&self) -> AuthScheme {
        self.auth
    }

    /// Outer tokio timeout in milliseconds.
    #[cfg(test)]
    pub(crate) const fn outer_timeout_ms(&self) -> u64 {
        self.outer_timeout_ms
    }

    /// Issue a `GET <url>` with the configured auth header.
    /// Returns the response body on success (curl exit 0).
    pub async fn get(&self, url: &str, key: &str) -> Result<String> {
        self.exec(url, key, None).await.map(|(body, _)| body)
    }

    /// Issue a `POST <url>` with `application/json` body.
    pub async fn post_json(&self, url: &str, key: &str, body: &str) -> Result<String> {
        self.exec(url, key, Some(body)).await.map(|(body, _)| body)
    }

    /// Like [`get`](Self::get) but ALSO returns the final HTTP status code, so a
    /// caller can distinguish a transient upstream `5xx`/CDN `502` (retryable)
    /// from a genuine empty/`4xx` result. The body is identical to `get`'s — the
    /// trailing `\n<code>` `-w` line is stripped before it is returned, so a
    /// consumer that `serde_json::from_str`s the body never sees the status.
    /// Status `0` means curl reported no HTTP response (e.g. a connection reset
    /// after connect).
    pub async fn get_with_status(&self, url: &str, key: &str) -> Result<(String, u16)> {
        self.exec(url, key, None).await
    }

    /// [`post_json`](Self::post_json) variant returning the final HTTP status
    /// alongside the body. See [`get_with_status`](Self::get_with_status).
    pub async fn post_json_with_status(
        &self,
        url: &str,
        key: &str,
        body: &str,
    ) -> Result<(String, u16)> {
        self.exec(url, key, Some(body)).await
    }

    /// Build the curl [`Command`] for one request. `doh_url = Some(..)` adds the
    /// `--doh-url` resolver flag (the reachability fallback); `None` is the
    /// normal path, whose argument vector is byte-identical to the historical
    /// inline construction.
    fn build_command(
        &self,
        url: &str,
        key: &str,
        post_body: Option<&str>,
        doh_url: Option<&str>,
    ) -> Command {
        let secs = self.curl_timeout_secs.to_string();
        let auth_header = self.auth.header_line(key);
        let args = curl_args(&secs, auth_header.as_deref(), post_body, doh_url, url);
        let mut cmd = Command::new("curl");
        cmd.args(&args);
        cmd.kill_on_drop(true);
        cmd
    }

    /// Spawn `cmd`, drain stdout/stderr concurrently under a hard decoded-size
    /// ceiling, and return `(exit status, stdout, stderr)`. Bounded read instead
    /// of `cmd.output()`: `--compressed` makes curl inflate the response
    /// in-process, and `--max-filesize` only bounds the COMPRESSED transfer — so
    /// a tiny compressed body could decode past available memory (a decompression
    /// bomb from a compromised or operator-overridden provider host) and OOM-kill
    /// the tool on a low-RAM phone. stdout and stderr are drained CONCURRENTLY so
    /// neither pipe filling can deadlock the child; `kill_on_drop(true)` reaps a
    /// still-writing curl if the ceiling trips or the outer timeout fires.
    async fn run_curl(
        &self,
        mut cmd: Command,
    ) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>)> {
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        timeout(Duration::from_millis(self.outer_timeout_ms), async {
            use tokio::io::AsyncReadExt as _;
            let mut child = cmd
                .spawn()
                .map_err(|e| Error::module(self.module, e.to_string()))?;
            let mut child_out = child.stdout.take().expect("stdout piped");
            let mut child_err = child.stderr.take().expect("stderr piped");
            let cap = crate::util::http::JSON_BODY_CAP as u64;
            let mut body = Vec::new();
            let mut err = Vec::new();
            // `take(cap + 1)` reads one byte past the ceiling so an exactly-cap
            // body still succeeds while a bomb trips the guard below.
            let mut capped_out = (&mut child_out).take(cap + 1);
            let (out_res, _err_res) = tokio::join!(
                capped_out.read_to_end(&mut body),
                child_err.read_to_end(&mut err),
            );
            out_res.map_err(|e| Error::module(self.module, e.to_string()))?;
            if body.len() as u64 > cap {
                // Over the decoded ceiling → decompression bomb. Returning drops
                // `child`, and `kill_on_drop(true)` reaps the still-writing curl.
                return Err(Error::module(
                    self.module,
                    "response exceeded the decoded size cap (possible decompression bomb)",
                ));
            }
            // Both pipes hit EOF (body ≤ cap), so curl has finished writing —
            // reaping the exit status won't block.
            let status = child
                .wait()
                .await
                .map_err(|e| Error::module(self.module, e.to_string()))?;
            Ok::<(std::process::ExitStatus, Vec<u8>, Vec<u8>), Error>((status, body, err))
        })
        .await
        .map_err(|_| Error::module(self.module, "timeout"))?
    }

    async fn exec(&self, url: &str, key: &str, post_body: Option<&str>) -> Result<(String, u16)> {
        // First attempt via the system resolver (the normal, byte-identical path).
        let mut result = self
            .run_curl(self.build_command(url, key, post_body, None))
            .await?;
        let mut via_doh = false;

        // Self-healing DNS reachability: curl exit 6 == "could not resolve host".
        // On a device whose carrier/ISP resolver filters a provider domain the
        // host is reachable but unresolvable, so retry the identical request ONCE
        // through a DoH resolver, which resolves over HTTPS and bypasses the
        // broken/filtering resolver. Only this already-failed path pays the extra
        // call; success paths are unaffected. Disabled via `HUNTSMAN_DOH_URL=off`.
        let could_not_resolve =
            !result.0.success() && result.0.code() == Some(CURL_EXIT_COULD_NOT_RESOLVE);
        if let Some(doh) = could_not_resolve.then(doh_fallback_url).flatten() {
            result = self
                .run_curl(self.build_command(url, key, post_body, Some(&doh)))
                .await?;
            via_doh = true;
        }

        let (exit_status, stdout_bytes, stderr_bytes) = result;

        if !exit_status.success() {
            // Surface curl's own exit code (28 = timeout, 6 = could-not-resolve,
            // 7 = connect-refused, …) plus a trimmed stderr snippet, instead of
            // an opaque "curl failed", so transient upstream failures are
            // diagnosable from the logs. Note the DoH fallback when it was tried,
            // so a still-failing resolve is distinguishable from a bare one.
            let code = exit_status
                .code()
                .map_or_else(|| "signal".to_string(), |c| c.to_string());
            let via = if via_doh {
                " (after DoH resolver fallback)"
            } else {
                ""
            };
            let stderr = String::from_utf8_lossy(&stderr_bytes);
            let snippet: String = stderr.trim().chars().take(200).collect();
            let detail = if snippet.is_empty() {
                format!("curl exited {code}{via}")
            } else {
                // Redact in case curl echoes an effective URL carrying a key.
                format!(
                    "curl exited {code}{via}: {}",
                    crate::util::http::redact_credentials(&snippet)
                )
            };
            return Err(Error::module(self.module, detail));
        }

        // Lossy decode (matching the free `curl::curl_exec` path): a paid-API
        // response with a stray non-UTF-8 byte (e.g. a Latin-1 char in an error
        // string) must still yield a usable body rather than being dropped as a
        // hard failure — full-fidelity policy. Downstream `serde_json` still
        // validates the JSON structure, so a genuinely malformed body is caught
        // there, not silently here.
        let raw = String::from_utf8_lossy(&stdout_bytes).into_owned();
        Ok(split_status(&raw))
    }
}

/// Build curl's full ordered argument list. Pure and free-standing so the exact
/// arg vector — auth header, POST framing, the optional DoH resolver flag, and
/// the trailing `-w`/`--` — is unit-testable without spawning a process. With
/// `doh_url = None` the vector is byte-identical to the historical inline args.
fn curl_args(
    secs: &str,
    auth_header: Option<&str>,
    post_body: Option<&str>,
    doh_url: Option<&str>,
    url: &str,
) -> Vec<String> {
    let mut a: Vec<String> = Vec::with_capacity(20);
    a.extend(CLIENT_BASE_ARGS.iter().map(|s| (*s).to_string()));
    a.push("--max-time".to_string());
    a.push(secs.to_string());
    a.push("-A".to_string());
    a.push(DEFAULT_UA.to_string());
    a.extend(
        crate::util::curl::FETCH_HARDENING_ARGS
            .iter()
            .map(|s| (*s).to_string()),
    );
    if let Some(doh) = doh_url {
        a.push("--doh-url".to_string());
        a.push(doh.to_string());
    }
    if let Some(h) = auth_header {
        a.push("-H".to_string());
        a.push(h.to_string());
    }
    a.push("-H".to_string());
    a.push("Accept: application/json".to_string());
    if let Some(body) = post_body {
        a.push("-X".to_string());
        a.push("POST".to_string());
        a.push("-H".to_string());
        a.push("Content-Type: application/json".to_string());
        a.push("-d".to_string());
        a.push(body.to_string());
    }
    a.push("-w".to_string());
    a.push("\n%{http_code}".to_string());
    a.push("--".to_string());
    a.push(url.to_string());
    a
}

/// Resolve the DoH fallback URL from a raw env value. Pure so the policy is
/// unit-tested without mutating process env: on the crate's Rust 2024 edition
/// `std::env::set_var` is an `unsafe fn`, and this crate is `#![forbid(unsafe_code)]`,
/// so a test could not call it even in an `unsafe` block. Default-on (Cloudflare)
/// when unset; disabled by an empty value or `off`/`none`/`false`/`0`
/// (case-insensitive). Any other value is treated as a custom DoH endpoint URL.
fn resolve_doh(raw: Option<&str>) -> Option<String> {
    match raw {
        None => Some(DEFAULT_DOH_URL.to_string()),
        Some(v) => {
            let t = v.trim();
            if t.is_empty()
                || t.eq_ignore_ascii_case("off")
                || t.eq_ignore_ascii_case("none")
                || t.eq_ignore_ascii_case("false")
                || t == "0"
            {
                None
            } else {
                Some(t.to_string())
            }
        }
    }
}

/// The DoH fallback URL resolved from the process env (`HUNTSMAN_DOH_URL`), or
/// the Cloudflare default. See [`resolve_doh`].
fn doh_fallback_url() -> Option<String> {
    resolve_doh(std::env::var(DOH_ENV).ok().as_deref())
}

/// Split curl's `-w '\n%{http_code}'` output into `(body, status)`. The status
/// is the final line; everything before the last newline is the body (any
/// internal newlines preserved). A missing/unparseable code yields status `0`
/// ("no HTTP response observed"), which callers treat as transient. Pure, so
/// the split — the one place a mistake could corrupt every paid-API body — is
/// unit-tested directly.
fn split_status(raw: &str) -> (String, u16) {
    match raw.rsplit_once('\n') {
        Some((body, code)) => (body.to_string(), code.trim().parse().unwrap_or(0)),
        // No newline at all: curl wrote only the code (empty body) or nothing.
        None => {
            let trimmed = raw.trim();
            if !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_digit()) {
                (String::new(), trimmed.parse().unwrap_or(0))
            } else {
                (raw.to_string(), 0)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
