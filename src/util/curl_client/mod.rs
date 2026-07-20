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

    async fn exec(&self, url: &str, key: &str, post_body: Option<&str>) -> Result<(String, u16)> {
        let secs = self.curl_timeout_secs.to_string();
        let auth_header = self.auth.header_line(key);

        let mut cmd = Command::new("curl");
        // Static transfer flags (`-s -S -L --compressed`) — silent-with-errors,
        // follow redirects, and request/decompress a compressed response.
        // `-S`/`--show-error` alongside `-s`: silent mode alone suppresses BOTH
        // the progress meter AND curl's own fatal-error text, so a DNS/connect
        // failure previously surfaced as a bare "curl exited 6" with an empty
        // `output.stderr` below — diagnosable only by looking up what curl exit
        // code 6 means, never WHICH host or WHY. `-S` keeps the progress meter
        // suppressed but restores the one-line diagnostic ("curl: (6) Could not
        // resolve host: …") into stderr, which the failure branch below already
        // captures and reports. `--compressed` shrinks the paid-API JSON transfer
        // ~4× with a byte-identical decompressed body (see [`CLIENT_BASE_ARGS`]).
        cmd.args(CLIENT_BASE_ARGS);
        cmd.args(["--max-time", &secs, "-A", DEFAULT_UA]);
        // Protocol/redirect/size hardening, single-sourced so this keyed-API
        // path and the free-function curl path can never drift apart.
        //
        // Unlike `curl::curl_exec`, this path applies no in-process private-IP
        // `ssrf_resolve_pin`: every `url` here targets a hardcoded paid-provider
        // API base (OathNet, SeekNow, …) declared by the provider module, with
        // discovered values confined to the path/query — the host is never
        // attacker-controlled, so there is no rebinding target to pin.
        cmd.args(crate::util::curl::FETCH_HARDENING_ARGS);
        if let Some(ref h) = auth_header {
            cmd.args(["-H", h]);
        }
        cmd.args(["-H", "Accept: application/json"]);
        if let Some(body) = post_body {
            cmd.args([
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-d",
                body,
            ]);
        }
        // Append the final HTTP status on its own trailing line so a caller can
        // distinguish a transient upstream 5xx from a genuine empty result. It is
        // written to stdout AFTER the body; [`split_status`] strips it back off so
        // the returned body is byte-identical to the pre-status behaviour.
        cmd.args(["-w", "\n%{http_code}"]);
        cmd.args(["--", url]);
        cmd.kill_on_drop(true);

        let output = timeout(Duration::from_millis(self.outer_timeout_ms), cmd.output())
            .await
            .map_err(|_| Error::module(self.module, "timeout"))?
            .map_err(|e| Error::module(self.module, e.to_string()))?;

        if !output.status.success() {
            // Surface curl's own exit code (28 = timeout, 6 = could-not-resolve,
            // 7 = connect-refused, …) plus a trimmed stderr snippet, instead of
            // an opaque "curl failed", so transient upstream failures are
            // diagnosable from the logs.
            let code = output
                .status
                .code()
                .map_or_else(|| "signal".to_string(), |c| c.to_string());
            let stderr = String::from_utf8_lossy(&output.stderr);
            let snippet: String = stderr.trim().chars().take(200).collect();
            let detail = if snippet.is_empty() {
                format!("curl exited {code}")
            } else {
                // Redact in case curl echoes an effective URL carrying a key.
                format!(
                    "curl exited {code}: {}",
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
        let raw = String::from_utf8_lossy(&output.stdout).into_owned();
        Ok(split_status(&raw))
    }
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
