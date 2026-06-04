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
const DEFAULT_UA: &str = "Mozilla/5.0 (Linux; Android 14; Pixel 8) \
     AppleWebKit/537.36 (KHTML, like Gecko) \
     Chrome/125.0.0.0 Mobile Safari/537.36";

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
        self.exec(url, key, None).await
    }

    /// Issue a `POST <url>` with `application/json` body.
    pub async fn post_json(&self, url: &str, key: &str, body: &str) -> Result<String> {
        self.exec(url, key, Some(body)).await
    }

    async fn exec(&self, url: &str, key: &str, post_body: Option<&str>) -> Result<String> {
        let secs = self.curl_timeout_secs.to_string();
        let auth_header = self.auth.header_line(key);

        let mut cmd = Command::new("curl");
        cmd.args(["-s", "-L", "--max-time", &secs, "-A", DEFAULT_UA]);
        cmd.args([
            "--proto",
            "=http,https",
            "--proto-redir",
            "=http,https",
            "--max-redirs",
            "5",
        ]);
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
        String::from_utf8(output.stdout).map_err(|e| Error::module(self.module, e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_scheme_renders_bearer_header() {
        assert_eq!(
            AuthScheme::Bearer.header_line("abc123"),
            Some("Authorization: Bearer abc123".to_string())
        );
    }

    #[test]
    fn auth_scheme_renders_x_api_key_header() {
        assert_eq!(
            AuthScheme::XApiKey.header_line("abc123"),
            Some("x-api-key: abc123".to_string())
        );
    }

    #[test]
    fn auth_scheme_none_emits_no_header() {
        assert_eq!(AuthScheme::None.header_line("ignored"), None);
    }

    #[tokio::test]
    async fn curl_failure_reports_exit_code_not_opaque_message() {
        // Point at an unroutable host with a tiny timeout so curl exits
        // non-zero (typically 28 timeout or 6/7 resolve/connect). The error
        // must carry curl's exit code, not the old opaque "curl failed".
        static C: CurlClient = CurlClient::new("test_seeknow", AuthScheme::None, 1, 3_000);
        let err = C
            .get("https://10.255.255.1/definitely-not-real", "")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("curl exited"),
            "error must surface curl's exit code, got: {err}"
        );
        assert!(
            !err.contains("curl failed"),
            "opaque message must be gone: {err}"
        );
    }

    #[test]
    fn const_constructor_admits_static_declaration() {
        // The whole point of `const fn new()` is that the caller can
        // declare a `static`. Construct one here so the test fails
        // at compile time if that ever stops being possible.
        static C: CurlClient = CurlClient::new("test_module", AuthScheme::Bearer, 12, 15_000);
        // Field accessors (via methods if added later) would be
        // exercised here. For now the test is a compile-time assertion.
        let _ = &C;
    }

    #[test]
    fn auth_scheme_equality_and_clone() {
        let a = AuthScheme::Bearer;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(AuthScheme::Bearer, AuthScheme::XApiKey);
    }

    // Note: the curl-invocation failure path (`Error::module(self.module,
    // "curl failed" | "timeout")`) is intentionally NOT unit-tested here.
    // Such a test would depend on the host's curl version and on `curl
    // not-a-url`'s exact exit code, both of which vary across CI runners
    // and developer machines (e.g. captive-portal DNS that resolves
    // arbitrary hostnames to an HTTP capture page). The failure-path
    // wiring is exercised end-to-end whenever the `see_know` or
    // `oathnet` modules attempt a real call in a network-unreachable
    // test environment.
}
