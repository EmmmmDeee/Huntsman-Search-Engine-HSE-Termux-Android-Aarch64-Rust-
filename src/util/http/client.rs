//! Public reqwest client constructors.

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
pub fn build_client() -> reqwest::Client {
    super::ssrf::client_builder()
        .build()
        // expect justification: `client_builder()` is a fully static configuration
        // (SSRF DNS resolver, redirect policy, fixed timeouts, compile-time UA), so
        // `ClientBuilder::build()` can only fail if the rustls TLS backend cannot
        // initialise — a build/environment misconfiguration, never a runtime or
        // input condition. Fail fast at construction so every caller can treat the
        // client as infallibly available rather than threading a Result everywhere.
        .expect("reqwest client (rustls backend) failed to build")
}

/// Client for a **bulk file download** — a large, container-compressed artefact
/// streamed to disk rather than a JSON body parsed in memory.
///
/// Shares [`build_client`]'s hardening (the SSRF DNS resolver, the per-hop
/// private-IP redirect guard, `connect_timeout`, and the 30 s read-inactivity
/// backstop) and differs in exactly two deliberate ways:
///
/// * **A total timeout.** The module fetch paths set none on purpose — the
///   engine bounds them per-module (see the module docstring). A download driven
///   by `hse cells import` / `POST /cells/import` runs outside that engine
///   timeout, so it carries its own ceiling.
/// * **No transparent gzip.** The caller is fetching a `.gz` *container* it
///   decompresses itself. `gzip(true)` decodes only when the server sends
///   `Content-Encoding: gzip`, so enabling it would silently hand the caller
///   already-inflated bytes for such a server and break a downstream
///   `flate2` pass. Off, so the bytes written to disk are exactly the bytes on
///   the wire.
///
/// Exists so that no caller has to hand-roll a `reqwest::Client::builder()` and
/// thereby opt out of the crate's HTTP hardening — the bypass this replaced set
/// only a total timeout and inherited none of the four protections above.
/// Enforced by `tests/architecture.rs::http_client_construction_is_centralised`.
pub fn build_download_client(total_timeout: std::time::Duration) -> reqwest::Client {
    super::ssrf::client_builder()
        .no_gzip()
        .timeout(total_timeout)
        .build()
        // expect justification: identical static-config / rustls-init-only
        // failure mode as `build_client` — `total_timeout` is a plain `Duration`
        // and introduces no fallible build input.
        .expect("reqwest client (rustls backend) failed to build")
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
    super::ssrf::client_builder()
        .default_headers(headers)
        .build()
        // expect justification: identical static-config / rustls-init-only failure
        // mode as `build_client` — the trace header was already validated above
        // (non-conforming ids are skipped, not panicked on), so it introduces no
        // new fallible build input. A failure here is a misbuilt binary, not a
        // runtime condition.
        .expect("reqwest client (rustls backend) failed to build")
}
