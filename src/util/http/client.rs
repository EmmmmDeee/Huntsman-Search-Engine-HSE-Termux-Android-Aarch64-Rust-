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

/// Like [`build_client`] but stamps every outbound request with a default
/// `x-huntsman-trace: <trace_id>` header. End-to-end traceability across external
/// calls (item #3 of the operator program): the same id the NDJSON scan logs
/// carry in their span chain now rides on the wire, so an outbound request can be
/// matched to its scan in a proxy's or upstream's access log — closing the loop
/// logs → services → external calls. The id is non-secret (the scan id). A header
/// value must be visible ASCII; a non-conforming id falls back to the plain
/// client rather than panicking, logging a `tracing::warn!` breadcrumb so an
/// operator can see why `x-huntsman-trace` went missing instead of the header
/// vanishing silently.
pub fn build_client_with_trace(trace_id: &str) -> reqwest::Client {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    let mut headers = HeaderMap::new();
    match HeaderValue::from_str(trace_id) {
        Ok(value) => {
            headers.insert(HeaderName::from_static("x-huntsman-trace"), value);
        }
        // A non-ASCII / control-char id can't ride in a header value; fall back to
        // an un-stamped client but leave a breadcrumb so an operator can see why
        // x-huntsman-trace went missing (it's the non-secret scan id, safe to log).
        Err(e) => {
            tracing::warn!(
                error = %e,
                "trace id rejected as a header value; outbound requests will be un-stamped"
            );
        }
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
