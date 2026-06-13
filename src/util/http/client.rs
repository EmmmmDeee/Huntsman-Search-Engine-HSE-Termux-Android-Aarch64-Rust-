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
    super::ssrf::client_builder()
        .default_headers(headers)
        .build()
        .expect("reqwest client build failed")
}
