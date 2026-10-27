//! The access gates of the HTTP server, in one place: the bearer token, the same-site and
//! host checks that stop cross-site and DNS-rebinding requests, and the constant-time token
//! comparison. Each check is unchanged from the version that lived in `web_server.rs`.

use super::response::json_error;
use super::{
    INSPECT_PATH, INVESTIGATE_PATH, KEYS_PATH, OSINT_CASE_PATH, OSINT_RISK_PATH, ParsedRequest,
    ServeConfig, TRACK_PATH,
};
use crate::scan_api::ScanApi;

/// Only the scan API and the key save change state, so only they take POST, with the file
/// inspection, whose upload is too large for a query string.
pub(super) fn takes_post(path: &str) -> bool {
    ScanApi::handles(path)
        || path == KEYS_PATH
        || path == INSPECT_PATH
        || path == TRACK_PATH
        || path == INVESTIGATE_PATH
        || path == OSINT_CASE_PATH
        || path == OSINT_RISK_PATH
}

/// `none` is a typed URL or bookmark; `same-origin` is this page. Anything else came from another
/// site.
pub(super) fn same_site(sec_fetch_site: Option<&str>) -> bool {
    sec_fetch_site.is_none_or(|site| matches!(site, "same-origin" | "none"))
}

/// The `403` a browser-facing API route answers before anything else, naming the route as `noun`:
/// a fetch another site started, or, when the route `needs_header`, one without the page's
/// `X-Huntsman-Lookup: 1` header, which another origin cannot send without a CORS preflight this
/// server never approves. `None` when the request may go on. Every such route asks this one
/// function, so their guards cannot drift apart.
pub(super) fn page_refusal(
    parsed: &ParsedRequest<'_>,
    noun: &str,
    needs_header: bool,
) -> Option<String> {
    if !same_site(parsed.sec_fetch_site) {
        return Some(json_error(403, &format!("cross-site {noun} refused")));
    }
    (needs_header && !parsed.lookup_header).then(|| {
        json_error(
            403,
            &format!("{noun} needs the X-Huntsman-Lookup: 1 header"),
        )
    })
}

/// Whether the request carries the bearer token this server needs, or the server needs none.
pub(super) fn authorized(parsed: &ParsedRequest<'_>, config: &ServeConfig) -> bool {
    config
        .bearer_token
        .as_deref()
        .is_none_or(|expected| bearer_matches(parsed.authorization, expected))
}

/// The DNS-rebinding guard. A loopback server is reached from a page whose origin is a public name
/// rebound to a loopback address, so the browser sends that public name in `Host`: a loopback
/// server answers only loopback authorities (or an absent `Host`). A non-loopback bind is
/// intentionally public, gated by the bearer token, and its legitimate `Host` is not known here, so
/// the guard passes it.
pub(super) fn host_allowed(parsed: &ParsedRequest<'_>, config: &ServeConfig) -> bool {
    !config.bind.ip().is_loopback() || host_is_allowed_for_loopback(parsed.host)
}

/// Whether a loopback server should answer a request carrying this `Host`.
///
/// A DNS-rebinding attack reaches a loopback bind from a page whose origin is a
/// public name rebound to a loopback address, so the browser sends that public
/// name in `Host`. Accepting only loopback authorities refuses the rebound
/// request while real local clients (which send `localhost`, `127.0.0.1`, or
/// `[::1]`) are unaffected. A missing or empty `Host` is allowed: a browser never
/// omits it, so its absence is not a rebinding vector and a raw client stays
/// answerable.
pub(super) fn host_is_allowed_for_loopback(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return true;
    };
    let host = host.trim();
    if host.is_empty() {
        return true;
    }
    let name = if let Some(rest) = host.strip_prefix('[') {
        // IPv6 literal in brackets: `[::1]` or `[::1]:port`.
        match rest.split_once(']') {
            Some((inner, _)) => inner,
            None => return false,
        }
    } else {
        // `host` or `host:port`; strip only a trailing port.
        host.rsplit_once(':').map_or(host, |(name, _)| name)
    };
    if name.eq_ignore_ascii_case("localhost") {
        return true;
    }
    name.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

pub(super) fn bearer_matches(header: Option<&str>, expected: &str) -> bool {
    let Some(header) = header else {
        return false;
    };
    let mut parts = header.split_whitespace();
    let Some(scheme) = parts.next() else {
        return false;
    };
    let Some(actual) = parts.next() else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("bearer") || parts.next().is_some() {
        return false;
    }
    fixed_time_eq(actual.as_bytes(), expected.as_bytes())
}

pub(super) fn fixed_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}
