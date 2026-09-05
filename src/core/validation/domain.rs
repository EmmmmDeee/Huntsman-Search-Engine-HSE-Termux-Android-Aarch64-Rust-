use std::net::IpAddr;

use super::report::ValidationReport;

/// True when `value` is — or carries as its host — a Tor `.onion` address, the
/// dark-web exposure locations `ahmia` surfaces.
///
/// HSE is an exposure sensor, not an onion client: it records THAT a hidden
/// service mentions a target and must never fetch one — no Tor transport exists
/// on the target platform, and reaching indexed dark-web content is outside the
/// tool's defensive scope. The engine's expansion loop calls this to refuse to
/// pivot on a discovered `.onion` `Url`, so the no-fetch doctrine is enforced
/// structurally rather than trusted to each module (and to each future one).
///
/// Accepts a full URL (`http://<addr>.onion/path`), a bare host
/// (`<addr>.onion`), or a host carrying a port or userinfo; case- and
/// trailing-dot-insensitive. Requires a non-empty label before `.onion` so a
/// degenerate `".onion"` does not match. Pure and total: no panics, no I/O.
///
/// ```
/// use huntsman_search_engine::core::validation::is_onion_url;
///
/// assert!(is_onion_url("http://exampleabcdefghij234567.onion/leak"));
/// assert!(is_onion_url("ExampleABCDEFGHIJ234567.ONION"));      // case-insensitive
/// assert!(is_onion_url("http://user@host.onion:9050/"));       // userinfo + port
/// assert!(!is_onion_url("https://example.com/onion"));          // path, not host
/// assert!(!is_onion_url("notonion.com"));
/// ```
#[must_use]
pub fn is_onion_url(value: &str) -> bool {
    let v = value.trim();
    // Drop a scheme, then take the authority up to the first path/query/fragment
    // delimiter, then drop any userinfo and :port so only the host remains.
    let after_scheme = v.split_once("://").map_or(v, |(_, rest)| rest);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = host_port.split(':').next().unwrap_or(host_port);
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host.len() > ".onion".len() && host.ends_with(".onion")
}

/// Validate a domain has at least one label, contains a '.', uses only
/// LDH characters (letter-digit-hyphen) per label, and is not a pure
/// IP literal. Trailing dot is stripped before validation.
pub fn validate_domain_shape(s: &str) -> ValidationReport {
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty() || s.len() > 253 {
        return ValidationReport::fail("domain.length", "1..=253 chars");
    }
    if !s.contains('.') {
        return ValidationReport::fail("domain.no_dot", "must contain '.'");
    }
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return ValidationReport::fail("domain.label_length", "label 1..=63 chars");
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return ValidationReport::fail("domain.ldh", "non-LDH char in label");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return ValidationReport::fail("domain.hyphen_edge", "leading/trailing '-' in label");
        }
    }
    if s.parse::<IpAddr>().is_ok() {
        return ValidationReport::fail("domain.is_ip", "value parses as IP literal");
    }
    ValidationReport::ok()
}
