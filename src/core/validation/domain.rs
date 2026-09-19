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
    let host = host_of(value);
    host.len() > ".onion".len() && host.ends_with(".onion")
}

/// The HOST of a URL-ish value: scheme, userinfo, port, path, query, fragment
/// and any trailing root dot removed, lowercased. A bare host passes through
/// unchanged, so the same call works on a `Domain` value and a full `Url`.
///
/// Named rather than left inline inside [`is_onion_url`], which is where this
/// logic lived. `core` may not reach into `util::url_util` (the architecture
/// test `core_does_not_import_util_directly` enforces that, and its allow-list
/// is a deliberate, individually-argued one), so the admission gate's
/// homograph check needed a host and `core` already had the parse — unnamed,
/// and usable by exactly one caller. Extracting it gives `core` ONE definition
/// of "the host of this value" instead of a second inline copy written for the
/// second caller (REQ-VALIDATION-001).
///
/// ```
/// use huntsman_search_engine::core::validation::host_of;
///
/// assert_eq!(host_of("https://user@Example.COM:8443/a?b#c"), "example.com");
/// assert_eq!(host_of("example.com."), "example.com");
/// assert_eq!(host_of("  EXAMPLE.com "), "example.com");
/// ```
#[must_use]
pub fn host_of(value: &str) -> String {
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
    host.trim_end_matches('.').to_ascii_lowercase()
}
