//! Entity-invariant validation framework.
//!
//! Centralises the small-but-frequent validation checks that used to
//! live scattered across modules (phone normalisation in
//! `util::address_au`, IP private-range filtering in `oathnet_pro`,
//! local-domain skip in `oathnet_pro`, coordinate bounds in
//! `util::geohash::parse_coords`, address state/postcode plausibility
//! in `util::address_au`). Each validator returns a [`ValidationReport`]
//! so modules can decide whether to accept, downgrade, or drop the
//! candidate entity uniformly.
//!
//! Design properties:
//!
//!  * Pure functions; no I/O, no allocation in the hot path beyond
//!    what the caller provides.
//!  * Fail-explicit: every rejection carries a machine-readable
//!    `reason` plus a human-readable `detail`.
//!  * Validators compose: a caller may run multiple validators and
//!    union the resulting reports.
//!  * Stable: adding a new validator does not change existing
//!    validator signatures, preserving binary compatibility for
//!    downstream modules.

use std::net::IpAddr;

use crate::core::entity::EntityKind;

/// Result of running one or more validators against an entity value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValidationReport {
    /// Whether the value passed every validator the caller ran.
    pub valid: bool,
    /// Machine-readable reason code on failure (empty when `valid`).
    pub reason: &'static str,
    /// Human-readable detail string. May be empty on success.
    pub detail: String,
}

impl ValidationReport {
    pub fn ok() -> Self {
        Self {
            valid: true,
            reason: "",
            detail: String::new(),
        }
    }

    pub fn fail(reason: &'static str, detail: impl Into<String>) -> Self {
        Self {
            valid: false,
            reason,
            detail: detail.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Phone (E.164)
// ---------------------------------------------------------------------------

/// True if `s` is a syntactically valid E.164 number: leading `+`,
/// then 8 to 15 digits, with the country code in the conventional
/// 1-3 digit range. Does NOT verify the number is dial-able; only
/// the format.
pub fn validate_phone_e164(s: &str) -> ValidationReport {
    if !s.starts_with('+') {
        return ValidationReport::fail("e164.missing_plus", "must start with '+'");
    }
    let digits = &s[1..];
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return ValidationReport::fail("e164.non_digit", "non-digit after '+'");
    }
    if !(8..=15).contains(&digits.len()) {
        return ValidationReport::fail(
            "e164.length",
            format!("expected 8..=15 digits, got {}", digits.len()),
        );
    }
    ValidationReport::ok()
}

// ---------------------------------------------------------------------------
// Email (RFC 5322 light)
// ---------------------------------------------------------------------------

/// Light syntactic email check. Enforces: exactly one '@', a non-empty
/// local part shorter than 64 chars, a domain with at least one '.',
/// no consecutive dots, no leading/trailing dot in either part. Does
/// NOT verify MX or mailbox existence.
pub fn validate_email_syntax(s: &str) -> ValidationReport {
    let parts: Vec<&str> = s.split('@').collect();
    if parts.len() != 2 {
        return ValidationReport::fail("email.bad_at_count", "expected exactly one '@'");
    }
    let local = parts[0];
    let domain = parts[1];
    if local.is_empty() || local.len() > 64 {
        return ValidationReport::fail("email.local_length", "local part 1..=64 chars");
    }
    if domain.is_empty() || !domain.contains('.') {
        return ValidationReport::fail("email.domain_shape", "domain must contain '.'");
    }
    if local.starts_with('.') || local.ends_with('.') {
        return ValidationReport::fail("email.local_dot_edge", "leading/trailing '.' in local");
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return ValidationReport::fail("email.domain_dot_edge", "leading/trailing '.' in domain");
    }
    if local.contains("..") || domain.contains("..") {
        return ValidationReport::fail("email.consecutive_dots", "consecutive '.' forbidden");
    }
    ValidationReport::ok()
}

// ---------------------------------------------------------------------------
// Coordinates
// ---------------------------------------------------------------------------

/// Validate that `(lat, lon)` lie inside the Earth's coordinate bounds
/// and are not the Null Island origin (0.0, 0.0) which is almost
/// always a parser failure rather than a real location.
pub fn validate_coordinates(lat: f64, lon: f64) -> ValidationReport {
    if !lat.is_finite() || !lon.is_finite() {
        return ValidationReport::fail("coord.non_finite", "lat or lon is NaN/Inf");
    }
    if !(-90.0..=90.0).contains(&lat) {
        return ValidationReport::fail(
            "coord.lat_oob",
            format!("latitude {lat} outside [-90, 90]"),
        );
    }
    if !(-180.0..=180.0).contains(&lon) {
        return ValidationReport::fail(
            "coord.lon_oob",
            format!("longitude {lon} outside [-180, 180]"),
        );
    }
    if lat == 0.0 && lon == 0.0 {
        return ValidationReport::fail("coord.null_island", "(0.0, 0.0) is null-island");
    }
    ValidationReport::ok()
}

// ---------------------------------------------------------------------------
// IP address routability (centralised from `oathnet_pro::is_private_ip`)
// ---------------------------------------------------------------------------

/// True if `s` parses to a non-routable or otherwise un-queryable IP. Covers
/// RFC1918 private, loopback, link-local, CGN, broadcast, unspecified,
/// multicast, IPv6 ULA — **plus** the reserved/unrealistic ranges that leak in
/// from scraped pages and tutorials and would only waste expansion budget:
/// RFC5737 documentation (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`),
/// RFC2544 benchmarking (`198.18.0.0/15`), IETF protocol (`192.0.0.0/24`),
/// "this-host" (`0.0.0.0/8`), reserved/future (`240.0.0.0/4`), and IPv6
/// documentation (`2001:db8::/32`). No external OSINT source can resolve any of
/// these, so the engine must never pivot on them.
pub fn is_non_routable_ip(s: &str) -> bool {
    let Ok(addr) = s.parse::<IpAddr>() else {
        return false;
    };
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                || (o[0] == 100 && (o[1] & 0xC0) == 64)              // CGN 100.64/10
                || o[0] == 0                                          // 0.0.0.0/8 this-host
                || o[0] >= 240                                        // 240/4 reserved/future
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)           // 192.0.0.0/24 IETF protocol
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)           // 192.0.2.0/24 TEST-NET-1
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)        // 198.51.100.0/24 TEST-NET-2
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)         // 203.0.113.0/24 TEST-NET-3
                || (o[0] == 198 && (o[1] & 0xFE) == 18) // 198.18.0.0/15 benchmarking
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (o[0] == 0xfc || o[0] == 0xfd)                    // ULA fc00::/7
                || (o[0] == 0xfe && (o[1] & 0xC0) == 0x80)           // link-local fe80::/10
                || (o[0] == 0x20 && o[1] == 0x01 && o[2] == 0x0d && o[3] == 0xb8) // 2001:db8::/32 doc
        }
    }
}

/// True if `s` parses to an IP that can **never** be a real host *anywhere*:
/// RFC5737 documentation (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`),
/// RFC2544 benchmarking (`198.18.0.0/15`), IETF-protocol (`192.0.0.0/24`),
/// "this-host" (`0.0.0.0/8`), reserved/future (`240.0.0.0/4`), and IPv6
/// documentation (`2001:db8::/32`).
///
/// Unlike [`is_non_routable_ip`] this **deliberately excludes** RFC1918 private,
/// loopback, link-local, CGN and multicast — addresses that local sensors
/// (`local_net`, `device_sensors`, `wifi_intel`) legitimately surface on-device.
/// It is therefore safe to drop matches at *entity admission* without losing any
/// real local-network finding; only addresses scraped from documentation/examples
/// (e.g. `192.0.2.1` lifted off a tutorial page) are rejected.
pub fn is_bogus_ip(s: &str) -> bool {
    let Ok(addr) = s.parse::<IpAddr>() else {
        return false;
    };
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 0                                            // 0.0.0.0/8 this-host
                || o[0] >= 240                                   // 240/4 reserved/future + broadcast
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)       // 192.0.0.0/24 IETF protocol
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)       // 192.0.2.0/24 TEST-NET-1
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)    // 198.51.100.0/24 TEST-NET-2
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)     // 203.0.113.0/24 TEST-NET-3
                || (o[0] == 198 && (o[1] & 0xFE) == 18) // 198.18.0.0/15 benchmarking
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            o[0] == 0x20 && o[1] == 0x01 && o[2] == 0x0d && o[3] == 0xb8 // 2001:db8::/32 doc
        }
    }
}

// ---------------------------------------------------------------------------
// Documentation / placeholder values (RFC 2606 / RFC 6761 + `example.*`)
// ---------------------------------------------------------------------------

/// True if `host` is a reserved/documentation/placeholder domain that can never
/// be a real OSINT target: the RFC 2606/6761 reserved names (via
/// [`is_local_domain`](crate::util::preflight::is_local_domain)) plus the
/// ubiquitous `example.*` documentation domains and the fake `*.tld` placeholder.
///
/// Matched on whole DNS labels after stripping a leading `www.` and trailing
/// dot, so genuine domains that merely *contain* the substring — `exampleshop.com`,
/// `myexample.io`, `testflight.apple.com` — are deliberately NOT rejected.
pub fn is_placeholder_domain(host: &str) -> bool {
    let owned = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let h = owned.strip_prefix("www.").unwrap_or(owned.as_str());
    if h.is_empty() {
        return true;
    }
    // RFC 2606/6761 reserved TLDs + the localhost/.local/.test/.invalid family.
    if crate::util::preflight::is_local_domain(h) {
        return true;
    }
    // Any whole label literally "example": example.com/.org/.net, foo.example.co.uk…
    if h.split('.').any(|l| l == "example") {
        return true;
    }
    // Fake `*.tld` placeholder + a curated set of pure doc placeholders.
    let tld = h.rsplit('.').next().unwrap_or("");
    tld == "tld"
        || matches!(
            h,
            "domain.tld" | "yourdomain.com" | "yourdomain.tld" | "mydomain.com"
        )
}

/// Host of a URL value is a [`is_placeholder_domain`]. Cheap hand-parse (no `url`
/// crate dependency here): strips scheme, userinfo, port, and path/query/frag.
fn url_host_is_placeholder(u: &str) -> bool {
    let after_scheme = u.split_once("://").map(|(_, r)| r).unwrap_or(u);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    !host.is_empty() && is_placeholder_domain(host)
}

/// Canonical placeholder person names (synthetic "John Doe"-style values that
/// breach/permutation modules surface). Kept tight to avoid rejecting real
/// people who happen to share a common name.
fn is_placeholder_person(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    matches!(
        n.as_str(),
        "john doe"
            | "jane doe"
            | "john q. public"
            | "john q public"
            | "test user"
            | "first last"
            | "firstname lastname"
            | "first name last name"
            | "full name"
            | "your name"
            | "name surname"
    )
}

/// True if a discovered entity is a documentation/placeholder artifact that
/// should never enter the graph — `example.com`, `jordan@example.com`,
/// `http://example.com`, the `example` username, `John Doe`, … Enforced at the
/// engine's admission gate alongside [`is_bogus_ip`] so it covers every module.
///
/// Exception (the operator's rule): kinds whose VALUE is inherently unique —
/// passwords, API keys, raw credentials — are NEVER rejected, even if the value
/// happens to contain the word "example", because the secret itself is the
/// signal and is overwhelmingly unlikely to be a placeholder.
pub fn is_placeholder_entity(kind: &EntityKind, value: &str) -> bool {
    match kind {
        // Inherently-unique secrets: always kept.
        EntityKind::Password | EntityKind::ApiKey | EntityKind::Credential => false,
        EntityKind::Domain => is_placeholder_domain(value),
        EntityKind::Email => value
            .rsplit_once('@')
            .is_some_and(|(_, host)| is_placeholder_domain(host)),
        EntityKind::Url => url_host_is_placeholder(value),
        EntityKind::Username => crate::util::preflight::is_placeholder_username(value),
        EntityKind::Person => is_placeholder_person(value),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Domain shape
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Composite runner
// ---------------------------------------------------------------------------

/// Apply every validator that is relevant to the given entity-kind
/// string and return the first failure (or `ok` if all pass). The
/// kind set is intentionally narrow; callers with unusual kinds
/// should call the individual validators.
pub fn validate_for_kind(kind: &str, value: &str) -> ValidationReport {
    match kind {
        "phone" => validate_phone_e164(value),
        "email" => validate_email_syntax(value),
        "domain" => validate_domain_shape(value),
        "coordinates" => {
            // Accept "lat,lon" only.
            match value.split_once(',') {
                Some((a, b)) => {
                    let lat: f64 = a.trim().parse().unwrap_or(f64::NAN);
                    let lon: f64 = b.trim().parse().unwrap_or(f64::NAN);
                    validate_coordinates(lat, lon)
                }
                None => ValidationReport::fail("coord.shape", "expected 'lat,lon'"),
            }
        }
        _ => ValidationReport::ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_domain_catches_reserved_and_example() {
        for bad in [
            "example.com",
            "example.org",
            "example.net",
            "EXAMPLE.COM",
            "www.example.com",
            "foo.example.co.uk",
            "sub.example.io",
            "host.test",
            "thing.invalid",
            "x.localhost",
            "anything.example",
            "yourdomain.com",
            "domain.tld",
            "host.tld",
        ] {
            assert!(is_placeholder_domain(bad), "{bad} must be a placeholder");
        }
        // Real domains that merely CONTAIN the substring are NOT rejected.
        for ok in [
            "cloudflare.com",
            "exampleshop.com",
            "myexample.io",
            "testflight.apple.com",
            "github.com",
            "wikipedia.org",
        ] {
            assert!(!is_placeholder_domain(ok), "{ok} is a real domain");
        }
    }

    #[test]
    fn placeholder_entity_filters_artifacts_but_keeps_secrets() {
        use EntityKind::*;
        assert!(is_placeholder_entity(&Domain, "example.com"));
        assert!(is_placeholder_entity(&Email, "jordan@example.com"));
        assert!(is_placeholder_entity(&Url, "https://example.com/login"));
        assert!(is_placeholder_entity(
            &Url,
            "http://user:pw@example.org:8080/x"
        ));
        assert!(is_placeholder_entity(&Username, "example"));
        assert!(is_placeholder_entity(&Person, "John Doe"));
        // Real values pass through.
        assert!(!is_placeholder_entity(&Domain, "cloudflare.com"));
        assert!(!is_placeholder_entity(&Email, "matthewdiegmann@gmail.com"));
        assert!(!is_placeholder_entity(&Person, "Matthew Diegmann"));
        // Inherently-unique secrets are NEVER filtered, even containing "example".
        assert!(!is_placeholder_entity(&Password, "example.com"));
        assert!(!is_placeholder_entity(
            &ApiKey,
            "sk-example-9f8a7b6c5d4e3f2a1"
        ));
        assert!(!is_placeholder_entity(&Credential, "example:hunter2"));
    }

    #[test]
    fn phone_e164_accepts_valid() {
        assert!(validate_phone_e164("+61410959140").valid);
        assert!(validate_phone_e164("+14155552671").valid);
        assert!(validate_phone_e164("+611300846637").valid);
    }

    #[test]
    fn phone_e164_rejects_invalid() {
        assert_eq!(
            validate_phone_e164("0410959140").reason,
            "e164.missing_plus"
        );
        assert_eq!(validate_phone_e164("+abc").reason, "e164.non_digit");
        assert_eq!(validate_phone_e164("+1234").reason, "e164.length");
        assert_eq!(
            validate_phone_e164("+1234567890123456").reason,
            "e164.length"
        );
    }

    #[test]
    fn email_syntax_accepts_valid() {
        assert!(validate_email_syntax("haigen@goatlegal.com.au").valid);
        assert!(validate_email_syntax("a.b+c@example.co.uk").valid);
    }

    #[test]
    fn email_syntax_rejects_invalid() {
        assert_eq!(validate_email_syntax("noat").reason, "email.bad_at_count");
        assert_eq!(validate_email_syntax("a@b").reason, "email.domain_shape");
        assert_eq!(
            validate_email_syntax(".a@b.com").reason,
            "email.local_dot_edge"
        );
        assert_eq!(
            validate_email_syntax("a..b@c.com").reason,
            "email.consecutive_dots"
        );
    }

    #[test]
    fn coordinates_accept_valid() {
        assert!(validate_coordinates(-27.4712679, 153.0283242).valid); // Brisbane CBD
        assert!(validate_coordinates(90.0, 180.0).valid); // edge ok
        assert!(validate_coordinates(-90.0, -180.0).valid);
    }

    #[test]
    fn coordinates_reject_invalid() {
        assert_eq!(validate_coordinates(91.0, 0.0).reason, "coord.lat_oob");
        assert_eq!(validate_coordinates(0.0, 181.0).reason, "coord.lon_oob");
        assert_eq!(validate_coordinates(0.0, 0.0).reason, "coord.null_island");
        assert_eq!(
            validate_coordinates(f64::NAN, 0.0).reason,
            "coord.non_finite"
        );
    }

    #[test]
    fn non_routable_ip_classifies_correctly() {
        assert!(is_non_routable_ip("192.168.1.1"));
        assert!(is_non_routable_ip("10.0.0.1"));
        assert!(is_non_routable_ip("127.0.0.1"));
        assert!(is_non_routable_ip("169.254.1.1"));
        assert!(is_non_routable_ip("100.64.0.1")); // CGN
        assert!(is_non_routable_ip("224.0.0.251")); // mDNS multicast
        assert!(is_non_routable_ip("::1"));
        assert!(is_non_routable_ip("fe80::1"));
        assert!(is_non_routable_ip("fd00::1")); // ULA
        assert!(!is_non_routable_ip("8.8.8.8"));
        assert!(!is_non_routable_ip("2606:4700:4700::1111"));
        assert!(!is_non_routable_ip("not-an-ip"));
    }

    #[test]
    fn bogus_ip_rejects_documentation_but_keeps_private_and_real() {
        // Never-real ranges → bogus.
        for ip in [
            "192.0.2.1",
            "198.51.100.5",
            "203.0.113.9",
            "192.0.0.8",
            "198.18.0.1",
            "0.1.2.3",
            "240.0.0.1",
            "255.255.255.255",
            "2001:db8::1",
        ] {
            assert!(is_bogus_ip(ip), "{ip} should be bogus");
        }
        // Private / loopback / link-local / real → kept (NOT bogus), because
        // local sensors legitimately surface these and real hosts use them.
        for ip in [
            "192.168.1.5",
            "10.0.0.1",
            "172.16.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "not-an-ip",
        ] {
            assert!(!is_bogus_ip(ip), "{ip} should NOT be bogus");
        }
    }

    #[test]
    fn non_routable_ip_catches_reserved_and_documentation_ranges() {
        // RFC5737 documentation (the canonical "example IP" that leaks in
        // from scraped tutorial pages and used to get expanded).
        assert!(is_non_routable_ip("192.0.2.1")); // TEST-NET-1
        assert!(is_non_routable_ip("198.51.100.7")); // TEST-NET-2
        assert!(is_non_routable_ip("203.0.113.9")); // TEST-NET-3
        assert!(is_non_routable_ip("192.0.0.8")); // IETF protocol assignments
        assert!(is_non_routable_ip("198.18.0.1")); // RFC2544 benchmarking
        assert!(is_non_routable_ip("198.19.255.1")); // RFC2544 upper half
        assert!(is_non_routable_ip("0.1.2.3")); // 0.0.0.0/8 this-host
        assert!(is_non_routable_ip("240.0.0.1")); // reserved/future
        assert!(is_non_routable_ip("255.255.255.255")); // broadcast
        assert!(is_non_routable_ip("2001:db8::1")); // IPv6 documentation
        // Real, routable addresses adjacent to the reserved blocks stay valid.
        assert!(!is_non_routable_ip("192.0.3.1"));
        assert!(!is_non_routable_ip("198.20.0.1"));
        assert!(!is_non_routable_ip("203.0.114.1"));
        assert!(!is_non_routable_ip("1.1.1.1"));
    }

    #[test]
    fn domain_shape_accepts_valid() {
        assert!(validate_domain_shape("goatlegal.com.au").valid);
        assert!(validate_domain_shape("a.b").valid);
        assert!(validate_domain_shape("example.com.").valid); // trailing dot stripped
    }

    #[test]
    fn domain_shape_rejects_invalid() {
        assert_eq!(validate_domain_shape("").reason, "domain.length");
        assert_eq!(validate_domain_shape("nodot").reason, "domain.no_dot");
        assert_eq!(validate_domain_shape("bad_label.com").reason, "domain.ldh");
        assert_eq!(
            validate_domain_shape("-bad.com").reason,
            "domain.hyphen_edge"
        );
        assert_eq!(validate_domain_shape("192.168.1.1").reason, "domain.is_ip");
    }

    #[test]
    fn validate_for_kind_dispatches() {
        assert!(validate_for_kind("phone", "+61410959140").valid);
        assert!(validate_for_kind("email", "x@y.com").valid);
        assert!(validate_for_kind("domain", "goatlegal.com.au").valid);
        assert!(validate_for_kind("coordinates", "-27.47,153.03").valid);
        assert!(!validate_for_kind("coordinates", "junk").valid);
        // Unknown kind passes through OK (validators are opt-in)
        assert!(validate_for_kind("anything-else", "value").valid);
    }
}
