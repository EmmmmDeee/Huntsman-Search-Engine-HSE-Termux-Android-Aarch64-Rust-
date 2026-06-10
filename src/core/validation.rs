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
    // ITU-T E.164: a country code is 1-3 digits and never begins with 0, so the
    // first digit after the `+` is 1-9. (`+0…` is what the loose digit-only check
    // used to wave through despite the documented country-code rule.)
    if digits.starts_with('0') {
        return ValidationReport::fail("e164.cc_leading_zero", "country code cannot start with 0");
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

/// The "can never be a real host *anywhere*" ranges shared by [`is_bogus_ip`]
/// and [`is_non_routable_ip`]: RFC5737 documentation (`192.0.2.0/24`,
/// `198.51.100.0/24`, `203.0.113.0/24`), RFC2544 benchmarking (`198.18.0.0/15`),
/// IETF-protocol (`192.0.0.0/24`), the deprecated 6to4 relay (`192.88.99.0/24`,
/// RFC 7526), this-host (`0.0.0.0/8`), reserved/future (`240.0.0.0/4`, which
/// also covers the v4 broadcast), IPv6 documentation (`2001:db8::/32` plus the
/// RFC 9637 `3fff::/20` allocation), and IPv6 benchmarking (`2001:2::/48`).
/// IPv4-mapped IPv6 spellings (`::ffff:a.b.c.d`) classify as their v4 address.
///
/// Single source of truth for the documentation/reserved set so the two callers
/// can never drift on which ranges count — a new RFC reservation is added here
/// once and both `is_bogus_ip` and `is_non_routable_ip` pick it up.
fn is_documentation_or_reserved(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 0                                            // 0.0.0.0/8 this-host
                || o[0] >= 240                                   // 240/4 reserved/future + broadcast
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)       // 192.0.0.0/24 IETF protocol
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)       // 192.0.2.0/24 TEST-NET-1
                || (o[0] == 192 && o[1] == 88 && o[2] == 99)     // 192.88.99.0/24 6to4 relay (deprecated, RFC 7526)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)    // 198.51.100.0/24 TEST-NET-2
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)     // 203.0.113.0/24 TEST-NET-3
                || (o[0] == 198 && (o[1] & 0xFE) == 18) // 198.18.0.0/15 benchmarking
        }
        IpAddr::V6(v6) => {
            // An IPv4-mapped spelling (::ffff:192.0.2.1) is the SAME address as
            // its v4 form and must classify identically — otherwise the v6
            // spelling of a documentation IP walks straight through the gate.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_documentation_or_reserved(&IpAddr::V4(v4));
            }
            let o = v6.octets();
            (o[0] == 0x20 && o[1] == 0x01 && o[2] == 0x0d && o[3] == 0xb8) // 2001:db8::/32 doc
                || (o[0] == 0x3f && o[1] == 0xff && (o[2] & 0xF0) == 0)    // 3fff::/20 doc (RFC 9637)
                || (o[0] == 0x20 && o[1] == 0x01 && o[2] == 0 && o[3] == 2
                    && o[4] == 0 && o[5] == 0) // 2001:2::/48 benchmarking (RFC 5180)
        }
    }
}

/// True if `s` parses to a non-routable or otherwise un-queryable IP. Covers
/// RFC1918 private, loopback, link-local, CGN, broadcast, unspecified,
/// multicast, IPv6 ULA — **plus** every documentation/reserved range in
/// [`is_documentation_or_reserved`] (RFC5737 TEST-NETs, RFC2544 benchmarking,
/// IETF protocol, this-host, reserved/future, IPv6 documentation). No external
/// OSINT source can resolve any of these, so the engine must never pivot on
/// them.
pub fn is_non_routable_ip(s: &str) -> bool {
    let Ok(addr) = s.parse::<IpAddr>() else {
        return false;
    };
    // Unmap an IPv4-mapped spelling (::ffff:192.168.1.1) so it classifies
    // exactly like its v4 form — the v6 branch below has no private/CGN logic,
    // so the mapped spelling of a private address would otherwise pass.
    let addr = match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, IpAddr::V4),
        v4 => v4,
    };
    // Documentation/reserved ranges (shared with is_bogus_ip) PLUS the private /
    // local addresses that a non-routable check additionally rejects.
    if is_documentation_or_reserved(&addr) {
        return true;
    }
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                || (o[0] == 100 && (o[1] & 0xC0) == 64) // CGN 100.64/10
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (o[0] == 0xfc || o[0] == 0xfd)         // ULA fc00::/7
                || (o[0] == 0xfe && (o[1] & 0xC0) == 0x80) // link-local fe80::/10
        }
    }
}

/// True if `s` is an IPv4 address inside a major CDN's anycast edge range
/// (Cloudflare's published ranges + Fastly's primary block).
///
/// A CDN edge IP fronts thousands of unrelated sites, so a reverse-IP /
/// co-hosting lookup on it returns a flood of co-tenant strangers (a real
/// person-scan pulled 480+ such domains — and then each one's subdomains —
/// through two Cloudflare edges). The engine therefore does not expand a
/// discovered CDN-edge IP as a target: its geo/reputation belong to the CDN, not
/// the subject, and reverse-IP on it is pure noise. This is decided by IP RANGE,
/// not by a `cdn`/`cloudflare` tag, so it holds BEFORE any reverse-IP module runs
/// in the same round — no tag-ordering race. IPv6 returns `false` (the reverse-IP
/// modules here are v4-only and the v6 CDN space is impractical to enumerate).
///
/// Cloudflare ranges are stable and authoritative (`cloudflare.com/ips-v4`); a
/// stray IP that drifts out of the list simply isn't gated (graceful, never a
/// false skip of a non-CDN host).
pub fn is_cdn_edge_ip(s: &str) -> bool {
    // The v4 ranges below, with an IPv4-mapped v6 spelling (::ffff:104.16.0.1)
    // unmapped first so it gates identically to its v4 form. Native v6
    // addresses return false by design (see above).
    let v4 = match s.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4,
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4,
            None => return false,
        },
        Err(_) => return false,
    };
    let o = v4.octets();
    // Cloudflare (cloudflare.com/ips-v4) keyed on the first octet; Fastly's
    // primary anycast block (151.101.0.0/16) is the lone non-Cloudflare entry.
    match o[0] {
        104 => (o[1] & 0xF8) == 16 || (o[1] & 0xFC) == 24, // 104.16/13 + 104.24/14
        172 => (o[1] & 0xF8) == 64,                        // 172.64.0.0/13
        162 => (o[1] & 0xFE) == 158,                       // 162.158.0.0/15
        173 => o[1] == 245 && (o[2] & 0xF0) == 48,         // 173.245.48.0/20
        141 => o[1] == 101 && (o[2] & 0xC0) == 64,         // 141.101.64.0/18
        108 => o[1] == 162 && (o[2] & 0xC0) == 192,        // 108.162.192.0/18
        190 => o[1] == 93 && (o[2] & 0xF0) == 240,         // 190.93.240.0/20
        188 => o[1] == 114 && (o[2] & 0xF0) == 96,         // 188.114.96.0/20
        197 => o[1] == 234 && (o[2] & 0xFC) == 240,        // 197.234.240.0/22
        198 => o[1] == 41 && (o[2] & 0x80) == 128,         // 198.41.128.0/17
        131 => o[1] == 0 && (o[2] & 0xFC) == 72,           // 131.0.72.0/22
        103 => {
            (o[1] == 21 && (o[2] & 0xFC) == 244)           // 103.21.244.0/22
                || (o[1] == 22 && (o[2] & 0xFC) == 200)    // 103.22.200.0/22
                || (o[1] == 31 && (o[2] & 0xFC) == 4) // 103.31.4.0/22
        }
        151 => o[1] == 101, // Fastly 151.101.0.0/16
        _ => false,
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
    // Exactly the documentation/reserved set — no private/loopback/local ranges,
    // which on-device sensors legitimately surface (see the doc comment above).
    s.parse::<IpAddr>()
        .map(|addr| is_documentation_or_reserved(&addr))
        .unwrap_or(false)
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

/// Canonical documentation/template email **local-parts** — the `firstname` in
/// `firstname@gmail.com`, the `your.email` in `your.email@domain`, … These are
/// form-field templates and tutorial placeholders scraped from web pages, never
/// a real person's mailbox, yet their host is a real provider (`gmail.com`), so
/// the domain check alone can't catch them. A live `firstname@gmail.com` reached
/// VERIFIED (0.85) before this gate. Deliberately tight — only unambiguous
/// templates, compared both verbatim and separator-stripped (so `first.last`,
/// `first_last` and `firstlast` all match) — so a real handle like `matt` or a
/// real `john.smith` is never rejected.
fn is_placeholder_email_local(local: &str) -> bool {
    let l = local.trim().to_ascii_lowercase();
    let stripped: String = l.chars().filter(char::is_ascii_alphanumeric).collect();
    const TEMPLATE: &[&str] = &[
        "firstname",
        "lastname",
        "firstnamelastname",
        "firstlast",
        "namesurname",
        "yourname",
        "fullname",
        "youremail",
        "emailaddress",
        "yourusername",
        "johndoe",
        "janedoe",
        "example",
        "sample",
    ];
    TEMPLATE.contains(&l.as_str()) || TEMPLATE.contains(&stripped.as_str())
}

/// True if a discovered entity is a documentation/placeholder artifact that
/// should never enter the graph — `example.com`, `jordan@example.com`,
/// `firstname@gmail.com`, `http://example.com`, the `example` username,
/// `John Doe`, … Enforced at the engine's admission gate alongside
/// [`is_bogus_ip`] so it covers every module.
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
        EntityKind::Email => value.rsplit_once('@').is_some_and(|(local, host)| {
            is_placeholder_domain(host) || is_placeholder_email_local(local)
        }),
        EntityKind::Url => url_host_is_placeholder(value),
        EntityKind::Username => crate::util::preflight::is_placeholder_username(value),
        EntityKind::Person => is_placeholder_person(value),
        _ => false,
    }
}

/// True when an address string is specific enough to identify a *residence*
/// rather than a region. Requires a street-number signal (an ASCII digit) and at
/// least three comma/whitespace tokens, so `"123 Main St, Springfield"` qualifies
/// while a bare `"USA"` / `"California"` does not.
///
/// Single-sourced here so the breach importer (which decides whether to promote
/// an `address` field to a first-class `Address` entity) and the household
/// correlation rules (AU-049/051, which cluster co-residents by address) apply
/// the *same* definition. If they diverged, the importer could emit addresses
/// the rules never group, or the rules could expect a specificity the importer
/// never enforced. Accepts either a raw or a normalised address — the
/// comma/whitespace split and the digit/length checks are invariant under the
/// punctuation-stripping the household rule applies first.
pub fn is_specific_residence(s: &str) -> bool {
    let tokens = s
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|t| !t.is_empty())
        .count();
    let has_digit = s.bytes().any(|b| b.is_ascii_digit());
    tokens >= 3 && has_digit && s.trim().len() >= 8
}

/// True when `value` is a truncated / incomplete reference that cannot be
/// verified without reconstruction — the `@gmail`-style fragment the user must
/// never see in results. Centralised here so the engine (which rejects these at
/// admission) and the auditor (which flags any that slip through) judge them
/// identically. Conservative: only the kinds with an unambiguous "complete"
/// shape are checked, and inherently-opaque kinds are never fragments.
pub fn is_fragment_value(kind: &EntityKind, value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return true;
    }
    // A trailing ellipsis or a dangling `@`/`@…prefix` is a truncation artifact
    // for ANY textual kind — except inherently-unique secrets, which may contain
    // arbitrary bytes and must never be dropped.
    if matches!(
        kind,
        EntityKind::Password | EntityKind::ApiKey | EntityKind::Credential
    ) {
        return false;
    }
    if v.ends_with('…') || v.ends_with("...") || v.ends_with('@') {
        return true;
    }
    match kind {
        EntityKind::Email => {
            // Must be local@domain.tld — reject "@gmail", "matthew@", "a@b".
            match v.split_once('@') {
                Some((local, domain)) => {
                    local.is_empty() || !domain.contains('.') || domain.starts_with('.')
                }
                None => true,
            }
        }
        // A label with no dot ("gmail" — the "@gmail" fragment in domain form)
        // or shorter than the shortest real registrable domain ("a.b") is a
        // fragment. A COMPLETE freemail provider domain (gmail.com) is
        // deliberately kept: it is a verifiable host — keeping the subject off
        // it is the expansion gate's job (`is_noncentral_domain`), not
        // admission's.
        EntityKind::Domain => v.len() < 4 || !v.contains('.'),
        // A leading `@` is a real truncation only on non-handle kinds — usernames
        // are normalised to strip a `@handle` prefix, so by the time a Username
        // reaches here a leading `@` would be a genuine fragment.
        EntityKind::Username => v.starts_with('@'),
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
    fn specific_residence_accepts_streets_and_rejects_regions() {
        // Real residences (a street number + locality) — accepted.
        assert!(is_specific_residence("123 Main St, Springfield, IL"));
        assert!(is_specific_residence("388 George Street, Sydney NSW 2000"));
        // Bare regions — rejected (thousands share them).
        assert!(!is_specific_residence("USA"));
        assert!(!is_specific_residence("California"));
        assert!(!is_specific_residence("New York"));
        // No street-number signal, or too short — rejected.
        assert!(!is_specific_residence("Main Street"));
        assert!(!is_specific_residence("12 A"));
        // Invariant under the household rule's punctuation-stripping normalisation.
        assert_eq!(
            is_specific_residence("123 Main St., Apt #4"),
            is_specific_residence("123 main st apt 4")
        );
    }

    #[test]
    fn fragment_value_rejects_truncated_and_keeps_complete() {
        use EntityKind as K;
        // Fragments — must be rejected.
        assert!(is_fragment_value(&K::Email, "@gmail"));
        assert!(is_fragment_value(&K::Email, "matthew@"));
        assert!(is_fragment_value(&K::Email, "a@b")); // no TLD dot
        assert!(is_fragment_value(&K::Email, "x@.com")); // leading-dot domain
        assert!(is_fragment_value(&K::Email, "notanemail"));
        assert!(is_fragment_value(&K::Domain, "gmail")); // no dot
        assert!(is_fragment_value(&K::Domain, "a.b")); // < 4 chars
        assert!(is_fragment_value(&K::Username, "@handle")); // unstripped sigil
        assert!(is_fragment_value(&K::Person, "Matthew Dieg…")); // ellipsis
        assert!(is_fragment_value(&K::Email, "   "));

        // Complete, verifiable values — must be kept.
        assert!(!is_fragment_value(&K::Email, "matthewdiegmann@gmail.com"));
        assert!(!is_fragment_value(&K::Domain, "goatlegal.com.au"));
        assert!(!is_fragment_value(&K::Domain, "x.co"));
        assert!(!is_fragment_value(&K::Username, "matthewdiegmann"));
        assert!(!is_fragment_value(&K::Person, "Matthew Diegmann"));

        // Inherently-unique secrets are never fragments even if oddly shaped.
        assert!(!is_fragment_value(&K::Password, "@p"));
        assert!(!is_fragment_value(&K::ApiKey, "sk-..."));
        assert!(!is_fragment_value(&K::Credential, "user@"));
    }

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
        // Template local-parts on a REAL provider domain (regression: a live
        // scan surfaced `firstname@gmail.com` at VERIFIED 0.85).
        assert!(is_placeholder_entity(&Email, "firstname@gmail.com"));
        assert!(is_placeholder_entity(&Email, "first.last@outlook.com"));
        assert!(is_placeholder_entity(&Email, "your.email@company.com"));
        assert!(is_placeholder_entity(&Email, "john.doe@gmail.com"));
        // Real values pass through — including real mailboxes that merely START
        // with a template-ish token.
        assert!(!is_placeholder_entity(&Domain, "cloudflare.com"));
        assert!(!is_placeholder_entity(&Email, "matthewdiegmann@gmail.com"));
        assert!(!is_placeholder_entity(&Email, "matt@gmail.com"));
        assert!(!is_placeholder_entity(&Email, "john.smith@gmail.com"));
        assert!(!is_placeholder_entity(&Email, "firstnations@gmail.com"));
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
        // Regression: a +1 (NANP) number with only 6 national digits — a scrape
        // artifact a live scan surfaced as a PROBABLE Phone — is too short (7
        // total < 8) and must be rejected. The engine admission gate drops any
        // `+`-prefixed Phone that fails here, codebase-wide.
        assert_eq!(validate_phone_e164("+1240893").reason, "e164.length");
        // ...while the genuine 11-digit numbers the same scan also found stay
        // valid (the gate must keep these).
        assert!(validate_phone_e164("+12069156775").valid);
        assert!(validate_phone_e164("+971555542290").valid);
        assert_eq!(
            validate_phone_e164("+1234567890123456").reason,
            "e164.length"
        );
        // ITU-T E.164: a country code never starts with 0, so `+0…` is invalid
        // even though its length is in range (it used to slip through).
        assert_eq!(
            validate_phone_e164("+0123456789").reason,
            "e164.cc_leading_zero"
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
            "192.88.99.1", // deprecated 6to4 relay (RFC 7526)
            "2001:db8::1",
            "3fff::1",          // IPv6 documentation (RFC 9637)
            "3fff:fff:ffff::1", // top of 3fff::/20
            "2001:2::1",        // benchmarking (RFC 5180)
            "::ffff:192.0.2.1", // v4-mapped spelling of a documentation IP
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
            "3fff:1000::1",       // just past 3fff::/20
            "::ffff:8.8.8.8",     // v4-mapped spelling of a real host
            "::ffff:192.168.1.5", // v4-mapped private — sensors surface these
            "not-an-ip",
        ] {
            assert!(!is_bogus_ip(ip), "{ip} should NOT be bogus");
        }
    }

    /// An IPv4-mapped IPv6 spelling (::ffff:a.b.c.d) is the SAME address as its
    /// v4 form, so every IP classifier must gate both spellings identically —
    /// otherwise the mapped spelling walks through admission/expansion/CDN
    /// gates its v4 form is rejected by.
    #[test]
    fn ipv4_mapped_spellings_classify_like_their_v4_form() {
        // Private/CGN → non-routable (but NOT bogus — sensors surface these).
        assert!(is_non_routable_ip("::ffff:192.168.1.1"));
        assert!(is_non_routable_ip("::ffff:10.0.0.1"));
        assert!(is_non_routable_ip("::ffff:100.64.0.1"));
        // Documentation → non-routable AND bogus.
        assert!(is_non_routable_ip("::ffff:192.0.2.1"));
        // CDN edge → gated like the v4 form.
        assert!(is_cdn_edge_ip("::ffff:104.16.0.1"));
        assert!(is_cdn_edge_ip("::ffff:151.101.1.1"));
        // Mapped spellings of real public hosts stay valid everywhere.
        assert!(!is_non_routable_ip("::ffff:8.8.8.8"));
        assert!(!is_cdn_edge_ip("::ffff:8.8.8.8"));
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
    fn cdn_edge_ip_catches_cloudflare_and_fastly() {
        // The two Cloudflare edges that reverse-IP'd 480+ co-tenant strangers in
        // the real scan that motivated this gate.
        assert!(is_cdn_edge_ip("104.20.37.187")); // 104.16.0.0/13
        assert!(is_cdn_edge_ip("172.66.147.185")); // 172.64.0.0/13
        // Other Cloudflare blocks + Fastly.
        assert!(is_cdn_edge_ip("162.158.0.1")); // 162.158.0.0/15
        assert!(is_cdn_edge_ip("104.24.1.1")); // 104.24.0.0/14
        assert!(is_cdn_edge_ip("151.101.1.1")); // Fastly 151.101.0.0/16
        // Adjacent non-CDN addresses (and DNS resolvers) are NOT gated — only the
        // shared anycast edges are.
        assert!(!is_cdn_edge_ip("104.40.0.1")); // outside 104.16/13 + 104.24/14
        assert!(!is_cdn_edge_ip("172.72.0.1")); // just above 172.64/13
        assert!(!is_cdn_edge_ip("8.8.8.8"));
        assert!(!is_cdn_edge_ip("1.1.1.1")); // CF resolver, not an edge range
        assert!(!is_cdn_edge_ip("not-an-ip"));
        assert!(!is_cdn_edge_ip("2606:4700::1")); // v6 → false by design
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
