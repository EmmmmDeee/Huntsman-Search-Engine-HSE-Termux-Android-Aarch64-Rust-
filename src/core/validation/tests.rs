use super::*;
use crate::core::entity::EntityKind;

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
    assert!(is_fragment_value(&K::Person, "Jordan Ave…")); // ellipsis
    assert!(is_fragment_value(&K::Email, "   "));
    // Address with no alphabetic locality — a breach numeric `city` (a
    // postcode) glued to a street number, e.g. "4125, 327".
    assert!(is_fragment_value(&K::Address, "4125, 327"));
    assert!(is_fragment_value(&K::Address, "4110, 327"));

    // Complete, verifiable values — must be kept.
    assert!(!is_fragment_value(&K::Email, "jordanavery@gmail.com"));
    assert!(!is_fragment_value(&K::Domain, "goatlegal.com.au"));
    assert!(!is_fragment_value(&K::Domain, "x.co"));
    assert!(!is_fragment_value(&K::Username, "jordanavery"));
    assert!(!is_fragment_value(&K::Person, "Jordan Avery"));
    // Genuine addresses (alphabetic locality present) are kept.
    assert!(!is_fragment_value(&K::Address, "Brisbane, QLD"));
    assert!(!is_fragment_value(
        &K::Address,
        "327 Main St, Brisbane QLD 4125"
    ));

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
    assert!(!is_placeholder_entity(&Email, "jordanavery@gmail.com"));
    assert!(!is_placeholder_entity(&Email, "matt@gmail.com"));
    assert!(!is_placeholder_entity(&Email, "john.smith@gmail.com"));
    assert!(!is_placeholder_entity(&Email, "firstnations@gmail.com"));
    assert!(!is_placeholder_entity(&Person, "Jordan Avery"));
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
