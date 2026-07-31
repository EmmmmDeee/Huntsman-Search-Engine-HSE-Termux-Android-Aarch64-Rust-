use super::*;
use crate::core::entity::EntityKind;

#[test]
fn phone_e164_rejects_short_numbers_and_accepts_real_ones() {
    // 8-digit and 9-digit strings — web-scrape noise, must be rejected.
    assert!(!validate_phone_e164("+21002112").valid); // 8 digits
    assert!(!validate_phone_e164("+219421994").valid); // 9 digits
    // 10-digit minimum (Niue +683 XXXXXXX, Australia +61 XXXXXXXXX, etc.).
    assert!(validate_phone_e164("+6569504420").valid); // 10 digits, Singapore
    assert!(validate_phone_e164("+61412345678").valid); // 11 digits, AU mobile
    assert!(validate_phone_e164("+14155552671").valid); // 11 digits, US
    // Leading zero in country code — always invalid.
    assert!(!validate_phone_e164("+0612345678").valid);
    // Missing plus — invalid.
    assert!(!validate_phone_e164("61412345678").valid);
    // 16 digits — too long.
    assert!(!validate_phone_e164("+1234567890123456").valid);
}

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
    // A PO box / locked bag is a mail drop, not a dwelling — rejected in every
    // punctuation variant so it never clusters a false household (AU-049/051).
    assert!(!is_specific_residence("PO Box 123, Sydney NSW 2000"));
    assert!(!is_specific_residence("P.O. Box 4567, Melbourne"));
    assert!(!is_specific_residence("po box 99 brisbane")); // normalised form
    assert!(!is_specific_residence("Locked Bag 12, Parramatta NSW"));
    // A real street whose suburb merely contains "box" (Box Hill) is unaffected.
    assert!(is_specific_residence("42 Station St, Box Hill VIC 3128"));
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

    // A BARE ISO country code is a COUNTRY, not an address. Breach `country`
    // fields emit it, and the shared 2-letter code corroborates across hundreds
    // of unrelated co-occurrence rows into a VERIFIED phantom address (a live
    // scan produced "US" at corroboration=106 for a QLD subject). Reject it; a
    // real locality that merely names a country is still kept.
    assert!(is_fragment_value(&K::Address, "AU"));
    assert!(is_fragment_value(&K::Address, "US"));
    assert!(is_fragment_value(&K::Address, "br")); // case-insensitive
    // Codes ABSENT from the country display-name table must reject too — the table
    // names only ~54 countries, but breach corpora carry every ISO alpha-2 code.
    // Gating on the table left these reproducing the "US" phantom unblocked.
    for code in [
        "PK", "BD", "VE", "IR", "BG", "HR", "LT", "LV", "EE", "LK", "QA", "wa",
    ] {
        assert!(
            is_fragment_value(&K::Address, code),
            "bare 2-letter code {code} must be a fragment, not a phantom address"
        );
    }
    assert!(!is_fragment_value(&K::Address, "Sydney, Australia"));
    assert!(!is_fragment_value(&K::Address, "Perth, WA")); // locality present, kept

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
    // Test / redaction / placeholder local-parts an admission gate must drop (these
    // are not caught by the role-mailbox gate, which `is_placeholder_entity` does
    // not consult). The separator-stripped form matches too (`re.dacted`).
    assert!(is_placeholder_entity(&Email, "test@gmail.com"));
    assert!(is_placeholder_entity(&Email, "redacted@gmail.com"));
    assert!(is_placeholder_entity(&Email, "placeholder@gmail.com"));
    assert!(is_placeholder_entity(&Username, "redacted"));
    assert!(is_placeholder_entity(&Username, "placeholder"));
    // Real values pass through — including real mailboxes that merely START WITH or
    // CONTAIN a template-ish token (exact match only).
    assert!(!is_placeholder_entity(&Domain, "cloudflare.com"));
    assert!(!is_placeholder_entity(&Email, "jordanavery@gmail.com"));
    assert!(!is_placeholder_entity(&Email, "matt@gmail.com"));
    assert!(!is_placeholder_entity(&Email, "john.smith@gmail.com"));
    assert!(!is_placeholder_entity(&Email, "firstnations@gmail.com"));
    assert!(!is_placeholder_entity(&Email, "tester@gmail.com")); // contains "test", not equal
    assert!(!is_placeholder_entity(&Username, "redactedtruth")); // contains "redacted"
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
fn username_derived_name_catches_doubled_and_slug_tokens_not_real_names() {
    // The exact previously-observed live case: a breach DB storing
    // `full_name = "{username} {username}"` when no real name is available.
    assert!(is_username_derived_name("rhino-ryno23 rhino-ryno23"));
    // Case-insensitive doubled-token match.
    assert!(is_username_derived_name("Rhino-Ryno23 rhino-ryno23"));
    // A lone hyphen+digit slug token (no second token needed).
    assert!(is_username_derived_name("rhino-ryno23"));
    // Real names must never trip this: a hyphenated surname carries NO digit,
    // and two different real given+family names are neither doubled nor slugs.
    assert!(!is_username_derived_name("Smith-Jones"));
    assert!(!is_username_derived_name("Jordan Avery"));
    assert!(!is_username_derived_name("Mary Smith-Jones"));
    assert!(!is_username_derived_name("John Doe")); // caught by is_placeholder_person instead
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
fn role_mailbox_flags_infrastructure_desks() {
    // Generic registrar / DNS / CDN desks — on an identity scan these are never
    // the subject, so the engine drops them at admission.
    for e in [
        "abuse@cloudflare.com",
        "dns@jomax.net",
        "hostmaster@example.com",
        "postmaster@example.org",
        "noreply@sendgrid.net",
        "registry@verisign.com",
        "soa@example.net",
    ] {
        assert!(is_role_mailbox(e), "{e} should be a role mailbox");
    }
    // Separator and plus-tag variants normalise to the same base.
    assert!(is_role_mailbox("no-reply@x.com"));
    assert!(is_role_mailbox("no_reply@x.com"));
    assert!(is_role_mailbox("abuse+spam@x.com"));
}

#[test]
fn role_mailbox_keeps_personal_addresses() {
    // A person's address — including freemail — must NOT be flagged: it is the
    // prime finding of an identity scan, never noise.
    for e in [
        "haigen@gmail.com",
        "haigen.bamford@goatlegal.com.au",
        "jsmith2000@outlook.com",
        "becky@example.com",
        "not-an-email",
    ] {
        assert!(!is_role_mailbox(e), "{e} must not be a role mailbox");
    }
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
fn untrusted_ip_geo_reason_gates_cdn_edges_only() {
    // CDN/anycast edge → its geo is the datacenter, not the subject.
    assert_eq!(
        untrusted_ip_geo_reason("104.16.0.1"),
        Some("cdn/anycast edge")
    );
    assert_eq!(
        untrusted_ip_geo_reason("151.101.1.1"),
        Some("cdn/anycast edge")
    );
    // A real public host's geo is trusted (no reason to suppress).
    assert_eq!(untrusted_ip_geo_reason("8.8.8.8"), None);
    // Garbage parses to no reason rather than panicking.
    assert_eq!(untrusted_ip_geo_reason("not-an-ip"), None);
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
}

#[test]
fn cdn_edge_ip_catches_ipv6_anycast() {
    // A Cloudflare-fronted domain commonly has AAAA records too; the v6 edge must
    // gate exactly like the v4 edge (else its datacenter geo leaks as the
    // subject's, and the address gets pivoted on).
    assert!(is_cdn_edge_ip("2606:4700::1")); // Cloudflare 2606:4700::/32
    assert!(is_cdn_edge_ip("2606:4700:4700::1111")); // CF (1.1.1.1's v6 sibling block)
    assert!(is_cdn_edge_ip("2400:cb00::1")); // Cloudflare 2400:cb00::/32
    assert!(is_cdn_edge_ip("2803:f800::1")); // Cloudflare 2803:f800::/32
    assert!(is_cdn_edge_ip("2405:b500::1")); // Cloudflare 2405:b500::/32
    assert!(is_cdn_edge_ip("2405:8100::1")); // Cloudflare 2405:8100::/32
    assert!(is_cdn_edge_ip("2c0f:f248::1")); // Cloudflare 2c0f:f248::/32
    assert!(is_cdn_edge_ip("2a06:98c0::1")); // Cloudflare 2a06:98c0::/29 (low edge)
    assert!(is_cdn_edge_ip("2a06:98c7:ffff::1")); // …/29 (top of range)
    assert!(is_cdn_edge_ip("2a04:4e42::1")); // Fastly 2a04:4e42::/32
    // Untrusted-geo gate consumes the same predicate, so it follows for v6.
    assert_eq!(
        untrusted_ip_geo_reason("2606:4700::1"),
        Some("cdn/anycast edge")
    );
    // Just outside the /29 (2a06:98c8::) and unrelated public v6 are NOT gated.
    assert!(!is_cdn_edge_ip("2a06:98c8::1")); // one block past the /29
    assert!(!is_cdn_edge_ip("2001:4860:4860::8888")); // Google DNS v6
    assert!(!is_cdn_edge_ip("2a00:1450:4001::1")); // Google v6
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

mod confusable_tests {
    use super::super::{
        is_confusable_mixed_script, is_whois_privacy_placeholder, looks_like_gibberish_name,
        skeleton, strip_invisible,
    };
    use std::borrow::Cow;

    #[test]
    fn strip_invisible_removes_zero_width_and_borrows_clean() {
        // A zero-width joiner padded into a value is removed (so the two spellings
        // of "john" collapse to one and finally deduplicate).
        assert_eq!(strip_invisible("jo\u{200D}hn"), "john");
        // Already-clean input is returned borrowed — no allocation on the hot path.
        let clean = strip_invisible("john");
        assert!(matches!(clean, Cow::Borrowed("john")));
        // A bidi override (the "Trojan Source" vector) is stripped.
        assert_eq!(strip_invisible("a\u{202E}b"), "ab");
        // Soft hyphen, word joiner and BOM all go too.
        assert_eq!(strip_invisible("ab\u{00AD}cd\u{2060}ef\u{FEFF}"), "abcdef");
    }

    #[test]
    fn homograph_detection_is_case_insensitive() {
        // The confusable table is written in lowercase, but `skeleton_char` runs
        // BEFORE `to_lowercase`, so an UPPERCASE Cyrillic lookalike never met the
        // table: `PАYPAL.com` (U+0410 CYRILLIC CAPITAL LETTER A) folded to itself,
        // then lowercased to Cyrillic `а` — never ASCII `a`. A spoof typed in
        // capitals therefore slipped both the skeleton collapse and the
        // mixed-script gate, and `Target::validate` scanned it as a legitimate
        // distinct target. Uppercase is if anything the more natural way to write
        // a spoofed brand.
        //
        // U+0410 is CYRILLIC CAPITAL A; the rest of the string is ASCII.
        let upper_spoof = "P\u{0410}YPAL.com";
        assert_eq!(
            skeleton(upper_spoof),
            "paypal.com",
            "an uppercase Cyrillic lookalike must collapse to the same skeleton \
             as its ASCII twin"
        );
        assert!(
            is_confusable_mixed_script(upper_spoof),
            "an uppercase Cyrillic lookalike mixed with ASCII is the same \
             homograph spoof as the lowercase form"
        );

        // Mixed case, Greek capitals (U+039F CYRILLIC/GREEK CAPITAL O is Greek
        // Omicron; U+0421 is CYRILLIC CAPITAL ES).
        assert_eq!(skeleton("G\u{039F}\u{0421}gle"), "gocgle");
        assert!(is_confusable_mixed_script("G\u{039F}\u{0421}gle"));

        // Control: a genuine all-ASCII uppercase value is untouched and clean.
        assert_eq!(skeleton("PAYPAL.com"), "paypal.com");
        assert!(!is_confusable_mixed_script("PAYPAL.com"));
    }

    #[test]
    fn skeleton_folds_cyrillic_homograph_to_ascii() {
        // The Cyrillic-`а` paypal collapses to the ASCII skeleton.
        assert_eq!(skeleton("p\u{0430}ypal.com"), "paypal.com");
        // Clean ASCII is unchanged (modulo lowercasing).
        assert_eq!(skeleton("PayPal.com"), "paypal.com");
        // Full-width ASCII folds to plain ASCII.
        assert_eq!(skeleton("\u{FF41}\u{FF42}\u{FF43}"), "abc");
    }

    #[test]
    fn mixed_script_flags_only_the_deceptive_mix() {
        // Cyrillic-`а` mixed with ASCII letters — flagged.
        assert!(is_confusable_mixed_script("p\u{0430}ypal.com"));
        // Pure ASCII — not flagged.
        assert!(!is_confusable_mixed_script("paypal.com"));
        // A legitimate all-Cyrillic string (no ASCII Latin letters) — not flagged.
        assert!(!is_confusable_mixed_script(
            "\u{043F}\u{0440}\u{0438}\u{0432}\u{0435}\u{0442}"
        ));
    }

    #[test]
    fn gibberish_name_flags_random_strings_but_spares_real_names() {
        // L5: the breach-dump junk "names" — caught.
        assert!(looks_like_gibberish_name("ZonJZRJHHWD GvkJCJRWHWD"));
        assert!(looks_like_gibberish_name("GvkJCJRWHWD")); // all-consonant token
        assert!(looks_like_gibberish_name("ZonJZRJHHWD")); // 6+ consonant run

        // Real names — never flagged, including the hard cases:
        assert!(!looks_like_gibberish_name("Cindy Haynes"));
        assert!(!looks_like_gibberish_name("Jordan Avery"));
        assert!(!looks_like_gibberish_name("Müller")); // accented (non-ASCII)
        assert!(!looks_like_gibberish_name("Nguyễn")); // accented vowels
        assert!(!looks_like_gibberish_name("Krzysztof")); // Slavic, max run < 6
        assert!(!looks_like_gibberish_name("Vrkljan")); // 5-consonant run, under bar
        assert!(!looks_like_gibberish_name("Ng")); // short token, ignored
        assert!(!looks_like_gibberish_name("Strzelecki"));
        // A real surname next to a short particle stays safe.
        assert!(!looks_like_gibberish_name("Le Guin"));
    }

    #[test]
    fn whois_privacy_placeholder_catches_brands_but_spares_real_registrants() {
        // The recurring privacy-proxy brand strings that used to slip through the
        // incomplete "privacy"/"redacted" substring lists and get emitted as real
        // Person/Organisation identity — the cross-domain false-merge hazard.
        for p in [
            "Registration Private",
            "Domains By Proxy, LLC",
            "WhoisGuard, Inc.",
            "Contact Privacy Inc. Customer 0123",
            "Perfect Privacy, LLC",
            "Withheld for Privacy ehf",
            "REDACTED FOR PRIVACY",
            "Data Protected",
            "Statutory Masking Enabled",
            "Name Unavailable",
        ] {
            assert!(is_whois_privacy_placeholder(p), "{p} must be a placeholder");
        }
        // Real registrants — including the legitimate "Private Limited" company
        // suffix (India/Singapore) that a bare `private` token match would wrongly
        // drop — must survive.
        for r in [
            "Jordan Avery",
            "Acme Networks Pty Ltd",
            "Infosys Private Limited",
            "Tata Consultancy Services",
            "Privette Holdings", // contains "priv" but not a placeholder marker
        ] {
            assert!(
                !is_whois_privacy_placeholder(r),
                "{r} is a real registrant, must not be flagged"
            );
        }
    }
}
