use crate::core::module::Module;
use crate::core::scan::{Target, TargetKind};

use super::{
    DnsIntel,
    constants::SUBDOMAINS,
    helpers::{
        VERIFICATION_VENDORS, reverse_ip, soa_rname_to_email, unescape_dns_label,
        verification_vendor,
    },
};

// -- DnsIntel accepts --------------------------------------------------

#[test]
fn accepts_domain() {
    let m = DnsIntel;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
}

#[test]
fn accepts_ip() {
    let m = DnsIntel;
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
}

#[test]
fn rejects_email() {
    let m = DnsIntel;
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y")));
}

// -- DNS resolution tests -------------------------------------------------

#[test]
fn soa_rname_decodes() {
    assert_eq!(
        soa_rname_to_email("hostmaster.example.com"),
        "hostmaster@example.com"
    );
    assert_eq!(
        soa_rname_to_email("admin.sub.example.org"),
        "admin@sub.example.org"
    );
    assert_eq!(soa_rname_to_email(""), "");
    assert_eq!(soa_rname_to_email("notanemail"), "");
}

#[test]
fn soa_admin_role_mailbox_is_gated_as_infrastructure() {
    // The SOA RNAME is the zone's administrative contact, never the subject's
    // PII. A live domain-heavy scan surfaced dozens of these (dns@, abuse@,
    // hostmaster@) identity-clustered as the person — `resolve` now gates the
    // emitted Email through `is_infrastructure_email` (mirroring whois/ripestat/
    // SERP). Verify the SOA-derived address trips that gate for role/provider
    // contacts while a genuine personal admin on a non-infra domain is kept.
    use crate::util::domains::is_infrastructure_email;
    assert!(is_infrastructure_email(&soa_rname_to_email(
        "hostmaster.example.com"
    )));
    assert!(is_infrastructure_email(&soa_rname_to_email(
        "dns.cloudflare.com"
    )));
    assert!(is_infrastructure_email(&soa_rname_to_email(
        "root.subjectsite.com.au"
    )));
    assert!(!is_infrastructure_email(&soa_rname_to_email(
        "alice.personaldomain.org"
    )));
}

#[test]
fn soa_rname_unescapes_dotted_local_part() {
    // A literal dot in the mailbox local part is `\.`-escaped in the RNAME;
    // the split must skip it AND the output must drop the backslash.
    assert_eq!(
        soa_rname_to_email(r"hostmaster\.ops.example.com"),
        "hostmaster.ops@example.com"
    );
    // `\DDD` decimal escape (46 = '.') decodes the same way.
    assert_eq!(
        soa_rname_to_email(r"first\046last.example.org"),
        "first.last@example.org"
    );
}

#[test]
fn unescape_dns_label_handles_literal_and_decimal_escapes() {
    assert_eq!(unescape_dns_label(r"a\.b"), "a.b");
    assert_eq!(unescape_dns_label(r"a\\b"), r"a\b");
    assert_eq!(unescape_dns_label(r"x\046y"), "x.y"); // \046 = '.'
    assert_eq!(unescape_dns_label("plain"), "plain");
    assert_eq!(unescape_dns_label(r"trailing\"), "trailing"); // lone backslash dropped
}

#[test]
fn verification_vendor_maps_known_records_case_insensitively() {
    assert_eq!(
        verification_vendor("google-site-verification=abc123"),
        Some("google")
    );
    assert_eq!(
        verification_vendor("facebook-domain-verification=deadbeef"),
        Some("facebook")
    );
    assert_eq!(
        verification_vendor("atlassian-domain-verification=xyz"),
        Some("atlassian")
    );
    // Microsoft 365's short `MS=` tenant token, matched case-insensitively.
    assert_eq!(verification_vendor("MS=ms12345678"), Some("microsoft"));
    // Not a verification record → None (SPF, a random TXT, empty).
    assert_eq!(verification_vendor("v=spf1 -all"), None);
    assert_eq!(verification_vendor("just some text"), None);
    assert_eq!(verification_vendor(""), None);
}

#[test]
fn verification_vendor_table_is_sound() {
    // Every entry maps a non-empty, lowercase prefix to a non-empty vendor —
    // a sanity guard so a future addition can't break the lookup.
    for (prefix, vendor) in VERIFICATION_VENDORS {
        let prefix: &&str = prefix;
        let vendor: &&str = vendor;
        assert!(!prefix.is_empty() && !vendor.is_empty());
        assert_eq!(
            *vendor,
            vendor.to_lowercase(),
            "vendor tag must be lowercase"
        );
    }

    // Specific-before-generic ORDERING. `verification_vendor` returns the
    // FIRST prefix match in declaration order, so when an earlier prefix is a
    // prefix of a later one mapping to a DIFFERENT vendor, the later entry is
    // shadowed and its records are mis-attributed (the same class the
    // key-prefix table's `pattern_table_is_structurally_sound` guards, and the
    // ordering the `ms=`-goes-last comment maintains only by hand). Move the
    // more-specific prefix above the generic stem to fix.
    let mut violations = Vec::new();
    for (i, (earlier, es)) in VERIFICATION_VENDORS.iter().enumerate() {
        for (offset, (later, ls)) in VERIFICATION_VENDORS[i + 1..].iter().enumerate() {
            if es != ls && later.starts_with(*earlier) {
                let j = i + 1 + offset;
                violations.push(format!(
                    "#{j} ({later} → {ls}) shadowed by earlier #{i} ({earlier} → {es})"
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "verification-vendor table has shadowed entries — move the more-specific \
         prefix above the generic stem:\n  {}",
        violations.join("\n  ")
    );
}

// -- Subdomain brute tests ----------------------------------------------------

#[test]
fn dictionary_is_unique_and_lowercase() {
    let mut sorted: Vec<&&str> = SUBDOMAINS.iter().collect();
    sorted.sort();
    let mut deduped = sorted.clone();
    deduped.dedup();
    assert_eq!(sorted.len(), deduped.len(), "dictionary has duplicates");
    for s in SUBDOMAINS {
        assert!(
            s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "non-lowercase entry: {s}"
        );
        assert!(
            !s.is_empty() && !s.contains('.'),
            "subdomains must be single label without dots: {s}"
        );
    }
}

// -- from dns_blocklist ------------------------------------------------

#[test]
fn reverse_ipv4() {
    assert_eq!(reverse_ip("1.2.3.4"), Some("4.3.2.1".into()));
    assert_eq!(reverse_ip("192.168.1.100"), Some("100.1.168.192".into()));
}

#[test]
fn reverse_ipv6_unsupported() {
    assert_eq!(reverse_ip("::1"), None);
    assert_eq!(reverse_ip("2001:db8::1"), None);
}

#[test]
fn reverse_invalid_returns_none() {
    assert_eq!(reverse_ip("not-an-ip"), None);
    assert_eq!(reverse_ip(""), None);
}

// -- module metadata ---------------------------------------------------

#[test]
fn metadata() {
    let m = DnsIntel;
    assert_eq!(m.name(), "dns_intel");
    assert_eq!(m.priority(), 31);
    assert_eq!(m.max_timeout_ms(), 15_000);
}
