use crate::core::module::Module;
use crate::core::scan::{Target, TargetKind};

use super::{
    DnsIntel,
    constants::SUBDOMAINS,
    helpers::{
        VERIFICATION_VENDORS, reverse_ip, soa_rname_to_email, unescape_dns_label,
        verification_vendor,
    },
    resolve::{iodef_entities, tlsrpt_entities},
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
fn iodef_mailto_becomes_a_security_contact_email() {
    use crate::core::entity::EntityKind;
    let ents = iodef_entities("mailto:security@example.com", "example.com", "scan-iodef");
    assert_eq!(ents.len(), 1);
    let e = &ents[0];
    assert_eq!(e.kind, EntityKind::Email);
    assert_eq!(e.value, "security@example.com");
    assert!(e.has_tag("iodef") && e.has_tag("security-contact") && e.has_tag("caa"));
}

#[test]
fn iodef_https_endpoint_yields_a_domain_lead() {
    use crate::core::entity::EntityKind;
    // The reporting host is a pivotable Domain — but only when it differs from
    // the target domain (a self-referential iodef adds no new lead).
    let ents = iodef_entities(
        "https://iodef.reporter.net/report",
        "example.com",
        "scan-iodef",
    );
    assert_eq!(ents.len(), 1);
    assert_eq!(ents[0].kind, EntityKind::Domain);
    // The full reporting-endpoint host is the lead (the engine's own expansion
    // derives its registrable domain when it re-dispatches).
    assert_eq!(ents[0].value, "iodef.reporter.net");
    assert!(ents[0].has_tag("iodef"));

    // Self-referential host (same registrable domain host) adds no new entity.
    let self_ref = iodef_entities("https://example.com/report", "example.com", "scan-iodef");
    assert!(self_ref.is_empty(), "iodef host == target adds no new lead");
}

#[test]
fn iodef_rejects_malformed_and_unknown_schemes() {
    // A malformed mailto (no domain dot, whitespace, or missing @) yields nothing.
    assert!(iodef_entities("mailto:notanemail", "example.com", "s").is_empty());
    assert!(iodef_entities("mailto:a@b", "example.com", "s").is_empty());
    assert!(iodef_entities("mailto:a b@c.com", "example.com", "s").is_empty());
    // A non-mailto/non-http scheme (or bare URN) yields nothing.
    assert!(iodef_entities("urn:example:report", "example.com", "s").is_empty());
    assert!(iodef_entities("", "example.com", "s").is_empty());
}

#[test]
fn tlsrpt_mailto_becomes_report_email() {
    use crate::core::entity::EntityKind;
    // A non-infra reporting mailbox (real live TLSRPT records like google.com's
    // `sts-reports@google.com` sit on a provider domain and are correctly gated
    // by the infra filter below — so exercise the happy path with a corp domain).
    let ents = tlsrpt_entities(
        &["v=TLSRPTv1;rua=mailto:tlsrpt@fabrikam.example".to_string()],
        "fabrikam.example",
        "s",
    );
    let email = ents
        .iter()
        .find(|e| e.kind == EntityKind::Email)
        .expect("TLSRPT rua mailto → Email");
    assert_eq!(email.value, "tlsrpt@fabrikam.example");
    assert!(email.has_tag("tlsrpt-report") && email.has_tag("dns"));
}

#[test]
fn tlsrpt_infrastructure_mailbox_is_gated() {
    // Parity with DMARC/SOA gating: a provider-domain reporting desk (google.com
    // is in the curated infra-mail set) must NOT be surfaced as a subject email.
    let ents = tlsrpt_entities(
        &["v=TLSRPTv1;rua=mailto:sts-reports@google.com".to_string()],
        "google.com",
        "s",
    );
    assert!(
        ents.iter()
            .all(|e| e.kind != crate::core::entity::EntityKind::Email),
        "infrastructure reporting mailbox must be gated"
    );
}

#[test]
fn tlsrpt_https_endpoint_becomes_domain_lead() {
    use crate::core::entity::EntityKind;
    // Verbatim live shape from microsoft.com's _smtp._tls record.
    let ents = tlsrpt_entities(
        &["v=TLSRPTv1; rua=https://tlsrpt.azurewebsites.net/report".to_string()],
        "microsoft.com",
        "s",
    );
    let dom = ents
        .iter()
        .find(|e| e.kind == EntityKind::Domain)
        .expect("TLSRPT rua https → Domain host");
    assert_eq!(dom.value, "tlsrpt.azurewebsites.net");
    assert!(dom.has_tag("tlsrpt-report"));
}

#[test]
fn tlsrpt_ignores_non_tlsrpt_and_empty() {
    assert!(tlsrpt_entities(&["v=spf1 -all".to_string()], "x.com", "s").is_empty());
    assert!(tlsrpt_entities(&["v=TLSRPTv1;".to_string()], "x.com", "s").is_empty());
    assert!(tlsrpt_entities(&[], "x.com", "s").is_empty());
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

// -- Subdomain dictionary coverage -------------------------------------------

#[test]
fn dictionary_covers_modern_infrastructure_labels() {
    // Spot-check that the cycle-30 additions are present and correctly formatted.
    let set: std::collections::HashSet<&&str> = SUBDOMAINS.iter().collect();
    // Large-org / SaaS platform patterns
    assert!(set.contains(&"gist"), "missing: gist");
    assert!(set.contains(&"pages"), "missing: pages");
    assert!(set.contains(&"education"), "missing: education");
    assert!(set.contains(&"enterprise"), "missing: enterprise");
    assert!(set.contains(&"marketplace"), "missing: marketplace");
    // Modern API
    assert!(set.contains(&"graphql"), "missing: graphql");
    assert!(set.contains(&"webhooks"), "missing: webhooks");
    assert!(set.contains(&"ws"), "missing: ws");
    // Customer account infra
    assert!(set.contains(&"dashboard"), "missing: dashboard");
    assert!(set.contains(&"billing"), "missing: billing");
    assert!(set.contains(&"accounts"), "missing: accounts");
    // Health / readiness
    assert!(set.contains(&"health"), "missing: health");
    assert!(set.contains(&"healthz"), "missing: healthz");
    assert!(set.contains(&"ping"), "missing: ping");
    // Build / deploy
    assert!(set.contains(&"build"), "missing: build");
    assert!(set.contains(&"deploy"), "missing: deploy");
    assert!(set.contains(&"artifacts"), "missing: artifacts");
    // Regional shards
    assert!(set.contains(&"us1"), "missing: us1");
    assert!(set.contains(&"eu1"), "missing: eu1");
    assert!(set.contains(&"ap1"), "missing: ap1");
    // Security / secrets
    assert!(set.contains(&"vault"), "missing: vault");
    assert!(set.contains(&"security"), "missing: security");
}

#[test]
fn dictionary_size_is_146() {
    assert_eq!(SUBDOMAINS.len(), 146, "expected 146 subdomain labels");
}

// -- Verification vendor expansion (cycle 30) --------------------------------

#[test]
fn verification_vendor_detects_new_vendors() {
    assert_eq!(
        verification_vendor("hubspot-developer-verification=abc"),
        Some("hubspot")
    );
    assert_eq!(
        verification_vendor("salesforce-authorization-verification=xyz"),
        Some("salesforce")
    );
    assert_eq!(verification_vendor("loaderio=token123"), Some("loaderio"));
    assert_eq!(
        verification_vendor("twilio-domain-verification=abc123"),
        Some("twilio")
    );
    assert_eq!(
        verification_vendor("yandex-verification:abc123"),
        Some("yandex")
    );
    assert_eq!(
        verification_vendor("shopify-domain-verification=abc"),
        Some("shopify")
    );
    // Existing entries still work after the expansion
    assert_eq!(
        verification_vendor("google-site-verification=abc"),
        Some("google")
    );
    assert_eq!(verification_vendor("MS=ms12345678"), Some("microsoft"));
}

// -- module metadata ---------------------------------------------------

#[test]
fn metadata() {
    let m = DnsIntel;
    assert_eq!(m.name(), "dns_intel");
    assert_eq!(m.priority(), 31);
    assert_eq!(m.max_timeout_ms(), 15_000);
}
