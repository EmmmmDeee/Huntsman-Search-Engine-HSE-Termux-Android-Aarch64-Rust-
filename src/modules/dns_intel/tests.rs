use crate::core::module::Module;
use crate::core::scan::{Target, TargetKind};

use super::{
    DnsIntel,
    brute::is_apex_echo,
    constants::SUBDOMAINS,
    helpers::{
        VERIFICATION_VENDORS, reverse_ip, soa_rname_to_email, unescape_dns_label,
        verification_vendor,
    },
    resolve::{iodef_entities, is_spamhaus_abuse_listing, tlsrpt_entities},
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
    // A non-role local part: the happy path where the iodef mailbox is a
    // genuine, individually-addressed pivot rather than a role desk.
    let ents = iodef_entities("mailto:j.smith@example.com", "example.com", "scan-iodef");
    assert_eq!(ents.len(), 1);
    let e = &ents[0];
    assert_eq!(e.kind, EntityKind::Email);
    assert_eq!(e.value, "j.smith@example.com");
    assert!(e.has_tag("iodef") && e.has_tag("security-contact") && e.has_tag("caa"));
}

#[test]
fn iodef_mailto_role_desk_is_suppressed_as_infrastructure() {
    // Regression: a CAA iodef mailto is BY DEFINITION a designated security/
    // cert-issuance-violation reporting desk (RFC 8659) — "security@"/
    // "abuse@" are the textbook real-world values, and every other
    // contact-email path in this module (SOA admin, DMARC, TLSRPT) already
    // suppresses a role mailbox. This was the one path that didn't, letting
    // it leak through as if it were the subject's own PII.
    let ents = iodef_entities("mailto:security@example.com", "example.com", "scan-iodef");
    assert!(
        ents.is_empty(),
        "a role-desk iodef mailbox must be suppressed: {ents:?}"
    );
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

#[test]
fn apex_echo_excludes_a_www_hit_from_the_dictionary() {
    // Regression: the dictionary always includes "www", which resolves for
    // nearly every real domain. `Entity::new` strips a leading "www." label
    // internally, so "www.<parent>" collapses onto the scan's own
    // apex/subject uid — a hit here must never be tagged as a discovered
    // subdomain via `Entity::merge`'s tag-union onto that entity.
    assert!(is_apex_echo("www.example.com", "example.com"));
    // Case-insensitive, matching `Entity::new`'s own normalisation.
    assert!(is_apex_echo("WWW.Example.COM", "example.com"));
    // The literal apex itself (should the dictionary ever produce it) is
    // also an echo.
    assert!(is_apex_echo("example.com", "example.com"));
    // A genuine dictionary hit is not an echo.
    assert!(!is_apex_echo("mail.example.com", "example.com"));
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

// ─── A DNS outage must not become a clean reputation verdict ──────────────

use super::resolve::BlocklistTally;

/// `blocklist_check` ALWAYS emits an entity, unlike the CAA and PTR lookups in
/// the same file which emit only on a positive result. That makes this the one
/// place in the module where a resolver failure did not merely lose data — it
/// manufactured a finding.
///
/// The old loop was `if resolver.lookup_ip(..).await.is_ok() { listed }` with
/// `checked += 1` every iteration. "Listed" is `Ok`; a genuine NXDOMAIN, a
/// SERVFAIL and a timeout are all `Err`, so all three read as *not listed*.
/// With DNS down, eight zones failed, nothing was listed, `checked` reached 8,
/// and the entity asserted `status: clean`, `checked_count: 8`,
/// "clean on 8 blocklists" — about an address nothing had been established for.
#[test]
fn a_dns_outage_is_not_a_clean_blocklist_verdict() {
    // Every zone tried, none answered: no reputation statement is supported.
    assert!(
        BlocklistTally {
            attempted: 8,
            answered: 0,
            unresolved: 8,
        }
        .is_wholly_unresolved()
    );

    // One zone answered "not listed" and the rest failed. The verdict is
    // supportable but PARTIAL — it must be emitted, not errored, and the
    // denominator must be the 1 that answered, never the 8 attempted.
    let partial = BlocklistTally {
        attempted: 8,
        answered: 1,
        unresolved: 7,
    };
    assert!(!partial.is_wholly_unresolved());
    assert_eq!(partial.answered, 1, "the denominator is what ANSWERED");
    assert!(
        partial.unresolved > 0,
        "partial coverage must be disclosable"
    );

    // A full, healthy sweep.
    let full = BlocklistTally {
        attempted: 8,
        answered: 8,
        unresolved: 0,
    };
    assert!(!full.is_wholly_unresolved());
    assert_eq!(full.unresolved, 0, "nothing to disclose on a full sweep");

    // Nothing ran at all — cancelled before the first zone. That is the
    // operator's own stop, not an outage, and must NOT be reported as one.
    assert!(!BlocklistTally::default().is_wholly_unresolved());
    assert!(
        !BlocklistTally {
            attempted: 0,
            answered: 0,
            unresolved: 0,
        }
        .is_wholly_unresolved()
    );

    // A single zone that answered is enough to keep the module out of the
    // error path — it proves the resolver path works.
    assert!(
        !BlocklistTally {
            attempted: 1,
            answered: 1,
            unresolved: 0,
        }
        .is_wholly_unresolved()
    );
    // ...and a single zone that did not answer is an outage for that sweep.
    assert!(
        BlocklistTally {
            attempted: 1,
            answered: 0,
            unresolved: 1,
        }
        .is_wholly_unresolved()
    );
}

/// No answers, no verdict — whatever the reason there were none.
///
/// `is_wholly_unresolved` decides whether an outage is worth *reporting*, and it
/// excludes the nothing-ran case on purpose. That is the wrong question for
/// deciding whether to EMIT: gating only the error on cancellation left a sweep
/// that was cancelled before any zone answered falling straight through to
/// `status: clean, checked_count: 0` — "clean on 0 blocklists" — the same
/// verdict-without-evidence by another route. `supports_a_verdict` is the guard
/// that closes it, and it asks only whether anything answered.
#[test]
fn no_answers_means_no_verdict_however_the_sweep_ended() {
    // Cancelled before the first zone: nothing ran, nothing to say.
    assert!(!BlocklistTally::default().supports_a_verdict());

    // Cancelled after some zones failed: still nothing authoritative.
    assert!(
        !BlocklistTally {
            attempted: 3,
            answered: 0,
            unresolved: 3,
        }
        .supports_a_verdict()
    );

    // Total outage: also no verdict — this one is additionally an error.
    let outage = BlocklistTally {
        attempted: 8,
        answered: 0,
        unresolved: 8,
    };
    assert!(!outage.supports_a_verdict());
    assert!(outage.is_wholly_unresolved());

    // One authoritative answer is the whole requirement.
    assert!(
        BlocklistTally {
            attempted: 8,
            answered: 1,
            unresolved: 7,
        }
        .supports_a_verdict()
    );
    assert!(
        BlocklistTally {
            attempted: 8,
            answered: 8,
            unresolved: 0,
        }
        .supports_a_verdict()
    );

    // The two predicates answer different questions and must not be conflated:
    // "nothing ran" supports no verdict, yet is NOT an outage to report.
    let nothing_ran = BlocklistTally::default();
    assert!(!nothing_ran.supports_a_verdict());
    assert!(!nothing_ran.is_wholly_unresolved());
}

// -- Spamhaus policy-code filtering -----------------------------------------------

#[test]
fn spamhaus_abuse_listing_accepts_sbl() {
    let sbl = std::net::IpAddr::from([127, 0, 0, 2]);
    assert!(is_spamhaus_abuse_listing(sbl));
}

#[test]
fn spamhaus_abuse_listing_accepts_css() {
    let css = std::net::IpAddr::from([127, 0, 0, 3]);
    assert!(is_spamhaus_abuse_listing(css));
}

#[test]
fn spamhaus_abuse_listing_accepts_drop() {
    let drop = std::net::IpAddr::from([127, 0, 0, 9]);
    assert!(is_spamhaus_abuse_listing(drop));
}

#[test]
fn spamhaus_abuse_listing_accepts_xbl() {
    let xbl = std::net::IpAddr::from([127, 0, 0, 4]);
    assert!(is_spamhaus_abuse_listing(xbl));
}

/// Spamhaus allocates 127.0.0.5–7 to XBL and 127.0.0.8 to SBL. The test this
/// replaces asserted 127.0.0.5 was PBL, a policy code, so an XBL listing on
/// that code read as a clean ZEN check.
#[test]
fn spamhaus_abuse_listing_accepts_the_codes_allocated_to_xbl_and_sbl() {
    for last in 5..=8 {
        let code = std::net::IpAddr::from([127, 0, 0, last]);
        assert!(is_spamhaus_abuse_listing(code), "127.0.0.{last}");
    }
}

#[test]
fn spamhaus_abuse_listing_rejects_pbl_variant_10() {
    let pbl = std::net::IpAddr::from([127, 0, 0, 10]);
    assert!(!is_spamhaus_abuse_listing(pbl));
}

#[test]
fn spamhaus_abuse_listing_rejects_pbl_dialup() {
    let pbl = std::net::IpAddr::from([127, 0, 0, 11]);
    assert!(!is_spamhaus_abuse_listing(pbl));
}

#[test]
fn spamhaus_abuse_listing_rejects_unknown_codes() {
    let unknown = std::net::IpAddr::from([127, 0, 0, 1]);
    assert!(!is_spamhaus_abuse_listing(unknown));

    let unknown2 = std::net::IpAddr::from([127, 0, 0, 99]);
    assert!(!is_spamhaus_abuse_listing(unknown2));
}

#[test]
fn spamhaus_abuse_listing_rejects_non_127() {
    let non_127 = std::net::IpAddr::from([192, 168, 1, 1]);
    assert!(!is_spamhaus_abuse_listing(non_127));

    let non_127_second = std::net::IpAddr::from([127, 0, 1, 2]);
    assert!(!is_spamhaus_abuse_listing(non_127_second));
}

#[test]
fn spamhaus_abuse_listing_rejects_ipv6() {
    let ipv6 = std::net::IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]);
    assert!(!is_spamhaus_abuse_listing(ipv6));
}

// ─── A DNSBL's answer is its value, from a zone shown to be answering ─────────

use super::constants::BLOCKLISTS;
use super::resolve::{DnsblAnswer, DnsblLookup, dnsbl_answer, zone_answer};

/// Spamhaus's answer to a query that reaches it through a public resolver.
const REFUSED: [u8; 4] = [127, 255, 255, 254];

/// A DNSBL answer carrying these A values.
fn a_values(values: &[[u8; 4]]) -> DnsblLookup {
    Ok(values
        .iter()
        .copied()
        .map(std::net::Ipv4Addr::from)
        .collect())
}

/// The zone's "no such name".
fn nxdomain() -> DnsblLookup {
    use hickory_resolver::proto::op::{Query, ResponseCode};
    Err(hickory_resolver::net::NoRecords::new(Query::default(), ResponseCode::NXDomain).into())
}

/// Spamhaus answers ZEN and CBL queries that reach it through a public
/// resolver with `127.255.255.254`, "query via public/open resolver" — observed
/// through Cloudflare and Quad9 for the `127.0.0.2` test entry itself. It is in
/// the range Spamhaus reserves for errors, which "must not be taken to imply
/// that the object of the query is listed". The sweep read it as a CBL listing
/// on every IPv4 target, and as a clean ZEN check.
#[test]
fn a_dnsbl_error_code_is_neither_a_listing_nor_a_clean_answer() {
    for zone in ["zen.spamhaus.org", "cbl.abuseat.org", "bl.spamcop.net"] {
        for last in [252, 254, 255] {
            assert_eq!(
                dnsbl_answer(zone, &a_values(&[[127, 255, 255, last]])),
                DnsblAnswer::Unresolved,
                "{zone}: 127.255.255.{last}"
            );
        }
    }
    let mut tally = BlocklistTally {
        attempted: 2,
        ..BlocklistTally::default()
    };
    for zone in ["zen.spamhaus.org", "cbl.abuseat.org"] {
        assert!(
            !tally.record(dnsbl_answer(zone, &a_values(&[REFUSED]))),
            "{zone} refused; it lists nothing"
        );
    }
    assert_eq!(tally.answered, 0, "a refusal is not a check that passed");
    assert_eq!(tally.unresolved, 2, "it is disclosed as partial coverage");
    assert!(!tally.supports_a_verdict());
}

/// A value outside `127.0.0.0/8` is not a DNSBL answer: it is an NXDOMAIN a
/// carrier or hijacking resolver rewrote to a landing page. Every zone but ZEN
/// read any value as a listing, so on such a network every address was "listed
/// on 7 of 8" — `high-risk`, and AU-007's High correlation.
#[test]
fn an_answer_outside_127_slash_8_is_a_rewritten_nxdomain_not_a_listing() {
    for (zone, _) in BLOCKLISTS {
        assert_eq!(
            dnsbl_answer(zone, &a_values(&[[93, 184, 216, 34]])),
            DnsblAnswer::Unresolved,
            "{zone}"
        );
    }
    assert_eq!(
        dnsbl_answer("bl.spamcop.net", &a_values(&[])),
        DnsblAnswer::Unresolved,
        "no A value is no answer"
    );
}

/// Over-correction guard: failing closed on every value would erase the check.
/// A listing code is a listing, a PBL-only ZEN answer is answered but not a
/// listing, and NXDOMAIN is the zone saying "not listed".
#[test]
fn a_documented_listing_code_is_still_a_listing() {
    use DnsblAnswer::{Listed, NotListed, Unresolved};
    assert_eq!(
        dnsbl_answer("bl.spamcop.net", &a_values(&[[127, 0, 0, 2]])),
        Listed
    );
    // RFC 5782 §2.3: a sublist may use any 127/8 value.
    assert_eq!(
        dnsbl_answer("b.barracudacentral.org", &a_values(&[[127, 0, 1, 2]])),
        Listed
    );
    // ZEN's answer for its own test entry, per Spamhaus: SBL, XBL and PBL.
    let zen_test_entry = a_values(&[[127, 0, 0, 2], [127, 0, 0, 4], [127, 0, 0, 10]]);
    assert_eq!(dnsbl_answer("zen.spamhaus.org", &zen_test_entry), Listed);
    for pbl in [10, 11] {
        assert_eq!(
            dnsbl_answer("zen.spamhaus.org", &a_values(&[[127, 0, 0, pbl]])),
            NotListed,
            "127.0.0.{pbl} is policy-zone membership"
        );
    }
    assert_eq!(dnsbl_answer("bl.spamcop.net", &nxdomain()), NotListed);
    assert_eq!(
        dnsbl_answer(
            "bl.spamcop.net",
            &Err(hickory_resolver::net::NetError::Timeout)
        ),
        Unresolved
    );
}

/// A value check cannot see every refusal. Through Google Public DNS, Spamhaus
/// answers NXDOMAIN — for the address and for `127.0.0.2`, which RFC 5782 §5
/// requires every list to hold — so its refusal read as a clean ZEN and CBL
/// check. A retired zone (SORBS, whose `127.0.0.2` entry is gone) read the
/// same, and a list that "lists the world" answers `127.0.0.1` too. The test
/// entries are how a zone shows it is answering.
#[test]
fn a_zone_that_fails_its_rfc5782_test_entries_establishes_nothing() {
    use DnsblAnswer::{Listed, NotListed, Unresolved};
    let listed = || a_values(&[[127, 0, 0, 2]]);
    // Google for ZEN, and SORBS through any resolver: NXDOMAIN for all three.
    for zone in ["zen.spamhaus.org", "dnsbl.sorbs.net"] {
        assert_eq!(
            zone_answer(zone, &nxdomain(), &nxdomain(), &nxdomain()),
            Unresolved,
            "{zone}"
        );
    }
    // A list that lists the world.
    assert_eq!(
        zone_answer("psbl.surriel.com", &listed(), &listed(), &listed()),
        Unresolved
    );
    // Over-correction guard: a zone that passes both is believed either way.
    assert_eq!(
        zone_answer("bl.spamcop.net", &nxdomain(), &listed(), &nxdomain()),
        NotListed
    );
    assert_eq!(
        zone_answer("bl.spamcop.net", &listed(), &listed(), &nxdomain()),
        Listed
    );
}

/// The sweep as it runs through Cloudflare for `8.8.8.8`, zone by zone as
/// observed live: ZEN and CBL refuse, SORBS is retired, and the other five
/// answer and do not list it. It reported "listed on 1 of 8 blocklists" (CBL),
/// tagged the address `blocklisted`, and counted ZEN and SORBS as clean.
#[test]
fn the_public_resolver_sweep_lists_nothing_and_counts_no_refusal_as_clean() {
    let mut tally = BlocklistTally::default();
    let mut listed_on = Vec::new();
    for (zone, label) in BLOCKLISTS {
        let refused = || a_values(&[REFUSED]);
        let (address, listed_test, unlisted_test) = match *zone {
            "zen.spamhaus.org" | "cbl.abuseat.org" => (refused(), refused(), refused()),
            "dnsbl.sorbs.net" => (nxdomain(), nxdomain(), nxdomain()),
            _ => (nxdomain(), a_values(&[[127, 0, 0, 2]]), nxdomain()),
        };
        tally.attempted += 1;
        if tally.record(zone_answer(zone, &address, &listed_test, &unlisted_test)) {
            listed_on.push(*label);
        }
    }
    assert!(listed_on.is_empty(), "8.8.8.8 is on no list: {listed_on:?}");
    assert_eq!(
        tally,
        BlocklistTally {
            attempted: 8,
            answered: 5,
            unresolved: 3,
        }
    );
}

// ─── A wildcard zone's catch-all is not a discovered subdomain ────────────────

use super::resolve_batch::{ResolvedHost, reportable_hits};
use super::wildcard::{Canary, Wildcard, wildcard_verdict};
use crate::core::module::ModuleResult;

fn ip_set(ips: &[&str]) -> std::collections::BTreeSet<String> {
    ips.iter().map(ToString::to_string).collect()
}

/// `n` resolved candidates under `zone`, as `resolve_hosts_concurrently`
/// returns them.
fn resolved(n: usize, zone: &str) -> Vec<ResolvedHost> {
    (0..n)
        .map(|i| (format!("h{i}.{zone}"), "203.0.113.7".to_string(), 1))
        .collect()
}

/// A GUID label resolves only through a wildcard, so two canaries that both
/// resolve prove one, whatever they resolve to. The verdict demanded identical
/// IP sets and read anything else as NO wildcard. A CDN or PaaS ingress
/// wildcard answers each name differently — `herokuapp.com` gave the two
/// canaries different CNAME targets and disjoint sets through one provider —
/// so nothing was filtered, and every candidate was emitted as a discovered
/// subdomain at high confidence and re-dispatched into the scan.
#[test]
fn two_canaries_that_resolve_to_different_sets_are_a_wildcard_not_its_absence() {
    let verdict = wildcard_verdict(
        Canary::Resolved(ip_set(&["3.219.96.23", "23.22.144.165"])),
        Canary::Resolved(ip_set(&["34.241.115.67", "54.78.134.111"])),
    );
    assert_eq!(verdict, Wildcard::Unstable);
    let mut result = ModuleResult::new();
    let kept = reportable_hits(
        "herokuapp.com",
        &verdict,
        49,
        resolved(49, "herokuapp.com"),
        &mut result,
    );
    assert!(
        kept.is_empty(),
        "no candidate can be told from a per-name catch-all"
    );
    let why = result
        .truncation
        .expect("the withheld pass is declared, not a silent empty");
    assert!(why.contains("herokuapp.com"), "{why}");
}

/// A canary that timed out established nothing; it is not the zone answering
/// "no such name". It read as "no wildcard", so one lost packet on a wildcard
/// zone let the whole dictionary through. With the canaries unsettled, the
/// hits decide: a wildcard answers for the whole dictionary, a zone's real
/// records are a handful of it.
#[test]
fn a_failed_canary_is_not_proof_there_is_no_wildcard() {
    // One canary resolved: a wildcard, filtered by the one sample it gave.
    assert_eq!(
        wildcard_verdict(Canary::Failed, Canary::Resolved(ip_set(&["192.0.2.1"]))),
        Wildcard::CatchAll(ip_set(&["192.0.2.1"]))
    );
    let unknown = wildcard_verdict(Canary::Failed, Canary::NoSuchName);
    assert_eq!(unknown, Wildcard::Unknown);
    let mut result = ModuleResult::new();
    let kept = reportable_hits(
        "corp.example",
        &unknown,
        146,
        resolved(146, "corp.example"),
        &mut result,
    );
    assert!(kept.is_empty());
    assert!(result.truncation.is_some());
    // Over-correction guard: a handful of hits is a zone's real records.
    let mut result = ModuleResult::new();
    let kept = reportable_hits(
        "corp.example",
        &unknown,
        146,
        resolved(6, "corp.example"),
        &mut result,
    );
    assert_eq!(kept.len(), 6);
    assert!(result.truncation.is_none());
}

/// A stable catch-all is still filtered by its fingerprint. A candidate that
/// escapes the exact-match filter only because another upstream answered it
/// with different edge addresses is caught by the count: most of the
/// dictionary resolving is the catch-all, not the zone's records.
#[test]
fn hits_that_swamp_the_dictionary_under_a_catch_all_are_the_catch_all() {
    let fp = ip_set(&["192.0.2.10"]);
    let verdict = wildcard_verdict(Canary::Resolved(fp.clone()), Canary::Resolved(fp.clone()));
    assert_eq!(verdict, Wildcard::CatchAll(fp.clone()));
    assert_eq!(verdict.fingerprint().as_deref(), Some(&fp));
    let mut result = ModuleResult::new();
    let kept = reportable_hits(
        "blogspot.com",
        &verdict,
        146,
        resolved(120, "blogspot.com"),
        &mut result,
    );
    assert!(kept.is_empty());
    assert!(result.truncation.is_some());
    // Over-correction guard: the few records that differ from the catch-all
    // are real, and reported.
    let mut result = ModuleResult::new();
    let kept = reportable_hits(
        "blogspot.com",
        &verdict,
        146,
        resolved(3, "blogspot.com"),
        &mut result,
    );
    assert_eq!(kept.len(), 3);
    assert!(result.truncation.is_none());
}

/// Over-correction guard: a zone both canaries prove has no wildcard is the
/// common case, and every name that resolves there is a real record, however
/// many there are.
#[test]
fn a_zone_the_canaries_prove_has_no_wildcard_reports_every_hit() {
    let verdict = wildcard_verdict(Canary::NoSuchName, Canary::NoSuchName);
    assert_eq!(verdict, Wildcard::Absent);
    assert!(verdict.fingerprint().is_none(), "nothing to filter");
    let mut result = ModuleResult::new();
    let kept = reportable_hits(
        "example.com",
        &verdict,
        146,
        resolved(90, "example.com"),
        &mut result,
    );
    assert_eq!(kept.len(), 90);
    assert!(result.truncation.is_none());
}
