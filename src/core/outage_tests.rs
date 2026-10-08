// Tests for `core::outage::classify`. Plain `//`: `include!`d into `mod tests`.

use super::*;
use std::net::{IpAddr, Ipv4Addr};

fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// A path with every probe reading as expected — the baseline every test
/// mutates ONE field of, so a failing test names exactly what changed.
fn healthy_path() -> OutagePath {
    OutagePath {
        at: 1_700_000_000,
        system_dns: vec![ip(1, 1, 1, 1)],
        doh_dns: Some(vec![ip(1, 1, 1, 1)]),
        ip_literal_reachable: true,
        connectivity_status: Some(204),
        tls_cert_captured: true,
        tls_issuer_org: Some("Google Trust Services LLC".to_string()),
    }
}

#[test]
fn a_healthy_path_reads_clear() {
    let r = classify(&healthy_path());
    assert_eq!(r.kind, OutageKind::Clear, "{r:?}");
    assert_eq!(r.at, 1_700_000_000);
}

#[test]
fn no_dns_and_no_direct_path_is_offline() {
    let mut p = healthy_path();
    p.system_dns.clear();
    p.doh_dns = None;
    p.ip_literal_reachable = false;
    let r = classify(&p);
    assert_eq!(r.kind, OutageKind::Offline, "{r:?}");
    assert!(r.evidence.contains("no path"), "{}", r.evidence);
}

#[test]
fn no_dns_but_a_direct_path_works_is_dns_unavailable_not_offline() {
    let mut p = healthy_path();
    p.system_dns.clear();
    p.doh_dns = None;
    // ip_literal_reachable stays true from healthy_path().
    let r = classify(&p);
    assert_eq!(r.kind, OutageKind::DnsUnavailable, "{r:?}");
}

#[test]
fn a_resolver_disagreement_with_no_shared_address_is_divergent_not_hijack_proof() {
    let mut p = healthy_path();
    p.system_dns = vec![ip(203, 0, 113, 1)];
    p.doh_dns = Some(vec![ip(198, 51, 100, 1)]);
    let r = classify(&p);
    assert_eq!(r.kind, OutageKind::DnsDivergent, "{r:?}");
    assert!(r.evidence.contains("203.0.113.1") && r.evidence.contains("198.51.100.1"));
}

#[test]
fn a_shared_address_between_resolvers_is_not_divergent_even_if_the_sets_differ() {
    // A CDN answering with a different SUBSET each time is not interception
    // — real agreement needs only overlap, not an identical set or order.
    let mut p = healthy_path();
    p.system_dns = vec![ip(1, 1, 1, 1), ip(1, 0, 0, 1)];
    p.doh_dns = Some(vec![ip(1, 0, 0, 1), ip(1, 1, 1, 2)]);
    let r = classify(&p);
    assert_ne!(r.kind, OutageKind::DnsDivergent, "{r:?}");
}

#[test]
fn doh_not_run_is_no_signal_never_a_false_divergence() {
    let mut p = healthy_path();
    p.doh_dns = None;
    let r = classify(&p);
    assert_ne!(r.kind, OutageKind::DnsDivergent, "{r:?}");
    assert_eq!(r.kind, OutageKind::Clear, "{r:?}");
}

#[test]
fn doh_running_and_finding_nothing_is_not_by_itself_a_divergence() {
    // An empty DoH answer alone is weaker evidence than a genuine collision
    // with a different address — `disjoint` requires both sides non-empty.
    let mut p = healthy_path();
    p.doh_dns = Some(vec![]);
    let r = classify(&p);
    assert_ne!(r.kind, OutageKind::DnsDivergent, "{r:?}");
}

#[test]
fn a_non_204_connectivity_answer_is_a_captive_portal() {
    let mut p = healthy_path();
    p.connectivity_status = Some(200);
    let r = classify(&p);
    assert_eq!(r.kind, OutageKind::CaptivePortal, "{r:?}");
    assert!(r.evidence.contains("200"), "{}", r.evidence);
}

#[test]
fn a_204_answer_is_not_a_captive_portal() {
    let r = classify(&healthy_path());
    assert_ne!(r.kind, OutageKind::CaptivePortal, "{r:?}");
}

#[test]
fn a_connectivity_probe_that_never_answered_is_inconclusive_not_a_portal() {
    let mut p = healthy_path();
    p.connectivity_status = None;
    let r = classify(&p);
    assert_ne!(r.kind, OutageKind::CaptivePortal, "{r:?}");
    // Falls through to the TLS check, which still reads clean here.
    assert_eq!(r.kind, OutageKind::Clear, "{r:?}");
}

#[test]
fn an_unrecognised_issuer_is_tls_intercepted() {
    let mut p = healthy_path();
    p.tls_issuer_org = Some("Totally Legit Corporate MITM CA".to_string());
    let r = classify(&p);
    assert_eq!(r.kind, OutageKind::TlsIntercepted, "{r:?}");
    assert!(r.evidence.contains("Totally Legit Corporate MITM CA"));
}

#[test]
fn a_recognised_issuers_exact_full_name_is_not_intercepted() {
    let mut p = healthy_path();
    p.tls_issuer_org = Some("DigiCert Inc".to_string());
    let r = classify(&p);
    assert_ne!(r.kind, OutageKind::TlsIntercepted, "{r:?}");
}

#[test]
fn an_issuer_name_that_merely_contains_an_allow_listed_fragment_is_still_intercepted() {
    // Regression: EXPECTED_CA_ORGS was previously matched by
    // `org.contains(..)`, so a self-signed interception certificate could
    // name its own issuer organisation "Not DigiCert" or "DigiCert clone" —
    // both contain the allow-listed fragment "DigiCert" — and pass. Exact
    // equality must reject both.
    for forged in ["Not DigiCert", "DigiCert clone", "XDigiCert Inc"] {
        let mut p = healthy_path();
        p.tls_issuer_org = Some(forged.to_string());
        let r = classify(&p);
        assert_eq!(
            r.kind,
            OutageKind::TlsIntercepted,
            "{forged:?} must not pass as a recognised CA: {r:?}"
        );
    }
}

#[test]
fn a_captured_certificate_with_no_readable_issuer_is_still_intercepted() {
    // A cert HSE cannot identify is not evidence the connection is safe.
    let mut p = healthy_path();
    p.tls_issuer_org = None;
    let r = classify(&p);
    assert_eq!(r.kind, OutageKind::TlsIntercepted, "{r:?}");
}

#[test]
fn no_certificate_captured_at_all_never_reads_as_intercepted() {
    // The TLS check never ran far enough to see a cert — that is not
    // evidence of interception, only that this probe leg did not complete.
    let mut p = healthy_path();
    p.tls_cert_captured = false;
    p.tls_issuer_org = None;
    let r = classify(&p);
    assert_ne!(r.kind, OutageKind::TlsIntercepted, "{r:?}");
    assert_eq!(r.kind, OutageKind::Clear, "{r:?}");
}

#[test]
fn captive_portal_evidence_outranks_ambiguous_dns_divergence() {
    // Disjoint DNS answers can be normal CDN/anycast behaviour, whereas a
    // connectivity probe that was expected to return 204 but was answered with
    // 200 is direct evidence of interception on that HTTP path.
    let mut p = healthy_path();
    p.system_dns = vec![ip(203, 0, 113, 1)];
    p.doh_dns = Some(vec![ip(198, 51, 100, 1)]);
    p.connectivity_status = Some(200);
    let r = classify(&p);
    assert_eq!(r.kind, OutageKind::CaptivePortal, "{r:?}");
}

#[test]
fn a_captive_portal_is_reported_over_a_tls_issuer_it_never_let_the_probe_reach() {
    let mut p = healthy_path();
    p.connectivity_status = Some(200);
    p.tls_issuer_org = Some("Unrecognised CA".to_string());
    let r = classify(&p);
    assert_eq!(r.kind, OutageKind::CaptivePortal, "{r:?}");
}

#[test]
fn classify_is_pure_the_same_input_yields_the_same_output() {
    let p = healthy_path();
    assert_eq!(classify(&p), classify(&p));
    let mut bad = healthy_path();
    bad.connectivity_status = Some(302);
    assert_eq!(classify(&bad), classify(&bad));
}

#[test]
fn every_kind_carries_non_empty_advice() {
    for kind in [
        OutageKind::Offline,
        OutageKind::DnsUnavailable,
        OutageKind::DnsDivergent,
        OutageKind::CaptivePortal,
        OutageKind::TlsIntercepted,
        OutageKind::Clear,
    ] {
        let r = OutageReport {
            kind,
            at: 0,
            evidence: String::new(),
        };
        assert!(!r.advice().is_empty(), "{kind:?}");
    }
}

#[test]
fn the_kind_serialises_as_a_stable_snake_case_tag() {
    let json = serde_json::to_value(OutageKind::DnsDivergent).unwrap();
    assert_eq!(json, serde_json::json!("dns_divergent"));
    let json = serde_json::to_value(OutageKind::CaptivePortal).unwrap();
    assert_eq!(json, serde_json::json!("captive_portal"));
}

#[test]
fn disjoint_requires_both_sides_non_empty_and_no_shared_address() {
    assert!(!disjoint(&[], &[ip(1, 1, 1, 1)]));
    assert!(!disjoint(&[ip(1, 1, 1, 1)], &[]));
    assert!(!disjoint(&[], &[]));
    assert!(!disjoint(&[ip(1, 1, 1, 1)], &[ip(1, 1, 1, 1)]));
    assert!(disjoint(&[ip(1, 1, 1, 1)], &[ip(8, 8, 8, 8)]));
}
