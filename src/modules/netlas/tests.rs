use super::Netlas;
use crate::core::{
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
};

#[test]
fn metadata() {
    let m = Netlas;
    assert_eq!(m.name(), "netlas");
    assert_eq!(m.priority(), 79);
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::KeyGated);
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Phone, "+61400000000")));
    assert!(m.max_timeout_ms() > 3000);
    assert!(!m.attack_techniques().is_empty());
}

#[test]
fn build_entities_surfaces_previously_dropped_cert_issuer_and_http_fields() {
    use crate::core::entity::EntityKind;
    // fields=* fetches the cert issuer CA, the HTTP page title and status code;
    // they were decoded into the response structs but never surfaced. The pure
    // builder must now fold all three onto the IP entity's evidence. The
    // top-level `count` (total matches for the query) was likewise dropped and
    // must now surface as `result_count`.
    let body: super::NetlasResp = serde_json::from_value(serde_json::json!({
        "count": 42,
        "items": [{
            "data": {
                "ip": "203.0.113.10",
                "port": 443,
                "protocol": "tcp",
                "certificate": {
                    "subject": { "common_name": "example.com" },
                    "issuer": { "common_name": "Let's Encrypt R3" }
                },
                "http": { "title": "ACME Corporate Portal", "status_code": 200 }
            }
        }]
    }))
    .unwrap();
    let r = super::build_entities(&body, "203.0.113.10", "scan");
    let ip = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress)
        .expect("ip entity");
    let attr = |k: &str| {
        ip.evidence[0]
            .attributes
            .get(k)
            .cloned()
            .unwrap_or_default()
    };
    assert_eq!(attr("ssl_issuer"), "Let's Encrypt R3");
    assert_eq!(attr("http_title"), "ACME Corporate Portal");
    assert_eq!(attr("http_status"), "200");
    // The query's total match count, decoded but previously dropped.
    assert_eq!(attr("result_count"), "42");
    // Pre-existing behaviour preserved: the subject CN still surfaces as ssl_cn.
    assert_eq!(attr("ssl_cn"), "example.com");
}

#[test]
fn build_entities_emits_every_unique_san_domain_and_email() {
    use crate::core::entity::EntityKind;
    // A multi-SAN certificate with 25 distinct SAN domains and an HTTP body exposing
    // 12 distinct contact emails: every UNIQUE record must surface as a Domain/Email
    // BFS pivot — no silent `.take(20)` / `.take(10)`. Fail-before: 20 domains + 10
    // emails; the certificate's own genuine pivots past those caps were dropped.
    let domains: Vec<String> = (0..25).map(|i| format!("sub{i:02}.example.com")).collect();
    let emails: Vec<String> = (0..12).map(|i| format!("user{i:02}@example.com")).collect();
    let body: super::NetlasResp = serde_json::from_value(serde_json::json!({
        "items": [{ "data": {
            "ip": "203.0.113.10",
            "certificate": { "domains": domains },
            "http": { "emails": emails }
        }}]
    }))
    .unwrap();
    let r = super::build_entities(&body, "203.0.113.10", "scan");
    let domain_ct = r
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain && e.has_tag("ssl-san"))
        .count();
    let email_ct = r
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email && e.has_tag("ssl-extracted"))
        .count();
    assert_eq!(
        domain_ct, 25,
        "every unique SAN domain must be emitted, not capped at 20"
    );
    assert_eq!(
        email_ct, 12,
        "every unique extracted email must be emitted, not capped at 10"
    );
}

#[test]
fn build_entities_emits_every_unique_cert_subject_org() {
    use crate::core::entity::EntityKind;
    // A shared-hosting IP whose certificate Subject O carries 6 distinct verified
    // legal-entity names: each is an attribution pivot and must surface as an
    // Organisation — the prior `.take(3)` silently dropped three.
    let orgs: Vec<String> = (0..6).map(|i| format!("Acme Legal Entity {i}")).collect();
    let body: super::NetlasResp = serde_json::from_value(serde_json::json!({
        "items": [{ "data": {
            "ip": "203.0.113.10",
            "certificate": { "subject": { "organization": orgs } }
        }}]
    }))
    .unwrap();
    let r = super::build_entities(&body, "203.0.113.10", "scan");
    let org_ct = r
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation && e.has_tag("ssl-subject-org"))
        .count();
    assert_eq!(
        org_ct, 6,
        "every unique cert Subject O must be emitted, not capped at 3"
    );
}

#[test]
fn build_entities_emits_a_deterministic_jarm_fingerprint() {
    use crate::core::entity::EntityKind;
    // A host can expose several JARM fingerprints (one per TLS service), but only
    // one is surfaced as `jarm_fingerprint`. It must be chosen DETERMINISTICALLY
    // (the lexicographically smallest), not by `HashSet` iteration order — which is
    // randomised per process and would emit a different fingerprint between
    // otherwise-identical runs, breaking byte-identical output. Items are supplied
    // in non-sorted order to prove the choice is by value, not insertion.
    let body: super::NetlasResp = serde_json::from_value(serde_json::json!({
        "items": [
            { "data": { "ip": "203.0.113.10", "port": 443,  "jarm": "cccc3333" } },
            { "data": { "ip": "203.0.113.10", "port": 8443, "jarm": "aaaa1111" } },
            { "data": { "ip": "203.0.113.10", "port": 9443, "jarm": "bbbb2222" } },
        ]
    }))
    .unwrap();
    let r = super::build_entities(&body, "203.0.113.10", "scan");
    let ip = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress)
        .expect("ip entity");
    assert_eq!(
        ip.evidence[0]
            .attributes
            .get("jarm_fingerprint")
            .map(String::as_str),
        Some("aaaa1111"),
        "the smallest JARM fingerprint must be emitted, deterministically"
    );
}

#[test]
fn netlas_query_by_kind() {
    use super::netlas_query;
    use crate::core::scan::Target;
    let ip_q = netlas_query(&Target::new(TargetKind::IpAddress, "1.2.3.4"));
    assert!(ip_q.starts_with("ip:"));
    let domain_q = netlas_query(&Target::new(TargetKind::Domain, "example.com"));
    assert!(domain_q.starts_with("host:"));
    let email_q = netlas_query(&Target::new(TargetKind::Email, "a@b.com"));
    assert!(email_q.starts_with("certificate.subject.email:"));
}
