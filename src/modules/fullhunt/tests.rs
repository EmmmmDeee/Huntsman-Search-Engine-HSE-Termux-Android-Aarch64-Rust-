use super::*;
use crate::core::module::ModuleCategory;

#[test]
fn accepts_domain_only() {
    let m = FullHunt;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
    assert!(!m.accepts(&Target::new(TargetKind::Url, "https://example.com/x")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@example.com")));
}

#[test]
fn metadata_sane() {
    let m = FullHunt;
    assert_eq!(m.name(), "fullhunt");
    assert!(!m.description().is_empty());
    assert!(matches!(m.cost(), ModuleCost::KeyGated));
    assert!(matches!(m.category(), ModuleCategory::Infrastructure));
    assert!(m.max_timeout_ms() >= crate::MODULE_TIMEOUT_MS);
    assert_eq!(m.cache_ttl_secs(), 86_400);
    assert_eq!(
        m.attack_techniques(),
        &["T1590.005", "T1591.002", "T1596.001", "T1596.005"]
    );
    assert!(m.produces().contains(&EntityKind::Domain));
    assert!(m.produces().contains(&EntityKind::IpAddress));
    assert!(m.produces().contains(&EntityKind::Asn));
    assert!(m.produces().contains(&EntityKind::Organisation));
}

fn body(json: &str) -> DomainResp {
    serde_json::from_str(json).expect("should succeed")
}

fn find<'a>(ents: &'a [Entity], kind: EntityKind, value: &str) -> Option<&'a Entity> {
    ents.iter().find(|e| e.kind == kind && e.value == value)
}

fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
    e.evidence[0].attributes.get(k).map(String::as_str)
}

#[test]
fn populated_response_builds_full_asset_graph() {
    // Mirrors the shape docs.fullhunt.io/docs/data-intelligence-apis documents
    // for `/api/v1/intel/domain`, extended with a second host sharing the same
    // IP/ASN/org (dedup) and a dns_ptr pivot.
    let b = body(
        r#"{
          "query": {"domain": "example.com"},
          "results": [
            {
              "asn": 13335,
              "dns_ptr": ["edge1.cdnhost.example.net", "203.0.113.5"],
              "domain": "example.com",
              "host": "www.example.com",
              "ip_address": "203.0.113.5",
              "organization": "Example Hosting Inc"
            },
            {
              "asn": 13335,
              "dns_ptr": null,
              "domain": "example.com",
              "host": "api.example.com",
              "ip_address": "203.0.113.5",
              "organization": "Example Hosting Inc"
            }
          ],
          "total_pages": 1,
          "total_query_results": 2
        }"#,
    );
    let ents = build_entities(&b, "example.com", "s");

    let www = ents
        .iter()
        .find(|e| e.kind == EntityKind::Domain && e.raw_value == "www.example.com")
        .expect("should succeed");
    assert!(www.has_tag("fullhunt") && www.has_tag(tags::SUBDOMAIN));
    assert!((www.confidence - confidence::EXPERT).abs() < 1e-9);
    assert_eq!(attr(www, "ip_address"), Some("203.0.113.5"));
    assert_eq!(attr(www, "asn"), Some("AS13335"));
    assert_eq!(attr(www, "organization"), Some("Example Hosting Inc"));
    assert_eq!(attr(www, "total_query_results"), Some("2"));

    assert!(find(&ents, EntityKind::Domain, "api.example.com").is_some());

    // Shared IP/ASN/org across both hosts are deduplicated to one entity each.
    assert_eq!(
        ents.iter()
            .filter(|e| e.kind == EntityKind::IpAddress && e.value == "203.0.113.5")
            .count(),
        1
    );
    assert_eq!(
        ents.iter()
            .filter(|e| e.kind == EntityKind::Asn && e.value == "AS13335")
            .count(),
        1
    );
    assert_eq!(
        ents.iter()
            .filter(|e| e.kind == EntityKind::Organisation && e.value == "Example Hosting Inc")
            .count(),
        1
    );

    // Real PTR hostname becomes a Domain pivot tagged `ptr`; the IP-literal
    // dns_ptr entry is dropped.
    let ptr = find(&ents, EntityKind::Domain, "edge1.cdnhost.example.net").expect("should succeed");
    assert!(ptr.has_tag("fullhunt") && ptr.has_tag(tags::PTR));
    assert!(find(&ents, EntityKind::Domain, "203.0.113.5").is_none());
}

#[test]
fn a_forward_confirmed_ptr_does_not_duplicate_the_host_domain() {
    // Regression: a host's own reverse-DNS PTR pointing back to its own name
    // (a "forward-confirmed" PTR — an ordinary shape for e.g. a dedicated
    // mail server) used to mint the SAME Domain value twice: once as the
    // primary discovered-asset entity, once again as a `ptr`-tagged pivot,
    // since the two code paths tracked separate `seen` sets.
    let b = body(
        r#"{
          "results": [
            {"asn": 13335, "dns_ptr": ["mail.example.com"], "domain": "example.com",
             "host": "mail.example.com", "ip_address": "203.0.113.5", "organization": "Example Hosting Inc"}
          ]
        }"#,
    );
    let ents = build_entities(&b, "example.com", "s");
    let domains: Vec<&str> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .map(|e| e.value.as_str())
        .collect();
    assert_eq!(
        domains.iter().filter(|v| **v == "mail.example.com").count(),
        1,
        "a forward-confirmed PTR must not duplicate its own host's Domain entity: {domains:?}"
    );
}

#[test]
fn the_same_host_repeating_across_result_rows_is_not_duplicated() {
    // The identical `host` value can in principle repeat verbatim across two
    // `results[]` rows (e.g. two differently-shaped records both naming the
    // same asset) — must still surface as one Domain entity.
    let b = body(
        r#"{
          "results": [
            {"asn": 1, "dns_ptr": null, "domain": "example.com",
             "host": "www.example.com", "ip_address": "203.0.113.5", "organization": "Org"},
            {"asn": 1, "dns_ptr": null, "domain": "example.com",
             "host": "www.example.com", "ip_address": "203.0.113.9", "organization": "Org"}
          ]
        }"#,
    );
    let ents = build_entities(&b, "example.com", "s");
    assert_eq!(
        ents.iter()
            .filter(|e| e.kind == EntityKind::Domain && e.raw_value == "www.example.com")
            .count(),
        1,
        "the same host repeating across rows must still be one Domain entity: {ents:?}"
    );
}

#[test]
fn apex_and_unrelated_hosts_are_skipped_entirely() {
    let b = body(
        r#"{
          "results": [
            {"asn": 1, "dns_ptr": null, "domain": "example.com",
             "host": "example.com", "ip_address": "203.0.113.5", "organization": "Org"},
            {"asn": 1, "dns_ptr": null, "domain": "example.com",
             "host": "evil.other.org", "ip_address": "203.0.113.9", "organization": "Org"}
          ]
        }"#,
    );
    let ents = build_entities(&b, "example.com", "s");
    assert!(ents.is_empty(), "apex + unrelated host must yield nothing: {ents:?}");
}

#[test]
fn zero_and_empty_sentinels_are_treated_as_absent() {
    // asn:0, ip_address:"", organization:"" are FullHunt's own documented
    // "nothing known" shape — only the bare subdomain Domain entity is emitted.
    let b = body(
        r#"{
          "results": [
            {"asn": 0, "dns_ptr": null, "domain": "example.com",
             "host": "bare.example.com", "ip_address": "", "organization": ""}
          ]
        }"#,
    );
    let ents = build_entities(&b, "example.com", "s");
    assert_eq!(ents.len(), 1, "only the subdomain itself: {ents:?}");
    let e = &ents[0];
    assert_eq!(e.kind, EntityKind::Domain);
    assert_eq!(e.value, "bare.example.com");
    assert_eq!(attr(e, "ip_address"), None);
    assert_eq!(attr(e, "asn"), None);
    assert_eq!(attr(e, "organization"), None);
}

#[test]
fn build_entities_empty_results_yields_nothing() {
    assert!(build_entities(&body(r#"{"results":[]}"#), "example.com", "s").is_empty());
}

#[test]
fn missing_host_field_is_skipped_not_panicked() {
    let b = body(r#"{"results":[{"asn":1,"dns_ptr":null,"domain":"example.com","ip_address":"","organization":""}]}"#);
    assert!(build_entities(&b, "example.com", "s").is_empty());
}
