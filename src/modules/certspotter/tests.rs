use super::*;

/// Build an `Issuance` for the pure `build_entities` tests without a live fetch.
fn issuance(dns: &[&str], issuer: Option<&str>) -> Issuance {
    Issuance {
        dns_names: dns.iter().map(|s| (*s).to_string()).collect(),
        issuer: issuer.map(|n| Issuer {
            name: Some(n.to_string()),
        }),
        not_before: Some("2024-01-01T00:00:00Z".into()),
        not_after: Some("2024-04-01T00:00:00Z".into()),
        cert_sha256: Some("deadbeef".into()),
    }
}

fn has_domain(es: &[Entity], value: &str) -> bool {
    es.iter()
        .any(|e| e.kind == EntityKind::Domain && e.value == value)
}

#[test]
fn accepts_domain_and_url_only() {
    let m = CertSpotter;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    assert!(m.accepts(&Target::new(TargetKind::Url, "https://x.com/a")));
    // Cert Spotter has no email search key (unlike crt.sh) and no non-host kinds.
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@x.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "u")));
}

#[test]
fn cost_is_free() {
    assert!(matches!(
        CertSpotter.cost(),
        crate::core::module::ModuleCost::Free
    ));
}

#[test]
fn description_non_empty() {
    assert!(!CertSpotter.description().is_empty());
}

#[test]
fn produces_declares_domain_and_organisation() {
    let p = CertSpotter.produces();
    assert!(p.contains(&EntityKind::Domain));
    assert!(p.contains(&EntityKind::Organisation));
}

#[test]
fn build_host_keys_on_the_hostname() {
    assert_eq!(build_host(TargetKind::Domain, "Example.COM"), Some("example.com".into()));
    // Trailing dot (FQDN root) is stripped.
    assert_eq!(build_host(TargetKind::Domain, "example.com."), Some("example.com".into()));
    // A URL is reduced to its host.
    assert_eq!(
        build_host(TargetKind::Url, "https://sub.example.com/path?q=1"),
        Some("sub.example.com".into())
    );
    // A bare label with no dot is not a queryable domain.
    assert_eq!(build_host(TargetKind::Domain, "localhost"), None);
    assert_eq!(build_host(TargetKind::Domain, "   "), None);
    // A kind with no host key.
    assert_eq!(build_host(TargetKind::Email, "a@x.com"), None);
}

#[test]
fn issuance_deserialises_from_the_expanded_api_shape() {
    let json = r#"[
        {"id":"6295991939",
         "dns_names":["example.com","www.example.com","*.example.com"],
         "issuer":{"name":"C=US, O=Let's Encrypt, CN=R3"},
         "not_before":"2024-01-01T00:00:00Z",
         "not_after":"2024-04-01T00:00:00Z",
         "cert_sha256":"deadbeef"}
    ]"#;
    let entries: Vec<Issuance> = serde_json::from_str(json).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].dns_names.len(), 3);
    assert_eq!(
        entries[0].issuer.as_ref().unwrap().name.as_deref(),
        Some("C=US, O=Let's Encrypt, CN=R3")
    );
    assert_eq!(entries[0].cert_sha256.as_deref(), Some("deadbeef"));
}

#[test]
fn missing_fields_degrade_gracefully() {
    // A minimal object (only dns_names) must still deserialize — every other
    // field is optional so a partial/renamed response yields fewer entities
    // rather than a hard error.
    let entries: Vec<Issuance> =
        serde_json::from_str(r#"[{"dns_names":["a.example.com"]}]"#).unwrap();
    let es = build_entities(&entries, "example.com", "scan1");
    assert!(has_domain(&es, "a.example.com"));
}

#[test]
fn build_entities_classifies_subdomains_and_skips_wildcards() {
    // Note: `Entity::new` normalises domains by stripping a leading `www.`, so a
    // `mail.` subdomain is used here to assert the sub-name survives verbatim.
    let entries = vec![issuance(
        &["example.com", "mail.example.com", "*.example.com", "unrelated.org"],
        None,
    )];
    let es = build_entities(&entries, "example.com", "scan1");

    // Subdomains of the base get the high-confidence subdomain treatment.
    let sub = es
        .iter()
        .find(|e| e.value == "mail.example.com")
        .expect("subdomain present");
    assert!((sub.confidence - 0.75).abs() < 1e-9);
    assert!(sub.tags.iter().any(|t| t == tags::SUBDOMAIN));
    assert!(sub.tags.iter().any(|t| t == tags::CT_LOG));

    // An off-base name from a multi-SAN cert is retained as a lower-confidence
    // pivot but NOT tagged a subdomain of the seed.
    let other = es
        .iter()
        .find(|e| e.value == "unrelated.org")
        .expect("off-base SAN present");
    assert!((other.confidence - 0.45).abs() < 1e-9);
    assert!(!other.tags.iter().any(|t| t == tags::SUBDOMAIN));

    // Wildcard SANs are never emitted (not resolvable hosts).
    assert!(!has_domain(&es, "*.example.com"));
}

#[test]
fn build_entities_dedups_names_across_certificates() {
    // The same hostname appearing on many certs yields exactly one entity.
    let entries = vec![
        issuance(&["mail.example.com"], None),
        issuance(&["mail.example.com"], None),
        issuance(&["mail.example.com", "api.example.com"], None),
    ];
    let es = build_entities(&entries, "example.com", "scan1");
    let mail_count = es.iter().filter(|e| e.value == "mail.example.com").count();
    assert_eq!(mail_count, 1, "duplicate SANs must collapse to one entity");
    assert!(has_domain(&es, "api.example.com"));
}

#[test]
fn build_entities_mines_only_nonpublic_issuers() {
    // A public CA issuer adds no signal → no Organisation entity.
    let public = vec![issuance(&["a.example.com"], Some("C=US, O=Let's Encrypt, CN=R3"))];
    let es = build_entities(&public, "example.com", "scan1");
    assert!(
        !es.iter().any(|e| e.kind == EntityKind::Organisation),
        "public CA must not become an Organisation"
    );

    // A custom / enterprise CA IS a high-value attribution pivot.
    let private = vec![issuance(&["a.example.com"], Some("O=Acme Internal CA Pty Ltd, C=AU"))];
    let es = build_entities(&private, "example.com", "scan1");
    let org = es
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .expect("non-public issuer becomes an Organisation");
    assert_eq!(org.value, "Acme Internal CA Pty Ltd");
    assert!(org.tags.iter().any(|t| t == "certificate-issuer"));
}

#[test]
fn build_entities_is_deterministic_and_confidence_sorted() {
    let entries = vec![issuance(
        &["z.example.com", "a.example.com", "unrelated.org"],
        Some("O=Acme Internal CA Pty Ltd"),
    )];
    let first = build_entities(&entries, "example.com", "scan1");
    let second = build_entities(&entries, "example.com", "scan1");
    // Reproducible order (Determinism Requirement).
    let order = |v: &[Entity]| v.iter().map(|e| e.value.clone()).collect::<Vec<_>>();
    assert_eq!(order(&first), order(&second));
    // Confidence-descending: the two 0.75 subdomains precede the 0.45 off-base name.
    let confs: Vec<f64> = first.iter().map(|e| e.confidence).collect();
    assert!(
        confs.windows(2).all(|w| w[0] >= w[1]),
        "entities must be emitted confidence-descending: {confs:?}"
    );
}
