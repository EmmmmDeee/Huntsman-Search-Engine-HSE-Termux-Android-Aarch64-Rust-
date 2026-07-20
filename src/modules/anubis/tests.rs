use super::*;

fn names(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_string()).collect()
}

fn has_domain(es: &[Entity], value: &str) -> bool {
    es.iter()
        .any(|e| e.kind == EntityKind::Domain && e.value == value)
}

#[test]
fn accepts_domain_and_url_only() {
    let m = Anubis;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    assert!(m.accepts(&Target::new(TargetKind::Url, "https://x.com/a")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@x.com")));
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
}

#[test]
fn cost_is_free() {
    assert!(matches!(
        Anubis.cost(),
        crate::core::module::ModuleCost::Free
    ));
}

#[test]
fn description_non_empty() {
    assert!(!Anubis.description().is_empty());
}

#[test]
fn produces_domains() {
    assert!(Anubis.produces().contains(&EntityKind::Domain));
}

#[test]
fn build_host_keys_on_the_hostname() {
    assert_eq!(build_host(TargetKind::Domain, "Example.COM"), Some("example.com".into()));
    assert_eq!(build_host(TargetKind::Domain, "example.com."), Some("example.com".into()));
    assert_eq!(
        build_host(TargetKind::Url, "https://sub.example.com/p"),
        Some("sub.example.com".into())
    );
    assert_eq!(build_host(TargetKind::Domain, "localhost"), None);
    assert_eq!(build_host(TargetKind::Email, "a@x.com"), None);
}

#[test]
fn null_body_deserialises_as_empty() {
    // The endpoint returns `null` (not `[]`) when it indexes nothing; the module
    // decodes through Option so that is a clean empty result.
    let parsed: Option<Vec<String>> = serde_json::from_str("null").unwrap();
    assert!(parsed.unwrap_or_default().is_empty());
    let parsed: Option<Vec<String>> =
        serde_json::from_str(r#"["a.example.com","b.example.com"]"#).unwrap();
    assert_eq!(parsed.unwrap_or_default().len(), 2);
}

#[test]
fn build_entities_classifies_subdomains_and_skips_junk() {
    let list = names(&[
        "mail.example.com",
        "dev.example.com",
        "*.example.com", // wildcard — skipped
        "notahost",      // no dot — skipped
        "",              // blank — skipped
        "unrelated.org", // off-base — retained, low confidence
    ]);
    let es = build_entities(&list, "example.com", "scan1");

    let sub = es
        .iter()
        .find(|e| e.value == "mail.example.com")
        .expect("subdomain present");
    assert!((sub.confidence - 0.72).abs() < 1e-9);
    assert!(sub.tags.iter().any(|t| t == tags::SUBDOMAIN));
    assert!(sub.tags.iter().any(|t| t == "passive-dns"));

    assert!(has_domain(&es, "dev.example.com"));
    assert!(!has_domain(&es, "*.example.com"), "wildcard skipped");
    assert!(!has_domain(&es, "notahost"), "non-host skipped");

    let other = es
        .iter()
        .find(|e| e.value == "unrelated.org")
        .expect("off-base name retained");
    assert!((other.confidence - 0.40).abs() < 1e-9);
    assert!(!other.tags.iter().any(|t| t == tags::SUBDOMAIN));
}

#[test]
fn build_entities_dedups_case_insensitively() {
    let list = names(&["API.example.com", "api.example.com", "api.example.com"]);
    let es = build_entities(&list, "example.com", "scan1");
    assert_eq!(
        es.iter().filter(|e| e.value == "api.example.com").count(),
        1,
        "case-folded duplicates collapse to one entity"
    );
}

#[test]
fn build_entities_is_deterministic_and_confidence_sorted() {
    let list = names(&["z.example.com", "a.example.com", "unrelated.org"]);
    let first = build_entities(&list, "example.com", "scan1");
    let second = build_entities(&list, "example.com", "scan1");
    let order = |v: &[Entity]| v.iter().map(|e| e.value.clone()).collect::<Vec<_>>();
    assert_eq!(order(&first), order(&second));
    let confs: Vec<f64> = first.iter().map(|e| e.confidence).collect();
    assert!(
        confs.windows(2).all(|w| w[0] >= w[1]),
        "entities must be confidence-descending: {confs:?}"
    );
}
