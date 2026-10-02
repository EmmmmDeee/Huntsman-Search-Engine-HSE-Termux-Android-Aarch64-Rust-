use super::*;
use crate::core::confidence;

#[test]
fn accepts_domain_and_url_only() {
    let m = SubdomainCenter;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "github.com")));
    assert!(m.accepts(&Target::new(TargetKind::Url, "https://github.com/x")));
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

#[test]
fn metadata_sane() {
    let m = SubdomainCenter;
    assert_eq!(m.name(), "subdomain_center");
    assert!(!m.description().is_empty());
    assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    assert!(matches!(m.category(), ModuleCategory::DnsRecon));
    assert!(m.max_timeout_ms() > crate::MODULE_TIMEOUT_MS);
    assert_eq!(m.attack_techniques(), &["T1596.001"]);
    assert!(m.produces().contains(&EntityKind::Domain));
}

#[test]
fn build_entities_keeps_real_subdomains_and_drops_noise() {
    // Shape mirrors the live API (a bare array of FQDNs).
    let subs = vec![
        "mail.github.com".to_string(),
        "API.GitHub.com".to_string(),      // case-normalised
        "web5341.github.com.".to_string(), // trailing root dot stripped
        "*.cdn.github.com".to_string(),    // wildcard defanged → cdn.github.com
        "github.com".to_string(),          // the apex itself → skipped
        "mail.github.com".to_string(),     // duplicate → folded
        "evil.example.org".to_string(),    // not under the queried domain → dropped
        "localhost".to_string(),           // non-dotted → skipped
        String::new(),                     // empty → skipped
    ];
    let ents = build_entities(&subs, "github.com", "s");

    let mut vals: Vec<&str> = ents.iter().map(|e| e.value.as_str()).collect();
    vals.sort_unstable();
    assert_eq!(
        vals,
        vec![
            "api.github.com",
            "cdn.github.com",
            "mail.github.com",
            "web5341.github.com"
        ]
    );
    assert!(ents.iter().all(|e| {
        e.kind == EntityKind::Domain
            && e.has_tag(SRC)
            && e.has_tag(tags::SUBDOMAIN)
            && (e.confidence - confidence::VERY_HIGH).abs() < 1e-9
    }));
}

#[test]
fn build_entities_empty_yields_nothing() {
    assert!(build_entities(&[], "github.com", "s").is_empty());
}

#[test]
fn a_www_alias_of_the_apex_is_skipped_like_the_bare_apex() {
    // Regression, mirroring the "github.com the apex itself → skipped" case
    // above: "www.github.com" is a DIFFERENT raw string from the queried
    // "github.com", so the pre-fix raw `host == domain_l` check missed it —
    // yet `Entity::new` strips the leading "www." label and collapses it
    // onto the queried domain's own apex uid. This function's own doc
    // comment says a real subdomain is kept "never the apex itself"; a
    // www-alias IS the apex once canonicalised, so it must be skipped too.
    let subs = vec![
        "www.github.com".to_string(),
        "mail.github.com".to_string(),
    ];
    let ents = build_entities(&subs, "github.com", "s");
    let vals: Vec<&str> = ents.iter().map(|e| e.value.as_str()).collect();
    assert_eq!(
        vals,
        vec!["mail.github.com"],
        "the www-alias must be skipped exactly like the bare apex: {ents:?}"
    );
}
