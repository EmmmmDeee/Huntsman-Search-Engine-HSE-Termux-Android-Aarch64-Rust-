use super::*;

#[test]
fn accepts_domain_only() {
    let m = C99;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Url, "https://example.com")));
}

#[test]
fn cost_is_paid() {
    assert!(matches!(C99.cost(), ModuleCost::Paid));
}

#[test]
fn description_non_empty() {
    assert!(!C99.description().is_empty());
}

#[test]
fn category_is_infrastructure() {
    assert!(matches!(C99.category(), ModuleCategory::Infrastructure));
}

fn body(json: &str) -> SubdomainFinderResp {
    serde_json::from_str(json).expect("should succeed")
}

fn of_kind(ents: &[Entity], kind: EntityKind) -> Vec<&Entity> {
    ents.iter().filter(|e| e.kind == kind).collect()
}

fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
    e.evidence[0].attributes.get(k).map(String::as_str)
}

// ── build_entities (pure) ──────────────────────────────────────────────

#[test]
fn realistic_response_yields_subdomains_and_resolved_ips() {
    // Mirrors the OpenAPI spec's own worked example shape: two unresolved
    // ("none") entries and one resolved, non-Cloudflare entry.
    let b = body(
        r#"{
            "success": true,
            "subdomains": [
                {"subdomain": "autodiscover.example.com", "ip": "none", "cloudflare": false},
                {"subdomain": "mail.example.com", "ip": "none", "cloudflare": false},
                {"subdomain": "www.example.com", "ip": "23.77.197.7", "cloudflare": false}
            ],
            "cached": true,
            "cache_time": "2025-06-18 03:54:11"
        }"#,
    );
    let ents = build_entities("example.com", &b, "s");

    let domains = of_kind(&ents, EntityKind::Domain);
    assert_eq!(domains.len(), 3, "one Domain per subdomain entry");
    assert!(domains.iter().all(|e| e.has_tag("c99") && e.has_tag(tags::SUBDOMAIN)));
    assert!(domains.iter().all(|e| !e.has_tag("cloudflare")));

    let www = domains
        .iter()
        .find(|e| e.raw_value == "www.example.com")
        .expect("should succeed");
    assert!((www.confidence - confidence::HIGH_PLUSPLUS).abs() < 1e-9);
    assert_eq!(attr(www, "resolved_ip"), Some("23.77.197.7"));
    assert_eq!(attr(www, "total_subdomains"), Some("3"));
    assert_eq!(attr(www, "cached"), Some("true"));
    assert_eq!(attr(www, "cache_time"), Some("2025-06-18 03:54:11"));
    assert_eq!(attr(www, "cloudflare"), Some("false"));

    let unresolved = domains
        .iter()
        .find(|e| e.value == "mail.example.com")
        .expect("should succeed");
    assert_eq!(attr(unresolved, "resolved_ip"), None, "\"none\" must not become an IP attr");

    // Only the one resolved, real address becomes a corroborating IP entity.
    let ips = of_kind(&ents, EntityKind::IpAddress);
    assert_eq!(ips.len(), 1);
    assert_eq!(ips[0].value, "23.77.197.7");
    assert!(ips[0].has_tag("c99") && !ips[0].has_tag("cloudflare"));
}

#[test]
fn cloudflare_flag_tags_both_domain_and_ip_without_dropping_either() {
    let b = body(
        r#"{
            "success": true,
            "subdomains": [
                {"subdomain": "cdn.example.com", "ip": "104.16.1.1", "cloudflare": true}
            ]
        }"#,
    );
    let ents = build_entities("example.com", &b, "s");
    let d = of_kind(&ents, EntityKind::Domain);
    let ip = of_kind(&ents, EntityKind::IpAddress);
    assert_eq!(d.len(), 1);
    assert_eq!(ip.len(), 1, "a cloudflare-flagged IP is still emitted, not dropped");
    assert!(d[0].has_tag("cloudflare"));
    assert!(ip[0].has_tag("cloudflare"));
    assert_eq!(attr(d[0], "cloudflare"), Some("true"));
}

#[test]
fn duplicate_resolved_ip_across_subdomains_deduplicates_the_ip_entity() {
    let b = body(
        r#"{
            "success": true,
            "subdomains": [
                {"subdomain": "a.example.com", "ip": "9.9.9.9", "cloudflare": false},
                {"subdomain": "b.example.com", "ip": "9.9.9.9", "cloudflare": false}
            ]
        }"#,
    );
    let ents = build_entities("example.com", &b, "s");
    assert_eq!(of_kind(&ents, EntityKind::Domain).len(), 2, "both subdomains kept");
    assert_eq!(of_kind(&ents, EntityKind::IpAddress).len(), 1, "shared IP emitted once");
}

#[test]
fn non_subdomain_entry_gets_lower_confidence_and_no_subdomain_tag() {
    // Defensive: if C99 ever echoes back a host that isn't actually under the
    // queried domain (e.g. a CNAME target), it must not be mislabelled.
    let b = body(
        r#"{"success": true, "subdomains": [{"subdomain": "cdn.fastly.net", "ip": "none", "cloudflare": false}]}"#,
    );
    let ents = build_entities("example.com", &b, "s");
    let d = &of_kind(&ents, EntityKind::Domain)[0];
    assert!((d.confidence - confidence::MEDIUM_PLUS).abs() < 1e-9);
    assert!(!d.has_tag(tags::SUBDOMAIN));
}

#[test]
fn queried_domain_echoed_back_verbatim_is_skipped() {
    let b = body(
        r#"{"success": true, "subdomains": [{"subdomain": "example.com", "ip": "none", "cloudflare": false}]}"#,
    );
    assert!(build_entities("example.com", &b, "s").is_empty());
}

#[test]
fn bare_ip_literal_and_blank_subdomain_entries_are_skipped() {
    let b = body(
        r#"{"success": true, "subdomains": [
            {"subdomain": "1.2.3.4", "ip": "none", "cloudflare": false},
            {"subdomain": "", "ip": "none", "cloudflare": false},
            {"subdomain": null, "ip": "none", "cloudflare": false}
        ]}"#,
    );
    assert!(build_entities("example.com", &b, "s").is_empty());
}

#[test]
fn empty_subdomains_yields_nothing() {
    let b = body(r#"{"success": true, "subdomains": []}"#);
    assert!(build_entities("example.com", &b, "s").is_empty());
}

#[test]
fn missing_optional_fields_default_cleanly() {
    // No `cached`/`cache_time` in the body at all — must not error or emit
    // those attrs.
    let b = body(r#"{"success": true, "subdomains": [{"subdomain": "www.example.com"}]}"#);
    let ents = build_entities("example.com", &b, "s");
    assert_eq!(ents.len(), 1, "no ip field at all -> no corroborating IpAddress");
    let d = &ents[0];
    assert_eq!(attr(d, "cached"), None);
    assert_eq!(attr(d, "cache_time"), None);
    assert_eq!(attr(d, "resolved_ip"), None);
}

// ── resolved_ip (pure) ──────────────────────────────────────────────────

#[test]
fn resolved_ip_rejects_none_placeholder_and_garbage() {
    assert_eq!(resolved_ip(Some("none")), None);
    assert_eq!(resolved_ip(Some("None")), None, "case-insensitive");
    assert_eq!(resolved_ip(Some("")), None);
    assert_eq!(resolved_ip(Some("not-an-ip")), None);
    assert_eq!(resolved_ip(None), None);
    assert_eq!(resolved_ip(Some(" 1.2.3.4 ")), Some("1.2.3.4"));
    assert_eq!(resolved_ip(Some("2001:db8::1")), Some("2001:db8::1"));
}

// ── normalize_subdomain (pure) ───────────────────────────────────────────

#[test]
fn normalize_subdomain_strips_trailing_dot_and_lowercases() {
    assert_eq!(
        normalize_subdomain(Some("WWW.Example.COM."), "example.com"),
        Some("www.example.com".to_string())
    );
}

#[test]
fn normalize_subdomain_rejects_whitespace_and_dotless() {
    assert_eq!(normalize_subdomain(Some("has space.com"), "example.com"), None);
    assert_eq!(normalize_subdomain(Some("localhost"), "example.com"), None);
}
