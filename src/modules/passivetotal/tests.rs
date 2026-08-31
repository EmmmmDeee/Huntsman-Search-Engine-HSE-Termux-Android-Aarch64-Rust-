use super::*;

#[allow(clippy::too_many_arguments)]
fn rec(
    value: &str,
    resolve: &str,
    resolve_type: &str,
    record_type: &str,
    first_seen: &str,
    last_seen: &str,
    collected: &str,
    source: &[&str],
) -> PdnsRecord {
    PdnsRecord {
        value: Some(value.to_string()),
        resolve: Some(resolve.to_string()),
        resolve_type: if resolve_type.is_empty() {
            None
        } else {
            Some(resolve_type.to_string())
        },
        record_type: if record_type.is_empty() {
            None
        } else {
            Some(record_type.to_string())
        },
        first_seen: if first_seen.is_empty() {
            None
        } else {
            Some(first_seen.to_string())
        },
        last_seen: if last_seen.is_empty() {
            None
        } else {
            Some(last_seen.to_string())
        },
        collected: if collected.is_empty() {
            None
        } else {
            Some(collected.to_string())
        },
        source: source.iter().map(|s| (*s).to_string()).collect(),
    }
}

fn of_kind(ents: &[Entity], kind: EntityKind) -> Vec<&Entity> {
    ents.iter().filter(|e| e.kind == kind).collect()
}

fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
    e.evidence[0].attributes.get(k).map(String::as_str)
}

// ── trait metadata ────────────────────────────────────────────────────

#[test]
fn accepts_domain_and_ip_only() {
    let m = PassiveTotal;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "github.com")));
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "140.82.114.3")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "torvalds")));
    assert!(!m.accepts(&Target::new(TargetKind::Url, "https://github.com/x")));
}

#[test]
fn metadata_sane() {
    let m = PassiveTotal;
    assert_eq!(m.name(), "passivetotal");
    assert!(!m.description().is_empty());
    assert!(matches!(m.cost(), ModuleCost::Paid));
    assert!(matches!(m.category(), ModuleCategory::Infrastructure));
    // Network module: budget must exceed the 3 s default (architecture guard).
    assert!(m.max_timeout_ms() > crate::MODULE_TIMEOUT_MS);
    let techniques = m.attack_techniques();
    assert!(techniques.contains(&"T1590.005"));
    assert!(techniques.contains(&"T1596.001"));
    let produces = m.produces();
    assert!(produces.contains(&EntityKind::Domain));
    assert!(produces.contains(&EntityKind::IpAddress));
    assert!(m.cache_ttl_secs() > 0);
}

// ── pure helpers ──────────────────────────────────────────────────────

#[test]
fn helper_classifiers() {
    assert!(is_ip("140.82.114.3"));
    assert!(is_ip("2606:4700:10::6814:179a"));
    assert!(!is_ip("github.com"));

    assert!(is_hostname("www.furth.com.ar"));
    assert!(!is_hostname("140.82.114.3")); // IP is not a hostname
    assert!(!is_hostname("localhost")); // no dot
    assert!(!is_hostname("")); // blank

    assert_eq!(normalise("Example.COM."), "example.com");
    assert_eq!(normalise("  example.com  "), "example.com");
}

// ── forward (domain target) ───────────────────────────────────

#[test]
fn forward_maps_ip_answers_and_infra_domains_and_scopes_them() {
    let recs = vec![
        rec(
            "github.com",
            "140.82.114.3",
            "ip",
            "A",
            "2019-08-06 22:20:46",
            "2026-07-30 08:14:20",
            "2026-07-30 08:14:20",
            &["riskiq"],
        ),
        // MX to an external provider -> EXTERNAL scope.
        rec(
            "github.com",
            "aspmx.l.google.com",
            "domain",
            "MX",
            "2015-01-01 00:00:00",
            "2026-07-01 00:00:00",
            "2026-07-01 00:00:00",
            &["riskiq", "pingly"],
        ),
        // NS delegation to an in-zone host -> SUBDOMAIN scope.
        rec(
            "github.com",
            "ns.github.com",
            "domain",
            "NS",
            "",
            "2026-07-01 00:00:00",
            "",
            &[],
        ),
        // Duplicate A row -> folded.
        rec("github.com", "140.82.114.3", "ip", "A", "", "", "", &[]),
        // Blank resolve -> skipped.
        rec("github.com", "", "ip", "A", "", "", "", &[]),
    ];
    let ents = build_entities(&recs, "github.com", false, "s");

    let ips = of_kind(&ents, EntityKind::IpAddress);
    assert_eq!(ips.len(), 1, "duplicate A folded: {ips:?}");
    assert_eq!(ips[0].value, "140.82.114.3");
    assert!((ips[0].confidence - confidence::HIGH).abs() < 1e-9);
    assert!(ips[0].has_tag(SRC) && ips[0].has_tag(PASSIVE_DNS));
    assert_eq!(attr(ips[0], "record_type"), Some("A"));
    assert_eq!(attr(ips[0], "first_seen"), Some("2019-08-06 22:20:46"));
    assert_eq!(attr(ips[0], "last_seen"), Some("2026-07-30 08:14:20"));
    assert_eq!(attr(ips[0], "sources"), Some("riskiq"));

    let domains = of_kind(&ents, EntityKind::Domain);
    assert_eq!(domains.len(), 2, "mx + ns; blank resolve skipped");

    let mx = domains
        .iter()
        .copied()
        .find(|e| e.value == "aspmx.l.google.com")
        .expect("external MX present");
    assert!(mx.has_tag("mx") && mx.has_tag(tags::EXTERNAL));
    assert!(!mx.has_tag(tags::SUBDOMAIN));
    assert_eq!(attr(mx, "sources"), Some("riskiq,pingly"));

    let ns = domains
        .iter()
        .copied()
        .find(|e| e.value == "ns.github.com")
        .expect("in-zone NS present");
    assert!(ns.has_tag("ns") && ns.has_tag(tags::SUBDOMAIN));
    assert!(!ns.has_tag(tags::EXTERNAL));
    // No sources / first_seen supplied on this record -> attrs omitted.
    assert_eq!(attr(ns, "sources"), None);
    assert_eq!(attr(ns, "first_seen"), None);
}

#[test]
fn forward_falls_back_to_shape_when_resolve_type_is_blank() {
    // No `resolveType` field at all — classification falls back to whether
    // `resolve` parses as an IP literal.
    let recs = vec![rec(
        "example.com",
        "93.184.216.34",
        "",
        "A",
        "",
        "",
        "",
        &[],
    )];
    let ents = build_entities(&recs, "example.com", false, "s");
    assert_eq!(ents.len(), 1);
    assert_eq!(ents[0].kind, EntityKind::IpAddress);
    assert_eq!(ents[0].value, "93.184.216.34");
}

#[test]
fn forward_rejects_a_type_ip_answer_that_does_not_actually_parse() {
    // resolveType says "ip" but the value is garbage — never fabricate an
    // IpAddress entity from an unparsable string.
    let recs = vec![rec("example.com", "not-an-ip", "ip", "A", "", "", "", &[])];
    assert!(build_entities(&recs, "example.com", false, "s").is_empty());
}

// ── reverse (IP target) ───────────────────────────────────────

#[test]
fn reverse_maps_value_side_to_domain_pivots() {
    let recs = vec![
        rec(
            "github.com",
            "140.82.114.3",
            "ip",
            "A",
            "2019-08-06 22:20:46",
            "2026-07-30 08:14:20",
            "",
            &["riskiq"],
        ),
        rec(
            "ghe.com",
            "140.82.114.3",
            "ip",
            "A",
            "",
            "",
            "",
            &["riskiq"],
        ),
        // Duplicate -> folded.
        rec("github.com", "140.82.114.3", "ip", "A", "", "", "", &[]),
        // IP-shaped `value` -> not a hostname, skipped.
        rec("9.9.9.9", "140.82.114.3", "ip", "A", "", "", "", &[]),
    ];
    let ents = build_entities(&recs, "140.82.114.3", true, "s");

    let mut vals: Vec<&str> = ents.iter().map(|e| e.value.as_str()).collect();
    vals.sort_unstable();
    assert_eq!(vals, vec!["ghe.com", "github.com"]);
    assert!(ents.iter().all(|e| {
        e.kind == EntityKind::Domain
            && e.has_tag(SRC)
            && e.has_tag(PASSIVE_DNS)
            && e.has_tag("reverse-ip")
    }));
}

// ── edge cases ────────────────────────────────────────────────────

#[test]
fn empty_response_yields_nothing() {
    assert!(build_entities(&[], "github.com", false, "s").is_empty());
    assert!(build_entities(&[], "140.82.114.3", true, "s").is_empty());
}

#[test]
fn missing_optional_fields_still_yield_an_entity_with_no_optional_attrs() {
    // Bare record: no recordType/timestamps/source at all.
    let recs = vec![PdnsRecord {
        value: Some("example.com".to_string()),
        resolve: Some("203.0.113.7".to_string()),
        resolve_type: Some("ip".to_string()),
        record_type: None,
        first_seen: None,
        last_seen: None,
        collected: None,
        source: vec![],
    }];
    let ents = build_entities(&recs, "example.com", false, "s");
    assert_eq!(ents.len(), 1);
    assert_eq!(ents[0].value, "203.0.113.7");
    assert_eq!(attr(&ents[0], "record_type"), None);
    assert_eq!(attr(&ents[0], "sources"), None);
    assert_eq!(attr(&ents[0], "collected"), None);
}

#[test]
fn record_count_is_capped_at_result_limit() {
    let recs: Vec<PdnsRecord> = (0..(RESULT_LIMIT + 50))
        .map(|i| {
            let ip = format!("10.0.{}.{}", i / 256, i % 256);
            rec("example.com", &ip, "ip", "A", "", "", "", &[])
        })
        .collect();
    let ents = build_entities(&recs, "example.com", false, "s");
    assert_eq!(ents.len(), RESULT_LIMIT);
}
