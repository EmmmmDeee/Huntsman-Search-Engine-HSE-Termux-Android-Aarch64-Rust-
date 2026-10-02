use super::*;

#[test]
fn accepts_domain_and_ip() {
    let m = ThreatFox;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

#[test]
fn cost_is_key_gated() {
    // ThreatFox requires an Auth-Key header on every request
    // (https://threatfox.abuse.ch/api).
    assert!(matches!(ThreatFox.cost(), ModuleCost::KeyGated));
}

fn ioc(json: &str) -> Ioc {
    serde_json::from_str(json).expect("should succeed")
}

fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
    e.evidence[0].attributes.get(k).map(String::as_str)
}

#[test]
fn single_ioc_marks_malicious_with_threat_band_confidence() {
    let e = build_ioc_entity(
        EntityKind::Domain,
        "evil.test",
        &[ioc(
            r#"{"ioc_type":"domain","threat_type":"botnet_cc","malware":"CobaltStrike",
                "confidence_level":75}"#,
        )],
        "s",
    );
    assert_eq!(e.kind, EntityKind::Domain);
    assert!(
        e.has_tag("threatfox")
            && e.has_tag(crate::core::tags::THREAT_INTEL)
            && e.has_tag(crate::core::tags::MALICIOUS)
    );
    assert!((e.confidence - 0.92).abs() < 1e-9);
    assert_eq!(attr(&e, "hits"), Some("1"));
    assert_eq!(attr(&e, "malware_families"), Some("CobaltStrike"));
    assert_eq!(attr(&e, "ioc_types"), Some("domain"));
    assert_eq!(attr(&e, "threat_types"), Some("botnet_cc"));
    assert_eq!(attr(&e, "max_confidence"), Some("75"));
}

#[test]
fn aggregates_dedup_sorted_and_takes_max_confidence_and_outer_window() {
    let e = build_ioc_entity(
        EntityKind::IpAddress,
        "1.2.3.4",
        &[
            ioc(
                r#"{"malware":"WSHRAT","ioc_type":"ip:port","confidence_level":40,
                    "first_seen":"2024-03-01","last_seen":"2024-03-10",
                    "tags":["RAT","keylogger"]}"#,
            ),
            ioc(
                r#"{"malware":"Magecart","ioc_type":"ip:port","confidence_level":90,
                    "first_seen":"2024-01-15","last_seen":"2024-06-20",
                    "tags":["skimmer","RAT"]}"#,
            ),
        ],
        "s",
    );
    assert_eq!(e.kind, EntityKind::IpAddress);
    assert_eq!(attr(&e, "hits"), Some("2"));
    // BTreeSet → deduplicated + lexicographically sorted.
    assert_eq!(attr(&e, "malware_families"), Some("Magecart,WSHRAT"));
    assert_eq!(attr(&e, "ioc_types"), Some("ip:port")); // deduped to one
    assert_eq!(attr(&e, "ioc_tags"), Some("RAT,keylogger,skimmer"));
    // max confidence, not last-wins.
    assert_eq!(attr(&e, "max_confidence"), Some("90"));
    // Outer window: earliest first_seen, latest last_seen across the batch.
    assert_eq!(attr(&e, "first_seen"), Some("2024-01-15"));
    assert_eq!(attr(&e, "last_seen"), Some("2024-06-20"));
}

#[test]
fn sparse_ioc_omits_absent_attributes() {
    // Only ioc_type present; everything else null/empty must be omitted,
    // not emitted blank.
    let e = build_ioc_entity(
        EntityKind::Domain,
        "x.test",
        &[ioc(
            r#"{"ioc_type":"domain","malware":"  ","confidence_level":0}"#,
        )],
        "s",
    );
    assert_eq!(attr(&e, "ioc_types"), Some("domain"));
    assert_eq!(attr(&e, "malware_families"), None); // whitespace-only dropped
    assert_eq!(attr(&e, "max_confidence"), None); // 0 is not surfaced
    assert_eq!(attr(&e, "first_seen"), None);
    assert_eq!(attr(&e, "threat_types"), None);
}

#[test]
fn family_and_tag_lists_are_capped() {
    let many_families: Vec<Ioc> = (0..20)
        .map(|i| ioc(&format!(r#"{{"malware":"fam{i:02}"}}"#)))
        .collect();
    let e = build_ioc_entity(EntityKind::Domain, "x.test", &many_families, "s");
    let fams = attr(&e, "malware_families").expect("should succeed");
    assert_eq!(fams.split(',').count(), MAX_FAMILIES);

    let big_tags = ioc(&format!(
        r#"{{"tags":[{}]}}"#,
        (0..30)
            .map(|i| format!(r#""t{i:02}""#))
            .collect::<Vec<_>>()
            .join(",")
    ));
    let e = build_ioc_entity(EntityKind::Domain, "x.test", &[big_tags], "s");
    assert_eq!(
        attr(&e, "ioc_tags").expect("should succeed").split(',').count(),
        MAX_IOC_TAGS
    );
}

#[test]
fn a_capped_list_records_the_true_distinct_count_and_flags_truncation() {
    // Regression: `.take(N)` silently dropped every family/tag past the cap
    // with nothing recording the true distinct count, so a shared C2
    // indicator correlated to more families than the cap showed only the
    // alphabetically-first ones with no way for an operator to tell the list
    // was incomplete.
    let many_families: Vec<Ioc> = (0..20)
        .map(|i| ioc(&format!(r#"{{"malware":"fam{i:02}"}}"#)))
        .collect();
    let e = build_ioc_entity(EntityKind::Domain, "x.test", &many_families, "s");
    assert_eq!(attr(&e, "malware_families_total"), Some("20"));
    assert!(
        attr(&e, "malware_families_truncated")
            .is_some_and(|s| s.contains("20") && s.contains(&MAX_FAMILIES.to_string())),
        "must name both the true total and the emitted cap, got {:?}",
        attr(&e, "malware_families_truncated")
    );

    let big_tags = ioc(&format!(
        r#"{{"tags":[{}]}}"#,
        (0..30)
            .map(|i| format!(r#""t{i:02}""#))
            .collect::<Vec<_>>()
            .join(",")
    ));
    let e = build_ioc_entity(EntityKind::Domain, "x.test", &[big_tags], "s");
    assert_eq!(attr(&e, "ioc_tags_total"), Some("30"));
    assert!(attr(&e, "ioc_tags_truncated").is_some());
}

#[test]
fn an_uncapped_list_records_the_total_but_no_truncation_flag() {
    // No truncation → no misleading "_truncated" note, but the total count is
    // still recorded (matching gleif_lei::note_child_coverage's convention of
    // always stating emitted/total, not just on the truncated path).
    let e = build_ioc_entity(
        EntityKind::Domain,
        "evil.test",
        &[ioc(r#"{"malware":"CobaltStrike"}"#)],
        "s",
    );
    assert_eq!(attr(&e, "malware_families_total"), Some("1"));
    assert_eq!(attr(&e, "malware_families_truncated"), None);
}
