use super::*;

#[test]
fn accepts_fullname_and_organisation_only() {
    let m = SanctionsOfac;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Abu Abbas")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Banco Nacional de Cuba")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
}

#[test]
fn module_metadata() {
    assert_eq!(SanctionsOfac.name(), "sanctions_ofac");
    assert_eq!(SanctionsOfac.priority(), 111);
    assert_eq!(SanctionsOfac.cost(), ModuleCost::Free);
}

#[test]
fn produces_only_person_and_organisation() {
    let kinds = SanctionsOfac.produces();
    assert!(kinds.contains(&EntityKind::Person));
    assert!(kinds.contains(&EntityKind::Organisation));
    assert_eq!(kinds.len(), 2);
}

fn individual_record() -> SdnRecord {
    SdnRecord {
        ent_num: 2674,
        name: "ABBAS, Abu".to_string(),
        kind: SdnKind::Individual,
        program: "SDGT".to_string(),
        title: "Director of PALESTINE LIBERATION FRONT".to_string(),
        remarks: "DOB 10 Dec 1948; Director of PALESTINE LIBERATION FRONT.".to_string(),
    }
}

fn organisation_record() -> SdnRecord {
    SdnRecord {
        ent_num: 36,
        name: "AEROCARIBBEAN AIRLINES".to_string(),
        kind: SdnKind::Organisation,
        program: "CUBA".to_string(),
        title: String::new(),
        remarks: String::new(),
    }
}

fn vessel_record() -> SdnRecord {
    SdnRecord {
        ent_num: 4238,
        name: "MAR AZUL".to_string(),
        kind: SdnKind::Vessel,
        program: "CUBA".to_string(),
        title: String::new(),
        remarks: String::new(),
    }
}

#[test]
fn individual_hit_emits_person_with_reordered_name_and_caution() {
    let e = build_entity(&individual_record(), "s").expect("individual should emit an entity");
    assert_eq!(e.kind, EntityKind::Person);
    assert_eq!(e.value, "Abu Abbas");
    assert!((e.confidence - HIT_CONFIDENCE).abs() < 1e-9);
    assert!(e.has_tag("sanctions") && e.has_tag("ofac") && e.has_tag("regulatory-action"));
    assert!(e.has_tag("needs-identity-verification"));
    let attrs = &e.evidence[0].attributes;
    assert!(attrs.contains_key("caution"));
    assert_eq!(attrs.get("program").map(String::as_str), Some("SDGT"));
    assert_eq!(
        attrs.get("title").map(String::as_str),
        Some("Director of PALESTINE LIBERATION FRONT")
    );
    assert!(attrs.get("remarks").is_some_and(|r| r.contains("DOB 10 Dec 1948")));
}

#[test]
fn hit_with_blank_title_omits_title_attribute() {
    let e = build_entity(&organisation_record(), "s").expect("organisation should emit an entity");
    // organisation_record() has an empty title (the -0- placeholder normalises
    // to "") — the attribute must be absent, not present-and-empty.
    assert!(!e.evidence[0].attributes.contains_key("title"));
}

#[test]
fn organisation_hit_emits_organisation_without_reordering() {
    let e = build_entity(&organisation_record(), "s").expect("organisation should emit an entity");
    assert_eq!(e.kind, EntityKind::Organisation);
    assert_eq!(e.value, "AEROCARIBBEAN AIRLINES");
    assert!(e.has_tag("sanctions") && e.has_tag("needs-identity-verification"));
    // No remarks on this record → the attribute is simply absent, not empty-string.
    assert!(!e.evidence[0].attributes.contains_key("remarks"));
}

#[test]
fn vessel_and_aircraft_rows_emit_no_entity() {
    assert!(build_entity(&vessel_record(), "s").is_none());
    let mut aircraft = vessel_record();
    aircraft.kind = SdnKind::Aircraft;
    assert!(build_entity(&aircraft, "s").is_none());
}

fn indiv(ent_num: u64) -> SdnRecord {
    SdnRecord {
        ent_num,
        name: "SMITH, JOHN".to_string(),
        kind: SdnKind::Individual,
        program: "SDGT".to_string(),
        title: String::new(),
        remarks: String::new(),
    }
}

#[test]
fn screen_stamps_total_matches_and_flags_truncation_beyond_the_cap() {
    // T2.130 regression: 25 SDN individuals all matching "john smith" — more than
    // the MAX_HITS cap. Because parse_sdn_csv preserves file order with no
    // ranking, the old `.take(MAX_HITS)` dropped every match past the 20th in
    // arbitrary order with NO signal — a genuine OFAC hit could be the 21st and
    // vanish, and the operator saw 20 entities believing that was the whole set.
    let records: Vec<SdnRecord> = (0..25).map(indiv).collect();
    let tokens = name_tokens("John Smith");
    let ents = screen(&records, &tokens, "scan");

    assert_eq!(ents.len(), MAX_HITS, "only MAX_HITS entities are emitted");
    for e in &ents {
        assert_eq!(
            e.evidence[0]
                .attributes
                .get("total_matches")
                .map(String::as_str),
            Some("25"),
            "every emitted hit must record the TRUE match total, not just the cap"
        );
        assert!(
            e.has_tag("truncated"),
            "a capped result must be tagged truncated so it can't read as complete"
        );
    }
}

#[test]
fn screen_reports_true_total_without_truncating_below_the_cap() {
    // Below the cap: the total is still surfaced (3), but nothing is truncated.
    let records: Vec<SdnRecord> = (0..3).map(indiv).collect();
    let tokens = name_tokens("John Smith");
    let ents = screen(&records, &tokens, "scan");

    assert_eq!(ents.len(), 3);
    for e in &ents {
        assert_eq!(
            e.evidence[0]
                .attributes
                .get("total_matches")
                .map(String::as_str),
            Some("3")
        );
        assert!(
            !e.has_tag("truncated"),
            "an uncapped result must NOT be tagged truncated"
        );
    }
}

