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
        remarks: "DOB 10 Dec 1948; Director of PALESTINE LIBERATION FRONT.".to_string(),
    }
}

fn organisation_record() -> SdnRecord {
    SdnRecord {
        ent_num: 36,
        name: "AEROCARIBBEAN AIRLINES".to_string(),
        kind: SdnKind::Organisation,
        program: "CUBA".to_string(),
        remarks: String::new(),
    }
}

fn vessel_record() -> SdnRecord {
    SdnRecord {
        ent_num: 4238,
        name: "MAR AZUL".to_string(),
        kind: SdnKind::Vessel,
        program: "CUBA".to_string(),
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
    assert!(attrs.get("remarks").is_some_and(|r| r.contains("DOB 10 Dec 1948")));
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

// ── has_enough_signal ────────────────────────────────────────────────────

#[test]
fn has_enough_signal_rejects_a_bare_single_word_query() {
    // "Zawahiri" alone (one word, one token) is exactly the too-weak-a-
    // discriminator case the gate exists to reject.
    assert!(!has_enough_signal(&["zawahiri".to_string()], 1));
}

#[test]
fn has_enough_signal_accepts_a_multiword_query_that_collapses_to_one_token() {
    // Regression: "Al Zawahiri" is two words, but name_tokens drops the
    // 2-character "Al" particle, leaving only ["zawahiri"]. Rejecting this
    // identically to a bare one-word query would silently unscreen every
    // short-particle name shape (Arabic "Al"/"El", Vietnamese "Vo"/"Le", …)
    // this list is full of — the querier DID supply two distinguishing parts.
    assert!(has_enough_signal(&["zawahiri".to_string()], 2));
}

#[test]
fn has_enough_signal_rejects_empty_tokens_regardless_of_word_count() {
    // Every token was filtered out (e.g. "It Is") — nothing left to match
    // against, so querying would be pointless no matter how many words.
    assert!(!has_enough_signal(&[], 2));
}

#[test]
fn has_enough_signal_accepts_two_surviving_tokens_as_before() {
    let toks = ["abu".to_string(), "abbas".to_string()];
    assert!(has_enough_signal(&toks, 2));
}

// ── match_records ────────────────────────────────────────────────────────

#[test]
fn match_records_take_cap_applies_after_filtering_non_entities() {
    // Regression: MAX_HITS must cap emitted ENTITIES, not raw matches. The
    // first 10 matching records are vessels (build_entity -> None); the next
    // 25 are real individuals — more than MAX_HITS on their own. The old,
    // buggy `.take(MAX_HITS)`-before-filter order would take the first 20 RAW
    // matches (10 vessels + 10 individuals), filter out the vessels, and
    // surface only 10 entities. The fix must surface the full MAX_HITS (20)
    // real hits, proving the vessels never consumed a cap slot.
    let tokens = vec!["mar".to_string(), "azul".to_string()];
    let mut records = Vec::new();
    for i in 0..10u64 {
        records.push(SdnRecord {
            ent_num: i,
            name: "MAR AZUL".to_string(),
            kind: SdnKind::Vessel,
            program: String::new(),
            remarks: String::new(),
        });
    }
    for i in 10..35u64 {
        records.push(SdnRecord {
            ent_num: i,
            name: "MAR AZUL".to_string(),
            kind: SdnKind::Individual,
            program: String::new(),
            remarks: String::new(),
        });
    }
    let entities = match_records(&records, &tokens, "s");
    assert_eq!(entities.len(), MAX_HITS, "cap must count emitted entities: {entities:?}");
    assert!(
        entities.iter().all(|e| e.kind == EntityKind::Person),
        "every emitted entity must be a real (Individual) hit, not a filtered-out vessel: {entities:?}"
    );
}

#[test]
fn match_records_returns_empty_for_no_matches() {
    let tokens = vec!["nomatch".to_string(), "atall".to_string()];
    let records = vec![individual_record()];
    assert!(match_records(&records, &tokens, "s").is_empty());
}

