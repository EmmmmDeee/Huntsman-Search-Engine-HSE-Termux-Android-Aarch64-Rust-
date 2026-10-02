use super::{
    GleifLei, ORG_EXACT,
    helpers::{au_abn_acn, locality, non_empty, query_url, record_evidence},
    transform::records_to_entities,
    types::{GleifAddress, GleifEntity, GleifResp},
};
use crate::core::{
    confidence,
    entity::EntityKind,
    module::{Module, ModuleCategory, ModuleCost},
    scan::{Target, TargetKind},
};

fn sample() -> GleifResp {
    // Mirrors real api.gleif.org rows (BHP: AU with ACN; a GB entity).
    let raw = r#"{
        "meta": {"pagination": {"total": 2}},
        "data": [
            {"attributes": {"lei": "WZE1WSENV6JSZFK0JC28", "entity": {
                "legalName": {"name": "BHP GROUP LIMITED"},
                "jurisdiction": "AU", "status": "ACTIVE",
                "registeredAs": "004 028 077",
                "legalAddress": {"addressLines": ["171 Collins Street"], "city": "Melbourne", "region": "AU-VIC", "postalCode": "3000", "country": "AU"},
                "headquartersAddress": {"addressLines": ["171 Collins Street"], "city": "Melbourne", "region": "AU-VIC", "postalCode": "3000", "country": "AU"}
            }}},
            {"attributes": {"lei": "894500OGEMX4F6STBR39", "entity": {
                "legalName": {"name": "BHP Billiton Group Limited"},
                "jurisdiction": "GB", "status": "ACTIVE",
                "registeredAs": "03298904",
                "legalAddress": {"addressLines": ["Nova South, 160 Victoria Street"], "city": "London", "region": "GB-LND", "postalCode": "SW1E 5LB", "country": "GB"}
            }}}
        ]
    }"#;
    serde_json::from_str(raw).expect("should succeed")
}

#[test]
fn accepts_organisation_only() {
    let m = GleifLei;
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "BHP Group Limited")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "John Smith")));
    assert!(!m.accepts(&Target::new(TargetKind::AbnAcn, "004028077")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

#[test]
fn module_metadata() {
    let m = GleifLei;
    assert_eq!(m.name(), "gleif_lei");
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::Free);
    assert_eq!(m.category(), ModuleCategory::Corporate);
    assert!(m.max_timeout_ms() > 3_000);
    assert!((110..=118).contains(&m.priority()));
}

#[test]
fn two_records_geocoding_to_the_same_point_dedup_to_one_coordinates_entity() {
    // Regression: `city_coords` is a many-to-one phrase lookup, so two exact
    // matches with different-grain HQ-address composition (one carrying a
    // postal code, one not) for the same city both independently resolved to
    // the identical centroid — `records_to_entities` has no gate of any kind
    // on the emitted Coordinates entity.
    let raw = r#"{
        "meta": {"pagination": {"total": 2}},
        "data": [
            {"attributes": {"lei": "AAAAAAAAAAAAAAAAAAAA", "entity": {
                "legalName": {"name": "Acme Holdings Pty Ltd"},
                "jurisdiction": "AU", "status": "ACTIVE",
                "headquartersAddress": {"city": "Sydney", "region": "AU-NSW", "postalCode": "2000", "country": "AU"}
            }}},
            {"attributes": {"lei": "BBBBBBBBBBBBBBBBBBBB", "entity": {
                "legalName": {"name": "Acme Trading Co"},
                "jurisdiction": "AU", "status": "ACTIVE",
                "headquartersAddress": {"city": "Sydney", "country": "AU"}
            }}}
        ]
    }"#;
    let resp: GleifResp = serde_json::from_str(raw).expect("should succeed");
    let mut ents = records_to_entities(&resp, "Acme", "scan");
    let raw_coords = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Coordinates)
        .count();
    assert_eq!(
        raw_coords, 2,
        "sanity: two differently-composed Sydney addresses must both resolve via city_coords, or this fixture doesn't exercise the bug"
    );
    crate::core::entity::dedup_merge_entities(&mut ents);
    let coords = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Coordinates)
        .count();
    assert_eq!(
        coords, 1,
        "two records resolving to the same point must dedup to one Coordinates entity: {ents:?}"
    );
}

#[test]
fn au_entity_emits_acn_but_foreign_does_not() {
    let resp = sample();
    // Seed "BHP" matches both rows on the token "BHP".
    let ents = records_to_entities(&resp, "BHP", "scan-1");

    // The AU row emits an AbnAcn (its ACN, digits-only); the GB row must not
    // (its UK company number is not an ABN/ACN).
    let abns: Vec<&str> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::AbnAcn)
        .map(|e| e.value.as_str())
        .collect();
    assert_eq!(abns, vec!["004028077"], "only the AU ACN, spaces stripped");

    // Foreign registry id is still preserved in the GB org's evidence (no omission).
    let gb = ents
        .iter()
        .find(|e| e.value == "BHP Billiton Group Limited")
        .expect("should succeed");
    assert!(
        gb.evidence[0]
            .attributes
            .iter()
            .any(|(k, v)| k == "registered_as" && v == "03298904")
    );
    assert!(gb.tags.iter().any(|t| t == "country:GB"));
}

#[test]
fn exact_match_fans_out_address_candidate_does_not() {
    let resp = sample();
    // "BHP Group Limited" matches the AU row exactly; the GB row ("Billiton")
    // is missing the token "Group"? It has Group -> also matches "BHP","Group".
    // Use a query that is exact for AU only: tokens BHP, GROUP, LIMITED.
    let ents = records_to_entities(&resp, "BHP Group Limited", "s");
    let au = ents
        .iter()
        .find(|e| e.kind == EntityKind::Organisation && e.value == "BHP GROUP LIMITED")
        .expect("should succeed");
    assert!(au.tags.iter().any(|t| t == "exact-name-match"));
    assert!((au.confidence - ORG_EXACT).abs() < f64::EPSILON);

    // The AU exact hit produces a geocodable Address (locality, region trimmed).
    let addr = ents
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("AU exact hit emits an address");
    assert_eq!(addr.value, "Melbourne, VIC 3000, AU");
    assert!(addr.tags.iter().any(|t| t == "geoint"));
    // The street line rides in evidence, not the geocode value.
    assert!(
        addr.evidence[0]
            .attributes
            .iter()
            .any(|(k, v)| k == "street" && v == "171 Collins Street")
    );

    // The GB row ("BHP Billiton Group Limited") lacks the token "Limited"? it
    // has Limited -> but lacks nothing... it lacks "BHP"? it has BHP. It has
    // Billiton extra, but all query tokens (bhp,group,limited) ARE present, so
    // it is ALSO exact. Assert it is classified (either way it must surface).
    assert!(ents.iter().any(|e| e.value == "BHP Billiton Group Limited"));
}

#[test]
fn loose_candidate_surfaces_with_full_evidence_but_no_pivot() {
    // A row that does NOT contain every seed token is a candidate: one
    // sub-floor Organisation, no AbnAcn/Address pivot, full record in evidence.
    let resp = sample();
    let ents = records_to_entities(&resp, "Rio Tinto", "s"); // matches neither name fully
    // Both rows lack "Rio"/"Tinto" -> both candidates, none exact.
    assert!(ents.iter().all(|e| e.kind == EntityKind::Organisation));
    assert!(ents.iter().all(|e| e.confidence < confidence::MEDIUM));
    assert!(
        ents.iter()
            .all(|e| e.tags.iter().any(|t| t == "name-candidate"))
    );
    // No ABN/Address entities manufactured from loose matches.
    assert!(!ents.iter().any(|e| e.kind == EntityKind::AbnAcn));
    assert!(!ents.iter().any(|e| e.kind == EntityKind::Address));
    // …but the AU row's ACN is still in evidence — nothing omitted.
    let au = ents
        .iter()
        .find(|e| e.value == "BHP GROUP LIMITED")
        .expect("should succeed");
    assert!(
        au.evidence[0]
            .attributes
            .iter()
            .any(|(k, v)| k == "registered_as" && v == "004 028 077")
    );
}

#[test]
fn locality_trims_region_prefix_and_handles_missing() {
    let a = GleifAddress {
        city: Some("Melbourne".into()),
        region: Some("AU-VIC".into()),
        postal_code: Some("3000".into()),
        country: Some("AU".into()),
        ..Default::default()
    };
    assert_eq!(locality(&a).as_deref(), Some("Melbourne, VIC 3000, AU"));
    // Nothing locating → None.
    assert!(locality(&GleifAddress::default()).is_none());
}

#[test]
fn query_url_encodes_brackets_and_value() {
    // JSON:API bracket params stay percent-encoded; the value is
    // form-encoded by `urlencode` (space -> '+', which servers decode back).
    let u = query_url("BHP Group");
    assert!(u.contains("filter%5Bentity.legalName%5D=BHP+Group"), "{u}");
    assert!(u.contains("page%5Bsize%5D=100"), "{u}");
}

#[test]
fn non_empty_trims_and_filters_blank() {
    assert_eq!(non_empty(Some("  hi ".to_string())), Some("hi".to_string()));
    assert_eq!(non_empty(Some("".to_string())), None);
    assert_eq!(non_empty(Some("   ".to_string())), None);
    assert_eq!(non_empty(None), None);
}

fn entity_from_json(json: &str) -> GleifEntity {
    serde_json::from_str(json).expect("should succeed")
}

#[test]
fn au_abn_acn_accepts_au_nine_and_eleven_digits() {
    let acn = entity_from_json(r#"{"jurisdiction":"AU","registeredAs":"004 028 077"}"#);
    assert_eq!(au_abn_acn(&acn).as_deref(), Some("004028077"));
    let abn = entity_from_json(r#"{"jurisdiction":"AU","registeredAs":"28 000 030 179"}"#);
    assert_eq!(au_abn_acn(&abn).as_deref(), Some("28000030179"));
}

#[test]
fn au_abn_acn_rejects_foreign_jurisdiction_and_wrong_length() {
    let gb = entity_from_json(r#"{"jurisdiction":"GB","registeredAs":"03298904"}"#);
    assert!(au_abn_acn(&gb).is_none());
    let bad = entity_from_json(r#"{"jurisdiction":"AU","registeredAs":"12345"}"#);
    assert!(au_abn_acn(&bad).is_none());
    let none = entity_from_json(r#"{"jurisdiction":"AU"}"#);
    assert!(au_abn_acn(&none).is_none());
}

#[test]
fn record_evidence_stamps_core_attrs_and_gates_optional_ones() {
    let entity = entity_from_json(
        r#"{"jurisdiction":"AU","status":"ACTIVE","registeredAs":"004 028 077",
            "legalAddress":{"addressLines":["171 Collins Street"],"city":"Melbourne","region":"AU-VIC","postalCode":"3000","country":"AU"}}"#,
    );
    let ev = record_evidence("WZE1WSENV6JSZFK0JC28", &entity, "BHP GROUP LIMITED", 2);
    assert_eq!(
        ev.attributes.get("lei").map(String::as_str),
        Some("WZE1WSENV6JSZFK0JC28")
    );
    assert_eq!(
        ev.attributes.get("total_matches").map(String::as_str),
        Some("2")
    );
    assert!(ev.attributes.contains_key("register"));
    assert_eq!(
        ev.attributes.get("jurisdiction").map(String::as_str),
        Some("AU")
    );
    assert_eq!(
        ev.attributes.get("entity_status").map(String::as_str),
        Some("ACTIVE")
    );
    assert_eq!(
        ev.attributes.get("registered_as").map(String::as_str),
        Some("004 028 077")
    );
    assert_eq!(
        ev.attributes
            .get("legal_address_street")
            .map(String::as_str),
        Some("171 Collins Street")
    );
    assert_eq!(
        ev.attributes.get("legal_address").map(String::as_str),
        Some("Melbourne, VIC 3000, AU")
    );
    assert!(ev.summary.contains("BHP GROUP LIMITED"));
}

#[test]
fn record_evidence_omits_absent_optional_attrs() {
    let entity = entity_from_json(r#"{}"#);
    let ev = record_evidence("LEI123", &entity, "Some Co", 1);
    assert!(ev.attributes.contains_key("lei"));
    assert!(!ev.attributes.contains_key("jurisdiction"));
    assert!(!ev.attributes.contains_key("entity_status"));
    assert!(!ev.attributes.contains_key("registered_as"));
    assert!(!ev.attributes.contains_key("legal_address"));
    assert!(!ev.attributes.contains_key("hq_address"));
}

#[test]
fn empty_response_yields_nothing() {
    let resp: GleifResp = serde_json::from_str(r#"{"data":[]}"#).expect("should succeed");
    assert!(records_to_entities(&resp, "Nonexistent Org", "s").is_empty());
}

/// Two DIFFERENT real companies that hold the identical legal name in
/// different jurisdictions. GLEIF returns both; `Entity::new` derives the uid
/// from the normalised value, which is the name, so the engine's merge fuses
/// them into ONE `Organisation` whose evidence attributes are joined
/// (`jurisdiction: "AU; DE"`, `entity_status: "ACTIVE; INACTIVE"`, both LEIs).
///
/// Nothing is lost — `merge_evidence_attrs` keeps both sides — but the fused
/// entity ASSERTS a single company at `ORG_EXACT`
/// (`confidence::HIGH_PLUSPLUS_PLUS`), which is above the noisy-OR expansion
/// floor, so a composite of two companies pivots immediately and seeds new
/// targets. `ahpra` already solved exactly this for practitioners
/// (REQ-AHPRA-001): a name THIS result set holds more than once is a proven
/// collision, so those rows score lower and say so.
fn colliding_pair() -> GleifResp {
    let raw = r#"{
        "meta": {"pagination": {"total": 2}},
        "data": [
            {"attributes": {"lei": "AAAAAAAAAAAAAAAAAAAA", "entity": {
                "legalName": {"name": "Meridian Holdings Limited"},
                "jurisdiction": "AU", "status": "ACTIVE",
                "registeredAs": "004 028 077",
                "headquartersAddress": {"city": "Sydney", "region": "AU-NSW", "postalCode": "2000", "country": "AU"}
            }}},
            {"attributes": {"lei": "BBBBBBBBBBBBBBBBBBBB", "entity": {
                "legalName": {"name": "Meridian Holdings Limited"},
                "jurisdiction": "DE", "status": "INACTIVE",
                "headquartersAddress": {"city": "Berlin", "region": "DE-BE", "postalCode": "10115", "country": "DE"}
            }}}
        ]
    }"#;
    serde_json::from_str(raw).expect("should succeed")
}

#[test]
fn a_legal_name_two_companies_hold_is_not_one_confident_company() {
    let resp = colliding_pair();
    let ents = records_to_entities(&resp, "Meridian Holdings Limited", "s");

    let orgs: Vec<_> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation)
        .collect();
    assert_eq!(orgs.len(), 2, "both records must still surface");

    // EVERY entity a colliding row produced, not just the Organisation: the
    // AbnAcn (`confidence::EXPERT`), the registered Address and the inline
    // Coordinates all rest on "the subject is this company" and would each
    // pivot on their own. Asserting over the whole result also catches a future
    // early `continue` in the row loop silently skipping the marking.
    assert!(
        ents.len() > orgs.len(),
        "the fixture must exercise the fan-out, not only the Organisation rows"
    );
    for e in &ents {
        assert!(
            e.tags.iter().any(|t| t == "ambiguous-name"),
            "{:?} entity {:?} escaped the ambiguity marking",
            e.kind,
            e.value
        );
        assert!(
            e.confidence < confidence::MEDIUM,
            "{:?} entity {:?} can still pivot at {}",
            e.kind,
            e.value,
            e.confidence
        );
    }

    for o in &orgs {
        assert!(
            o.tags.iter().any(|t| t == "ambiguous-name"),
            "a legal name held by two different companies in this very result \
             set is a PROVEN collision and must say so, like ahpra's \
             `ambiguous-name`; got tags {:?}",
            o.tags
        );
        assert!(
            o.confidence < confidence::MEDIUM,
            "a composite of two different companies must sit BELOW the noisy-OR \
             expansion floor so it cannot pivot; got {} (floor {})",
            o.confidence,
            confidence::MEDIUM
        );
    }
}

#[test]
fn an_ambiguous_legal_name_never_seeds_a_corporate_family_walk() {
    // `exact_seeds`' own doc comment: a walk "attributes a whole corporate
    // family to the operator's subject; doing that off a fuzzy match would
    // manufacture a confident graph around the wrong company." An ambiguous
    // EXACT match is the same harm — worse, because it arrives tagged
    // `exact-name-match` — and was not guarded.
    let resp = colliding_pair();
    let seeds = super::transform::exact_seeds(&resp, "Meridian Holdings Limited");
    assert!(
        seeds.is_empty(),
        "no corporate family may be attributed to a name two companies hold; \
         got {seeds:?}"
    );
}

#[test]
fn a_singly_held_exact_name_still_pivots_at_full_confidence() {
    // CONTROL — passes on the baseline AND the fix. The guard must fire only on
    // a proven collision, never on an ordinary unambiguous exact match.
    let raw = r#"{
        "meta": {"pagination": {"total": 1}},
        "data": [
            {"attributes": {"lei": "AAAAAAAAAAAAAAAAAAAA", "entity": {
                "legalName": {"name": "Meridian Holdings Limited"},
                "jurisdiction": "AU", "status": "ACTIVE",
                "registeredAs": "004 028 077",
                "headquartersAddress": {"city": "Sydney", "region": "AU-NSW", "postalCode": "2000", "country": "AU"}
            }}}
        ]
    }"#;
    let resp: GleifResp = serde_json::from_str(raw).expect("should succeed");
    let ents = records_to_entities(&resp, "Meridian Holdings Limited", "s");

    let org = ents
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .expect("the exact match must surface");
    assert!((org.confidence - ORG_EXACT).abs() < f64::EPSILON);
    assert!(!org.tags.iter().any(|t| t == "ambiguous-name"));
    assert!(org.tags.iter().any(|t| t == "exact-name-match"));
    // The exact-match fan-out is intact.
    assert!(ents.iter().any(|e| e.kind == EntityKind::AbnAcn));
    assert!(ents.iter().any(|e| e.kind == EntityKind::Address));
    assert_eq!(
        super::transform::exact_seeds(&resp, "Meridian Holdings Limited").len(),
        1,
        "an unambiguous exact match still earns its corporate-family walk"
    );
}

#[test]
fn two_different_names_both_matching_the_query_are_not_a_collision() {
    // CONTROL — passes on the baseline AND the fix, and pins the boundary: the
    // collision is between two records holding the SAME name, not between two
    // distinct names that each satisfy the query's tokens. `sample()`'s rows
    // ("BHP GROUP LIMITED" / "BHP Billiton Group Limited") are different
    // values, so they get different uids and never fuse.
    let resp = sample();
    let ents = records_to_entities(&resp, "BHP Group Limited", "s");
    assert!(
        !ents
            .iter()
            .any(|e| e.tags.iter().any(|t| t == "ambiguous-name")),
        "distinct legal names must not be read as a namesake collision"
    );
}
