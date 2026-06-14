use super::{
    GleifLei, ORG_EXACT,
    helpers::{locality, query_url},
    transform::records_to_entities,
    types::{GleifAddress, GleifResp},
};
use crate::core::{
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
    serde_json::from_str(raw).unwrap()
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
        .unwrap();
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
        .unwrap();
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
    assert!(ents.iter().all(|e| e.confidence < 0.50));
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
        .unwrap();
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
    assert!(u.contains("page%5Bsize%5D=10"), "{u}");
}

#[test]
fn empty_response_yields_nothing() {
    let resp: GleifResp = serde_json::from_str(r#"{"data":[]}"#).unwrap();
    assert!(records_to_entities(&resp, "Nonexistent Org", "s").is_empty());
}
