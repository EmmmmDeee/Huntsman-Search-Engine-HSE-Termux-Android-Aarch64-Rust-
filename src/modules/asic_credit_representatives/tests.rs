use super::entity::{
    abn_matches_query, looks_like_org, name_matches_query, pick_resource, record_is_exact,
    records_to_entities, rep_evidence, rep_locality,
};
use super::*;
use crate::core::entity::EntityKind;
use crate::core::module::{ModuleCategory, ModuleCost};
use crate::core::scan::{Target, TargetKind};
use crate::util::ckan::{PackageResponse, Resource, Response as CkanResp};
use serde_json::{Map, Value};

fn sample() -> Vec<Map<String, Value>> {
    // Row 1: a person ("SURNAME, FIRSTNAME") acting under a credit licence,
    // carrying an ABN. Row 2: an organisation (PTY LIMITED). Row 3: a near-
    // namesake person ("WEAVERLY") to guard whole-word matching.
    let raw = r#"[
        {"_id":1,"REGISTER_NAME":"Credit Representative","CRED_REP_NUM":"400500","CRED_LIC_NUM":"123456","CRED_REP_NAME":"WEAVER, BRUCE","CRED_REP_ABN_ACN":"51824753556","CRED_REP_START_DT":"01/02/2015","CRED_REP_LOCALITY":"Sydney","CRED_REP_STATE":"NSW","CRED_REP_PCODE":"2000","CRED_REP_AUTHORISATIONS":"Credit","CRED_REP_EDRS":"AFCA"},
        {"_id":2,"REGISTER_NAME":"Credit Representative","CRED_REP_NUM":"500600","CRED_LIC_NUM":"654321","CRED_REP_NAME":"THINK TANK GROUP PTY LIMITED","CRED_REP_ABN_ACN":"004085616","CRED_REP_STATE":"VIC"},
        {"_id":3,"REGISTER_NAME":"Credit Representative","CRED_REP_NUM":"600700","CRED_LIC_NUM":"999999","CRED_REP_NAME":"WEAVERLY, BRUCE","CRED_REP_END_DT":"01/01/2020","CRED_REP_STATE":"QLD"}
    ]"#;
    serde_json::from_str(raw).expect("sample fixture is valid JSON")
}

#[test]
fn accepts_fullname_org_and_abn() {
    let m = AsicCreditRepresentatives;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Bruce Weaver")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Think Tank Group")));
    assert!(m.accepts(&Target::new(TargetKind::AbnAcn, "51824753556")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

#[test]
fn module_metadata() {
    let m = AsicCreditRepresentatives;
    assert_eq!(m.name(), "asic_credit_representatives");
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::Free);
    assert_eq!(m.category(), ModuleCategory::Corporate);
    assert!(m.max_timeout_ms() > 3_000);
    assert_eq!(m.priority(), 105);
    assert_eq!(m.cache_ttl_secs(), 86_400);
    assert_eq!(m.attack_techniques(), &["T1589.003", "T1591.002"]);
}

#[test]
fn pick_resource_prefers_current_then_first_active() {
    let resources = vec![
        Resource {
            id: Some("old-id".into()),
            name: Some("Credit Representative - Historical".into()),
            datastore_active: Some(true),
        },
        Resource {
            id: Some("current-id".into()),
            name: Some("Credit Representative - Current".into()),
            datastore_active: Some(true),
        },
    ];
    assert_eq!(pick_resource(&resources).as_deref(), Some("current-id"));
    assert!(pick_resource(&[]).is_none());
}

#[test]
fn org_person_shape_detection() {
    assert!(looks_like_org("THINK TANK GROUP PTY LIMITED"));
    assert!(looks_like_org("ACME LTD"));
    assert!(looks_like_org("FOO HOLDINGS"));
    assert!(!looks_like_org("WEAVER, BRUCE"));
    assert!(!looks_like_org("SMITH, JOHN"));
}

#[test]
fn surname_comma_first_matches_first_surname_seed() {
    assert!(name_matches_query("WEAVER, BRUCE", "Bruce Weaver"));
    assert!(name_matches_query("WEAVER, BRUCE", "weaver bruce"));
    assert!(!name_matches_query("WEAVER, BRUCE", "Jane Weaver"));
    // Whole word, not substring: must not match inside "WEAVERLY".
    assert!(!name_matches_query("WEAVERLY, BRUCE", "Bruce Weaver"));
}

#[test]
fn abn_seed_matches_recorded_abn_exactly() {
    let recs = sample();
    assert!(abn_matches_query(&recs[0], "51 824 753 556"));
    assert!(abn_matches_query(&recs[0], "51824753556"));
    assert!(!abn_matches_query(&recs[0], "12345678901"));
    assert!(record_is_exact(&recs[0], "51824753556", true));
    // Row 3 carries no ABN/ACN → not exact on an ABN seed.
    assert!(!record_is_exact(&recs[2], "51824753556", true));
}

#[test]
fn person_row_matches_and_emits_person_with_licence_in_evidence() {
    let recs = sample();
    let ents = records_to_entities(&recs, 3, "Bruce Weaver", false, "scan-1");

    let person = ents
        .iter()
        .find(|e| e.kind == EntityKind::Person && e.value == "WEAVER, BRUCE")
        .expect("exact registered representative as Person");
    assert!(person.tags.iter().any(|t| t == "credit-representative"));
    assert!(person.tags.iter().any(|t| t == "financial-services"));
    assert!((person.confidence - NAME_EXACT).abs() < f64::EPSILON);
    // CRED_LIC_NUM appears in evidence as the licence it acts under.
    assert!(
        person.evidence[0]
            .attributes
            .iter()
            .any(|(k, v)| k == "acts_under" && v == "acts under credit licence 123456")
    );
    assert!(
        person.evidence[0]
            .attributes
            .iter()
            .any(|(k, v)| k == "status" && v == "Current")
    );

    let abn = ents
        .iter()
        .find(|e| e.kind == EntityKind::AbnAcn)
        .expect("ABN pivot");
    assert_eq!(abn.value, "51824753556");

    let addr = ents
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("locality pivot");
    assert_eq!(addr.value, "Sydney, NSW 2000, Australia");

    // Row 3 "WEAVERLY, BRUCE" only loosely matched → candidate, no pivots.
    let cand = ents
        .iter()
        .find(|e| e.value == "WEAVERLY, BRUCE")
        .expect("candidate still surfaced (no omission)");
    assert!(cand.tags.iter().any(|t| t == "name-candidate"));
    assert!(cand.confidence < 0.50, "candidate below expansion floor");
}

#[test]
fn org_row_matches_and_emits_organisation() {
    let recs = sample();
    let ents = records_to_entities(&recs, 3, "Think Tank Group", false, "scan-org");
    let org = ents
        .iter()
        .find(|e| e.kind == EntityKind::Organisation && e.value == "THINK TANK GROUP PTY LIMITED")
        .expect("exact registered representative as Organisation");
    assert!(org.tags.iter().any(|t| t == "credit-representative"));
    assert!((org.confidence - NAME_EXACT).abs() < f64::EPSILON);
    // ACN pivot from CRED_REP_ABN_ACN.
    let acn = ents
        .iter()
        .find(|e| e.kind == EntityKind::AbnAcn && e.value == "004085616")
        .expect("ABN/ACN pivot for org rep");
    assert!(acn.tags.iter().any(|t| t == "asic"));
}

#[test]
fn abn_seed_exact_match_emits_anchor() {
    let recs = sample();
    let ents = records_to_entities(&recs, 3, "51824753556", true, "scan-abn");
    let person = ents
        .iter()
        .find(|e| e.kind == EntityKind::Person && e.value == "WEAVER, BRUCE")
        .expect("ABN-seed exact match emits the person anchor");
    assert!(person.tags.iter().any(|t| t == "exact-name-match"));
}

#[test]
fn non_matching_page_yields_no_representative_finding() {
    // False-positive guard: a page that does NOT contain the seed emits no exact
    // representative. (Rows are still surfaced as inert candidates.)
    let recs = sample();
    let ents = records_to_entities(&recs, 3, "Mary Jones", false, "scan-2");
    assert!(
        !ents
            .iter()
            .any(|e| e.tags.iter().any(|t| t == "credit-representative")),
        "no row matches the seed → no high-confidence representative attributed"
    );
    assert!(
        ents.iter().all(|e| e.confidence < 0.50),
        "every surfaced row is a sub-floor candidate"
    );
}

#[test]
fn locality_assembles_present_parts_only() {
    let mut rec = Map::new();
    rec.insert("CRED_REP_STATE".into(), Value::String("QLD".into()));
    rec.insert("CRED_REP_PCODE".into(), Value::String("4000".into()));
    assert_eq!(rep_locality(&rec).as_deref(), Some("QLD 4000, Australia"));
    assert!(rep_locality(&Map::new()).is_none());
}

#[test]
fn evidence_gates_attrs_on_presence() {
    let recs = sample();
    let ev = rep_evidence(&recs[0], "WEAVER, BRUCE", 3);
    assert_eq!(
        ev.attributes
            .get("representative_number")
            .map(String::as_str),
        Some("400500")
    );
    // Absent column produces no empty attribute (row 1 has no cross_endorse).
    assert!(!ev.attributes.contains_key("cross_endorse"));
}

#[test]
fn ckan_envelopes_round_trip() {
    let ok: CkanResp =
        serde_json::from_str(r#"{"success":true,"result":{"total":0,"records":[]}}"#).unwrap();
    assert_eq!(ok.success, Some(true));

    let pkg: PackageResponse = serde_json::from_str(
        r#"{"success":true,"result":{"resources":[{"id":"r1","name":"Credit Rep - Current","datastore_active":true}]}}"#,
    )
    .unwrap();
    assert_eq!(
        pick_resource(&pkg.result.unwrap().resources).as_deref(),
        Some("r1")
    );
}

/// Live end-to-end proof against the REAL ASIC register on data.gov.au.
#[tokio::test]
#[ignore = "hits the live data.gov.au ASIC datastore; run manually"]
async fn asic_credit_representatives_live_resolves_and_searches() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Default::default(),
    };
    let r = AsicCreditRepresentatives
        .process(&Target::new(TargetKind::FullName, "Bruce Weaver"), &ctx)
        .await
        .expect("live ASIC query must not error");
    eprintln!(
        "asic_credit_representatives live: {} entities",
        r.entities.len()
    );
}
