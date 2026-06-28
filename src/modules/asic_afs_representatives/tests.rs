use super::entity::{
    abn_matches_query, name_matches_query, pick_resource, record_is_exact, records_to_entities,
    rep_evidence, rep_locality,
};
use super::*;
use crate::core::entity::EntityKind;
use crate::core::module::{ModuleCategory, ModuleCost};
use crate::core::scan::{Target, TargetKind};
use crate::util::ckan::{PackageResponse, Resource, Response as CkanResp};
use serde_json::{Map, Value};

fn sample() -> Vec<Map<String, Value>> {
    // Names in "SURNAME, FIRSTNAME"; row 2 is a near-namesake; row 1 also acts
    // under an AFS licence and carries an ABN.
    let raw = r#"[
        {"_id":1,"REGISTER_NAME":"AFS Authorised Representative","AFS_REP_NUM":"100200","AFS_LIC_NUM":"123456","AFS_REP_NAME":"SMITH, JOHN","AFS_REP_ABN":"51824753556","AFS_REP_START_DT":"01/02/2015","AFS_REP_STATUS":"Current","AFS_REP_APPOINTED_BY":"ACME FINANCIAL PTY LTD","AFS_REP_ADD_LOCAL":"Sydney","AFS_REP_ADD_STATE":"NSW","AFS_REP_ADD_PCODE":"2000","AFS_REP_ADD_COUNTRY":"Australia"},
        {"_id":2,"REGISTER_NAME":"AFS Authorised Representative","AFS_REP_NUM":"200300","AFS_LIC_NUM":"999999","AFS_REP_NAME":"SMITHSON, JOHN","AFS_REP_STATUS":"Ceased","AFS_REP_ADD_STATE":"VIC"}
    ]"#;
    serde_json::from_str(raw).unwrap()
}

#[test]
fn accepts_fullname_org_and_abn() {
    let m = AsicAfsRepresentatives;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "John Smith")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Pty Ltd")));
    assert!(m.accepts(&Target::new(TargetKind::AbnAcn, "51824753556")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

#[test]
fn module_metadata() {
    let m = AsicAfsRepresentatives;
    assert_eq!(m.name(), "asic_afs_representatives");
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::Free);
    assert_eq!(m.category(), ModuleCategory::Corporate);
    assert!(m.max_timeout_ms() > 3_000);
    assert_eq!(m.priority(), 106);
    assert_eq!(m.cache_ttl_secs(), 86_400);
    assert_eq!(m.attack_techniques(), &["T1589.003", "T1591.002"]);
}

#[test]
fn pick_resource_prefers_current_then_first_active() {
    let resources = vec![
        Resource {
            id: Some("old-id".into()),
            name: Some("AFS Authorised Representative - Historical".into()),
            datastore_active: Some(true),
        },
        Resource {
            id: Some("current-id".into()),
            name: Some("AFS Authorised Representative - Current".into()),
            datastore_active: Some(true),
        },
    ];
    assert_eq!(pick_resource(&resources).as_deref(), Some("current-id"));
    assert!(pick_resource(&[]).is_none());
}

#[test]
fn surname_comma_first_matches_first_surname_seed() {
    // The register stores "SURNAME, FIRSTNAME"; a "Firstname Surname" seed must
    // match regardless of order.
    assert!(name_matches_query("SMITH, JOHN", "John Smith"));
    assert!(name_matches_query("SMITH, JOHN", "smith john"));
    assert!(!name_matches_query("SMITH, JOHN", "Jane Smith"));
    // Whole word, not substring: "smith" must not match inside "SMITHSON".
    assert!(!name_matches_query("SMITHSON, JOHN", "John Smith"));
}

#[test]
fn abn_seed_matches_recorded_abn_exactly() {
    let recs = sample();
    // Digit-only equality: spacing in the seed must not defeat the match.
    assert!(abn_matches_query(&recs[0], "51 824 753 556"));
    assert!(abn_matches_query(&recs[0], "51824753556"));
    assert!(!abn_matches_query(&recs[0], "12345678901"));
    assert!(record_is_exact(&recs[0], "51824753556", true));
    // Row 2 carries no ABN/ACN → not exact on an ABN seed.
    assert!(!record_is_exact(&recs[1], "51824753556", true));
}

#[test]
fn exact_match_emits_person_abn_address_and_licence_in_evidence() {
    let recs = sample();
    let ents = records_to_entities(&recs, 2, "John Smith", false, "scan-1");

    let person = ents
        .iter()
        .find(|e| e.kind == EntityKind::Person && e.value == "SMITH, JOHN")
        .expect("exact registered representative");
    assert!(person.tags.iter().any(|t| t == "afs-representative"));
    assert!(person.tags.iter().any(|t| t == "financial-services"));
    assert!((person.confidence - PERSON_EXACT).abs() < f64::EPSILON);
    assert!(
        person.evidence[0]
            .attributes
            .iter()
            .any(|(k, v)| k == "status" && v == "Current")
    );
    // The licence it acts under is noted in evidence (pivot to the licensee).
    assert!(
        person.evidence[0]
            .attributes
            .iter()
            .any(|(k, v)| k == "acts_under" && v == "acts under AFS licence 123456")
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

    // Row 2 "SMITHSON, JOHN" only loosely matched → candidate, no pivots.
    let cand = ents
        .iter()
        .find(|e| e.value == "SMITHSON, JOHN")
        .expect("candidate still surfaced (no omission)");
    assert!(cand.tags.iter().any(|t| t == "name-candidate"));
    assert!(cand.confidence < 0.50, "candidate below expansion floor");
    assert!(!cand.tags.iter().any(|t| t == "afs-representative"));
}

#[test]
fn corporate_rep_acn_emitted_and_tagged() {
    let raw = r#"[{"_id":3,"AFS_REP_NUM":"303030","AFS_LIC_NUM":"123456","AFS_REP_NAME":"GLOBEX ADVISERS PTY LTD","AFS_REP_ACN":"004085616","AFS_REP_STATUS":"Current"}]"#;
    let recs: Vec<Map<String, Value>> = serde_json::from_str(raw).unwrap();
    let ents = records_to_entities(&recs, 1, "Globex Advisers", false, "scan-3");
    let acn = ents
        .iter()
        .find(|e| e.kind == EntityKind::AbnAcn)
        .expect("ACN pivot for corporate rep");
    assert_eq!(acn.value, "004085616");
    assert!(acn.tags.iter().any(|t| t == "acn"));
}

#[test]
fn non_matching_page_yields_no_representative_finding() {
    // False-positive guard: a page that does NOT contain the seed emits no exact
    // representative. (Rows are still surfaced as inert candidates.)
    let recs = sample();
    let ents = records_to_entities(&recs, 2, "Mary Jones", false, "scan-2");
    assert!(
        !ents
            .iter()
            .any(|e| e.tags.iter().any(|t| t == "afs-representative")),
        "no row matches the seed → no high-confidence representative attributed"
    );
    assert!(
        ents.iter().all(|e| e.confidence < 0.50),
        "every surfaced row is a sub-floor candidate"
    );
    assert_eq!(
        ents.iter().filter(|e| e.kind == EntityKind::Person).count(),
        2
    );
}

#[test]
fn locality_assembles_present_parts_only() {
    let mut rec = Map::new();
    rec.insert("AFS_REP_ADD_STATE".into(), Value::String("QLD".into()));
    rec.insert("AFS_REP_ADD_PCODE".into(), Value::String("4000".into()));
    assert_eq!(rep_locality(&rec).as_deref(), Some("QLD 4000"));
    assert!(rep_locality(&Map::new()).is_none());
}

#[test]
fn evidence_gates_attrs_on_presence() {
    let recs = sample();
    let ev = rep_evidence(&recs[0], "SMITH, JOHN", 2);
    assert_eq!(
        ev.attributes.get("status").map(String::as_str),
        Some("Current")
    );
    assert_eq!(
        ev.attributes
            .get("representative_number")
            .map(String::as_str),
        Some("100200")
    );
    // Absent column produces no empty attribute (row 2 has no ABN).
    let ev2 = rep_evidence(&recs[1], "SMITHSON, JOHN", 2);
    assert!(!ev2.attributes.contains_key("abn"));
}

#[test]
fn ckan_envelopes_round_trip() {
    let ok: CkanResp =
        serde_json::from_str(r#"{"success":true,"result":{"total":0,"records":[]}}"#).unwrap();
    assert_eq!(ok.success, Some(true));

    let pkg: PackageResponse = serde_json::from_str(
        r#"{"success":true,"result":{"resources":[{"id":"r1","name":"AFS Auth Rep - Current","datastore_active":true}]}}"#,
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
async fn asic_afs_representatives_live_resolves_and_searches() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Default::default(),
    };
    let r = AsicAfsRepresentatives
        .process(&Target::new(TargetKind::FullName, "John Smith"), &ctx)
        .await
        .expect("live ASIC query must not error");
    eprintln!(
        "asic_afs_representatives live: {} entities",
        r.entities.len()
    );
}
