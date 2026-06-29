use super::entity::{liquidator_evidence, liquidator_locality, pick_resource, records_to_entities};
use super::*;
use crate::core::entity::EntityKind;
use crate::core::module::{ModuleCategory, ModuleCost};
use crate::core::scan::{Target, TargetKind};
use crate::util::ckan::{PackageResponse, Resource, Response as CkanResp};
use serde_json::{Map, Value};

fn sample() -> Vec<Map<String, Value>> {
    // Names in "SURNAME, FIRSTNAME"; row 2 is a near-namesake.
    let raw = r#"[
        {"_id":1,"REGISTER_NAME":"Liquidator","LIQ_NUM":"L100","LIQ_NAME":"SMITH, JOHN","LIQ_START_DT":"01/02/2015","LIQ_STATUS":"APPR","LIQ_ADD_LOCAL":"Sydney","LIQ_ADD_STATE":"NSW","LIQ_ADD_PCODE":"2000","LIQ_ADD_COUNTRY":"Australia","LIQ_FIRM":"SMITH INSOLVENCY PARTNERS"},
        {"_id":2,"REGISTER_NAME":"Liquidator","LIQ_NUM":"L200","LIQ_NAME":"SMITHSON, JOHN","LIQ_STATUS":"APPR","LIQ_ADD_STATE":"VIC"}
    ]"#;
    serde_json::from_str(raw).unwrap()
}

#[test]
fn accepts_fullname_only() {
    let m = AsicLiquidators;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "John Smith")));
    assert!(!m.accepts(&Target::new(TargetKind::Organisation, "Acme Pty Ltd")));
    assert!(!m.accepts(&Target::new(TargetKind::AbnAcn, "51824753556")));
}

#[test]
fn module_metadata() {
    let m = AsicLiquidators;
    assert_eq!(m.name(), "asic_liquidators");
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::Free);
    assert_eq!(m.category(), ModuleCategory::Corporate);
    assert!(m.max_timeout_ms() > 3_000);
    assert_eq!(m.priority(), 110);
    assert_eq!(m.cache_ttl_secs(), 86_400);
    assert_eq!(m.attack_techniques(), &["T1589.003", "T1591.002"]);
}

#[test]
fn pick_resource_prefers_current_then_first_active() {
    let resources = vec![
        Resource {
            id: Some("old-id".into()),
            name: Some("Liquidator - Historical".into()),
            datastore_active: Some(true),
        },
        Resource {
            id: Some("current-id".into()),
            name: Some("Liquidator - Current".into()),
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
    assert!(crate::util::target_match::name_all_tokens_match(
        "SMITH, JOHN",
        "John Smith"
    ));
    assert!(crate::util::target_match::name_all_tokens_match(
        "SMITH, JOHN",
        "smith john"
    ));
    assert!(!crate::util::target_match::name_all_tokens_match(
        "SMITH, JOHN",
        "Jane Smith"
    ));
    // Whole word, not substring: "smith" must not match inside "SMITHSON".
    assert!(!crate::util::target_match::name_all_tokens_match(
        "SMITHSON, JOHN",
        "John Smith"
    ));
}

#[test]
fn exact_match_emits_person_firm_and_locality() {
    let recs = sample();
    let ents = records_to_entities(&recs, 2, "John Smith", "scan-1");

    let person = ents
        .iter()
        .find(|e| e.kind == EntityKind::Person && e.value == "SMITH, JOHN")
        .expect("exact registered liquidator");
    assert!(person.tags.iter().any(|t| t == "liquidator"));
    assert!(person.tags.iter().any(|t| t == "insolvency-practitioner"));
    assert!((person.confidence - PERSON_EXACT).abs() < f64::EPSILON);
    assert!(
        person.evidence[0]
            .attributes
            .iter()
            .any(|(k, v)| k == "status" && v == "APPR")
    );

    let firm = ents
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .expect("firm pivot");
    assert_eq!(firm.value, "SMITH INSOLVENCY PARTNERS");
    assert!(firm.tags.iter().any(|t| t == "insolvency-firm"));

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
    assert!(!cand.tags.iter().any(|t| t == "liquidator"));
}

#[test]
fn non_matching_page_yields_no_liquidator_finding() {
    // False-positive guard: a page that does NOT contain the seed emits no exact
    // liquidator. (Rows are still surfaced as inert candidates.)
    let recs = sample();
    let ents = records_to_entities(&recs, 2, "Mary Jones", "scan-2");
    assert!(
        !ents
            .iter()
            .any(|e| e.tags.iter().any(|t| t == "liquidator")),
        "no row matches the seed → no high-confidence liquidator attributed"
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
    rec.insert("LIQ_ADD_STATE".into(), Value::String("QLD".into()));
    rec.insert("LIQ_ADD_PCODE".into(), Value::String("4000".into()));
    assert_eq!(liquidator_locality(&rec).as_deref(), Some("QLD 4000"));
    assert!(liquidator_locality(&Map::new()).is_none());
}

#[test]
fn evidence_gates_attrs_on_presence() {
    let recs = sample();
    let ev = liquidator_evidence(&recs[0], "SMITH, JOHN", 2);
    assert_eq!(
        ev.attributes.get("status").map(String::as_str),
        Some("APPR")
    );
    assert_eq!(
        ev.attributes.get("firm").map(String::as_str),
        Some("SMITH INSOLVENCY PARTNERS")
    );
    // Absent column produces no empty attribute (row 2 has no firm).
    let ev2 = liquidator_evidence(&recs[1], "SMITHSON, JOHN", 2);
    assert!(!ev2.attributes.contains_key("firm"));
}

#[test]
fn ckan_envelopes_round_trip() {
    let ok: CkanResp =
        serde_json::from_str(r#"{"success":true,"result":{"total":0,"records":[]}}"#).unwrap();
    assert_eq!(ok.success, Some(true));

    let pkg: PackageResponse = serde_json::from_str(
        r#"{"success":true,"result":{"resources":[{"id":"r1","name":"Liquidator - Current","datastore_active":true}]}}"#,
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
async fn asic_liquidators_live_resolves_and_searches() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Default::default(),
    };
    let r = AsicLiquidators
        .process(&Target::new(TargetKind::FullName, "John Smith"), &ctx)
        .await
        .expect("live ASIC query must not error");
    eprintln!("asic_liquidators live: {} entities", r.entities.len());
}
