use super::entity::{
    name_matches_query, person_evidence, person_locality, pick_resource, records_to_entities,
};
use super::*;
use crate::core::entity::EntityKind;
use crate::core::module::{ModuleCategory, ModuleCost};
use crate::core::scan::{Target, TargetKind};
use crate::util::ckan::{PackageResponse, Resource, Response as CkanResp};
use serde_json::{Map, Value};

fn sample() -> Vec<Map<String, Value>> {
    // Shapes mirror real datastore_search rows; names in "SURNAME, FIRSTNAME".
    let raw = r#"[
        {"_id":1,"REGISTER_NAME":"Banned and Disqualified","BD_PER_NAME":"SMITH, JOHN","BD_PER_TYPE":"Disqualified Director","BD_PER_DOC_NUM":"D12345","BD_PER_START_DT":"01/02/2020","BD_PER_END_DT":"01/02/2025","BD_PER_ADD_LOCAL":"Sydney","BD_PER_ADD_STATE":"NSW","BD_PER_ADD_PCODE":"2000","BD_PER_ADD_COUNTRY":"Australia","BD_PER_COMMENTS":"Managed corporations while insolvent."},
        {"_id":2,"REGISTER_NAME":"Banned and Disqualified","BD_PER_NAME":"SMITHSON, JOHN","BD_PER_TYPE":"Banned Securities","BD_PER_ADD_STATE":"VIC"}
    ]"#;
    serde_json::from_str(raw).unwrap()
}

#[test]
fn accepts_fullname_and_org_only() {
    let m = AsicBannedPersons;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "John Smith")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Pty Ltd")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::AbnAcn, "51824753556")));
}

#[test]
fn module_metadata() {
    let m = AsicBannedPersons;
    assert_eq!(m.name(), "asic_banned_persons");
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::Free);
    assert_eq!(m.category(), ModuleCategory::Corporate);
    // Two-step network module must beat the 3s default timeout (CI guard).
    assert!(m.max_timeout_ms() > 3_000);
    // ASIC public-records band, non-colliding with the asic_* family.
    assert_eq!(m.priority(), 113);
    // Slow-moving adverse register → 24h TTL.
    assert_eq!(m.cache_ttl_secs(), 86_400);
    // Adverse / sanctions-screening posture (mirrors dfat_sanctions).
    assert_eq!(m.attack_techniques(), &["T1589.003", "T1591.002"]);
}

#[test]
fn pick_resource_prefers_current_then_first_active() {
    let resources = vec![
        Resource {
            id: Some("old-id".into()),
            name: Some("ASIC Banned and Disqualified - Historical".into()),
            datastore_active: Some(true),
        },
        Resource {
            id: Some("current-id".into()),
            name: Some("ASIC Banned and Disqualified - Current".into()),
            datastore_active: Some(true),
        },
    ];
    assert_eq!(pick_resource(&resources).as_deref(), Some("current-id"));

    // No "Current" name → first datastore-active resource.
    let fallback = vec![
        Resource {
            id: Some("csv-id".into()),
            name: Some("Data dictionary".into()),
            datastore_active: Some(false),
        },
        Resource {
            id: Some("active-id".into()),
            name: Some("Unnamed".into()),
            datastore_active: Some(true),
        },
    ];
    assert_eq!(pick_resource(&fallback).as_deref(), Some("active-id"));
    // Nothing active → None.
    assert!(pick_resource(&[]).is_none());
}

#[test]
fn surname_comma_first_matches_first_surname_seed() {
    // The register stores "SURNAME, FIRSTNAME"; a "Firstname Surname" seed must
    // match regardless of order.
    assert!(name_matches_query("SMITH, JOHN", "John Smith"));
    assert!(name_matches_query("SMITH, JOHN", "smith john"));
    // Missing a seed token → not a match.
    assert!(!name_matches_query("SMITH, JOHN", "Jane Smith"));
    // Whole word, not substring: "smith" must not match inside "SMITHSON".
    assert!(!name_matches_query("SMITHSON, JOHN", "John Smith"));
}

#[test]
fn exact_match_emits_adverse_person_and_locality() {
    let recs = sample();
    let ents = records_to_entities(&recs, 2, "John Smith", "scan-1");

    let person = ents
        .iter()
        .find(|e| e.kind == EntityKind::Person && e.value == "SMITH, JOHN")
        .expect("exact banned person");
    assert!(person.tags.iter().any(|t| t == "asic-banned"));
    assert!(person.tags.iter().any(|t| t == "disqualified"));
    assert!(person.tags.iter().any(|t| t == "adverse-record"));
    assert!((person.confidence - PERSON_EXACT).abs() < f64::EPSILON);
    // Ban details ride in evidence (no omission).
    assert!(
        person.evidence[0]
            .attributes
            .iter()
            .any(|(k, v)| k == "ban_type" && v == "Disqualified Director")
    );

    let addr = ents
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("exact hit emits a locality pivot");
    assert_eq!(addr.value, "Sydney, NSW 2000, Australia");
    assert!(addr.tags.iter().any(|t| t == "geoint"));

    // Row 2 "SMITHSON, JOHN" only loosely matched → candidate: a single
    // sub-floor Person, no Address pivot from it.
    let cand = ents
        .iter()
        .find(|e| e.value == "SMITHSON, JOHN")
        .expect("candidate still surfaced (no omission)");
    assert!(cand.tags.iter().any(|t| t == "name-candidate"));
    assert!(
        cand.confidence < 0.50,
        "candidate must stay below expansion floor"
    );
    assert!(!cand.tags.iter().any(|t| t == "asic-banned"));
}

#[test]
fn non_matching_page_yields_no_banned_finding() {
    // A page of rows that does NOT contain the seed must emit no exact ban —
    // false-positive guard. (Rows are still surfaced as inert candidates.)
    let recs = sample();
    let ents = records_to_entities(&recs, 2, "Mary Jones", "scan-2");
    assert!(
        !ents
            .iter()
            .any(|e| e.tags.iter().any(|t| t == "asic-banned")),
        "no row matches the seed → no high-confidence ban attributed"
    );
    assert!(
        ents.iter().all(|e| e.confidence < 0.50),
        "every surfaced row is a sub-floor candidate"
    );
    // Nothing dropped: both rows are still present as candidates.
    assert_eq!(
        ents.iter().filter(|e| e.kind == EntityKind::Person).count(),
        2
    );
}

#[test]
fn locality_assembles_present_parts_only() {
    let mut rec = Map::new();
    rec.insert("BD_PER_ADD_STATE".into(), Value::String("QLD".into()));
    rec.insert("BD_PER_ADD_PCODE".into(), Value::String("4000".into()));
    assert_eq!(person_locality(&rec).as_deref(), Some("QLD 4000"));
    assert!(person_locality(&Map::new()).is_none());
}

#[test]
fn evidence_gates_attrs_on_presence() {
    let recs = sample();
    let ev = person_evidence(&recs[0], "SMITH, JOHN", 2);
    assert_eq!(
        ev.attributes.get("comments").map(String::as_str),
        Some("Managed corporations while insolvent.")
    );
    assert_eq!(
        ev.attributes.get("total_matches").map(String::as_str),
        Some("2")
    );
    // Absent column produces no empty attribute (row 2 has no comments column).
    let ev2 = person_evidence(&recs[1], "SMITHSON, JOHN", 2);
    assert!(!ev2.attributes.contains_key("comments"));
    assert!(!ev2.attributes.contains_key("ban_start"));
}

#[test]
fn ckan_envelopes_round_trip() {
    let ok: CkanResp =
        serde_json::from_str(r#"{"success":true,"result":{"total":0,"records":[]}}"#).unwrap();
    assert_eq!(ok.success, Some(true));
    assert_eq!(ok.result.unwrap().records.len(), 0);

    let pkg: PackageResponse = serde_json::from_str(
        r#"{"success":true,"result":{"resources":[{"id":"r1","name":"ASIC ... - Current","datastore_active":true}]}}"#,
    )
    .unwrap();
    assert_eq!(pkg.success, Some(true));
    assert_eq!(
        pick_resource(&pkg.result.unwrap().resources).as_deref(),
        Some("r1")
    );
}

/// Live end-to-end proof against the REAL ASIC register on data.gov.au — no
/// mock. Run with
/// `cargo test -p huntsman-search-engine asic_banned_persons_live -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "hits the live data.gov.au ASIC datastore; run manually"]
async fn asic_banned_persons_live_resolves_and_searches() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Default::default(),
    };
    let r = AsicBannedPersons
        .process(&Target::new(TargetKind::FullName, "John Smith"), &ctx)
        .await
        .expect("live ASIC query must not error");
    eprintln!("asic_banned_persons live: {} entities", r.entities.len());
}
