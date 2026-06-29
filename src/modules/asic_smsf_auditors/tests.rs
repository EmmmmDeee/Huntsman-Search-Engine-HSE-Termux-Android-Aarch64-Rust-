use super::entity::{
    abn_matches_query, pick_resource, record_is_exact, records_to_entities, smsf_evidence,
    smsf_locality, status_is_suspended,
};
use super::*;
use crate::core::entity::EntityKind;
use crate::core::module::{ModuleCategory, ModuleCost};
use crate::core::scan::{Target, TargetKind};
use crate::util::ckan::{PackageResponse, Resource, Response as CkanResp};
use serde_json::{Map, Value};

fn sample() -> Vec<Map<String, Value>> {
    // SMSF_NAME is plain "First Last". Row 1 is a registered auditor with a firm
    // and ABN; row 2 is a near-namesake ("Benjamin" vs "Ben") to exercise the
    // whole-word guard.
    let raw = r#"[
        {"_id":1,"REGISTER_NAME":"SMSF Auditor","SMSF_NUM":"100200","SMSF_NAME":"Benjamin Jenkins","SMSF_STATUS":"Registered","SMSF_PERSON_ABN":"51824753556","SMSF_REG_DT":"01/02/2015","SMSF_CAPACITY_FIRM_NAME":"Acme Audit Partners","SMSF_CONDITION":"Education","SMSF_CONDITION_DTL":"Complete CPD","SMSF_LOCALITY":"Sydney","SMSF_STATE":"NSW","SMSF_POST_CODE":"2000"},
        {"_id":2,"REGISTER_NAME":"SMSF Auditor","SMSF_NUM":"200300","SMSF_NAME":"Ben Jenkinson","SMSF_STATUS":"Registered","SMSF_STATE":"VIC"}
    ]"#;
    serde_json::from_str(raw).unwrap()
}

#[test]
fn accepts_fullname_org_and_abn() {
    let m = AsicSmsfAuditors;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Benjamin Jenkins")));
    assert!(m.accepts(&Target::new(
        TargetKind::Organisation,
        "Acme Audit Partners"
    )));
    assert!(m.accepts(&Target::new(TargetKind::AbnAcn, "51824753556")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

#[test]
fn module_metadata() {
    let m = AsicSmsfAuditors;
    assert_eq!(m.name(), "asic_smsf_auditors");
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::Free);
    assert_eq!(m.category(), ModuleCategory::Corporate);
    assert!(m.max_timeout_ms() > 3_000);
    assert_eq!(m.priority(), 104);
    assert_eq!(m.cache_ttl_secs(), 86_400);
    assert_eq!(m.attack_techniques(), &["T1589.003", "T1591.002"]);
}

#[test]
fn pick_resource_prefers_current_then_first_active() {
    let resources = vec![
        Resource {
            id: Some("old-id".into()),
            name: Some("SMSF Auditor - Historical".into()),
            datastore_active: Some(true),
        },
        Resource {
            id: Some("current-id".into()),
            name: Some("SMSF Auditor - Current".into()),
            datastore_active: Some(true),
        },
    ];
    assert_eq!(pick_resource(&resources).as_deref(), Some("current-id"));
    assert!(pick_resource(&[]).is_none());
}

#[test]
fn plain_first_last_matches_and_whole_word_guards() {
    // SMSF_NAME is plain "First Last" — a "First Last" seed matches directly.
    assert!(crate::util::target_match::name_all_tokens_match(
        "Benjamin Jenkins",
        "Benjamin Jenkins"
    ));
    assert!(crate::util::target_match::name_all_tokens_match(
        "Benjamin Jenkins",
        "jenkins benjamin"
    ));
    assert!(!crate::util::target_match::name_all_tokens_match(
        "Benjamin Jenkins",
        "Mary Jenkins"
    ));
    // Whole word, not substring: "Ben" must not match inside "Benjamin".
    assert!(!crate::util::target_match::name_all_tokens_match(
        "Benjamin Jenkins",
        "Ben Jenkins"
    ));
}

#[test]
fn abn_seed_matches_recorded_abn_exactly() {
    let recs = sample();
    assert!(abn_matches_query(&recs[0], "51 824 753 556"));
    assert!(abn_matches_query(&recs[0], "51824753556"));
    assert!(!abn_matches_query(&recs[0], "12345678901"));
    assert!(record_is_exact(&recs[0], "51824753556", true));
    // Row 2 carries no ABN → not exact on an ABN seed.
    assert!(!record_is_exact(&recs[1], "51824753556", true));
}

#[test]
fn suspended_status_detection() {
    assert!(status_is_suspended("Suspended"));
    assert!(status_is_suspended("Cancelled"));
    assert!(!status_is_suspended("Registered"));
}

#[test]
fn exact_match_emits_person_firm_abn_address_and_number() {
    let recs = sample();
    let ents = records_to_entities(&recs, 2, "Benjamin Jenkins", false, "scan-1");

    let person = ents
        .iter()
        .find(|e| e.kind == EntityKind::Person && e.value == "Benjamin Jenkins")
        .expect("exact registered auditor");
    assert!(person.tags.iter().any(|t| t == "smsf-auditor"));
    assert!(person.tags.iter().any(|t| t == "auditor"));
    assert!(!person.tags.iter().any(|t| t == "suspended"));
    assert!((person.confidence - PERSON_EXACT).abs() < f64::EPSILON);
    // SMSF_NUM is carried in evidence.
    assert!(
        person.evidence[0]
            .attributes
            .iter()
            .any(|(k, v)| k == "auditor_number" && v == "100200")
    );

    let firm = ents
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .expect("firm Organisation pivot");
    assert_eq!(firm.value, "Acme Audit Partners");
    assert!(firm.tags.iter().any(|t| t == "auditor-firm"));

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

    // Row 2 "Ben Jenkinson" only loosely matched → candidate, no pivots.
    let cand = ents
        .iter()
        .find(|e| e.value == "Ben Jenkinson")
        .expect("candidate still surfaced (no omission)");
    assert!(cand.tags.iter().any(|t| t == "name-candidate"));
    assert!(cand.confidence < 0.50, "candidate below expansion floor");
    assert!(!cand.tags.iter().any(|t| t == "smsf-auditor"));
}

#[test]
fn suspended_row_tags_person_suspended() {
    let raw = r#"[{"_id":9,"SMSF_NUM":"909090","SMSF_NAME":"Carol Withers","SMSF_STATUS":"Suspended","SMSF_SUSP_START_DT":"01/01/2024","SMSF_CONDITION":"Suspension"}]"#;
    let recs: Vec<Map<String, Value>> = serde_json::from_str(raw).unwrap();
    let ents = records_to_entities(&recs, 1, "Carol Withers", false, "scan-9");
    let person = ents
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("auditor");
    assert!(person.tags.iter().any(|t| t == "suspended"));
    assert!(person.tags.iter().any(|t| t == "smsf-auditor"));
}

#[test]
fn non_matching_page_yields_no_auditor_finding() {
    // False-positive guard: a page not containing the seed emits no exact auditor.
    let recs = sample();
    let ents = records_to_entities(&recs, 2, "Mary Jones", false, "scan-2");
    assert!(
        !ents
            .iter()
            .any(|e| e.tags.iter().any(|t| t == "smsf-auditor")),
        "no row matches the seed → no high-confidence auditor attributed"
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
    rec.insert("SMSF_STATE".into(), Value::String("QLD".into()));
    rec.insert("SMSF_POST_CODE".into(), Value::String("4000".into()));
    assert_eq!(smsf_locality(&rec).as_deref(), Some("QLD 4000, Australia"));
    assert!(smsf_locality(&Map::new()).is_none());
}

#[test]
fn evidence_gates_attrs_on_presence() {
    let recs = sample();
    let ev = smsf_evidence(&recs[0], "Benjamin Jenkins", 2);
    assert_eq!(
        ev.attributes.get("status").map(String::as_str),
        Some("Registered")
    );
    assert_eq!(
        ev.attributes.get("auditor_number").map(String::as_str),
        Some("100200")
    );
    assert_eq!(
        ev.attributes.get("condition").map(String::as_str),
        Some("Education")
    );
    // Absent column produces no empty attribute (row 2 has no ABN).
    let ev2 = smsf_evidence(&recs[1], "Ben Jenkinson", 2);
    assert!(!ev2.attributes.contains_key("abn"));
}

#[test]
fn ckan_envelopes_round_trip() {
    let ok: CkanResp =
        serde_json::from_str(r#"{"success":true,"result":{"total":0,"records":[]}}"#).unwrap();
    assert_eq!(ok.success, Some(true));

    let pkg: PackageResponse = serde_json::from_str(
        r#"{"success":true,"result":{"resources":[{"id":"r1","name":"SMSF Auditor - Current","datastore_active":true}]}}"#,
    )
    .unwrap();
    assert_eq!(
        pick_resource(&pkg.result.unwrap().resources).as_deref(),
        Some("r1")
    );
}

/// Live end-to-end proof against the REAL ASIC SMSF register on data.gov.au.
#[tokio::test]
#[ignore = "hits the live data.gov.au ASIC datastore; run manually"]
async fn asic_smsf_auditors_live_resolves_and_searches() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Default::default(),
    };
    let r = AsicSmsfAuditors
        .process(&Target::new(TargetKind::FullName, "Benjamin Jenkins"), &ctx)
        .await
        .expect("live ASIC query must not error");
    eprintln!("asic_smsf_auditors live: {} entities", r.entities.len());
}
