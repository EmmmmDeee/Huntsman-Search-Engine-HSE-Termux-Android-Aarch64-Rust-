use super::entity::{
    acn_matches_query, auditor_evidence, auditor_locality, name_matches_query, pick_resource,
    record_is_exact, records_to_entities,
};
use super::*;
use crate::core::entity::EntityKind;
use crate::core::module::{ModuleCategory, ModuleCost};
use crate::core::scan::{Target, TargetKind};
use crate::util::ckan::{PackageResponse, Resource, Response as CkanResp};
use serde_json::{Map, Value};

fn sample() -> Vec<Map<String, Value>> {
    let raw = r#"[
        {"_id":1,"REGISTER_NAME":"Registered Auditor","REG_AUD_NUM":"AUD0001","REG_AUD_NAME":"ACME AUDIT PTY LTD","REG_AUD_ACN":"123456789","REG_AUD_START_DT":"01/03/2005","REG_AUD_STATUS":"Registered","REG_AUD_ADD_LOCAL":"Melbourne","REG_AUD_ADD_STATE":"VIC","REG_AUD_ADD_PCODE":"3000","REG_AUD_ADD_COUNTRY":"Australia"},
        {"_id":2,"REGISTER_NAME":"Registered Auditor","REG_AUD_NUM":"AUD0002","REG_AUD_NAME":"ACME WIDGETS PTY LTD","REG_AUD_ACN":"987654321","REG_AUD_STATUS":"Registered"}
    ]"#;
    serde_json::from_str(raw).unwrap()
}

#[test]
fn accepts_org_fullname_and_abn() {
    let m = AsicRegisteredAuditors;
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Pty Ltd")));
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Jane Auditor")));
    assert!(m.accepts(&Target::new(TargetKind::AbnAcn, "123456789")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

#[test]
fn module_metadata() {
    let m = AsicRegisteredAuditors;
    assert_eq!(m.name(), "asic_registered_auditors");
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::Free);
    assert_eq!(m.category(), ModuleCategory::Corporate);
    assert!(m.max_timeout_ms() > 3_000);
    assert_eq!(m.priority(), 107);
    assert_eq!(m.cache_ttl_secs(), 86_400);
    assert_eq!(m.attack_techniques(), &["T1591.002"]);
}

#[test]
fn pick_resource_prefers_current_then_first_active() {
    let resources = vec![
        Resource {
            id: Some("old-id".into()),
            name: Some("Registered Auditor - Historical".into()),
            datastore_active: Some(true),
        },
        Resource {
            id: Some("current-id".into()),
            name: Some("Registered Auditor - Current".into()),
            datastore_active: Some(true),
        },
    ];
    assert_eq!(pick_resource(&resources).as_deref(), Some("current-id"));
    assert!(pick_resource(&[]).is_none());
}

#[test]
fn acn_seed_matches_recorded_acn_exactly() {
    let recs = sample();
    assert!(acn_matches_query(&recs[0], "123 456 789"));
    assert!(acn_matches_query(&recs[0], "123456789"));
    assert!(!acn_matches_query(&recs[0], "987654321"));
    assert!(record_is_exact(&recs[0], "123456789", true));
    assert!(!record_is_exact(&recs[0], "987654321", true));
}

#[test]
fn name_seed_matches_whole_word() {
    assert!(name_matches_query("ACME AUDIT PTY LTD", "Acme Audit"));
    assert!(!name_matches_query("ACME AUDIT PTY LTD", "Acme Holdings"));
}

#[test]
fn org_match_emits_org_acn_and_address() {
    let recs = sample();
    // Seed by org name; only row 1 matches whole-word.
    let ents = records_to_entities(&recs, 2, "Acme Audit", false, "scan-1");

    let org = ents
        .iter()
        .find(|e| e.kind == EntityKind::Organisation && e.value == "ACME AUDIT PTY LTD")
        .expect("exact registered auditor organisation");
    assert!(org.tags.iter().any(|t| t == "registered-auditor"));
    assert!(org.tags.iter().any(|t| t == "auditor"));
    assert!((org.confidence - ORG_EXACT).abs() < f64::EPSILON);

    // ACN pivot (tagged as an ACN).
    let acn = ents
        .iter()
        .find(|e| e.kind == EntityKind::AbnAcn)
        .expect("ACN pivot");
    assert_eq!(acn.value, "123456789");
    assert!(acn.tags.iter().any(|t| t == "acn"));

    let addr = ents
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("address pivot");
    assert_eq!(addr.value, "Melbourne, VIC 3000, Australia");

    // Row 2 only loosely matched → sub-floor candidate, no pivots.
    let cand = ents
        .iter()
        .find(|e| e.value == "ACME WIDGETS PTY LTD")
        .expect("candidate still surfaced (no omission)");
    assert!(cand.tags.iter().any(|t| t == "name-candidate"));
    assert!(cand.confidence < 0.50, "candidate below expansion floor");
}

#[test]
fn non_matching_page_yields_no_auditor_finding() {
    // A page that does NOT contain the seed must emit no exact auditor —
    // false-positive guard. (Rows are still surfaced as inert candidates.)
    let recs = sample();
    let ents = records_to_entities(&recs, 2, "Globex Holdings", false, "scan-2");
    assert!(
        !ents
            .iter()
            .any(|e| e.tags.iter().any(|t| t == "registered-auditor")),
        "no row matches the seed → no high-confidence auditor attributed"
    );
    assert!(
        ents.iter().all(|e| e.confidence < 0.50),
        "every surfaced row is a sub-floor candidate"
    );
    assert_eq!(
        ents.iter()
            .filter(|e| e.kind == EntityKind::Organisation)
            .count(),
        2
    );
}

#[test]
fn locality_assembles_present_parts_only() {
    let mut rec = Map::new();
    rec.insert("REG_AUD_ADD_STATE".into(), Value::String("QLD".into()));
    rec.insert("REG_AUD_ADD_PCODE".into(), Value::String("4000".into()));
    assert_eq!(
        auditor_locality(&rec).as_deref(),
        Some("QLD 4000, Australia")
    );
    assert!(auditor_locality(&Map::new()).is_none());
}

#[test]
fn evidence_gates_attrs_on_presence() {
    let recs = sample();
    let ev = auditor_evidence(&recs[0], "ACME AUDIT PTY LTD", 2);
    assert_eq!(
        ev.attributes.get("registration_number").map(String::as_str),
        Some("AUD0001")
    );
    assert_eq!(
        ev.attributes.get("acn").map(String::as_str),
        Some("123456789")
    );
    // Absent column produces no empty attribute (row 2 has no locality).
    let ev2 = auditor_evidence(&recs[1], "ACME WIDGETS PTY LTD", 2);
    assert!(!ev2.attributes.contains_key("address_locality"));
}

#[test]
fn ckan_envelopes_round_trip() {
    let ok: CkanResp =
        serde_json::from_str(r#"{"success":true,"result":{"total":0,"records":[]}}"#).unwrap();
    assert_eq!(ok.success, Some(true));

    let pkg: PackageResponse = serde_json::from_str(
        r#"{"success":true,"result":{"resources":[{"id":"r1","name":"Auditor ... - Current","datastore_active":true}]}}"#,
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
async fn asic_registered_auditors_live_resolves_and_searches() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Default::default(),
    };
    let r = AsicRegisteredAuditors
        .process(
            &Target::new(TargetKind::Organisation, "Deloitte Touche Tohmatsu"),
            &ctx,
        )
        .await
        .expect("live ASIC query must not error");
    eprintln!(
        "asic_registered_auditors live: {} entities",
        r.entities.len()
    );
}
