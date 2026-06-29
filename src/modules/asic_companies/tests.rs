use super::entity::{
    acn_matches_query, company_evidence, pick_resource, record_is_exact, records_to_entities,
};
use super::*;
use crate::core::entity::EntityKind;
use crate::core::module::{ModuleCategory, ModuleCost};
use crate::core::scan::{Target, TargetKind};
use crate::util::ckan::{PackageResponse, Resource, Response as CkanResp};
use serde_json::{Map, Value};

fn sample() -> Vec<Map<String, Value>> {
    let raw = r#"[
        {"_id":1,"Company Name":"ACME WIDGETS PTY LTD","ACN":"123456789","Type":"Australian Proprietary Company","Class":"Limited By Shares","Sub Class":"Proprietary Other","Status":"Registered","Date of Registration":"01/03/2005","Previous State of Registration":"NSW","State Registration number":"R123","Current Name Ind":"Y"},
        {"_id":2,"Company Name":"GLOBEX HOLDINGS PTY LTD","ACN":"987654321","Type":"Australian Proprietary Company","Class":"Limited By Shares","Status":"Registered"}
    ]"#;
    serde_json::from_str(raw).unwrap()
}

#[test]
fn accepts_org_fullname_and_abn() {
    let m = AsicCompanies;
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Pty Ltd")));
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Jane Director")));
    assert!(m.accepts(&Target::new(TargetKind::AbnAcn, "123456789")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

#[test]
fn module_metadata() {
    let m = AsicCompanies;
    assert_eq!(m.name(), "asic_companies");
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::Free);
    assert_eq!(m.category(), ModuleCategory::Corporate);
    assert!(m.max_timeout_ms() > 3_000);
    assert_eq!(m.priority(), 111);
    assert_eq!(m.cache_ttl_secs(), 86_400);
    assert_eq!(m.attack_techniques(), &["T1591.002"]);
    // No address/coordinates in this dataset.
    assert_eq!(
        m.produces(),
        &[EntityKind::Organisation, EntityKind::AbnAcn]
    );
}

#[test]
fn pick_resource_prefers_current_over_help_file() {
    // The real package shape: a "Help File" datastore resource AND the real
    // "Current" CSV. The "Current" preference must win so the 27-row help file is
    // never queried as if it were the register.
    let resources = vec![
        Resource {
            id: Some("help-id".into()),
            name: Some("Company Dataset - Help File".into()),
            datastore_active: Some(true),
        },
        Resource {
            id: Some("current-id".into()),
            name: Some("Company Dataset - Current".into()),
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
    assert!(crate::util::target_match::name_all_tokens_match(
        "ACME WIDGETS PTY LTD",
        "Acme Widgets"
    ));
    assert!(!crate::util::target_match::name_all_tokens_match(
        "ACME WIDGETS PTY LTD",
        "Acme Holdings"
    ));
    // A common token must not match inside another word.
    assert!(!crate::util::target_match::name_all_tokens_match(
        "ACMEX PTY LTD",
        "Acme"
    ));
}

#[test]
fn org_match_emits_org_and_acn() {
    let recs = sample();
    // Seed by org name; only row 1 matches whole-word.
    let ents = records_to_entities(&recs, 2, "Acme Widgets", false, "scan-1");

    let org = ents
        .iter()
        .find(|e| e.kind == EntityKind::Organisation && e.value == "ACME WIDGETS PTY LTD")
        .expect("exact registered company organisation");
    assert!(org.tags.iter().any(|t| t == "registered-company"));
    assert!(org.tags.iter().any(|t| t == "asic"));
    assert!((org.confidence - ORG_EXACT).abs() < f64::EPSILON);

    // ACN pivot (tagged as an ACN).
    let acn = ents
        .iter()
        .find(|e| e.kind == EntityKind::AbnAcn)
        .expect("ACN pivot");
    assert_eq!(acn.value, "123456789");
    assert!(acn.tags.iter().any(|t| t == "acn"));

    // No address is produced by this dataset.
    assert!(ents.iter().all(|e| e.kind != EntityKind::Address));

    // Row 2 only loosely matched → sub-floor candidate, no ACN pivot.
    let cand = ents
        .iter()
        .find(|e| e.value == "GLOBEX HOLDINGS PTY LTD")
        .expect("candidate still surfaced (no omission)");
    assert!(cand.tags.iter().any(|t| t == "name-candidate"));
    assert!(cand.confidence < 0.50, "candidate below expansion floor");
}

#[test]
fn acn_seed_emits_matched_company_and_acn() {
    let recs = sample();
    let ents = records_to_entities(&recs, 2, "987654321", true, "scan-acn");
    let org = ents
        .iter()
        .find(|e| e.kind == EntityKind::Organisation && e.value == "GLOBEX HOLDINGS PTY LTD")
        .expect("ACN-matched company");
    assert!(org.tags.iter().any(|t| t == "registered-company"));
    let acn = ents
        .iter()
        .find(|e| e.kind == EntityKind::AbnAcn && e.value == "987654321")
        .expect("ACN pivot for the ACN-seeded match");
    assert!(acn.tags.iter().any(|t| t == "acn"));
}

#[test]
fn non_matching_page_yields_no_company_finding() {
    // A page that does NOT contain the seed must emit no exact company —
    // false-positive guard. (Rows are still surfaced as inert candidates.)
    let recs = sample();
    let ents = records_to_entities(&recs, 2, "Initech Systems", false, "scan-2");
    assert!(
        !ents
            .iter()
            .any(|e| e.tags.iter().any(|t| t == "registered-company")),
        "no row matches the seed → no high-confidence company attributed"
    );
    assert!(
        ents.iter().all(|e| e.confidence < 0.50),
        "every surfaced row is a sub-floor candidate"
    );
    assert!(
        ents.iter().all(|e| e.kind != EntityKind::AbnAcn),
        "no ACN pivot from a non-matching page"
    );
    assert_eq!(
        ents.iter()
            .filter(|e| e.kind == EntityKind::Organisation)
            .count(),
        2
    );
}

#[test]
fn evidence_gates_attrs_on_presence() {
    let recs = sample();
    let ev = company_evidence(&recs[0], "ACME WIDGETS PTY LTD", 2);
    assert_eq!(
        ev.attributes.get("acn").map(String::as_str),
        Some("123456789")
    );
    assert_eq!(
        ev.attributes
            .get("date_of_registration")
            .map(String::as_str),
        Some("01/03/2005")
    );
    // Absent column produces no empty attribute (row 2 has no Sub Class).
    let ev2 = company_evidence(&recs[1], "GLOBEX HOLDINGS PTY LTD", 2);
    assert!(!ev2.attributes.contains_key("sub_class"));
    assert!(!ev2.attributes.contains_key("date_of_registration"));
}

#[test]
fn ckan_envelopes_round_trip() {
    let ok: CkanResp =
        serde_json::from_str(r#"{"success":true,"result":{"total":0,"records":[]}}"#).unwrap();
    assert_eq!(ok.success, Some(true));

    let pkg: PackageResponse = serde_json::from_str(
        r#"{"success":true,"result":{"resources":[{"id":"help","name":"Company Dataset - Help File","datastore_active":true},{"id":"r1","name":"Company Dataset - Current","datastore_active":true}]}}"#,
    )
    .unwrap();
    assert_eq!(
        pick_resource(&pkg.result.unwrap().resources).as_deref(),
        Some("r1")
    );
}

/// Live end-to-end proof against the REAL ASIC company register on data.gov.au.
#[tokio::test]
#[ignore = "hits the live data.gov.au ASIC datastore; run manually"]
async fn asic_companies_live_resolves_and_searches() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Default::default(),
    };
    let r = AsicCompanies
        .process(
            &Target::new(TargetKind::Organisation, "Commonwealth Bank Australia"),
            &ctx,
        )
        .await
        .expect("live ASIC query must not error");
    eprintln!("asic_companies live: {} entities", r.entities.len());
}
