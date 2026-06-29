use super::entity::{
    abn_matches_query, licensee_coords, licensee_evidence, licensee_locality, pick_resource,
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
        {"_id":1,"REGISTER_NAME":"AFS Licensee","AFS_LIC_NUM":"123456","AFS_LIC_NAME":"ACME FINANCIAL PTY LTD","AFS_LIC_ABN_ACN":"51824753556","AFS_LIC_START_DT":"01/02/2010","AFS_LIC_ADD_LOCAL":"Sydney","AFS_LIC_ADD_STATE":"NSW","AFS_LIC_ADD_PCODE":"2000","AFS_LIC_ADD_COUNTRY":"Australia","AFS_LIC_LAT":"-33.8688","AFS_LIC_LNG":"151.2093","AFS_LIC_CONDITION":"Standard"},
        {"_id":2,"REGISTER_NAME":"AFS Licensee","AFS_LIC_NUM":"999999","AFS_LIC_NAME":"ACME WIDGETS PTY LTD","AFS_LIC_ABN_ACN":"11111111111","AFS_LIC_ADD_STATE":"VIC","AFS_LIC_LAT":"0","AFS_LIC_LNG":"0"}
    ]"#;
    serde_json::from_str(raw).unwrap()
}

#[test]
fn accepts_org_fullname_and_abn() {
    let m = AsicAfsLicensees;
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Pty Ltd")));
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Jane Trader")));
    assert!(m.accepts(&Target::new(TargetKind::AbnAcn, "51824753556")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

#[test]
fn module_metadata() {
    let m = AsicAfsLicensees;
    assert_eq!(m.name(), "asic_afs_licensees");
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::Free);
    assert_eq!(m.category(), ModuleCategory::Corporate);
    assert!(m.max_timeout_ms() > 3_000);
    assert_eq!(m.priority(), 109);
    assert_eq!(m.cache_ttl_secs(), 86_400);
    assert_eq!(m.attack_techniques(), &["T1591.001", "T1591.002"]);
}

#[test]
fn pick_resource_prefers_current_then_first_active() {
    let resources = vec![
        Resource {
            id: Some("old-id".into()),
            name: Some("AFS Licensee - Historical".into()),
            datastore_active: Some(true),
        },
        Resource {
            id: Some("current-id".into()),
            name: Some("AFS Licensee - Current".into()),
            datastore_active: Some(true),
        },
    ];
    assert_eq!(pick_resource(&resources).as_deref(), Some("current-id"));
    assert!(pick_resource(&[]).is_none());
}

#[test]
fn abn_seed_matches_recorded_abn_exactly() {
    let recs = sample();
    // Digit-only equality: spacing in the seed must not defeat the match.
    assert!(abn_matches_query(&recs[0], "51 824 753 556"));
    assert!(abn_matches_query(&recs[0], "51824753556"));
    assert!(!abn_matches_query(&recs[0], "12345678901"));
    assert!(record_is_exact(&recs[0], "51824753556", true));
    // A non-matching ABN seed on row 2 is not exact.
    assert!(!record_is_exact(&recs[1], "51824753556", true));
}

#[test]
fn name_seed_matches_whole_word() {
    assert!(crate::util::target_match::name_all_tokens_match(
        "ACME FINANCIAL PTY LTD",
        "Acme Financial"
    ));
    // Missing a seed token → not a match.
    assert!(!crate::util::target_match::name_all_tokens_match(
        "ACME FINANCIAL PTY LTD",
        "Acme Holdings"
    ));
}

#[test]
fn coords_parse_only_when_plausible() {
    let recs = sample();
    assert_eq!(licensee_coords(&recs[0]), Some((-33.8688, 151.2093)));
    // Row 2 has the 0,0 sentinel → rejected.
    assert!(licensee_coords(&recs[1]).is_none());
}

#[test]
fn abn_exact_emits_org_abn_address_and_coords() {
    let recs = sample();
    // Seed by ABN; only row 1 carries that ABN.
    let ents = records_to_entities(&recs, 2, "51824753556", true, "scan-1");

    let org = ents
        .iter()
        .find(|e| e.kind == EntityKind::Organisation && e.value == "ACME FINANCIAL PTY LTD")
        .expect("exact AFS licensee organisation");
    assert!(org.tags.iter().any(|t| t == "afs-licensee"));
    assert!(org.tags.iter().any(|t| t == "financial-services"));
    assert!((org.confidence - ORG_EXACT).abs() < f64::EPSILON);

    let abn = ents
        .iter()
        .find(|e| e.kind == EntityKind::AbnAcn)
        .expect("ABN pivot");
    assert_eq!(abn.value, "51824753556");

    let addr = ents
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("address pivot");
    assert_eq!(addr.value, "Sydney, NSW 2000, Australia");

    let coord = ents
        .iter()
        .find(|e| e.kind == EntityKind::Coordinates)
        .expect("exact coordinates emitted");
    assert_eq!(coord.value, "-33.868800,151.209300");
    assert!(coord.tags.iter().any(|t| t == "asic-supplied"));

    // Row 2 ("ACME WIDGETS") only loosely matched → sub-floor candidate, no
    // pivots, no coords.
    let cand = ents
        .iter()
        .find(|e| e.value == "ACME WIDGETS PTY LTD")
        .expect("candidate still surfaced (no omission)");
    assert!(cand.tags.iter().any(|t| t == "name-candidate"));
    assert!(cand.confidence < 0.50, "candidate below expansion floor");
}

#[test]
fn non_matching_page_yields_no_licensee_finding() {
    // A page that does NOT contain the seed must emit no exact licensee —
    // false-positive guard. (Rows are still surfaced as inert candidates.)
    let recs = sample();
    let ents = records_to_entities(&recs, 2, "Globex Holdings", false, "scan-2");
    assert!(
        !ents
            .iter()
            .any(|e| e.tags.iter().any(|t| t == "afs-licensee")),
        "no row matches the seed → no high-confidence licensee attributed"
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
    rec.insert("AFS_LIC_ADD_STATE".into(), Value::String("QLD".into()));
    rec.insert("AFS_LIC_ADD_PCODE".into(), Value::String("4000".into()));
    assert_eq!(licensee_locality(&rec).as_deref(), Some("QLD 4000"));
    assert!(licensee_locality(&Map::new()).is_none());
}

#[test]
fn evidence_gates_attrs_on_presence() {
    let recs = sample();
    let ev = licensee_evidence(&recs[0], "ACME FINANCIAL PTY LTD", 2);
    assert_eq!(
        ev.attributes.get("afs_licence_number").map(String::as_str),
        Some("123456")
    );
    assert_eq!(
        ev.attributes.get("latitude").map(String::as_str),
        Some("-33.8688")
    );
    // Absent column produces no empty attribute (row 2 has no start date).
    let ev2 = licensee_evidence(&recs[1], "ACME WIDGETS PTY LTD", 2);
    assert!(!ev2.attributes.contains_key("licence_start"));
}

#[test]
fn ckan_envelopes_round_trip() {
    let ok: CkanResp =
        serde_json::from_str(r#"{"success":true,"result":{"total":0,"records":[]}}"#).unwrap();
    assert_eq!(ok.success, Some(true));

    let pkg: PackageResponse = serde_json::from_str(
        r#"{"success":true,"result":{"resources":[{"id":"r1","name":"AFS ... - Current","datastore_active":true}]}}"#,
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
async fn asic_afs_licensees_live_resolves_and_searches() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Default::default(),
    };
    let r = AsicAfsLicensees
        .process(
            &Target::new(TargetKind::Organisation, "AMP Financial Planning"),
            &ctx,
        )
        .await
        .expect("live ASIC query must not error");
    eprintln!("asic_afs_licensees live: {} entities", r.entities.len());
}
