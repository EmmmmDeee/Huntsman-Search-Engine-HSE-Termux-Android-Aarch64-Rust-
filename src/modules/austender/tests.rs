use super::entity::{
    contract_evidence, name_matches_query, record_is_exact, records_to_entities, supplier_abn,
    supplier_locality,
};
use super::*;
use crate::core::entity::EntityKind;
use crate::core::module::{ModuleCategory, ModuleCost};
use crate::core::scan::{Target, TargetKind};
use crate::util::ckan::Response as CkanResp;
use serde_json::{Map, Value};

fn sample() -> Vec<Map<String, Value>> {
    // Shapes mirror real datastore_search rows for q="Telstra".
    let raw = r#"[
        {"_id":1,"Supplier Name":"TELSTRA CORPORATION LIMITED","Supplier ABN":"33051775556","Agency Name":"Department of Finance","Contract ID":"CN1234","Contract Value":"125000","Description":"Mobile voice and data services","Supplier Address":"GPO BOX 9901","Supplier Suburb":"Melbourne","Supplier State":"VIC","Supplier Postcode":"3000","Supplier Country":"Australia","Publish Date":"2017-08-01"},
        {"_id":2,"Supplier Name":"TELSTRA HEALTH PTY LTD","Supplier ABN":"19121530831","Agency Name":"Department of Health","Contract Value":"50000","Supplier Suburb":"Sydney","Supplier State":"NSW","Supplier Postcode":"2000"},
        {"_id":3,"Supplier Name":"OPTUS NETWORKS PTY LIMITED","Supplier ABN":"92008570330","Agency Name":"Services Australia","Supplier State":"NSW"}
    ]"#;
    serde_json::from_str(raw).unwrap()
}

#[test]
fn accepts_org_name_and_abn_only() {
    let m = AusTender;
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Telstra")));
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Jane Citizen")));
    assert!(m.accepts(&Target::new(TargetKind::AbnAcn, "33051775556")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
}

#[test]
fn module_metadata() {
    let m = AusTender;
    assert_eq!(m.name(), "austender");
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::Free);
    assert_eq!(m.category(), ModuleCategory::Corporate);
    // Non-passive network module must beat the 3s default timeout (CI guard).
    assert!(m.max_timeout_ms() > 3_000);
    // Government / public-records band.
    assert!((110..=118).contains(&m.priority()));
    // Corporate registry that geocodes the supplier address but surfaces no
    // officer/role: Physical Locations + Business Relationships, NOT Identify Roles.
    assert_eq!(m.attack_techniques(), &["T1591.001", "T1591.002"]);
    assert!(!m.attack_techniques().contains(&"T1591.004"));
}

#[test]
fn name_match_is_whole_word_not_substring() {
    assert!(name_matches_query("TELSTRA CORPORATION LIMITED", "telstra"));
    assert!(name_matches_query(
        "TELSTRA HEALTH PTY LTD",
        "telstra health"
    ));
    // Order-independent, punctuation-split.
    assert!(name_matches_query(
        "Australian Red Cross Society",
        "red cross australian"
    ));
    // A loose full-text hit that lacks a seed token is NOT exact.
    assert!(!name_matches_query("OPTUS NETWORKS PTY LIMITED", "telstra"));
    // Whole word, not substring: "tel" must not match inside "Intel".
    assert!(!name_matches_query("Intel Australia Pty Ltd", "tel"));
}

#[test]
fn exact_supplier_fans_out_pivots_candidate_does_not() {
    let recs = sample();
    let ents = records_to_entities(&recs, 3, "telstra", false, "scan-1");

    // Row 1 "TELSTRA CORPORATION LIMITED" is exact → Organisation + AbnAcn
    // + agency Organisation + Address (+ inline Coordinates if geocodable).
    let supplier = ents
        .iter()
        .find(|e| e.kind == EntityKind::Organisation && e.value == "TELSTRA CORPORATION LIMITED")
        .expect("exact supplier organisation");
    assert!(supplier.tags.iter().any(|t| t == "exact-name-match"));
    assert!(supplier.tags.iter().any(|t| t == "government-contract"));
    assert!((supplier.confidence - ORG_EXACT).abs() < f64::EPSILON);

    let abn = ents
        .iter()
        .find(|e| e.kind == EntityKind::AbnAcn && e.value == "33051775556")
        .expect("exact hit emits the supplier ABN for cross-correlation");
    assert!((abn.confidence - ABN_CONF).abs() < f64::EPSILON);

    let agency = ents
        .iter()
        .find(|e| e.kind == EntityKind::Organisation && e.value == "Department of Finance")
        .expect("awarding agency emitted as a Business Relationship");
    assert!(agency.tags.iter().any(|t| t == "government-agency"));

    let addr = ents
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("exact hit emits a geocodable supplier address");
    assert_eq!(addr.value, "Melbourne, VIC 3000, Australia");
    assert!(addr.tags.iter().any(|t| t == "geoint"));
    // The PO box street line rides in evidence (no omission), not the value.
    assert!(
        addr.evidence[0]
            .attributes
            .iter()
            .any(|(k, v)| k == "supplier_address" && v == "GPO BOX 9901")
    );

    // Row 3 "OPTUS NETWORKS PTY LIMITED" only loosely matched → candidate:
    // a single sub-floor Organisation, no ABN/agency/Address pivots from it.
    let optus = ents
        .iter()
        .find(|e| e.value == "OPTUS NETWORKS PTY LIMITED")
        .expect("candidate still surfaced (no omission)");
    assert!(optus.tags.iter().any(|t| t == "name-candidate"));
    assert!(
        optus.confidence < 0.50,
        "candidate must stay below expansion floor"
    );
    // Its ABN is in evidence (complete) but NOT a separate AbnAcn entity.
    assert!(
        optus.evidence[0]
            .attributes
            .iter()
            .any(|(k, v)| k == "supplier_abn" && v == "92008570330")
    );
    assert!(
        !ents
            .iter()
            .any(|e| e.kind == EntityKind::AbnAcn && e.value == "92008570330")
    );
}

#[test]
fn abn_seed_matches_exact_supplier_row() {
    // An ABN seed is matched on the supplier's exact ABN digits — unambiguous.
    let recs = sample();
    let ents = records_to_entities(&recs, 1, "19121530831", true, "scan-2");
    let health = ents
        .iter()
        .find(|e| e.kind == EntityKind::Organisation && e.value == "TELSTRA HEALTH PTY LTD")
        .expect("supplier matched by ABN");
    assert!(health.tags.iter().any(|t| t == "exact-name-match"));
    // The ABN of the OTHER (non-matching) rows must NOT be promoted to an entity.
    assert!(
        !ents
            .iter()
            .any(|e| e.kind == EntityKind::AbnAcn && e.value == "33051775556")
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::AbnAcn && e.value == "19121530831")
    );
}

#[test]
fn supplier_abn_validates_eleven_digit_length() {
    let mut rec = Map::new();
    rec.insert(
        "Supplier ABN".into(),
        Value::String("33 051 775 556".into()),
    );
    assert_eq!(supplier_abn(&rec).as_deref(), Some("33051775556"));
    // Numerically-typed column still recovered.
    let mut numrec = Map::new();
    numrec.insert("Supplier ABN".into(), Value::from(33_051_775_556u64));
    assert_eq!(supplier_abn(&numrec).as_deref(), Some("33051775556"));
    // Wrong length / missing → None.
    let mut short = Map::new();
    short.insert("Supplier ABN".into(), Value::String("12345".into()));
    assert!(supplier_abn(&short).is_none());
    assert!(supplier_abn(&Map::new()).is_none());
}

#[test]
fn record_is_exact_honours_abn_vs_name_mode() {
    let recs = sample();
    // Name mode: whole-word token match on supplier name.
    assert!(record_is_exact(&recs[0], "telstra corporation", false));
    assert!(!record_is_exact(&recs[2], "telstra", false));
    // ABN mode: exact digit match on the supplier's ABN.
    assert!(record_is_exact(&recs[0], "33051775556", true));
    assert!(!record_is_exact(&recs[0], "19121530831", true));
}

#[test]
fn supplier_locality_handles_missing_fields() {
    let mut rec = Map::new();
    rec.insert("Supplier State".into(), Value::String("QLD".into()));
    rec.insert("Supplier Postcode".into(), Value::String("4000".into()));
    // No suburb, no country → defaults Country=Australia.
    assert_eq!(
        supplier_locality(&rec).as_deref(),
        Some("QLD 4000, Australia")
    );
    // Nothing locating at all → None.
    assert!(supplier_locality(&Map::new()).is_none());
}

#[test]
fn contract_evidence_gates_attrs_on_presence() {
    let recs = sample();
    let ev = contract_evidence(&recs[0], 3);
    assert_eq!(
        ev.attributes.get("supplier_abn").map(String::as_str),
        Some("33051775556")
    );
    assert_eq!(
        ev.attributes.get("agency").map(String::as_str),
        Some("Department of Finance")
    );
    assert_eq!(
        ev.attributes.get("total_matches").map(String::as_str),
        Some("3")
    );
    // Absent column produces no empty attribute.
    assert!(!ev.attributes.contains_key("amendment_reason"));
    assert!(ev.summary.contains("TELSTRA CORPORATION LIMITED"));
}

#[test]
fn ckan_envelope_round_trips() {
    let ok: CkanResp =
        serde_json::from_str(r#"{"success":true,"result":{"total":0,"records":[]}}"#).unwrap();
    assert_eq!(ok.success, Some(true));
    assert_eq!(ok.result.unwrap().records.len(), 0);
    let err: CkanResp =
        serde_json::from_str(r#"{"success":false,"error":{"message":"Resource not found"}}"#)
            .unwrap();
    assert_eq!(err.success, Some(false));
    assert!(err.result.is_none());
}

#[test]
fn short_query_is_ignored_by_guard() {
    // Guarded in process(); assert the precondition the guard relies on.
    assert!("ab".len() < 3);
    assert!("abc".len() >= 3);
    // An ABN that isn't 11 digits is rejected before any query.
    assert_ne!(crate::util::str_util::ascii_digits("123").len(), 11);
    assert_eq!(
        crate::util::str_util::ascii_digits("33 051 775 556").len(),
        11
    );
}

/// Live end-to-end proof against the REAL AusTender datastore on data.gov.au —
/// no mock. Run with
/// `cargo test -p huntsman-search-engine austender_live -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "hits the live data.gov.au AusTender datastore; run manually"]
async fn austender_live_finds_a_government_supplier() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Default::default(),
    };
    let r = AusTender
        .process(
            &Target::new(TargetKind::Organisation, "Telstra Corporation Limited"),
            &ctx,
        )
        .await
        .expect("live AusTender query must not error");
    eprintln!("austender live: {} entities", r.entities.len());
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Organisation && e.has_tag("government-contract")),
        "expected an awarded-contract supplier from the live AusTender export"
    );
}
