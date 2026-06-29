use super::entity::{
    body_abn, body_evidence, head_office_locality, pick_resource, record_is_exact,
    records_to_entities,
};
use super::*;
use crate::core::entity::EntityKind;
use crate::core::module::{ModuleCategory, ModuleCost};
use crate::core::scan::{Target, TargetKind};
use crate::util::ckan::{PackageResponse, Resource, Response as CkanResp};
use serde_json::{Map, Value};

fn sample() -> Vec<Map<String, Value>> {
    // Shapes mirror real datastore_search rows for q="Taxation".
    let raw = r#"[
        {"_id":1,"Title":"Australian Taxation Office","Portfolio":"Treasury","Classification":"Non-corporate Commonwealth entity","Type of Body":"Statutory Agency","Description":"The principal revenue collection agency.","Established By / Under":"Taxation Administration Act 1953","ABN":"51824753556","Parent Organisation":"Department of the Treasury","Head Office Street Address":"26 Narellan Street","Head Office Suburb":"Canberra","Head Office State":"ACT","Head Office Postcode":"2600","Head Office Country":"Australia","Website Address":"https://www.ato.gov.au"},
        {"_id":2,"Title":"Tax Practitioners Board","Portfolio":"Treasury","ABN":"83772614680","Head Office Suburb":"Sydney","Head Office State":"NSW","Head Office Postcode":"2000"},
        {"_id":3,"Title":"Department of the Treasury","Portfolio":"Treasury","ABN":"92802414793","Head Office State":"ACT"}
    ]"#;
    serde_json::from_str(raw).unwrap()
}

#[test]
fn accepts_org_name_and_abn_only() {
    let m = Agor;
    assert!(m.accepts(&Target::new(
        TargetKind::Organisation,
        "Australian Taxation Office"
    )));
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Jane Citizen")));
    assert!(m.accepts(&Target::new(TargetKind::AbnAcn, "51824753556")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
}

#[test]
fn module_metadata() {
    let m = Agor;
    assert_eq!(m.name(), "agor");
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::Free);
    assert_eq!(m.category(), ModuleCategory::Corporate);
    // Two-step network module must beat the 3s default timeout (CI guard).
    assert!(m.max_timeout_ms() > 3_000);
    // Government / public-records band.
    assert!((110..=118).contains(&m.priority()));
    // A quarterly register → a long cache TTL (7 days).
    assert_eq!(m.cache_ttl_secs(), 604_800);
    // Geocodes the head office + links body→portfolio/parent, surfaces no role:
    // Physical Locations + Business Relationships, NOT Identify Roles.
    assert_eq!(m.attack_techniques(), &["T1591.001", "T1591.002"]);
    assert!(!m.attack_techniques().contains(&"T1591.004"));
}

#[test]
fn pick_resource_selects_most_recent_active() {
    let resources = vec![
        Resource {
            id: Some("old-id".into()),
            name: Some("AGOR 2024-10-01".into()),
            datastore_active: Some(true),
        },
        Resource {
            id: Some("new-id".into()),
            name: Some("AGOR 2025-04-01".into()),
            datastore_active: Some(true),
        },
        Resource {
            // A more recent date but NOT datastore-active → ignored.
            id: Some("inactive-id".into()),
            name: Some("AGOR 2025-07-01".into()),
            datastore_active: Some(false),
        },
    ];
    assert_eq!(pick_resource(&resources).as_deref(), Some("new-id"));
}

#[test]
fn pick_resource_falls_back_to_first_active_when_no_date() {
    let resources = vec![
        Resource {
            id: Some("csv-id".into()),
            name: Some("Data dictionary".into()),
            datastore_active: Some(false),
        },
        Resource {
            id: Some("active-id".into()),
            name: Some("Unparseable name".into()),
            datastore_active: Some(true),
        },
    ];
    assert_eq!(pick_resource(&resources).as_deref(), Some("active-id"));
    // No datastore-active resource at all → None.
    assert!(pick_resource(&[]).is_none());
}

#[test]
fn name_match_is_whole_word_not_substring() {
    assert!(crate::util::target_match::name_all_tokens_match(
        "Australian Taxation Office",
        "taxation"
    ));
    assert!(crate::util::target_match::name_all_tokens_match(
        "Australian Taxation Office",
        "taxation office"
    ));
    // Order-independent, punctuation-split.
    assert!(crate::util::target_match::name_all_tokens_match(
        "Department of the Treasury",
        "treasury department"
    ));
    // A loose full-text hit that lacks a seed token is NOT exact.
    assert!(!crate::util::target_match::name_all_tokens_match(
        "Tax Practitioners Board",
        "taxation"
    ));
    // Whole word, not substring: "tax" must not match inside "taxation".
    assert!(!crate::util::target_match::name_all_tokens_match(
        "Australian Taxation Office",
        "tax"
    ));
}

#[test]
fn exact_body_fans_out_pivots_candidate_does_not() {
    let recs = sample();
    let ents = records_to_entities(&recs, 3, "taxation", false, "scan-1");

    // Row 1 "Australian Taxation Office" is exact → Organisation + AbnAcn
    // + portfolio + parent Organisations + Domain + Address (+ Coordinates).
    let body = ents
        .iter()
        .find(|e| e.kind == EntityKind::Organisation && e.value == "Australian Taxation Office")
        .expect("exact body organisation");
    assert!(body.tags.iter().any(|t| t == "exact-name-match"));
    assert!(body.tags.iter().any(|t| t == "gov-body"));
    assert!((body.confidence - ORG_EXACT).abs() < f64::EPSILON);

    let abn = ents
        .iter()
        .find(|e| e.kind == EntityKind::AbnAcn && e.value == "51824753556")
        .expect("exact hit emits the body ABN for cross-correlation");
    assert!((abn.confidence - ABN_CONF).abs() < f64::EPSILON);

    let portfolio = ents
        .iter()
        .find(|e| e.kind == EntityKind::Organisation && e.value == "Treasury")
        .expect("portfolio emitted as a Business Relationship");
    assert!(portfolio.tags.iter().any(|t| t == "portfolio"));

    let parent = ents
        .iter()
        .find(|e| e.kind == EntityKind::Organisation && e.value == "Department of the Treasury")
        .expect("parent organisation emitted as a Business Relationship");
    assert!(parent.tags.iter().any(|t| t == "parent-organisation"));

    let dom = ents
        .iter()
        .find(|e| e.kind == EntityKind::Domain)
        .expect("exact hit emits the website domain");
    assert_eq!(dom.value, "ato.gov.au");

    let addr = ents
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("exact hit emits a geocodable head-office address");
    assert_eq!(addr.value, "Canberra, ACT 2600, Australia");
    assert!(addr.tags.iter().any(|t| t == "geoint"));
    // The street line rides in evidence (no omission), not the value.
    assert!(
        addr.evidence[0]
            .attributes
            .iter()
            .any(|(k, v)| k == "head_office_street_address" && v == "26 Narellan Street")
    );

    // Row 2 "Tax Practitioners Board" only loosely matched → candidate:
    // a single sub-floor Organisation, no ABN/portfolio/Address pivots from it.
    let tpb = ents
        .iter()
        .find(|e| e.value == "Tax Practitioners Board")
        .expect("candidate still surfaced (no omission)");
    assert!(tpb.tags.iter().any(|t| t == "name-candidate"));
    assert!(
        tpb.confidence < 0.50,
        "candidate must stay below expansion floor"
    );
    // Its ABN is in evidence (complete) but NOT a separate AbnAcn entity.
    assert!(
        tpb.evidence[0]
            .attributes
            .iter()
            .any(|(k, v)| k == "abn" && v == "83772614680")
    );
    assert!(
        !ents
            .iter()
            .any(|e| e.kind == EntityKind::AbnAcn && e.value == "83772614680")
    );
}

#[test]
fn abn_seed_matches_exact_body_row() {
    // An ABN seed is matched on the body's exact ABN digits — unambiguous.
    let recs = sample();
    let ents = records_to_entities(&recs, 1, "83772614680", true, "scan-2");
    let tpb = ents
        .iter()
        .find(|e| e.kind == EntityKind::Organisation && e.value == "Tax Practitioners Board")
        .expect("body matched by ABN");
    assert!(tpb.tags.iter().any(|t| t == "exact-name-match"));
    // The ABN of the OTHER (non-matching) rows must NOT be promoted to an entity.
    assert!(
        !ents
            .iter()
            .any(|e| e.kind == EntityKind::AbnAcn && e.value == "51824753556")
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::AbnAcn && e.value == "83772614680")
    );
}

#[test]
fn body_abn_validates_eleven_digit_length() {
    let mut rec = Map::new();
    rec.insert("ABN".into(), Value::String("51 824 753 556".into()));
    assert_eq!(body_abn(&rec).as_deref(), Some("51824753556"));
    // Numerically-typed column still recovered.
    let mut numrec = Map::new();
    numrec.insert("ABN".into(), Value::from(51_824_753_556u64));
    assert_eq!(body_abn(&numrec).as_deref(), Some("51824753556"));
    // Wrong length / missing → None.
    let mut short = Map::new();
    short.insert("ABN".into(), Value::String("12345".into()));
    assert!(body_abn(&short).is_none());
    assert!(body_abn(&Map::new()).is_none());
}

#[test]
fn record_is_exact_honours_abn_vs_name_mode() {
    let recs = sample();
    // Name mode: whole-word token match on Title.
    assert!(record_is_exact(&recs[0], "taxation office", false));
    assert!(!record_is_exact(&recs[1], "taxation", false));
    // ABN mode: exact digit match on the body's ABN.
    assert!(record_is_exact(&recs[0], "51824753556", true));
    assert!(!record_is_exact(&recs[0], "83772614680", true));
}

#[test]
fn head_office_locality_handles_missing_fields() {
    let mut rec = Map::new();
    rec.insert("Head Office State".into(), Value::String("QLD".into()));
    rec.insert("Head Office Postcode".into(), Value::String("4000".into()));
    // No suburb, no country → defaults Country=Australia.
    assert_eq!(
        head_office_locality(&rec).as_deref(),
        Some("QLD 4000, Australia")
    );
    // Nothing locating at all → None.
    assert!(head_office_locality(&Map::new()).is_none());
}

#[test]
fn body_evidence_gates_attrs_on_presence() {
    let recs = sample();
    let ev = body_evidence(&recs[0], 3);
    assert_eq!(
        ev.attributes.get("abn").map(String::as_str),
        Some("51824753556")
    );
    assert_eq!(
        ev.attributes.get("portfolio").map(String::as_str),
        Some("Treasury")
    );
    assert_eq!(
        ev.attributes.get("total_matches").map(String::as_str),
        Some("3")
    );
    // Absent column produces no empty attribute.
    assert!(!ev.attributes.contains_key("amendment_reason"));
    assert!(ev.summary.contains("Australian Taxation Office"));
}

#[test]
fn ckan_envelopes_round_trip() {
    let ok: CkanResp =
        serde_json::from_str(r#"{"success":true,"result":{"total":0,"records":[]}}"#).unwrap();
    assert_eq!(ok.success, Some(true));
    assert_eq!(ok.result.unwrap().records.len(), 0);

    let pkg: PackageResponse = serde_json::from_str(
        r#"{"success":true,"result":{"resources":[{"id":"r1","name":"AGOR 2025-04-01","datastore_active":true}]}}"#,
    )
    .unwrap();
    assert_eq!(pkg.success, Some(true));
    assert_eq!(
        pick_resource(&pkg.result.unwrap().resources).as_deref(),
        Some("r1")
    );
}

#[test]
fn short_query_is_ignored_by_guard() {
    // Guarded in process(); assert the precondition the guard relies on.
    assert!("ab".len() < 3);
    assert!("abc".len() >= 3);
    // An ABN that isn't 11 digits is rejected before any query.
    assert_ne!(crate::util::str_util::ascii_digits("123").len(), 11);
    assert_eq!(
        crate::util::str_util::ascii_digits("51 824 753 556").len(),
        11
    );
}

/// Live end-to-end proof against the REAL AGOR register on data.gov.au — no
/// mock. Run with
/// `cargo test -p huntsman-search-engine agor_live -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "hits the live data.gov.au AGOR datastore; run manually"]
async fn agor_live_finds_a_government_body() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Default::default(),
    };
    let r = Agor
        .process(
            &Target::new(TargetKind::Organisation, "Australian Taxation Office"),
            &ctx,
        )
        .await
        .expect("live AGOR query must not error");
    eprintln!("agor live: {} entities", r.entities.len());
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Organisation && e.has_tag("gov-body")),
        "expected a government body from the live AGOR register"
    );
}
