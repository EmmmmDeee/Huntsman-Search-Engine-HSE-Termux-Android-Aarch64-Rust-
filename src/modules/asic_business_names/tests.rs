use super::*;

const REC: &str = r#"{
  "BN_NAME":"A Cut Above Painting & Texture Coating","BN_STATUS":"Registered",
  "BN_REG_DT":"04/12/2019","BN_ABN":"86634681397","BN_STATE_OF_REG":"QLD"}"#;

fn rec(json: &str) -> Map<String, Value> {
    serde_json::from_str(json).unwrap()
}

#[test]
fn emits_registered_name_and_holder_abn() {
    let mut seen = std::collections::HashSet::new();
    let mut r = ModuleResult::new();
    emit_business_name(&rec(REC), "scan", &mut seen, &mut r);
    let e = &r.entities;

    let org = e
        .iter()
        .find(|x| x.kind == EntityKind::Organisation)
        .expect("organisation");
    assert_eq!(org.value, "A Cut Above Painting & Texture Coating");
    assert!(org.has_tag("business-name") && org.has_tag("status:registered"));

    let abn = e
        .iter()
        .find(|x| x.kind == EntityKind::AbnAcn)
        .expect("abn");
    assert_eq!(
        abn.value.chars().filter(char::is_ascii_digit).collect::<String>(),
        "86634681397"
    );
}

#[test]
fn registered_state_emits_au_state_address() {
    // BN_STATE_OF_REG was parsed into evidence but never became a geo anchor; it
    // must now emit a "{state}, Australia" Address tagged au-state, like the
    // sibling AU registries, so the jurisdiction reaches the AU geo correlators.
    let mut seen = std::collections::HashSet::new();
    let mut r = ModuleResult::new();
    emit_business_name(&rec(REC), "scan", &mut seen, &mut r);
    let addr = r
        .entities
        .iter()
        .find(|x| x.kind == EntityKind::Address)
        .expect("BN_STATE_OF_REG must emit an AU-state Address");
    assert_eq!(addr.value, "QLD, Australia");
    assert!(addr.has_tag("au-state:QLD") && addr.has_tag("country:AU"));
}

#[test]
fn abn_is_deduped_across_records() {
    let mut seen = std::collections::HashSet::new();
    let mut r = ModuleResult::new();
    // Same holder ABN under two different trading names.
    emit_business_name(&rec(REC), "scan", &mut seen, &mut r);
    let rec2 = rec(REC.replace("Texture Coating", "Texture Coatings").as_str());
    emit_business_name(&rec2, "scan", &mut seen, &mut r);
    assert_eq!(
        r.entities
            .iter()
            .filter(|x| x.kind == EntityKind::AbnAcn)
            .count(),
        1,
        "the shared ABN must be emitted once"
    );
    // But both registered names are surfaced.
    assert_eq!(
        r.entities
            .iter()
            .filter(|x| x.kind == EntityKind::Organisation)
            .count(),
        2
    );
}

#[test]
fn name_matching_requires_all_tokens() {
    let tokens = name_tokens("Cut Above Painting");
    assert!(record_name_matches(&rec(REC), &tokens));
    assert!(!record_name_matches(&rec(REC), &name_tokens("Smith Plumbing")));
}

#[test]
fn is_free_keyless_corporate_module() {
    let m = AsicBusinessNames;
    assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    assert_eq!(m.category(), ModuleCategory::Corporate);
    assert!(!m.attack_techniques().is_empty());
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Plumbing")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Jane Citizen")));
}

/// Live end-to-end proof against the REAL ASIC Business Names dataset — no mock.
/// Run with
/// `cargo test -p huntsman-search-engine asic_business_names_live -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "hits the live data.gov.au ASIC datastore; run manually"]
async fn asic_business_names_live_resolves_a_name() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    let r = AsicBusinessNames
        .process(&Target::new(TargetKind::Organisation, "Cut Above Painting"), &ctx)
        .await
        .expect("live ASIC query must not error");
    eprintln!("asic_business_names live: {} entities", r.entities.len());
    assert!(
        r.entities.iter().any(|e| e.kind == EntityKind::Organisation
            && e.value.to_ascii_lowercase().contains("painting")
            && e.has_tag("business-name")),
        "expected at least one matching registered business name"
    );
}
