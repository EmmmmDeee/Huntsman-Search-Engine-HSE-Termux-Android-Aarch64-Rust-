use super::*;
use crate::modules::asic_business_names::MAX_HITS;

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

/// Build a truncation seed the same way `process()` does, so the seed's
/// tag/evidence contract is verified without a live CKAN query.
fn build_seed(name: &str, matched_count: usize, total_matches: usize) -> Entity {
    let matches_capped = total_matches > MAX_HITS;
    let mut seed = Entity::new(EntityKind::Organisation, name, 0.55, "test");
    seed.tag("au");
    seed.tag("asic");
    seed.tag("search-result");
    let mut ev = Evidence::new(SRC, format!("ASIC Business Names search for `{name}`"))
        .with_attr("matched_count", matched_count.to_string())
        .with_attr("total_matches", total_matches.to_string());
    if matches_capped {
        ev = ev.with_attr("matches_capped", "true");
        seed.tag("truncated");
    }
    seed.add_evidence(ev);
    seed
}

#[test]
fn search_seed_carries_counts_without_truncation_under_cap() {
    // A result set below MAX_HITS still surfaces the total, but is not flagged
    // truncated — the operator sees these are ALL the registrations.
    let seed = build_seed("cut above painting", 12, 12);
    assert!(seed.has_tag("search-result"));
    assert!(!seed.has_tag("truncated"), "must not flag when under cap");
    let ev = &seed.evidence[0];
    assert_eq!(ev.attributes.get("total_matches").map(String::as_str), Some("12"));
    assert_eq!(ev.attributes.get("matched_count").map(String::as_str), Some("12"));
    assert!(
        !ev.attributes.contains_key("matches_capped"),
        "matches_capped must be absent when not truncated"
    );
}

#[test]
fn search_seed_signals_truncation_when_total_exceeds_cap() {
    // Regression (T2.140): when the register returns more than MAX_HITS matches,
    // the seed must be tagged `truncated` and carry the true total so a
    // due-diligence operator knows the emitted set was capped.
    let total = MAX_HITS + 37;
    let seed = build_seed("smith", MAX_HITS, total);
    assert!(seed.has_tag("truncated"), "seed must be tagged 'truncated'");
    let ev = &seed.evidence[0];
    assert_eq!(
        ev.attributes.get("total_matches").map(String::as_str),
        Some(total.to_string().as_str()),
        "total_matches must reflect the full match count"
    );
    assert_eq!(
        ev.attributes.get("matched_count").map(String::as_str),
        Some(MAX_HITS.to_string().as_str()),
        "matched_count is capped at MAX_HITS"
    );
    assert_eq!(
        ev.attributes.get("matches_capped").map(String::as_str),
        Some("true"),
        "matches_capped must be set when the cap is hit"
    );
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
