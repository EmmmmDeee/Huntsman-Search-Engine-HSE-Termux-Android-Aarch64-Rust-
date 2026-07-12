use super::*;

/// Real ABS SEIFA 2016 SA2 response (Sydney - Haymarket - The Rocks).
const FIXTURE: &str = r#"{"features":[{"attributes":{
  "SA2_MAINCODE_2016":"117031337","SA2_NAME_2016":"Sydney - Haymarket - The Rocks",
  "STATE_NAME_2016":"New South Wales","SA2_URP_2016":27407,
  "SA2_IEO_SCORE_2016":1128,"SA2_IEO_QUINTILE_2016":5,"SA2_IEO_PER_AUS_2016":91,
  "SA2_IRSD_SCORE_2016":977,"SA2_IRSD_QUINTILE_2016":2,"SA2_IRSD_PER_AUS_2016":35,
  "SA2_IRSAD_SCORE_2016":1065,"SA2_IRSAD_QUINTILE_2016":4,"SA2_IRSAD_PER_AUS_2016":78,
  "SA2_IER_SCORE_2016":804,"SA2_IER_QUINTILE_2016":1,"SA2_IER_PER_AUS_2016":2}}]}"#;

/// Parse the fixture's first feature's attributes (mirrors `fetch_attrs`).
fn fixture_attrs() -> Map<String, Value> {
    let parsed: QueryResp = serde_json::from_str(FIXTURE).unwrap();
    parsed.features.into_iter().next().unwrap().attributes
}

#[test]
fn assemble_enriches_coordinate_with_full_seifa_profile() {
    let attrs = fixture_attrs();
    let mut r = ModuleResult::new();
    assemble("-33.8568,151.2153", &attrs, "scan", &mut r);

    let coord = r
        .entities
        .iter()
        .find(|x| x.kind == EntityKind::Coordinates && x.has_tag("seifa"))
        .expect("enriched coordinate");
    let ev = coord.evidence.first().expect("seifa evidence");
    let get = |k: &str| ev.attributes.get(k).map(String::as_str);
    assert_eq!(get("seifa_sa2"), Some("Sydney - Haymarket - The Rocks"));
    assert_eq!(get("population"), Some("27407"));
    assert_eq!(get("seifa_irsd_quintile"), Some("2")); // disadvantage
    assert_eq!(get("seifa_irsad_quintile"), Some("4"));
    assert_eq!(get("seifa_ier_score"), Some("804"));
    assert_eq!(get("seifa_irsd_pct_aus"), Some("35"));
    assert_eq!(get("seifa_year"), Some("2016"));
}

#[test]
fn assemble_emits_population_and_disadvantage_pivots() {
    let attrs = fixture_attrs();
    let mut r = ModuleResult::new();
    assemble("-33.8568,151.2153", &attrs, "scan", &mut r);
    let e = &r.entities;

    assert!(e.iter().any(|x| x.kind == EntityKind::Other("au-population".into())
        && x.value == "27407"
        && x.has_tag("demographic")));
    assert!(e.iter().any(|x| x.kind == EntityKind::Other("au-seifa-disadvantage".into())
        && x.value == "IRSD quintile 2 of 5"));
}

#[test]
fn assemble_skips_a_point_with_no_sa2_coverage() {
    // Offshore / no-SEIFA polygon → empty attributes → nothing emitted.
    let empty: Map<String, Value> = Map::new();
    let mut r = ModuleResult::new();
    assemble("-40.0,150.0", &empty, "scan", &mut r);
    assert!(r.entities.is_empty());
}

#[tokio::test]
async fn non_au_or_malformed_coordinate_makes_no_request() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "t".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    // Outside the AU bbox → returns before any network I/O (offline in CI).
    let london = AuSeifa
        .process(&Target::new(TargetKind::Coordinates, "51.5074,-0.1276"), &ctx)
        .await
        .expect("non-AU coordinate is a clean miss");
    assert!(london.entities.is_empty());
    let junk = AuSeifa
        .process(&Target::new(TargetKind::Coordinates, "xyz"), &ctx)
        .await
        .expect("malformed coordinate is a clean miss");
    assert!(junk.entities.is_empty());
}

#[test]
fn is_free_geo_module() {
    let m = AuSeifa;
    assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    assert_eq!(m.category(), ModuleCategory::Geo);
    assert!(!m.attack_techniques().is_empty());
    assert!(m.accepts(&Target::new(TargetKind::Coordinates, "-33.8568,151.2153")));
    assert!(!m.accepts(&Target::new(TargetKind::Address, "1 Macquarie St")));
}

/// Live end-to-end proof against the REAL ABS SEIFA service — no mock. Ignored
/// by default (network); run with
/// `cargo test -p huntsman-search-engine au_seifa_live -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "hits the live ABS SEIFA ArcGIS service; run manually"]
async fn au_seifa_live_resolves_sydney() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    let r = AuSeifa
        .process(&Target::new(TargetKind::Coordinates, "-33.8568,151.2153"), &ctx)
        .await
        .expect("live SEIFA query must not error");
    for e in &r.entities {
        if let EntityKind::Other(k) = &e.kind {
            eprintln!("au_seifa live: {k} = {}", e.value);
        }
    }
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Other("au-population".into())),
        "expected the SA2 population from the live SEIFA document"
    );
}
