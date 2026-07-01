use super::*;

/// Real ABS response shape (Commonwealth Electoral Division, Sydney Opera House).
const CED_BODY: &str = r#"{"features":[{"attributes":{
  "ced_code_2021":"142","ced_name_2021":"Sydney",
  "state_code_2021":"1","state_name_2021":"New South Wales"}}]}"#;

/// Postal Area has no state field — exercises the `None` state path.
const POA_BODY: &str = r#"{"features":[{"attributes":{
  "poa_code_2021":"2000","poa_name_2021":"2000"}}]}"#;

#[test]
fn parse_feature_reads_name_code_and_state() {
    assert_eq!(
        parse_feature(CED_BODY, "ced_name_2021", "ced_code_2021"),
        Some(("Sydney".into(), "142".into(), Some("New South Wales".into())))
    );
    assert_eq!(
        parse_feature(POA_BODY, "poa_name_2021", "poa_code_2021"),
        Some(("2000".into(), "2000".into(), None))
    );
    // No covering polygon → no feature → None.
    assert_eq!(
        parse_feature(r#"{"features":[]}"#, "ced_name_2021", "ced_code_2021"),
        None
    );
    assert_eq!(parse_feature("not json", "x", "y"), None);
}

/// A fully-resolved point (aligned with LAYERS: POA, SAL, LGA, CED, SED, RA,
/// SA2, SA4).
fn full_resolution() -> Vec<Option<(String, String, Option<String>)>> {
    let nsw = Some("New South Wales".to_string());
    vec![
        Some(("2000".into(), "2000".into(), None)),
        Some(("Sydney".into(), "13730".into(), nsw.clone())),
        Some(("Sydney".into(), "17200".into(), nsw.clone())),
        Some(("Sydney".into(), "142".into(), nsw.clone())),
        Some(("Sydney (NSW)".into(), "10142".into(), nsw.clone())),
        Some(("Major Cities of Australia".into(), "10".into(), nsw.clone())),
        Some(("Sydney (North) - Millers Point".into(), "117031644".into(), nsw.clone())),
        Some(("Sydney - City and Inner South".into(), "117".into(), nsw.clone())),
        Some(("Commercial".into(), "10741860000".into(), nsw)),
    ]
}

#[test]
fn assemble_emits_regions_and_enriches_coordinate() {
    let mut r = ModuleResult::new();
    assemble("-33.8568,151.2153", &full_resolution(), "scan", &mut r);
    let e = &r.entities;

    // Each layer becomes a distinct, searchable Other region entity.
    assert!(e.iter().any(|x| x.kind == EntityKind::Other("au-postcode".into())
        && x.value == "2000"));
    assert!(e.iter().any(|x| x.kind == EntityKind::Other("au-lga".into())
        && x.value == "Sydney"
        && x.has_tag("asgs")));
    assert!(e.iter().any(|x| x.kind == EntityKind::Other("au-federal-electorate".into())
        && x.value == "Sydney"));
    assert!(e.iter().any(|x| x.kind == EntityKind::Other("au-state-electorate".into())
        && x.value == "Sydney (NSW)"));
    // Remoteness classification + ABS statistical areas.
    assert!(e.iter().any(|x| x.kind == EntityKind::Other("au-remoteness".into())
        && x.value == "Major Cities of Australia"));
    assert!(e.iter().any(|x| x.kind == EntityKind::Other("au-sa2".into())
        && x.value.contains("Millers Point")));
    assert!(e.iter().any(|x| x.kind == EntityKind::Other("au-sa4".into())
        && x.value == "Sydney - City and Inner South"));
    // Mesh-block land use — is this a home or a business?
    assert!(e.iter().any(|x| x.kind == EntityKind::Other("au-land-use".into())
        && x.value == "Commercial"));

    // The coordinate is enriched with the full administrative roll-up + state.
    let coord = e
        .iter()
        .find(|x| x.kind == EntityKind::Coordinates && x.has_tag("geoint"))
        .expect("enriched coordinate entity");
    let ev = coord.evidence.first().expect("roll-up evidence");
    assert_eq!(ev.attributes.get("au_state").map(String::as_str), Some("New South Wales"));
    assert_eq!(ev.attributes.get("au_federal_electorate").map(String::as_str), Some("Sydney"));
    assert_eq!(ev.attributes.get("au_postcode").map(String::as_str), Some("2000"));
    // The exact ABS point-in-polygon state must reach the coordinate as an
    // au-state:XX tag — this is what core::correlator::rules::geo::coord_state
    // prefers over its own coarse rectangular-bbox fallback.
    assert!(
        coord.has_tag("au-state:NSW"),
        "coordinate must carry the resolved state as an au-state tag: {:?}",
        coord.tags
    );
    assert!(coord.has_tag("country:AU"));
}

#[test]
fn assemble_no_state_tag_when_no_layer_resolves_a_state() {
    // The Postal Area layer alone (POA_BODY's shape: no state field) resolves,
    // but nothing in the response names a state — no bogus au-state tag.
    let mut partial: Vec<Option<(String, String, Option<String>)>> = vec![None; 9];
    partial[0] = Some(("2000".to_string(), "2000".to_string(), None));
    let mut r = ModuleResult::new();
    assemble("-33.8568,151.2153", &partial, "scan", &mut r);
    let coord = r
        .entities
        .iter()
        .find(|x| x.kind == EntityKind::Coordinates)
        .expect("enriched coordinate entity");
    assert!(
        !coord.tags.iter().any(|t| t.starts_with("au-state:")),
        "no state in the resolution must not invent an au-state tag: {:?}",
        coord.tags
    );
}

#[test]
fn assemble_skips_absent_layers_and_empty_resolution() {
    // Only the federal electorate resolved (e.g. a point with no SAL/SED cover).
    let mut partial: Vec<Option<(String, String, Option<String>)>> = vec![None; 9];
    partial[3] = Some(("Canberra".to_string(), "801".to_string(), Some("ACT".to_string())));
    let mut r = ModuleResult::new();
    assemble("-35.3081,149.1245", &partial, "scan", &mut r);
    assert!(r.entities.iter().any(|x| x.kind == EntityKind::Other("au-federal-electorate".into())
        && x.value == "Canberra"));
    assert!(r.entities.iter().all(|x| x.kind != EntityKind::Other("au-postcode".into())));

    // Nothing resolved → no entities at all (not even an empty coordinate).
    let empty_in: Vec<Option<(String, String, Option<String>)>> = vec![None; 9];
    let mut empty = ModuleResult::new();
    assemble("-35.0,149.0", &empty_in, "scan", &mut empty);
    assert!(empty.entities.is_empty());
}

#[tokio::test]
async fn non_au_or_malformed_coordinate_makes_no_request() {
    // London is outside the AU bbox → the module returns before any network I/O,
    // so this runs offline in CI.
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "t".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Default::default(),
    };
    let london = AuGeo
        .process(&Target::new(TargetKind::Coordinates, "51.5074,-0.1276"), &ctx)
        .await
        .expect("non-AU coordinate is a clean miss");
    assert!(london.entities.is_empty());

    let junk = AuGeo
        .process(&Target::new(TargetKind::Coordinates, "not-a-coord"), &ctx)
        .await
        .expect("malformed coordinate is a clean miss");
    assert!(junk.entities.is_empty());
}

#[test]
fn is_free_geo_module() {
    let m = AuGeo;
    assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    assert_eq!(m.category(), ModuleCategory::Geo);
    assert!(!m.attack_techniques().is_empty());
    assert!(m.accepts(&Target::new(TargetKind::Coordinates, "-33.8568,151.2153")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Jane Citizen")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

/// Live end-to-end proof against the REAL ABS ASGS service — no mock. Ignored by
/// default (network); run with
/// `cargo test -p huntsman-search-engine au_geo_live -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "hits the live ABS ASGS ArcGIS service; run manually"]
async fn au_geo_live_resolves_sydney() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Default::default(),
    };
    // Sydney Opera House.
    let r = AuGeo
        .process(&Target::new(TargetKind::Coordinates, "-33.8568,151.2153"), &ctx)
        .await
        .expect("live ASGS query must not error");
    eprintln!(
        "au_geo live (Sydney Opera House): {} entities",
        r.entities.len()
    );
    for e in &r.entities {
        if let EntityKind::Other(k) = &e.kind {
            eprintln!("  {k} = {}", e.value);
        }
    }
    // The Opera House sits in the federal Division of Sydney.
    assert!(
        r.entities.iter().any(|e| e.kind == EntityKind::Other("au-federal-electorate".into())
            && e.value == "Sydney"),
        "expected the federal Division of Sydney"
    );
    // …and postcode 2000.
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Other("au-postcode".into()) && e.value == "2000")
    );
}
