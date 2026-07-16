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

// -- fetch_attrs failure contract (T2.154) -----------------------------------

/// One-shot local HTTP server answering with `status` + `body`. Mirrors the
/// pgp / sanctions_ofac / app_links test pattern.
async fn serve_once(status: u16, body: &'static str) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut buf = vec![0u8; 2048];
        let _ = sock.read(&mut buf).await;
        let reason = if status == 200 { "OK" } else { "Error" };
        let head = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let _ = sock.write_all(head.as_bytes()).await;
        let _ = sock.write_all(body.as_bytes()).await;
        let _ = sock.flush().await;
    });
    addr
}

fn test_ctx() -> ModuleContext {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    ModuleContext {
        scan_id: "t".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    }
}

#[tokio::test]
async fn fetch_attrs_surfaces_transport_failure_as_error() {
    // T2.154 regression: an unreachable ABS host previously collapsed into
    // the same None as the genuine "no SA2 coverage" answer — silently
    // dropping the entire SEIFA profile for the coordinate. Port 1:
    // connection refused.
    let ctx = test_ctx();
    let out = fetch_attrs(&ctx, "http://127.0.0.1:1/").await;
    assert!(
        out.is_err(),
        "an unreachable ABS host must surface Err, not a swallowed empty result"
    );
}

#[tokio::test]
async fn fetch_attrs_surfaces_403_and_5xx_as_error() {
    // This ArcGIS endpoint has no distinguishable "not found" status — a 403
    // (the module's own doc calls out the WAF as a known failure mode) or a
    // 5xx is a real outage, never a legitimate SEIFA answer.
    let ctx = test_ctx();
    let addr_403 = serve_once(403, "blocked").await;
    assert!(fetch_attrs(&ctx, &format!("http://{addr_403}/")).await.is_err());
    let addr_500 = serve_once(500, "upstream down").await;
    assert!(fetch_attrs(&ctx, &format!("http://{addr_500}/")).await.is_err());
}

#[tokio::test]
async fn fetch_attrs_surfaces_malformed_json_as_error() {
    let ctx = test_ctx();
    let addr = serve_once(200, "not json").await;
    let out = fetch_attrs(&ctx, &format!("http://{addr}/")).await;
    assert!(out.is_err(), "unparseable 2xx body must surface Err");
}

#[tokio::test]
async fn fetch_attrs_keeps_empty_features_as_the_clean_no_coverage_miss() {
    // The genuine negative must be preserved: a 200 with an empty `features`
    // array (e.g. an offshore point) is a real, distinguishable "no SA2
    // coverage" answer — stays Ok(None), never Err.
    let ctx = test_ctx();
    let addr = serve_once(200, r#"{"features":[]}"#).await;
    let out = fetch_attrs(&ctx, &format!("http://{addr}/")).await;
    assert!(
        matches!(out, Ok(None)),
        "an empty-features 200 must stay the clean no-coverage miss: {out:?}"
    );
}

#[tokio::test]
async fn fetch_attrs_returns_attrs_on_a_real_feature() {
    let ctx = test_ctx();
    let addr = serve_once(200, FIXTURE).await;
    let out = fetch_attrs(&ctx, &format!("http://{addr}/")).await;
    let attrs = out.expect("must succeed").expect("must find a feature");
    assert_eq!(
        attr_str(&attrs, "SA2_NAME_2016").as_deref(),
        Some("Sydney - Haymarket - The Rocks")
    );
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
