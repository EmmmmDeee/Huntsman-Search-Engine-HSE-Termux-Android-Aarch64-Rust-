use super::*;

#[test]
fn accepts_fullname_and_organisation_only() {
    let m = SanctionsOfac;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Abu Abbas")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Banco Nacional de Cuba")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
}

#[test]
fn module_metadata() {
    assert_eq!(SanctionsOfac.name(), "sanctions_ofac");
    assert_eq!(SanctionsOfac.priority(), 111);
    assert_eq!(SanctionsOfac.cost(), ModuleCost::Free);
}

#[test]
fn produces_only_person_and_organisation() {
    let kinds = SanctionsOfac.produces();
    assert!(kinds.contains(&EntityKind::Person));
    assert!(kinds.contains(&EntityKind::Organisation));
    assert_eq!(kinds.len(), 2);
}

fn individual_record() -> SdnRecord {
    SdnRecord {
        ent_num: 2674,
        name: "ABBAS, Abu".to_string(),
        kind: SdnKind::Individual,
        program: "SDGT".to_string(),
        title: "Director of PALESTINE LIBERATION FRONT".to_string(),
        remarks: "DOB 10 Dec 1948; Director of PALESTINE LIBERATION FRONT.".to_string(),
    }
}

fn organisation_record() -> SdnRecord {
    SdnRecord {
        ent_num: 36,
        name: "AEROCARIBBEAN AIRLINES".to_string(),
        kind: SdnKind::Organisation,
        program: "CUBA".to_string(),
        title: String::new(),
        remarks: String::new(),
    }
}

fn vessel_record() -> SdnRecord {
    SdnRecord {
        ent_num: 4238,
        name: "MAR AZUL".to_string(),
        kind: SdnKind::Vessel,
        program: "CUBA".to_string(),
        title: String::new(),
        remarks: String::new(),
    }
}

#[test]
fn individual_hit_emits_person_with_reordered_name_and_caution() {
    let e = build_entity(&individual_record(), "s").expect("individual should emit an entity");
    assert_eq!(e.kind, EntityKind::Person);
    assert_eq!(e.value, "Abu Abbas");
    assert!((e.confidence - HIT_CONFIDENCE).abs() < 1e-9);
    assert!(e.has_tag("sanctions") && e.has_tag("ofac") && e.has_tag("regulatory-action"));
    assert!(e.has_tag("needs-identity-verification"));
    let attrs = &e.evidence[0].attributes;
    assert!(attrs.contains_key("caution"));
    assert_eq!(attrs.get("program").map(String::as_str), Some("SDGT"));
    assert_eq!(
        attrs.get("title").map(String::as_str),
        Some("Director of PALESTINE LIBERATION FRONT")
    );
    assert!(attrs.get("remarks").is_some_and(|r| r.contains("DOB 10 Dec 1948")));
}

#[test]
fn hit_with_blank_title_omits_title_attribute() {
    let e = build_entity(&organisation_record(), "s").expect("organisation should emit an entity");
    // organisation_record() has an empty title (the -0- placeholder normalises
    // to "") — the attribute must be absent, not present-and-empty.
    assert!(!e.evidence[0].attributes.contains_key("title"));
}

#[test]
fn organisation_hit_emits_organisation_without_reordering() {
    let e = build_entity(&organisation_record(), "s").expect("organisation should emit an entity");
    assert_eq!(e.kind, EntityKind::Organisation);
    assert_eq!(e.value, "AEROCARIBBEAN AIRLINES");
    assert!(e.has_tag("sanctions") && e.has_tag("needs-identity-verification"));
    // No remarks on this record → the attribute is simply absent, not empty-string.
    assert!(!e.evidence[0].attributes.contains_key("remarks"));
}

#[test]
fn vessel_and_aircraft_rows_emit_no_entity() {
    assert!(build_entity(&vessel_record(), "s").is_none());
    let mut aircraft = vessel_record();
    aircraft.kind = SdnKind::Aircraft;
    assert!(build_entity(&aircraft, "s").is_none());
}

fn indiv(ent_num: u64) -> SdnRecord {
    SdnRecord {
        ent_num,
        name: "SMITH, JOHN".to_string(),
        kind: SdnKind::Individual,
        program: "SDGT".to_string(),
        title: String::new(),
        remarks: String::new(),
    }
}

#[test]
fn screen_stamps_total_matches_and_flags_truncation_beyond_the_cap() {
    // T2.130 regression: 25 SDN individuals all matching "john smith" — more than
    // the MAX_HITS cap. Because parse_sdn_csv preserves file order with no
    // ranking, the old `.take(MAX_HITS)` dropped every match past the 20th in
    // arbitrary order with NO signal — a genuine OFAC hit could be the 21st and
    // vanish, and the operator saw 20 entities believing that was the whole set.
    let records: Vec<SdnRecord> = (0..25).map(indiv).collect();
    let tokens = name_tokens("John Smith");
    let ents = screen(&records, &tokens, "scan");

    assert_eq!(ents.len(), MAX_HITS, "only MAX_HITS entities are emitted");
    for e in &ents {
        assert_eq!(
            e.evidence[0]
                .attributes
                .get("total_matches")
                .map(String::as_str),
            Some("25"),
            "every emitted hit must record the TRUE match total, not just the cap"
        );
        assert!(
            e.has_tag("truncated"),
            "a capped result must be tagged truncated so it can't read as complete"
        );
    }
}

#[test]
fn screen_reports_true_total_without_truncating_below_the_cap() {
    // Below the cap: the total is still surfaced (3), but nothing is truncated.
    let records: Vec<SdnRecord> = (0..3).map(indiv).collect();
    let tokens = name_tokens("John Smith");
    let ents = screen(&records, &tokens, "scan");

    assert_eq!(ents.len(), 3);
    for e in &ents {
        assert_eq!(
            e.evidence[0]
                .attributes
                .get("total_matches")
                .map(String::as_str),
            Some("3")
        );
        assert!(
            !e.has_tag("truncated"),
            "an uncapped result must NOT be tagged truncated"
        );
    }
}

// -- fetch_sdn_list failure contract (T2.150) -------------------------------

// Serialise the tests below: they all mutate the process-global CACHE, which
// is shared across every test in this binary (mirrors util::found_keys's
// TEST_LOCK / util::see_know's BUDGET_TEST_LOCK for the same reason). An
// async-aware Mutex is required here (unlike those precedents) because the
// guard must stay held across `fetch_sdn_list`'s `.await` points.
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// One-shot local HTTP server answering with `status` + `body`. Mirrors the
/// pgp / chain_intel / geocode / opencellid test pattern.
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
async fn fetch_sdn_list_cold_cache_and_transport_failure_surfaces_err() {
    // T2.150 regression: fetch_sdn_list previously swallowed every transport
    // failure into an empty Vec, indistinguishable from "the SDN list
    // genuinely contains no sanctioned entities" — silently blinding
    // sanctions screening for the whole scan (CACHE is process-global, shared
    // across every target). A COLD cache (nothing to gracefully degrade to)
    // with an unreachable host (port 1: connection refused) must now surface
    // Err, not a fabricated empty result.
    let _guard = TEST_LOCK.lock().await;
    *CACHE.write().unwrap() = None;
    let ctx = test_ctx();

    let out = fetch_sdn_list(&ctx, "http://127.0.0.1:1/").await;
    assert!(
        out.is_err(),
        "a cold cache with an unreachable SDN host must surface Err"
    );
    assert!(
        CACHE.read().unwrap().is_none(),
        "a failed fetch must not fabricate a cache entry"
    );
}

#[tokio::test]
async fn fetch_sdn_list_cold_cache_and_5xx_surfaces_err() {
    // A 5xx is a real outage on a static bulk-download endpoint with no
    // legitimate "not found" status — it must not read as "no sanctions data".
    let _guard = TEST_LOCK.lock().await;
    *CACHE.write().unwrap() = None;
    let ctx = test_ctx();
    let addr = serve_once(503, "upstream down").await;

    let out = fetch_sdn_list(&ctx, &format!("http://{addr}/")).await;
    assert!(out.is_err(), "a 5xx with a cold cache must surface Err");
}

#[tokio::test]
async fn fetch_sdn_list_warms_cache_then_degrades_to_stale_on_later_failure() {
    // The documented outage-tolerance behavior must survive the fix: once the
    // cache holds a usable (even TTL-expired) list, a later failed re-fetch
    // gracefully degrades to Ok(stale list) rather than erroring — a
    // transient outage must not blind screening when a previous good fetch
    // exists to fall back on.
    let _guard = TEST_LOCK.lock().await;
    *CACHE.write().unwrap() = None;
    let ctx = test_ctx();

    // A real fetch of a minimal, valid SDN row warms the cache.
    let addr = serve_once(
        200,
        "2674,\"ABBAS, Abu\",\"individual\",\"SDGT\",\"Director\",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,\"remark\"\n",
    )
    .await;
    let warm = fetch_sdn_list(&ctx, &format!("http://{addr}/")).await;
    assert!(warm.is_ok(), "a healthy fetch must succeed and populate the cache");
    assert!(!warm.unwrap().is_empty());

    // Age the cache entry past the TTL so the next call re-attempts a fetch
    // instead of short-circuiting on the freshness check.
    {
        let mut w = CACHE.write().unwrap();
        if let Some((_, records)) = w.take() {
            *w = Some((
                Instant::now() - std::time::Duration::from_secs(LIST_CACHE_TTL_SECS + 1),
                records,
            ));
        }
    }

    // The stale-but-present cache + a fresh unreachable host → graceful
    // degrade to Ok(stale), NOT Err.
    let degraded = fetch_sdn_list(&ctx, "http://127.0.0.1:1/").await;
    assert!(
        matches!(degraded, Ok(ref r) if !r.is_empty()),
        "a failed re-fetch with a usable stale cache must degrade to Ok(cached), not Err: {degraded:?}"
    );
}

#[tokio::test]
async fn fetch_sdn_list_keeps_2xx_empty_body_as_a_clean_ok() {
    // The genuine negative must be preserved: a 200 with an empty/unmatched
    // body is a real (if unusual) answer, not a failure — stays Ok, never Err.
    let _guard = TEST_LOCK.lock().await;
    *CACHE.write().unwrap() = None;
    let ctx = test_ctx();
    let addr = serve_once(200, "").await;

    let out = fetch_sdn_list(&ctx, &format!("http://{addr}/")).await;
    assert!(
        matches!(out, Ok(ref r) if r.is_empty()),
        "a 2xx empty body is a genuine (if unusual) answer, not a failure: {out:?}"
    );
}

