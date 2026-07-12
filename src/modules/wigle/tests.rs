use super::account::{
    ProfileUserResp, WigleAccountStatus, account_status, account_status_cache, is_unverified,
    status_from_profile,
};
use super::emit::{
    emit_bssid_entities, emit_ssid_entities, extract_bluetooth_intel, extract_cell_intel,
};
use super::*;
use crate::core::{
    entity::EntityKind,
    module::ModuleResult,
    scan::{Target, TargetKind},
};
use crate::util::geo::parse_coords;

#[test]
fn wifi_ap_entities_emit_each_aps_own_observed_position() {
    // Query centre far from the APs so a mislabel (using the query point) is
    // obvious.
    let (qlat, qlon) = (-27.0, 153.0);
    let net = |netid: &str, tri: Option<(f64, f64)>| Network {
        ssid: None,
        netid: Some(netid.into()),
        encryption: None,
        lastupdt: None,
        trilat: tri.map(|t| t.0),
        trilong: tri.map(|t| t.1),
        city: None,
        region: None,
        country: None,
        postalcode: None,
    };
    let results = vec![
        net("AA:BB:CC:DD:EE:01", Some((-27.4766, 153.0280))), // real position
        net("AA:BB:CC:DD:EE:02", None),                       // no position
        net("AA:BB:CC:DD:EE:03", Some((0.0, 0.0))),           // null-island → invalid
    ];
    let ents = wifi_ap_entities(&results, qlat, qlon, "-27.0,153.0", "scan");

    // Every BSSID becomes a MacAddress pivot...
    let macs: Vec<_> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::MacAddress)
        .collect();
    assert_eq!(macs.len(), 3);
    // ...but only the AP with a real, non-null-island position yields a
    // first-class Coordinates node (geoint), at its OWN location.
    let coords: Vec<_> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Coordinates)
        .collect();
    assert_eq!(
        coords.len(),
        1,
        "only the located AP emits a Coordinates node"
    );
    assert_eq!(coords[0].value, "-27.476600,153.028000");
    assert!(coords[0].has_tag("wifi-observed") && coords[0].has_tag("geoint"));

    // The located AP's MacAddress carries ITS OWN coordinates, not the query
    // centre (the previous mislabel). MacAddress values normalise to lowercase.
    let ap1 = macs
        .iter()
        .find(|e| e.value == "aa:bb:cc:dd:ee:01")
        .unwrap();
    assert_eq!(
        ap1.evidence[0]
            .attributes
            .get("coordinates")
            .map(String::as_str),
        Some("-27.476600,153.028000")
    );
    // The position-less AP falls back to the query centre for its MAC attr and
    // mints no Coordinates node.
    let ap2 = macs
        .iter()
        .find(|e| e.value == "aa:bb:cc:dd:ee:02")
        .unwrap();
    assert_eq!(
        ap2.evidence[0]
            .attributes
            .get("coordinates")
            .map(String::as_str),
        Some("-27.000000,153.000000")
    );
}

#[test]
fn accepts_coordinates_and_mac_address() {
    let m = Wigle;
    assert!(m.accepts(&Target::new(TargetKind::Coordinates, "0,0")));
    assert!(m.accepts(&Target::new(TargetKind::MacAddress, "aa:bb:cc:dd:ee:ff")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

#[test]
fn cost_is_key_gated() {
    use crate::core::module::ModuleCost;
    assert!(matches!(Wigle.cost(), ModuleCost::KeyGated));
}

#[test]
fn mode_breaks_ties_deterministically() {
    assert_eq!(mode(&["bravo", "alpha", "alpha", "bravo"]), "alpha");
    assert_eq!(mode(&["alpha", "bravo", "bravo", "alpha"]), "alpha");
    assert_eq!(mode(&["zulu", "zulu", "alpha"]), "zulu");
    assert_eq!(mode(&[]), "");
}

#[test]
fn parse_coords_valid() {
    let (lat, lon) = parse_coords("-27.4766,153.0166").unwrap();
    assert!((lat - (-27.4766)).abs() < 0.001);
    assert!((lon - 153.0166).abs() < 0.001);
}

#[test]
fn parse_coords_invalid() {
    assert!(parse_coords("not-coords").is_err());
    assert!(parse_coords("").is_err());
}

#[test]
fn mode_finds_most_common() {
    assert_eq!(mode(&["a", "b", "a", "c", "a"]), "a");
    assert_eq!(mode(&["x"]), "x");
    assert_eq!(mode(&[]), "");
}

#[test]
fn generic_ssid_filter() {
    let lower = "telstra-home-123".to_lowercase();
    assert!(GENERIC_SSIDS.iter().any(|g| lower.contains(g)));
    let lower2 = "smith-family".to_lowercase();
    assert!(!GENERIC_SSIDS.iter().any(|g| lower2.contains(g)));
}

#[test]
fn resp_deserializes_with_full_fields() {
    let json = r#"{
        "success": true,
        "totalResults": 42,
        "results": [{
            "ssid": "Smith-Family-5G",
            "netid": "AA:BB:CC:DD:EE:FF",
            "encryption": "wpa2",
            "channel": 36,
            "lastupdt": "2024-06-15",
            "trilat": -27.4766,
            "trilong": 153.0166,
            "city": "Nundah",
            "region": "Queensland",
            "country": "AU",
            "postalcode": "4012",
            "type": "infra"
        }]
    }"#;
    let r: Resp = serde_json::from_str(json).unwrap();
    assert_eq!(r.success, Some(true));
    assert_eq!(r.total_results, Some(42));
    let net = &r.results[0];
    assert_eq!(net.ssid.as_deref(), Some("Smith-Family-5G"));
    assert_eq!(net.city.as_deref(), Some("Nundah"));
    assert_eq!(net.region.as_deref(), Some("Queensland"));
    assert_eq!(net.postalcode.as_deref(), Some("4012"));
    assert_eq!(net.netid.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
}

#[test]
fn network_kind_emits_wigle_typed_query_param() {
    assert_eq!(NetworkKind::Wifi.as_str(), "wifi");
    assert_eq!(NetworkKind::Cell.as_str(), "cell");
    assert_eq!(NetworkKind::Bluetooth.as_str(), "bluetooth");
}

#[test]
fn extract_cell_intel_emits_dominant_carrier_as_organisation() {
    let resp = Resp {
        success: Some(true),
        result_count: Some(3),
        total_results: Some(3),
        results: vec![
            Network {
                ssid: Some("Telstra".into()),
                netid: None,
                encryption: None,
                lastupdt: None,
                trilat: None,
                trilong: None,
                city: None,
                region: None,
                country: None,
                postalcode: None,
            },
            Network {
                ssid: Some("Telstra".into()),
                netid: None,
                encryption: None,
                lastupdt: None,
                trilat: None,
                trilong: None,
                city: None,
                region: None,
                country: None,
                postalcode: None,
            },
            Network {
                ssid: Some("Vodafone".into()),
                netid: None,
                encryption: None,
                lastupdt: None,
                trilat: None,
                trilong: None,
                city: None,
                region: None,
                country: None,
                postalcode: None,
            },
        ],
    };
    let mut r = ModuleResult::new();
    extract_cell_intel(&resp, "-27.5,153.0", "test-scan", &mut r);
    let orgs: Vec<_> = r
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation)
        .collect();
    assert_eq!(
        orgs.len(),
        0,
        "generic carriers (Telstra/Vodafone in GENERIC_SSIDS) must be filtered out"
    );
}

#[test]
fn extract_cell_intel_passes_non_generic_carrier_through() {
    let resp = Resp {
        success: Some(true),
        result_count: Some(2),
        total_results: Some(2),
        results: vec![
            Network {
                ssid: Some("AcmeMobileOps".into()),
                netid: None,
                encryption: None,
                lastupdt: None,
                trilat: None,
                trilong: None,
                city: None,
                region: None,
                country: None,
                postalcode: None,
            },
            Network {
                ssid: Some("AcmeMobileOps".into()),
                netid: None,
                encryption: None,
                lastupdt: None,
                trilat: None,
                trilong: None,
                city: None,
                region: None,
                country: None,
                postalcode: None,
            },
        ],
    };
    let mut r = ModuleResult::new();
    extract_cell_intel(&resp, "0,0", "test-scan", &mut r);
    assert_eq!(r.entities.len(), 1);
    assert_eq!(r.entities[0].kind, EntityKind::Organisation);
    assert_eq!(r.entities[0].value.to_lowercase(), "acmemobileops");
    assert!(r.entities[0].has_tag("cell-carrier"));
}

#[test]
fn extract_cell_intel_emits_coordinates_for_towers_with_position() {
    let resp = Resp {
        success: Some(true),
        result_count: Some(3),
        total_results: Some(3),
        results: vec![
            Network {
                ssid: None,
                netid: None,
                encryption: None,
                lastupdt: None,
                trilat: Some(-27.4766),
                trilong: Some(153.0166),
                city: None,
                region: None,
                country: None,
                postalcode: None,
            },
            Network {
                ssid: None,
                netid: None,
                encryption: None,
                lastupdt: None,
                trilat: Some(-27.5000),
                trilong: Some(153.0200),
                city: None,
                region: None,
                country: None,
                postalcode: None,
            },
            Network {
                ssid: None,
                netid: None,
                encryption: None,
                lastupdt: None,
                trilat: Some(-27.4800),
                trilong: Some(153.0100),
                city: None,
                region: None,
                country: None,
                postalcode: None,
            },
        ],
    };
    let mut r = ModuleResult::new();
    extract_cell_intel(&resp, "-27.4766,153.0166", "test-scan", &mut r);
    let coords: Vec<_> = r
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Coordinates)
        .collect();
    assert_eq!(coords.len(), 3);
    for c in &coords {
        assert!(
            c.has_tag(crate::core::tags::CELL_TOWER),
            "should carry cell-tower tag"
        );
        assert!(c.has_tag("cell-observed"), "should carry cell-observed tag");
        assert!(c.has_tag("wigle"), "should carry wigle tag");
    }
    // Closest tower (exact match on target) must come first
    assert!(
        coords[0].value.starts_with("-27.4766"),
        "proximity sort: closest tower first"
    );
    // The total distinct tower positions is surfaced on the coordinates evidence
    // (so the top-3 bound is visible even when the carrier Org is suppressed).
    assert!(
        coords[0].evidence.iter().any(|ev| ev
            .attributes
            .get("tower_positions_observed")
            .is_some_and(|n| n == "3")),
        "coordinates surface the total observed tower-position count"
    );
}

#[test]
fn extract_bluetooth_intel_emits_at_most_three_mac_entities() {
    let mut results = Vec::new();
    for i in 0..5 {
        results.push(Network {
            ssid: Some(format!("Beacon-{i}")),
            netid: Some(format!("AA:BB:CC:DD:EE:{i:02X}")),
            encryption: None,
            lastupdt: None,
            trilat: None,
            trilong: None,
            city: None,
            region: None,
            country: None,
            postalcode: None,
        });
    }
    let resp = Resp {
        success: Some(true),
        result_count: Some(5),
        total_results: Some(5),
        results,
    };
    let mut r = ModuleResult::new();
    extract_bluetooth_intel(&resp, "0,0", "test-scan", &mut r);
    assert_eq!(r.entities.len(), 3);
    for e in &r.entities {
        assert_eq!(e.kind, EntityKind::MacAddress);
        assert!(e.has_tag("bluetooth-beacon"));
        // The total beacons observed (5) is surfaced so the 3-beacon bound is
        // visible, not a silent drop.
        assert!(
            e.evidence.iter().any(|ev| ev
                .attributes
                .get("beacons_observed")
                .is_some_and(|n| n == "5")),
            "each beacon entity surfaces the total observed count"
        );
    }
}

#[test]
fn emit_ssid_entities_surfaces_all_admitted_location_fixes() {
    // An SSID admitted as unique can have up to SSID_UNIQUE_MAX (20) global
    // observations; every one is a subject-location fix that must be emitted. A
    // former SSID_RESULT_CAP of 10 (below the admission gate) dropped up to half.
    let results: Vec<Network> = (0..15)
        .map(|i| Network {
            ssid: Some("HaigenHomeWiFi".to_string()),
            netid: Some(format!("AA:BB:CC:DD:EE:{i:02X}")),
            encryption: None,
            lastupdt: None,
            trilat: Some(-27.4766 - f64::from(i) * 0.001),
            trilong: Some(153.0166 + f64::from(i) * 0.001),
            city: None,
            region: None,
            country: None,
            postalcode: None,
        })
        .collect();
    let r = emit_ssid_entities("HaigenHomeWiFi", &results, "test-scan");
    let coords = r
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Coordinates)
        .count();
    assert_eq!(
        coords, 15,
        "every admitted SSID location fix is emitted, not capped below the admission gate"
    );
}

#[test]
fn extract_bluetooth_intel_skips_short_macs() {
    let resp = Resp {
        success: Some(true),
        result_count: Some(1),
        total_results: Some(1),
        results: vec![Network {
            ssid: None,
            netid: Some("AA:BB".into()),
            encryption: None,
            lastupdt: None,
            trilat: None,
            trilong: None,
            city: None,
            region: None,
            country: None,
            postalcode: None,
        }],
    };
    let mut r = ModuleResult::new();
    extract_bluetooth_intel(&resp, "0,0", "test", &mut r);
    assert!(r.entities.is_empty());
}

#[test]
fn extract_cell_intel_skips_failed_responses() {
    let resp = Resp {
        success: Some(false),
        result_count: None,
        total_results: None,
        results: Vec::new(),
    };
    let mut r = ModuleResult::new();
    extract_cell_intel(&resp, "0,0", "test", &mut r);
    assert!(r.entities.is_empty());
}

#[test]
fn produces_declares_geo_and_mac_and_org_kinds() {
    let kinds = Wigle.produces();
    assert!(kinds.contains(&EntityKind::Coordinates));
    assert!(kinds.contains(&EntityKind::Address));
    assert!(kinds.contains(&EntityKind::MacAddress));
    assert!(kinds.contains(&EntityKind::Organisation));
}

#[test]
fn category_is_geo() {
    use crate::core::module::ModuleCategory;
    assert_eq!(Wigle.category(), ModuleCategory::Geo);
}

#[test]
fn budgets_reset_independently_per_observation_type() {
    GEO_BUDGET.reset_scan();
    for _ in 0..GEO_BUDGET.scan_cap() {
        GEO_BUDGET.increment();
    }
    assert!(!GEO_BUDGET.remaining());
    assert!(CELL_BUDGET.remaining());
    assert!(BLUETOOTH_BUDGET.remaining());
    reset_budget();
    assert!(GEO_BUDGET.remaining());
}

#[test]
fn budget_snapshot_aggregates_all_four_sub_budgets() {
    reset_budget();
    let s = budget_snapshot();
    assert!(s.geo.scan_cap >= 1);
    assert!(s.bssid.scan_cap >= 1);
    assert!(s.cell.scan_cap >= 1);
    assert!(s.bluetooth.scan_cap >= 1);
    assert_eq!(s.geo.scan_used, 0);
    assert_eq!(s.bssid.scan_used, 0);
    assert_eq!(s.cell.scan_used, 0);
    assert_eq!(s.bluetooth.scan_used, 0);
}

#[test]
fn account_status_state_transitions_and_unverified_detection() {
    struct CacheGuard;
    impl Drop for CacheGuard {
        fn drop(&mut self) {
            if let Ok(mut g) = account_status_cache().lock() {
                *g = WigleAccountStatus::default();
            }
        }
    }
    let _guard = CacheGuard;

    let s = WigleAccountStatus::default();
    assert!(s.verified.is_none());
    assert!(s.user.is_none());
    assert!(s.last_polled_ts.is_none());

    if let Ok(mut g) = account_status_cache().lock() {
        *g = WigleAccountStatus::default();
    }
    assert!(!is_unverified(), "default state must not report unverified");

    if let Ok(mut g) = account_status_cache().lock() {
        *g = WigleAccountStatus {
            verified: Some(false),
            user: Some("MattDieg".into()),
            ..Default::default()
        };
    }
    assert!(is_unverified());

    if let Ok(mut g) = account_status_cache().lock() {
        *g = WigleAccountStatus {
            verified: Some(true),
            user: Some("MattDieg".into()),
            last_polled_ts: Some(1000),
        };
    }
    let s = account_status();
    assert_eq!(s.verified, Some(true));
    assert_eq!(s.user.as_deref(), Some("MattDieg"));
    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("\"verified\":true"));
    assert!(json.contains("\"user\":\"MattDieg\""));
}

#[test]
fn profile_user_resp_parses_real_wigle_person_shape() {
    let json = r#"{
        "userid": "MattDieg ",
        "email": "x@example.com",
        "donate": "Y",
        "flags": 0,
        "emailVerified": false,
        "admin": false,
        "success": "true"
    }"#;
    let body: ProfileUserResp = serde_json::from_str(json).unwrap();
    assert_eq!(body.userid.as_deref(), Some("MattDieg "));
    assert_eq!(body.email_verified, Some(false));

    let status = status_from_profile(body, 1234);
    assert_eq!(status.user.as_deref(), Some("MattDieg"));
    assert_eq!(status.verified, Some(false));
    assert_eq!(status.last_polled_ts, Some(1234));
}

#[test]
fn status_from_profile_treats_absent_and_blank_userid_as_none() {
    let blank: ProfileUserResp = serde_json::from_str(r#"{"userid": "   "}"#).unwrap();
    assert!(status_from_profile(blank, 0).user.is_none());

    let absent: ProfileUserResp = serde_json::from_str(r#"{"emailVerified": true}"#).unwrap();
    let status = status_from_profile(absent, 0);
    assert!(status.user.is_none());
    assert_eq!(status.verified, Some(true));
}

#[test]
fn emit_bssid_entities_skips_when_no_location_data() {
    let net = Network {
        ssid: None,
        netid: Some("AA:BB:CC:DD:EE:FF".into()),
        encryption: None,
        lastupdt: None,
        trilat: None,
        trilong: None,
        city: None,
        region: None,
        country: None,
        postalcode: None,
    };
    let r = emit_bssid_entities("AA:BB:CC:DD:EE:FF", NetworkKind::Wifi, &[net], "test");
    assert!(r.entities.is_empty());
}

#[test]
fn emit_bssid_entities_tags_cell_lookup_with_cell_located() {
    let net = Network {
        ssid: None,
        netid: Some("AA:BB:CC:DD:EE:FF".into()),
        encryption: None,
        lastupdt: None,
        trilat: Some(-27.4766),
        trilong: Some(153.0166),
        city: Some("Brisbane".into()),
        region: Some("QLD".into()),
        country: Some("AU".into()),
        postalcode: None,
    };
    let r = emit_bssid_entities("310-410-12345", NetworkKind::Cell, &[net], "test");
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Coordinates && e.has_tag("cell-located"))
    );
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Address && e.has_tag("cell-located"))
    );
}

#[test]
fn emit_bssid_entities_tags_bluetooth_lookup_with_bluetooth_located() {
    let net = Network {
        ssid: Some("BeaconLabel".into()),
        netid: Some("DD:EE:FF:00:11:22".into()),
        encryption: None,
        lastupdt: None,
        trilat: Some(51.5074),
        trilong: Some(-0.1278),
        city: Some("London".into()),
        region: Some("England".into()),
        country: Some("GB".into()),
        postalcode: None,
    };
    let r = emit_bssid_entities("DD:EE:FF:00:11:22", NetworkKind::Bluetooth, &[net], "test");
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Coordinates && e.has_tag("bluetooth-located"))
    );
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Address && e.has_tag("bluetooth-located"))
    );
}

#[test]
fn emit_bssid_entities_emits_nothing_for_empty_results() {
    let r = emit_bssid_entities("anything", NetworkKind::Wifi, &[], "test");
    assert!(r.entities.is_empty());
}

#[test]
fn is_generic_ssid_matches_known_substrings_case_insensitively() {
    assert!(is_generic_ssid("linksys"));
    assert!(is_generic_ssid("xfinitywifi"));
    assert!(is_generic_ssid("NETGEAR-Guest"));
    assert!(is_generic_ssid("Telstra-Home-123"));
    assert!(is_generic_ssid("Free Public WiFi"));
}

#[test]
fn is_generic_ssid_rejects_custom_names() {
    assert!(!is_generic_ssid("Smith-Family"));
    assert!(!is_generic_ssid("Bamford-Residence"));
    assert!(!is_generic_ssid(""));
}

/// A one-shot local server: first connection answers 429 with a real
/// `Retry-After` header, second answers 200. Returns the address plus a
/// counter the caller can read after the exchange to confirm a retry
/// actually happened (not just a single request).
async fn serve_429_then_200(
    retry_after_secs: u64,
) -> (
    std::net::SocketAddr,
    std::sync::Arc<std::sync::atomic::AtomicU32>,
) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicU32::new(0));
    let hits_srv = hits.clone();
    tokio::spawn(async move {
        for _ in 0..2 {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let n = hits_srv.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                let body = b"{}";
                let head = format!(
                    "HTTP/1.1 429 Too Many Requests\r\nRetry-After: {retry_after_secs}\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body).await;
            } else {
                let body = br#"{"success":true,"resultCount":0,"results":[]}"#;
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body).await;
            }
            let _ = sock.flush().await;
        }
    });
    (addr, hits)
}

#[tokio::test]
async fn get_with_retry_recovers_from_a_429_using_the_servers_real_retry_after() {
    // Regression: `retry_secs` used to be computed from the response purely to
    // log it, then thrown away — the module failed on the FIRST 429 with no
    // retry at all, discarding a real, server-specified cooldown. Now a 429
    // retries once, honouring the server's own (bounded) Retry-After.
    let (addr, hits) = serve_429_then_200(1).await;
    let client = reqwest::Client::new();
    let started = std::time::Instant::now();
    let resp = get_with_retry(&client, "user", "token", &format!("http://{addr}/"))
        .await
        .expect("must recover on the retried request");
    let elapsed = started.elapsed();

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "must have retried exactly once, not given up after the first 429"
    );
    assert!(
        elapsed >= std::time::Duration::from_millis(900),
        "must actually wait for the server's real 1s Retry-After, not skip the sleep: {elapsed:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "must use the server's short real hint, not the old up-to-120s ceiling: {elapsed:?}"
    );
}

#[tokio::test]
async fn get_with_retry_gives_up_after_one_retry_on_a_persistent_429() {
    // A second consecutive 429 must still surface as an error (no infinite
    // retrying) — the module-level circuit breaker's soft/hard classification
    // takes over from there, exactly as before this fix.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..2 {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let body = b"{}";
            let head = format!(
                "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body).await;
            let _ = sock.flush().await;
        }
    });

    let client = reqwest::Client::new();
    let err = get_with_retry(&client, "user", "token", &format!("http://{addr}/"))
        .await
        .expect_err("a persistent 429 must still fail after the one retry");
    assert!(
        matches!(err, crate::core::error::Error::RateLimited(_)),
        "must classify as RateLimited so the shared circuit breaker paces it correctly: {err:?}"
    );
}
