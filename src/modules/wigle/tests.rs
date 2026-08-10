use super::account::{
    ProfileUserResp, WigleAccountStatus, account_status, account_status_cache, is_unverified,
    mark_unverified, mark_verified, status_from_profile,
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
        .expect("should succeed");
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
        .expect("should succeed");
    assert_eq!(
        ap2.evidence[0]
            .attributes
            .get("coordinates")
            .map(String::as_str),
        Some("-27.000000,153.000000")
    );
}

#[test]
fn named_ssid_evidence_headline_reports_the_true_count_not_the_10_item_sample() {
    // 14 distinct named/business-shaped SSIDs — more than the 10-item cap on
    // the `named_ssids` attribute string. The evidence headline must state
    // the TRUE count (14), not the truncated sample size (10).
    let net = |ssid: &str| Network {
        ssid: Some(ssid.to_string()),
        netid: None,
        encryption: None,
        lastupdt: None,
        trilat: None,
        trilong: None,
        city: None,
        region: None,
        country: None,
        postalcode: None,
    };
    let results: Vec<Network> = (0..14).map(|i| net(&format!("Family-Router{i}"))).collect();

    let ev = named_ssid_evidence(&results, "-27.0,153.0", None)
        .expect("14 named SSIDs must produce evidence");

    assert!(
        ev.summary.contains("14 named WiFi network(s)"),
        "headline must report the true count of 14, not the 10-item cap: {}",
        ev.summary
    );
    // The attribute string itself stays bounded to 10 entries.
    let listed = ev.attributes.get("named_ssids").expect("named_ssids attr");
    assert_eq!(listed.split(", ").count(), 10);
}

#[test]
fn named_ssid_evidence_returns_none_when_nothing_matches() {
    let net = Network {
        ssid: Some("linksys".to_string()),
        netid: None,
        encryption: None,
        lastupdt: None,
        trilat: None,
        trilong: None,
        city: None,
        region: None,
        country: None,
        postalcode: None,
    };
    assert!(named_ssid_evidence(&[net], "-27.0,153.0", None).is_none());
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
    let (lat, lon) = parse_coords("-27.4766,153.0166").expect("should succeed");
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
    assert!(is_generic_ssid("telstra-home-123"));
    assert!(!is_generic_ssid("smith-family"));
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
    let r: Resp = serde_json::from_str(json).expect("should succeed");
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
        "generic carriers (Telstra/Vodafone) must be filtered out"
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
fn extract_cell_intel_emits_address_from_city_region_country_consensus() {
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
                trilat: None,
                trilong: None,
                city: Some("Nundah".into()),
                region: Some("Queensland".into()),
                country: Some("AU".into()),
                postalcode: Some("4012".into()),
            },
            Network {
                ssid: None,
                netid: None,
                encryption: None,
                lastupdt: None,
                trilat: None,
                trilong: None,
                city: Some("Nundah".into()),
                region: Some("Queensland".into()),
                country: Some("AU".into()),
                postalcode: Some("4012".into()),
            },
            Network {
                ssid: None,
                netid: None,
                encryption: None,
                lastupdt: None,
                trilat: None,
                trilong: None,
                city: Some("Brisbane".into()),
                region: Some("Queensland".into()),
                country: Some("AU".into()),
                postalcode: Some("4000".into()),
            },
        ],
    };
    let mut r = ModuleResult::new();
    extract_cell_intel(&resp, "-27.4766,153.0166", "test-scan", &mut r);
    let addrs: Vec<_> = r
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Address)
        .collect();
    assert_eq!(
        addrs.len(),
        1,
        "one consensus Address entity, not one per observation"
    );
    let addr = addrs[0];
    // Nundah wins the city mode 2-1 over Brisbane; region/country/postcode
    // follow the Nundah records too.
    assert!(addr.value.contains("Nundah"));
    assert!(addr.value.contains("Queensland"));
    assert!(addr.value.contains("AU"));
    assert!(addr.value.contains("4012"));
    assert!(addr.has_tag("wigle"));
    assert!(addr.has_tag("cell-derived"));
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
fn emit_ssid_entities_emits_address_from_city_region_country_consensus() {
    // Reuses the resp_deserializes_with_full_fields fixture shape (Nundah,
    // Queensland, AU, 4012) across all matched networks so the mode()
    // consensus has real city/region/country/postalcode to agree on.
    let results: Vec<Network> = (0..3)
        .map(|i| Network {
            ssid: Some("HaigenHomeWiFi".to_string()),
            netid: Some(format!("AA:BB:CC:DD:EE:{i:02X}")),
            encryption: None,
            lastupdt: None,
            trilat: Some(-27.4766 - f64::from(i) * 0.001),
            trilong: Some(153.0166 + f64::from(i) * 0.001),
            city: Some("Nundah".to_string()),
            region: Some("Queensland".to_string()),
            country: Some("AU".to_string()),
            postalcode: Some("4012".to_string()),
        })
        .collect();
    let r = emit_ssid_entities("HaigenHomeWiFi", &results, "test-scan");
    let addrs: Vec<_> = r
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Address)
        .collect();
    assert_eq!(
        addrs.len(),
        1,
        "one consensus Address entity, not one per observation"
    );
    let addr = addrs[0];
    assert!(addr.value.contains("Nundah"));
    assert!(addr.value.contains("Queensland"));
    assert!(addr.value.contains("AU"));
    assert!(addr.value.contains("4012"));
    assert!(addr.has_tag("wigle"));
    assert!(addr.has_tag("ssid-located"));
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
    let _g = budget_guard();
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
    // Asserts `scan_used == 0` on shared statics, so it must not run
    // alongside anything that spends a unit.
    let _g = budget_guard();
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
    let json = serde_json::to_string(&s).expect("should succeed");
    assert!(json.contains("\"verified\":true"));
    assert!(json.contains("\"user\":\"MattDieg\""));
}

/// A stale `unverified` latch from an earlier 412 must self-correct the
/// moment a later query succeeds — `mark_verified` is the symmetric
/// counterpart of `mark_unverified`, both learned from live traffic in
/// `fetch.rs::classify_and_decode`, never a dedicated poll.
#[test]
fn mark_verified_clears_a_stale_unverified_latch() {
    struct CacheGuard;
    impl Drop for CacheGuard {
        fn drop(&mut self) {
            if let Ok(mut g) = account_status_cache().lock() {
                *g = WigleAccountStatus::default();
            }
        }
    }
    let _guard = CacheGuard;

    // Simulate an earlier 412: the account looks unverified.
    mark_unverified(1_000);
    assert!(is_unverified(), "a 412 must latch unverified");

    // A later query succeeds — e.g. the operator completed WiGLE's
    // email-verify step mid-process — and must un-latch the stale flag.
    mark_verified(2_000);
    assert!(
        !is_unverified(),
        "a successful query must clear the stale unverified latch"
    );
    let s = account_status();
    assert_eq!(s.verified, Some(true));
    assert_eq!(
        s.last_polled_ts,
        Some(2_000),
        "last_polled_ts tracks the most recent signal, not the first"
    );
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
    let body: ProfileUserResp = serde_json::from_str(json).expect("should succeed");
    assert_eq!(body.userid.as_deref(), Some("MattDieg "));
    assert_eq!(body.email_verified, Some(false));

    let status = status_from_profile(body, 1234);
    assert_eq!(status.user.as_deref(), Some("MattDieg"));
    assert_eq!(status.verified, Some(false));
    assert_eq!(status.last_polled_ts, Some(1234));
}

#[test]
fn status_from_profile_treats_absent_and_blank_userid_as_none() {
    let blank: ProfileUserResp =
        serde_json::from_str(r#"{"userid": "   "}"#).expect("should succeed");
    assert!(status_from_profile(blank, 0).user.is_none());

    let absent: ProfileUserResp =
        serde_json::from_str(r#"{"emailVerified": true}"#).expect("should succeed");
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

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should succeed");
    let addr = listener.local_addr().expect("should succeed");
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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should succeed");
    let addr = listener.local_addr().expect("should succeed");
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

/// A person-named network near the subject must become a pivotable entity, not
/// just a line of prose.
///
/// `TargetKind::Ssid` is a valid scan target that this same module accepts, and
/// `ssid_search` resolves a unique SSID to every GPS point it has been observed
/// at — the pivot that turns "a named network near this coordinate" into
/// "everywhere that network has been seen". Previously the names were recorded
/// only as a text attribute on another entity, so the edge could never be
/// walked.
#[test]
fn named_ssids_become_pivotable_entities() {
    let net = |ssid: &str| Network {
        ssid: Some(ssid.into()),
        netid: None,
        encryption: None,
        lastupdt: None,
        trilat: None,
        trilong: None,
        city: None,
        region: None,
        country: None,
        postalcode: None,
    };
    let results = vec![
        net("Smith-Family"),
        net("Bamford-Residence"),
        net("NETGEAR47"),       // vendor default — not a person's choice
        net("Telstra-Home-12"), // carrier default
        net("Smith-Family"),    // duplicate must collapse
    ];

    let ents = named_ssid_entities(&results, "-27.4698,153.0251", "scan");
    let names: Vec<&str> = ents.iter().map(|e| e.value.as_str()).collect();
    assert_eq!(
        names,
        vec!["Bamford-Residence", "Smith-Family"],
        "only person-named networks, deduplicated and sorted"
    );
    assert!(ents.iter().all(|e| e.kind == EntityKind::Ssid));
    assert!(ents.iter().all(|e| e.tags.iter().any(|t| t == "geo-lead")));
    // Above the expansion floor so the pivot actually runs, below MEDIUM so
    // nothing reads proximity as proven ownership.
    for e in &ents {
        assert!(
            e.confidence > crate::core::scan::DEFAULT_MIN_EXPAND_CONFIDENCE,
            "{} must clear the expansion floor to pivot",
            e.value
        );
        assert!(e.confidence < crate::core::confidence::MEDIUM);
    }
    // The true count rides along, per the no-silent-truncation policy.
    assert_eq!(
        ents[0].evidence[0]
            .attributes
            .get("named_ssids_observed")
            .map(String::as_str),
        Some("2")
    );
}

/// A BSSID WiGLE reports twice must not consume two emitted slots.
///
/// `dedup_by_key` removes only CONSECUTIVE duplicates, and the pass used to
/// deduplicate AFTER sorting by distance — so the same access point observed at
/// two slightly different positions stayed as two entries.
#[test]
fn duplicate_bssids_collapse_before_ranking() {
    let net = |netid: &str, tri: (f64, f64)| Network {
        ssid: None,
        netid: Some(netid.into()),
        encryption: None,
        lastupdt: None,
        trilat: Some(tri.0),
        trilong: Some(tri.1),
        city: None,
        region: None,
        country: None,
        postalcode: None,
    };
    // One AP reported twice at slightly different positions, plus five others,
    // so a failure to collapse would push a real AP out of the emitted set.
    let results = vec![
        net("AA:BB:CC:DD:EE:01", (-27.4700, 153.0251)),
        net("AA:BB:CC:DD:EE:01", (-27.4701, 153.0252)),
        net("AA:BB:CC:DD:EE:02", (-27.4702, 153.0253)),
        net("AA:BB:CC:DD:EE:03", (-27.4703, 153.0254)),
        net("AA:BB:CC:DD:EE:04", (-27.4704, 153.0255)),
        net("AA:BB:CC:DD:EE:05", (-27.4705, 153.0256)),
        net("AA:BB:CC:DD:EE:06", (-27.4706, 153.0257)),
    ];
    let ents = wifi_ap_entities(&results, -27.4698, 153.0251, "-27.4698,153.0251", "scan");
    let mut macs: Vec<&str> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::MacAddress)
        .map(|e| e.value.as_str())
        .collect();
    let before = macs.len();
    macs.sort_unstable();
    macs.dedup();
    assert_eq!(before, macs.len(), "a BSSID must be emitted at most once");
    assert_eq!(macs.len(), MAX_EMITTED_APS);

    // Six DISTINCT APs were observed; the emitted set is bounded, so the true
    // count must be stated rather than silently implied by the list length.
    let observed = ents
        .iter()
        .find(|e| e.kind == EntityKind::MacAddress)
        .and_then(|e| e.evidence[0].attributes.get("aps_observed"))
        .map(String::as_str);
    assert_eq!(observed, Some("6"));
}

/// Every declared WiGLE budget must appear on the diagnostic surface, or an
/// operator cannot tell why a sub-capability stopped firing.
#[test]
fn budget_snapshot_reports_every_declared_budget() {
    let snap = budget_snapshot();
    // Field access is the assertion: `ssid` was declared, reset and consumed
    // while being absent from this struct.
    let _ = (snap.geo, snap.bssid, snap.cell, snap.bluetooth, snap.ssid);
}

// ── Budget is denominated in HTTP requests, not dispatches ──────────────────
//
// Each sub-budget's documented cap ("3 geo searches per scan") is a promise
// about upstream requests against the operator's daily WiGLE allowance, so the
// charge has to sit next to the request it pays for. These pin the two ways
// that promise was broken: a request that is never issued must not be billed,
// and an exhausted allowance must stop the caller before it dials out.

/// Serialises every test that touches a WiGLE budget.
///
/// The budgets are process-global statics and the test harness runs threads in
/// parallel, so a test that resets or drains one races any other test doing the
/// same — `reset_budget()` in particular clears all five at once. Without this
/// the suite passes or fails depending on thread interleaving.
/// Async-aware because the dispatch-level tests hold it across `.await`; a
/// `std::sync::Mutex` guard is not safe to hold across a yield point.
static BUDGET_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Take [`BUDGET_LOCK`] from a synchronous test. Safe here because `#[test]`
/// functions run outside any Tokio runtime; async tests `.await` the lock
/// directly instead.
fn budget_guard() -> tokio::sync::MutexGuard<'static, ()> {
    BUDGET_LOCK.blocking_lock()
}

/// Context whose HTTP client resolves the WiGLE host to a closed loopback port.
///
/// These tests assert that no request is issued. Letting the real hostname
/// through would send live traffic to a third party — spending the quota this
/// very budget exists to protect, and making the suite depend on the network —
/// while an attempted call here fails instantly against a refused local
/// connection. So `Ok(empty)` means "never dialled" and `Err` means "dialled",
/// which is exactly the distinction under test.
fn offline_ctx() -> crate::core::module::ModuleContext {
    let http = reqwest::Client::builder()
        .resolve(
            "api.wigle.net",
            std::net::SocketAddr::from(([127, 0, 0, 1], 1)),
        )
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .expect("client with a loopback resolve override");
    crate::core::module::ModuleContext {
        scan_id: "budget-test".to_string(),
        bus: tokio::sync::broadcast::channel(16).0,
        http,
        // WiGLE credentials are REQUIRED — nothing is embedded in the build — so
        // the budget tests below must supply a pair or `process` would return
        // `MissingKey` before reaching the accounting they exist to check. The
        // values are never sent anywhere: `http` resolves api.wigle.net to a
        // closed loopback port.
        keys: std::collections::HashMap::from([
            ("HUNTSMAN_WIGLE_USER".to_string(), "AIDtest".to_string()),
            ("HUNTSMAN_WIGLE_TOKEN".to_string(), "token-test".to_string()),
        ]),
        cancel: crate::core::cancel::CancelHandle::new(),
    }
}

/// With no credential embedded in the build, an unconfigured WiGLE account is a
/// clean "needs key" skip — not a request, and not a charge against the
/// operator's daily allowance.
///
/// Both halves of the HTTP-Basic pair are required, so a half-configured account
/// must skip too rather than issue a request that can only 401.
#[tokio::test]
async fn an_unconfigured_wigle_account_skips_without_spending() {
    use crate::core::error::Error;

    let ctx_with = |pairs: &[(&str, &str)]| crate::core::module::ModuleContext {
        scan_id: "keygate-test".to_string(),
        bus: tokio::sync::broadcast::channel(16).0,
        http: reqwest::Client::new(),
        keys: pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };

    let _g = BUDGET_LOCK.lock().await;
    for keys in [
        &[][..],
        &[("HUNTSMAN_WIGLE_USER", "AIDtest")][..],
        &[("HUNTSMAN_WIGLE_TOKEN", "token-test")][..],
        // A blank half is unconfigured, not a credential.
        &[
            ("HUNTSMAN_WIGLE_USER", "AIDtest"),
            ("HUNTSMAN_WIGLE_TOKEN", ""),
        ][..],
    ] {
        SSID_BUDGET.reset_scan();
        let before = SSID_BUDGET.scan_remaining();
        let err = Wigle
            .process(
                &Target::new(TargetKind::Ssid, "alice-home"),
                &ctx_with(keys),
            )
            .await
            .expect_err("an unconfigured WiGLE account must not silently proceed");
        assert!(
            matches!(err, Error::MissingKey(_)),
            "expected MissingKey for {keys:?}, got: {err:?}"
        );
        assert_eq!(
            SSID_BUDGET.scan_remaining(),
            before,
            "a dispatch that never issues a request must cost no quota"
        );
    }
}

/// Regression: the SSID unit was charged in `process` *before* `ssid_search`
/// applied its skip filters, so a scan whose networks were all carrier
/// defaults burned its whole SSID allowance without issuing one request — and
/// the distinctive name later in the pivot chain, the only one that could
/// actually geolocate the subject, found the budget already spent.
#[tokio::test]
async fn a_skipped_generic_ssid_costs_no_budget() {
    let _g = BUDGET_LOCK.lock().await;
    SSID_BUDGET.reset_scan();
    let before = SSID_BUDGET.scan_remaining();

    let out = Wigle
        .ssid_search("user", "token", "NETGEAR", &offline_ctx())
        .await
        .expect("a generic SSID is skipped, not an error");

    assert!(out.entities.is_empty(), "generic SSID must not geolocate");
    assert_eq!(
        SSID_BUDGET.scan_remaining(),
        before,
        "no request was issued, so no unit may be spent"
    );
}

/// An empty SSID is filtered before the request too, and must likewise be free.
#[tokio::test]
async fn an_empty_ssid_costs_no_budget() {
    let _g = BUDGET_LOCK.lock().await;
    SSID_BUDGET.reset_scan();
    let before = SSID_BUDGET.scan_remaining();

    let out = Wigle
        .ssid_search("user", "token", "", &offline_ctx())
        .await
        .expect("an empty SSID is skipped, not an error");

    assert!(out.entities.is_empty());
    assert_eq!(SSID_BUDGET.scan_remaining(), before);
}

/// An exhausted SSID allowance must short-circuit ahead of the request.
///
/// Before the fix `ssid_search` held no guard at all — the single unit was
/// spent back in `process` — so a drained budget still dialled WiGLE. The
/// loopback resolve makes that visible: a call attempt surfaces as `Err`,
/// while the guard returns `Ok` with nothing.
#[tokio::test]
async fn an_exhausted_ssid_budget_issues_no_request() {
    let _g = BUDGET_LOCK.lock().await;
    SSID_BUDGET.reset_scan();
    while SSID_BUDGET.try_increment() {}
    assert!(!SSID_BUDGET.remaining(), "precondition: allowance drained");

    let out = Wigle
        .ssid_search("user", "token", "Kowalczyk-Family-5G", &offline_ctx())
        .await
        .expect("exhaustion is a skip, not a failed request");
    assert!(out.entities.is_empty());

    SSID_BUDGET.reset_scan();
}

/// Regression: `bssid_lookup` probes the WiFi, cell and Bluetooth corpora in
/// turn — up to three billable requests — while `process` charged one unit for
/// the whole dispatch, so a documented "5 BSSID lookups per scan" could spend
/// fifteen. The loop now charges per kind and breaks when the allowance runs
/// out, so a drained budget probes nothing.
#[tokio::test]
async fn an_exhausted_bssid_budget_probes_no_observation_kind() {
    let _g = BUDGET_LOCK.lock().await;
    BSSID_BUDGET.reset_scan();
    while BSSID_BUDGET.try_increment() {}
    assert!(!BSSID_BUDGET.remaining(), "precondition: allowance drained");

    let out = Wigle
        .bssid_lookup("user", "token", "AA:BB:CC:DD:EE:FF", &offline_ctx())
        .await
        .expect("exhaustion is a skip, not a failed request");
    assert!(out.entities.is_empty());

    BSSID_BUDGET.reset_scan();
}

/// The per-kind charge must be able to spend more than one unit per dispatch —
/// that is the whole fix — so the cap has to be able to fund a complete
/// three-corpus lookup.
#[test]
fn the_bssid_budget_can_fund_all_three_observation_kinds() {
    let _g = budget_guard();
    BSSID_BUDGET.reset_scan();
    assert!(
        BSSID_BUDGET.scan_cap() >= 3,
        "one BSSID dispatch probes WiFi, cell and Bluetooth; a cap below 3 \
         could never fund a single complete lookup"
    );
    for probe in 0..3 {
        assert!(
            BSSID_BUDGET.try_increment(),
            "probe {probe} of one lookup must be affordable"
        );
    }
    BSSID_BUDGET.reset_scan();
}

/// The two tests above call `ssid_search`/`bssid_lookup` directly, which pins
/// where the charge sits *now*. These drive the real `process` entry point,
/// which is where the single per-dispatch unit used to be taken — so they
/// measure the invariant the budget actually promises: units spent equals
/// requests issued.
///
/// Regression: `process` charged one SSID unit up front, before `ssid_search`
/// had a chance to skip a carrier-default name. Three such networks drained a
/// 3-unit allowance without a single request leaving the host.
#[tokio::test]
async fn a_generic_ssid_dispatch_spends_nothing() {
    let _g = BUDGET_LOCK.lock().await;
    SSID_BUDGET.reset_scan();
    let before = SSID_BUDGET.scan_remaining();

    let out = Wigle
        .process(&Target::new(TargetKind::Ssid, "NETGEAR"), &offline_ctx())
        .await
        .expect("a generic SSID is skipped, not an error");

    assert!(out.entities.is_empty());
    assert_eq!(
        SSID_BUDGET.scan_remaining(),
        before,
        "a dispatch that issues no request must cost no quota"
    );
}

/// Regression: one `MacAddress` dispatch probes the WiFi, cell and Bluetooth
/// corpora in sequence — three billable requests — and was charged a single
/// unit, so the documented "5 BSSID lookups per scan" could spend fifteen
/// against an allowance denominated in requests.
///
/// The probes fail here (the host resolves to a closed port), which is the
/// point: each is charged *before* it is issued, so the accounting holds
/// whether or not WiGLE answers.
#[tokio::test]
async fn one_bssid_dispatch_is_billed_for_every_corpus_it_probes() {
    let _g = BUDGET_LOCK.lock().await;
    BSSID_BUDGET.reset_scan();
    let before = BSSID_BUDGET.scan_remaining();

    let _ = Wigle
        .process(
            &Target::new(TargetKind::MacAddress, "AA:BB:CC:DD:EE:FF"),
            &offline_ctx(),
        )
        .await;

    assert_eq!(
        before - BSSID_BUDGET.scan_remaining(),
        3,
        "three corpora probed must cost three units, not one"
    );

    BSSID_BUDGET.reset_scan();
}
