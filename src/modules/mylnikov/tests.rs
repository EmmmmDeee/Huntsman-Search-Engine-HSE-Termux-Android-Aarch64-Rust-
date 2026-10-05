use crate::core::confidence;
use super::*;

    #[test]
    fn accepts_mac_only() {
        let m = Mylnikov;
        assert!(m.accepts(&Target::new(TargetKind::MacAddress, "AA:BB:CC:DD:EE:FF")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn module_metadata() {
        assert_eq!(Mylnikov.name(), "mylnikov");
        assert_eq!(Mylnikov.priority(), 17);
        assert_eq!(Mylnikov.max_timeout_ms(), 10_000);
    }

    #[test]
    fn parse_response() {
        let raw = r#"{"result": 200, "data": {"lat": -33.8688, "lon": 151.2093, "range": 250.0}}"#;
        let r: MylnikovResp = serde_json::from_str(raw).expect("should succeed");
        assert_eq!(r.result, Some(200));
        let d = classify(r).expect("a hit").expect("a fix");
        assert!((d.lat.expect("should succeed") - (-33.8688)).abs() < 0.001);
    }

    #[test]
    fn only_result_404_is_the_miss_every_other_code_is_a_failed_lookup() {
        // Backlog #29, bodies captured live 2026-09-15.
        let miss: MylnikovResp = serde_json::from_str(
            r#"{"result":404, "data":{}, "message":6, "desc":"Object was not found", "time":1789478664}"#,
        )
        .expect("decodes");
        assert!(classify(miss).expect("the miss").is_none());
        let rejected: MylnikovResp = serde_json::from_str(
            r#"{"result":400, "data":{}, "message":2, "desc":"Empty or bad search query", "time":1789478603}"#,
        )
        .expect("decodes");
        let err = classify(rejected).expect_err("a rejected query is not 'BSSID not located'");
        assert!(err.to_string().contains("result=400") && err.to_string().contains("Empty or bad search query"), "{err}");
        // A string `data` on an error body no longer breaks the decode.
        let odd: MylnikovResp = serde_json::from_str(r#"{"result":403, "data":"blocked", "desc":"Too many requests"}"#).expect("decodes");
        assert!(classify(odd).expect_err("403 is a failure").to_string().contains("Too many requests"));
        // No code at all is not a miss either.
        let none: MylnikovResp = serde_json::from_str(r#"{}"#).expect("decodes");
        assert!(classify(none).expect_err("absent code").to_string().contains("result=absent"));
    }

    #[test]
    fn confidence_bands_track_range_accuracy() {
        // Boundaries of each band, plus the missing-range default (wide → 5000).
        assert!((confidence_for_range(Some(0.0)) - confidence::HIGH_PLUSPLUS_PLUS).abs() < 1e-9);
        assert!((confidence_for_range(Some(50.0)) - confidence::HIGH_PLUSPLUS_PLUS).abs() < 1e-9);
        assert!((confidence_for_range(Some(51.0)) - confidence::VERY_HIGH).abs() < 1e-9);
        assert!((confidence_for_range(Some(300.0)) - confidence::VERY_HIGH).abs() < 1e-9);
        assert!((confidence_for_range(Some(301.0)) - confidence::HIGH).abs() < 1e-9);
        assert!((confidence_for_range(Some(1000.0)) - confidence::HIGH).abs() < 1e-9);
        assert!((confidence_for_range(Some(1001.0)) - confidence::MEDIUM).abs() < 1e-9);
        assert!((confidence_for_range(Some(5000.0)) - confidence::MEDIUM).abs() < 1e-9);
        assert!((confidence_for_range(Some(5001.0)) - 0.35).abs() < 1e-9);
        // None → 5000 default → the 1001..=5000 band.
        assert!((confidence_for_range(None) - confidence::MEDIUM).abs() < 1e-9);
    }

    fn data(lat: Option<f64>, lon: Option<f64>, range: Option<f64>) -> MylnikovData {
        MylnikovData { lat, lon, range }
    }

    #[test]
    fn tight_fix_builds_high_confidence_entity_with_range() {
        let e = build_location_entity(
            "AA:BB:CC:DD:EE:FF",
            &data(Some(-33.8688), Some(151.2093), Some(150.0)),
            "s",
        )
        .expect("should succeed");
        assert_eq!(e.kind, EntityKind::Coordinates);
        assert_eq!(e.value, "-33.868800,151.209300");
        assert!(e.has_tag("mylnikov") && e.has_tag("geoint") && e.has_tag("bssid-located"));
        assert!((e.confidence - confidence::VERY_HIGH).abs() < 1e-9);
        let a = &e.evidence[0].attributes;
        assert_eq!(
            a.get("bssid").map(String::as_str),
            Some("AA:BB:CC:DD:EE:FF")
        );
        assert_eq!(a.get("range_m").map(String::as_str), Some("150"));
    }

    #[test]
    fn missing_range_omits_attr_and_uses_default_band() {
        let e = build_location_entity("m", &data(Some(10.0), Some(20.0), None), "s").expect("should succeed");
        assert!((e.confidence - confidence::MEDIUM).abs() < 1e-9);
        assert_eq!(e.evidence[0].attributes.get("range_m"), None);
    }

    #[test]
    fn invalid_or_missing_coords_yield_no_entity() {
        // Missing components.
        assert!(build_location_entity("m", &data(None, Some(1.0), None), "s").is_none());
        assert!(build_location_entity("m", &data(Some(1.0), None, None), "s").is_none());
        // Null Island and out-of-range rejected by the shared validator.
        assert!(build_location_entity("m", &data(Some(0.0), Some(0.0), None), "s").is_none());
        assert!(build_location_entity("m", &data(Some(91.0), Some(0.0), None), "s").is_none());
    }
