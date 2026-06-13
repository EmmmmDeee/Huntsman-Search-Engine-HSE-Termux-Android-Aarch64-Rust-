use super::*;

    #[test]
    fn accepts_only_mac_address() {
        let m = Mls;
        assert!(m.accepts(&Target::new(TargetKind::MacAddress, "AA:BB:CC:DD:EE:FF")));
        assert!(!m.accepts(&Target::new(TargetKind::Coordinates, "0,0")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }

    #[test]
    fn category_is_geo() {
        assert_eq!(Mls.category(), ModuleCategory::Geo);
    }

    #[test]
    fn produces_coordinates_only() {
        let p = Mls.produces();
        assert_eq!(p, &[EntityKind::Coordinates]);
    }

    #[test]
    fn cost_is_free() {
        assert!(matches!(Mls.cost(), ModuleCost::Free));
    }

    #[test]
    fn priority_below_wigle_and_mylnikov() {
        // wigle = 18, mylnikov = 15 — MLS runs after both so its
        // result corroborates rather than dominates the expansion
        // weight on the same BSSID.
        assert!(Mls.priority() < 15);
    }

    #[test]
    fn confidence_steps_with_accuracy_buckets() {
        // Tight (<100m): high confidence
        assert!((confidence_from_accuracy(50.0) - 0.85).abs() < 1e-9);
        // Sub-km
        assert!((confidence_from_accuracy(300.0) - 0.75).abs() < 1e-9);
        // City-block
        assert!((confidence_from_accuracy(1_500.0) - 0.60).abs() < 1e-9);
        // City-wide single-AP
        assert!((confidence_from_accuracy(7_000.0) - 0.50).abs() < 1e-9);
        // Region (default fallback when MLS gives no accuracy)
        assert!((confidence_from_accuracy(20_000.0) - 0.40).abs() < 1e-9);
    }

    #[test]
    fn confidence_is_monotonic_in_accuracy() {
        // Tighter accuracy must never produce lower confidence.
        let samples = [
            50.0, 99.9, 100.0, 250.0, 500.0, 1_999.0, 2_000.0, 9_999.0, 10_000.0,
        ];
        let mut last = f64::INFINITY;
        for a in samples {
            let c = confidence_from_accuracy(a);
            assert!(c <= last, "monotonicity broken at accuracy={a}m");
            last = c;
        }
    }

    #[test]
    fn mls_resp_deserializes_typical_shape() {
        let json = r#"{"location":{"lat":-27.4766,"lng":153.0166},"accuracy":42.5}"#;
        let r: MlsResp = serde_json::from_str(json).unwrap();
        assert!(r.location.is_some());
        let loc = r.location.unwrap();
        assert!((loc.lat - (-27.4766)).abs() < 1e-9);
        assert!((loc.lng - 153.0166).abs() < 1e-9);
        assert!((r.accuracy.unwrap() - 42.5).abs() < 1e-9);
    }

    #[test]
    fn mls_resp_handles_missing_accuracy() {
        let json = r#"{"location":{"lat":0.0,"lng":0.0}}"#;
        let r: MlsResp = serde_json::from_str(json).unwrap();
        assert!(r.location.is_some());
        assert!(r.accuracy.is_none());
    }

    #[test]
    fn mls_resp_handles_empty_body() {
        let json = r#"{}"#;
        let r: MlsResp = serde_json::from_str(json).unwrap();
        assert!(r.location.is_none());
        assert!(r.accuracy.is_none());
    }
