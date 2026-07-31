use super::*;
use crate::core::confidence;

    #[test]
    fn accepts_mac_only() {
        let m = BeaconDb;
        assert!(m.accepts(&Target::new(TargetKind::MacAddress, "AA:BB:CC:DD:EE:FF")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Coordinates, "1.0,2.0")));
    }

    #[test]
    fn module_metadata() {
        assert_eq!(BeaconDb.name(), "beacondb");
        assert_eq!(BeaconDb.priority(), 17);
        // Must exceed the 3s default MODULE_TIMEOUT_MS or the engine kills a
        // slow-but-connected response as a spurious timeout.
        assert!(BeaconDb.max_timeout_ms() > 3_000);
    }

    /// The request must never let the server fall back to locating the caller.
    /// This is a request-shape guard, not a style check: flipping this constant
    /// turns every miss into the operator's own position (see the module header).
    ///
    /// Asserted in a `const` block on purpose — the safety property is knowable
    /// at compile time, so flipping the constant must fail the BUILD rather than
    /// wait for someone to run the tests.
    #[test]
    fn ip_fallback_is_always_disabled_in_the_request() {
        const {
            assert!(
                !CONSIDER_IP,
                "considerIp must stay false — with IP fallback on, an unknown BSSID \
                 resolves to the SCANNER's location and is reported as the target's"
            );
        }
    }

    fn parse(raw: &str) -> GeolocateResp {
        serde_json::from_str(raw).expect("fixture must deserialize")
    }

    /// A real wifi fix: no fallback marker, position present, tight accuracy.
    #[test]
    fn a_wireless_fix_builds_a_located_entity() {
        let r = parse(r#"{"location":{"lat":-33.8688,"lng":151.2093},"accuracy":150}"#);
        let e = build_location_entity("AA:BB:CC:DD:EE:FF", &r, "s").expect("a fix must build");
        assert_eq!(e.kind, EntityKind::Coordinates);
        assert_eq!(e.value, "-33.868800,151.209300");
        assert!(e.has_tag("beacondb") && e.has_tag("geoint") && e.has_tag("bssid-located"));
        assert!((e.confidence - confidence::VERY_HIGH).abs() < 1e-9);
        let a = &e.evidence[0].attributes;
        assert_eq!(
            a.get("bssid").map(String::as_str),
            Some("AA:BB:CC:DD:EE:FF")
        );
        assert_eq!(a.get("accuracy_m").map(String::as_str), Some("150"));
        // Inside AU, so the shared AU tagger fired.
        assert!(e.has_tag("country:AU"));
    }

    /// The regression this module exists to avoid, pinned against the EXACT body
    /// the live endpoint returned for two BSSIDs it had never seen. It is a
    /// syntactically perfect 200 carrying the scanner's own IP location; treating
    /// it as a BSSID fix would report the operator's position as the target's.
    #[test]
    fn the_observed_ip_fallback_response_is_rejected() {
        let r = parse(
            r#"{"accuracy":25000,"fallback":"ipf","license":"IP geolocation data sourced from IP to City Lite by DB-IP, licensed under CC BY 4.0.","location":{"lat":37.7901,"lng":-122.401}}"#,
        );
        // The coordinates are well-formed and would otherwise pass every check.
        assert!(is_valid_coords(37.7901, -122.401));
        assert!(
            build_location_entity("AA:BB:CC:DD:EE:FF", &r, "s").is_none(),
            "an IP-fallback answer must never become a BSSID location"
        );
    }

    /// Any fallback marker disqualifies the answer, not just the IP one — a cell
    /// fallback locates a tower, and an unrecognised future marker is unknown
    /// provenance. Unknown provenance must fail closed.
    #[test]
    fn every_fallback_marker_disqualifies_the_fix() {
        for marker in ["ipf", "lacf", "some-future-marker", ""] {
            let raw = format!(
                r#"{{"location":{{"lat":-33.8,"lng":151.2}},"accuracy":50,"fallback":"{marker}"}}"#
            );
            assert!(
                build_location_entity("m", &parse(&raw), "s").is_none(),
                "fallback marker {marker:?} must disqualify the fix"
            );
        }
    }

    #[test]
    fn missing_or_invalid_coordinates_yield_no_entity() {
        // Absent location block entirely.
        assert!(build_location_entity("m", &parse(r#"{"accuracy":50}"#), "s").is_none());
        // Half a position.
        assert!(build_location_entity("m", &parse(r#"{"location":{"lat":1.0}}"#), "s").is_none());
        assert!(build_location_entity("m", &parse(r#"{"location":{"lng":1.0}}"#), "s").is_none());
        // Null Island and out-of-range, rejected by the shared validator.
        assert!(
            build_location_entity("m", &parse(r#"{"location":{"lat":0.0,"lng":0.0}}"#), "s")
                .is_none()
        );
        assert!(
            build_location_entity("m", &parse(r#"{"location":{"lat":91.0,"lng":10.0}}"#), "s")
                .is_none()
        );
    }

    /// A wide accuracy radius is still a fix, but must not be scored like a tight
    /// one — it shares the ladder with `mylnikov` so peers rank comparably.
    #[test]
    fn accuracy_radius_drives_confidence_on_the_shared_ladder() {
        let at = |acc: f64| {
            let raw = format!(r#"{{"location":{{"lat":-33.8,"lng":151.2}},"accuracy":{acc}}}"#);
            build_location_entity("m", &parse(&raw), "s")
                .expect("a valid fix")
                .confidence
        };
        assert!((at(50.0) - confidence::VERY_HIGH).abs() < 1e-9);
        assert!((at(2_000.0) - confidence::MEDIUM).abs() < 1e-9);
        assert!((at(25_000.0) - 0.35).abs() < 1e-9);
        assert!(
            at(50.0) > at(25_000.0),
            "a tight fix must outrank a city-wide one"
        );
    }

    /// Absent accuracy is scored on the wide default and omits the attribute,
    /// rather than being treated as a perfect fix.
    #[test]
    fn missing_accuracy_omits_the_attr_and_uses_the_wide_default() {
        let e = build_location_entity("m", &parse(r#"{"location":{"lat":-33.8,"lng":151.2}}"#), "s")
            .expect("a fix without an accuracy radius is still a fix");
        assert!((e.confidence - confidence::MEDIUM).abs() < 1e-9);
        assert_eq!(e.evidence[0].attributes.get("accuracy_m"), None);
    }

    /// The live 404 body must deserialize without panicking, so the error branch
    /// is reached by status code rather than by a decode failure.
    #[test]
    fn the_observed_not_found_body_is_not_mistaken_for_a_fix() {
        let r = parse(
            r#"{"error":{"code":404,"errors":[{"domain":"geolocation","message":"No location could be estimated based on the data provided","reason":"notFound"}],"message":"Not found"}}"#,
        );
        assert!(build_location_entity("m", &r, "s").is_none());
    }
