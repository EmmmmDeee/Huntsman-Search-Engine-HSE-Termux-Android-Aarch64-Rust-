use super::*;

    #[test]
    fn parse_coords_accepts_well_formed_pairs() {
        assert_eq!(
            parse_coords("-27.4766,153.0166").unwrap(),
            (-27.4766, 153.0166)
        );
        assert_eq!(
            parse_coords(" 51.5074 , -0.1278 ").unwrap(),
            (51.5074, -0.1278)
        );
        // Null Island parses: it's a deliberately-typed seed, not a provider
        // sentinel — output filtering (is_valid_coords) is a separate concern.
        assert_eq!(parse_coords("0,0").unwrap(), (0.0, 0.0));
    }

    #[test]
    fn parse_coords_rejects_invalid_before_any_api_call() {
        assert!(parse_coords("not,coords").is_err()); // non-numeric
        assert!(parse_coords("153.02").is_err()); // not a pair
        assert!(parse_coords("200,300").is_err()); // out of range
        assert!(parse_coords("10,181").is_err()); // lon out of range
        assert!(parse_coords("nan,10").is_err()); // non-finite latitude
        assert!(parse_coords("10,inf").is_err()); // non-finite longitude
    }

    #[test]
    fn valid_coords_accepts_real_positions() {
        assert!(is_valid_coords(-27.4766, 153.0166)); // Brisbane
        assert!(is_valid_coords(51.5074, -0.1278)); // London
        assert!(is_valid_coords(90.0, 180.0)); // boundaries
        assert!(is_valid_coords(-90.0, -180.0));
    }

    #[test]
    fn valid_coords_rejects_bad_fixes() {
        assert!(!is_valid_coords(0.0, 0.0)); // Null Island
        assert!(!is_valid_coords(91.0, 10.0)); // lat out of range
        assert!(!is_valid_coords(10.0, 181.0)); // lon out of range
        assert!(!is_valid_coords(f64::NAN, 10.0)); // non-finite
        assert!(!is_valid_coords(10.0, f64::INFINITY));
    }

    #[test]
    fn in_australia_box_covers_continent_and_tasmania_only() {
        assert!(is_in_australia(-27.4766, 153.0166)); // Brisbane
        assert!(is_in_australia(-33.8688, 151.2093)); // Sydney
        assert!(is_in_australia(-31.9523, 115.8613)); // Perth
        assert!(is_in_australia(-42.8821, 147.3272)); // Hobart
        // Outside: neighbours, distant cities, and bad fixes are never in-box.
        assert!(!is_in_australia(-36.8485, 174.7633)); // Auckland, NZ
        assert!(!is_in_australia(-6.2088, 106.8456)); // Jakarta
        assert!(!is_in_australia(40.7128, -74.0060)); // New York
        assert!(!is_in_australia(0.0, 0.0)); // null island
        assert!(!is_in_australia(91.0, 130.0)); // out of range
    }

    #[test]
    fn au_state_for_coords_attributes_capitals_and_rejects_foreign() {
        assert_eq!(au_state_for_coords(-27.4766, 153.0166), Some("QLD")); // Brisbane
        assert_eq!(au_state_for_coords(-33.8688, 151.2093), Some("NSW")); // Sydney
        assert_eq!(au_state_for_coords(-37.8136, 144.9631), Some("VIC")); // Melbourne
        assert_eq!(au_state_for_coords(-34.9285, 138.6007), Some("SA")); // Adelaide
        assert_eq!(au_state_for_coords(-31.9523, 115.8613), Some("WA")); // Perth
        assert_eq!(au_state_for_coords(-42.8821, 147.3272), Some("TAS")); // Hobart
        assert_eq!(au_state_for_coords(-12.4634, 130.8456), Some("NT")); // Darwin
        // Canberra: inside the NSW box, but the ACT box is tested first.
        assert_eq!(au_state_for_coords(-35.2809, 149.1300), Some("ACT"));
        // Outside Australia → no state.
        assert_eq!(au_state_for_coords(-36.8485, 174.7633), None); // Auckland
        assert_eq!(au_state_for_coords(0.0, 0.0), None); // null island
    }

    #[test]
    fn nearest_au_locality_labels_capitals_and_rejects_foreign() {
        let (name, state, km) = nearest_au_locality(-27.47, 153.02).unwrap();
        assert_eq!((name, state), ("Brisbane", "QLD"));
        assert!(km < 5.0, "Brisbane CBD within 5km of the anchor, got {km}");
        // A regional fix resolves to its nearest centre.
        let (name, state, _) = nearest_au_locality(-26.729, 152.7554).unwrap();
        assert_eq!((name, state), ("Maleny", "QLD"));
        // Perth.
        assert_eq!(nearest_au_locality(-31.95, 115.86).map(|(n, s, _)| (n, s)), Some(("Perth", "WA")));
        // Outside Australia → None.
        assert!(nearest_au_locality(40.71, -74.0).is_none()); // New York
        assert!(nearest_au_locality(-36.8485, 174.7633).is_none()); // Auckland
    }

    #[test]
    fn haversine_km_matches_known_distances() {
        // Sydney ↔ Melbourne ≈ 714 km (great-circle).
        let d = haversine_km(-33.8688, 151.2093, -37.8136, 144.9631);
        assert!((700.0..730.0).contains(&d), "Sydney-Melbourne ≈ 714km, got {d}");
        // Zero distance.
        assert!(haversine_km(-27.47, 153.02, -27.47, 153.02) < 0.001);
    }

    #[test]
    fn plausible_provider_coord_keeps_real_fixes() {
        assert!(is_plausible_provider_coord(-27.4766, 153.0166)); // Brisbane
        assert!(is_plausible_provider_coord(51.5074, -0.1278)); // London
    }

    #[test]
    fn coarse_provider_coords_builds_a_gated_geoint_entity() {
        use crate::core::entity::EntityKind;
        // A real fix: 4-decimal value, Coordinates kind, geoint tag, the given
        // confidence. This is the identical birth the four IP-geo modules share.
        let e = coarse_provider_coords(-27.476600, 153.016601, 0.58, "scan-x")
            .expect("a plausible fix yields an entity");
        assert_eq!(e.kind, EntityKind::Coordinates);
        assert_eq!(e.raw_value, "-27.4766,153.0166"); // 4-decimal coarse format
        assert!(e.has_tag(crate::core::tags::GEOINT));
        // The Brisbane fix is inside the AU box → tagged on-region + state.
        assert!(e.has_tag("au-relevant"));
        assert!(e.has_tag("au-state:QLD"));
        assert!(!e.has_tag("off-region"));
        assert!((e.confidence - 0.58).abs() < 1e-9);
        // A plausible but foreign fix (London) is flagged off-region.
        let foreign = coarse_provider_coords(51.5074, -0.1278, 0.58, "scan-x")
            .expect("a plausible foreign fix still yields an entity");
        assert!(foreign.has_tag("off-region"));
        assert!(!foreign.has_tag("au-relevant"));
        // An implausible fix (null-island band / out-of-range) gates the whole
        // emit block to None.
        assert!(coarse_provider_coords(0.001, 0.001, 0.58, "scan-x").is_none());
        assert!(coarse_provider_coords(200.0, 10.0, 0.58, "scan-x").is_none());
    }

    #[test]
    fn plausible_provider_coord_drops_null_island_band() {
        // The band the IP/WiFi providers emit as "no fix".
        assert!(!is_plausible_provider_coord(0.0, 0.0));
        assert!(!is_plausible_provider_coord(0.001, 0.001));
        // Either component inside the band is enough to drop it.
        assert!(!is_plausible_provider_coord(0.005, 120.0));
        assert!(!is_plausible_provider_coord(45.0, -0.004));
    }

    #[test]
    fn ip_asn_entity_is_the_shared_provider_birth() {
        use crate::core::entity::EntityKind;
        // The identical Asn entity the five IP-geo providers emit: kind Asn,
        // confidence 0.80, value = the caller's already-formatted ASN string,
        // and a single "ASN for {ip}" evidence stamped with the caller's source.
        let e = ip_asn_entity("AS1221", "ip2location", "101.169.42.148", "scan-x");
        assert_eq!(e.kind, EntityKind::Asn);
        assert_eq!(e.value, "AS1221");
        assert!((e.confidence - 0.80).abs() < 1e-9);
        assert_eq!(e.evidence.len(), 1);
        assert_eq!(e.evidence[0].summary, "ASN for 101.169.42.148");
        assert_eq!(e.evidence[0].source, "ip2location");
        // No tag is added by the helper — the provider tag is the caller's job,
        // so a freshly-built entity carries none of them.
        assert!(!e.has_tag("ip2location"));
    }

    #[test]
    fn plausible_provider_coord_rejects_out_of_range_and_nonfinite() {
        // The gap the bare `abs() > 0.01` idiom left open: these used to pass
        // straight through into a high-confidence Coordinates entity.
        assert!(!is_plausible_provider_coord(500.0, 999.0));
        assert!(!is_plausible_provider_coord(91.0, 10.0));
        assert!(!is_plausible_provider_coord(10.0, 181.0));
        assert!(!is_plausible_provider_coord(f64::INFINITY, f64::INFINITY));
        assert!(!is_plausible_provider_coord(f64::NAN, 10.0));
    }
