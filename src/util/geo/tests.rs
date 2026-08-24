use super::*;

    #[test]
    fn parse_coords_accepts_well_formed_pairs() {
        assert_eq!(
            parse_coords("-27.4766,153.0166").expect("should succeed"),
            (-27.4766, 153.0166)
        );
        assert_eq!(
            parse_coords(" 51.5074 , -0.1278 ").expect("should succeed"),
            (51.5074, -0.1278)
        );
        // Null Island parses: it's a deliberately-typed seed, not a provider
        // sentinel — output filtering (is_valid_coords) is a separate concern.
        assert_eq!(parse_coords("0,0").expect("should succeed"), (0.0, 0.0));
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
    fn au_state_for_coords_is_border_accurate_across_states() {
        // A real multi-town fixture, weighted toward the border bands the old
        // overlapping-box scan misattributed. Coordinates are town centroids;
        // states are the true jurisdiction. This both fixes the gross bugs
        // (Lismore/Goondiwindi/Shepparton were on the wrong side of a first-match
        // box) and holds the exact meridian/parallel borders. The commented pairs
        // are river-twin towns a few km apart across the Murray — the fit splits
        // them correctly, which is the strongest evidence the border is real, not
        // a bounding box.
        let cases: &[(f64, f64, &str, &str)] = &[
            // QLD
            (-27.5606, 151.9539, "QLD", "Toowoomba"),
            (-16.9203, 145.7710, "QLD", "Cairns"),
            (-20.7256, 139.4927, "QLD", "Mount Isa"),
            (-25.8974, 139.3517, "QLD", "Birdsville"), // just N of 26°S in 138–141°E
            (-28.5450, 150.3097, "QLD", "Goondiwindi"), // just N of the 29°S line
            (-27.9707, 153.4088, "QLD", "Southport"),
            // NSW — the gross-bug fixes plus interior + coastal
            (-28.8103, 153.2830, "NSW", "Lismore"), // was QLD (N of 29°S, coastal border dips)
            (-28.6474, 153.6020, "NSW", "Byron Bay"),
            (-35.1082, 147.3598, "NSW", "Wagga Wagga"),
            (-31.9560, 141.4670, "NSW", "Broken Hill"), // just E of 141°E
            (-32.2569, 148.6011, "NSW", "Dubbo"),
            (-34.2891, 146.0378, "NSW", "Griffith"),
            (-35.5333, 144.9667, "NSW", "Deniliquin"), // N side of the Murray
            (-34.1050, 141.9186, "NSW", "Wentworth"),  // river-twin with Mildura (VIC)
            (-36.0737, 146.9135, "NSW", "Albury"),     // river-twin with Wodonga (VIC)
            // VIC — the gross-bug fix plus interior
            (-36.3805, 145.3980, "VIC", "Shepparton"), // was NSW (N Victoria)
            (-36.7570, 144.2794, "VIC", "Bendigo"),
            (-38.1499, 144.3617, "VIC", "Geelong"),
            (-36.3580, 146.3145, "VIC", "Wangaratta"),
            (-38.3810, 142.4870, "VIC", "Warrnambool"),
            (-34.1855, 142.1625, "VIC", "Mildura"), // river-twin with Wentworth (NSW)
            (-36.1214, 146.8881, "VIC", "Wodonga"), // river-twin with Albury (NSW)
            (-39.1300, 146.3700, "VIC", "Wilsons Promontory"), // S of −39, but not TAS
            // SA — both sides of 141°E and the 26°S parallel
            (-37.8284, 140.7807, "SA", "Mount Gambier"), // W of 141°E, S of VIC
            (-34.1745, 140.7458, "SA", "Renmark"),       // W of 141°E, Murray region
            (-32.4922, 137.7645, "SA", "Port Augusta"),
            (-29.0135, 134.7544, "SA", "Coober Pedy"), // S of 26°S in 129–138°E
            (-32.1264, 133.6772, "SA", "Ceduna"),
            // WA — the 129°E meridian
            (-30.7490, 121.4660, "WA", "Kalgoorlie"),
            (-17.9614, 122.2359, "WA", "Broome"),
            (-31.6774, 128.8853, "WA", "Eucla"), // just W of 129°E
            (-35.0270, 117.8837, "WA", "Albany"),
            // NT — N of 26°S in 129–138°E
            (-23.6980, 133.8807, "NT", "Alice Springs"),
            (-14.4650, 132.2635, "NT", "Katherine"),
            (-19.6480, 134.1870, "NT", "Tennant Creek"),
            // TAS — the island
            (-41.4332, 147.1441, "TAS", "Launceston"),
            (-41.1789, 146.3510, "TAS", "Devonport"),
            (-39.8700, 143.8700, "TAS", "King Island"),
        ];
        for &(lat, lon, want, name) in cases {
            assert_eq!(
                au_state_for_coords(lat, lon),
                Some(want),
                "{name} ({lat}, {lon}) should be {want}"
            );
        }
    }

    #[test]
    fn nearest_au_locality_labels_capitals_and_rejects_foreign() {
        let (name, state, km) = nearest_au_locality(-27.47, 153.02).expect("should succeed");
        assert_eq!((name, state), ("Brisbane", "QLD"));
        assert!(km < 5.0, "Brisbane CBD within 5km of the anchor, got {km}");
        // A regional fix resolves to its nearest centre.
        let (name, state, _) = nearest_au_locality(-26.729, 152.7554).expect("should succeed");
        assert_eq!((name, state), ("Maleny", "QLD"));
        // Perth.
        assert_eq!(nearest_au_locality(-31.95, 115.86).map(|(n, s, _)| (n, s)), Some(("Perth", "WA")));
        // Outside Australia → None.
        assert!(nearest_au_locality(40.71, -74.0).is_none()); // New York
        assert!(nearest_au_locality(-36.8485, 174.7633).is_none()); // Auckland
        // Metro suburb anchors sharpen a fix below city grain: a Parramatta
        // coordinate resolves to Parramatta, not "Sydney".
        assert_eq!(
            nearest_au_locality(-33.8150, 151.0011).map(|(n, s, _)| (n, s)),
            Some(("Parramatta", "NSW"))
        );
        // Regional/outer anchors: a Caboolture fix resolves to Caboolture, not
        // "Brisbane"; a Maitland fix to Maitland, not "Newcastle".
        assert_eq!(
            nearest_au_locality(-27.0850, 152.9510).map(|(n, s, _)| (n, s)),
            Some(("Caboolture", "QLD"))
        );
        assert_eq!(
            nearest_au_locality(-32.7316, 151.5566).map(|(n, s, _)| (n, s)),
            Some(("Maitland", "NSW"))
        );
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
    fn tag_flags_raises_only_explicit_true_signals() {
        use crate::core::entity::{Entity, EntityKind};
        let mut e = Entity::new(EntityKind::IpAddress, "203.0.113.7", 0.9, "scan-x");
        tag_flags(
            &mut e,
            &[
                (Some(true), "proxy"),    // explicit true → raised
                (Some(false), "hosting"), // reported false → skipped
                (None, "mobile"),         // not reported → skipped
                (Some(true), "vpn"),      // explicit true → raised
            ],
        );
        assert!(e.has_tag("proxy"));
        assert!(e.has_tag("vpn"));
        // A false or absent signal must never accrete a tag — the property the
        // three IP-reputation modules relied on when each hand-rolled this sweep.
        assert!(!e.has_tag("hosting"));
        assert!(!e.has_tag("mobile"));
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
