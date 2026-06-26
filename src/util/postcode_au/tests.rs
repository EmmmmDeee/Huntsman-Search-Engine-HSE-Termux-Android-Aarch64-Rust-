use super::*;

    #[test]
    fn parses_real_4552_payload() {
        // Trimmed-but-faithful Zippopotam response for AU 4552.
        let raw = r#"{
            "post code": "4552", "country": "Australia", "country abbreviation": "AU",
            "places": [
                {"place name": "Maleny", "longitude": "152.7554", "state": "Queensland", "state abbreviation": "QLD", "latitude": "-26.729"},
                {"place name": "Booroobin", "longitude": "152.7554", "state": "Queensland", "state abbreviation": "QLD", "latitude": "-26.729"},
                {"place name": "Conondale", "longitude": "152.7167", "state": "Queensland", "state abbreviation": "QLD", "latitude": "-26.7333"}
            ]
        }"#;
        let locs = parse(raw);
        assert_eq!(locs.len(), 3);
        assert_eq!(locs[0].suburb, "Maleny");
        assert!((locs[0].lat - -26.729).abs() < 1e-6);
        assert!((locs[0].lon - 152.7554).abs() < 1e-6);
        // The user's home locality is enumerated within 4552.
        assert!(locs.iter().any(|l| l.suburb == "Booroobin"));
        // Conondale has its own distinct centroid.
        assert!((locs[2].lat - -26.7333).abs() < 1e-6);
    }

    #[test]
    fn offline_fallback_keeps_validated_4552_geo() {
        // When the network gazetteer is unreachable, the ground-truth-confirmed
        // Sunshine Coast hinterland localities must still resolve (Maleny,
        // Booroobin, Conondale) so an operator's accurate geo survives offline.
        let locs = offline_fallback("4552");
        assert_eq!(locs.len(), 3);
        assert!(locs.iter().any(|l| l.suburb == "Maleny"));
        assert!(locs.iter().any(|l| l.suburb == "Booroobin"));
        assert!(locs.iter().any(|l| l.suburb == "Conondale"));
        // Centroids match the online Zippopotam values (offline == online).
        let maleny = locs.iter().find(|l| l.suburb == "Maleny").unwrap();
        assert!((maleny.lat - -26.729).abs() < 1e-6 && (maleny.lon - 152.7554).abs() < 1e-6);
        // Capital city postcodes now resolve offline.
        assert!(!offline_fallback("2000").is_empty());
        assert!(!offline_fallback("3000").is_empty());
        // Unknown postcodes stay empty → caller degrades to the bare postcode.
        assert!(offline_fallback("9999").is_empty());
    }

    #[test]
    fn regional_centres_resolve_in_bounds_and_to_the_right_state() {
        // Guards the regional-city additions against a transposed coordinate or a
        // mistyped postcode: every entry must resolve to a centroid inside the AU
        // bounding box AND to the state its postcode range implies
        // (`state_for_postcode`, the independent leading-digit classifier). A
        // coordinate dropped into the wrong hemisphere or a postcode assigned to
        // the wrong state fails here rather than silently shipping a bad fix.
        let cases: &[(&str, &str)] = &[
            ("2300", "NSW"), // Newcastle
            ("2500", "NSW"), // Wollongong
            ("2650", "NSW"), // Wagga Wagga
            ("2640", "NSW"), // Albury
            ("2340", "NSW"), // Tamworth
            ("2830", "NSW"), // Dubbo
            ("2800", "NSW"), // Orange
            ("2795", "NSW"), // Bathurst
            ("3220", "VIC"), // Geelong
            ("3630", "VIC"), // Shepparton
            ("4700", "QLD"), // Rockhampton
            ("4740", "QLD"), // Mackay
            ("4670", "QLD"), // Bundaberg
            ("4655", "QLD"), // Hervey Bay
            ("5290", "SA"),  // Mount Gambier
            ("5700", "SA"),  // Port Augusta
            ("6210", "WA"),  // Mandurah
            ("6230", "WA"),  // Bunbury
            ("6330", "WA"),  // Albany
            ("6430", "WA"),  // Kalgoorlie
            ("6530", "WA"),  // Geraldton
            ("7310", "TAS"), // Devonport
            ("7320", "TAS"), // Burnie
            ("0870", "NT"),  // Alice Springs
        ];
        for &(pc, state) in cases {
            let (lat, lon) =
                offline_centroid(pc).unwrap_or_else(|| panic!("{pc} resolves to a centroid"));
            // Australian mainland + Tasmania bounding box.
            assert!(
                (-44.0..=-10.0).contains(&lat) && (112.0..=154.0).contains(&lon),
                "{pc} centroid ({lat},{lon}) is inside Australia"
            );
            assert_eq!(
                crate::util::address_au::state_for_postcode(pc),
                Some(state),
                "{pc} maps to its expected state"
            );
        }
    }

    #[test]
    fn parse_skips_blank_place_name() {
        // An entry with an empty place name must be skipped even if coords parse.
        let json = r#"{"places":[{"place name":"","latitude":"-27.5","longitude":"153.0"}]}"#;
        assert!(parse(json).is_empty());
    }

    #[test]
    fn tolerates_garbage_and_empty() {
        assert!(parse("not json").is_empty());
        assert!(parse(r#"{"places":[]}"#).is_empty());
        // Entry with unparseable coords is skipped, valid one kept.
        let mixed = r#"{"places":[
            {"place name":"Bad","latitude":"x","longitude":"y"},
            {"place name":"Good","latitude":"-27.5","longitude":"153.0"}
        ]}"#;
        let locs = parse(mixed);
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].suburb, "Good");
    }
