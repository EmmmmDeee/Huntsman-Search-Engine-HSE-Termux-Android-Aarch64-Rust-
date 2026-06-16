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
