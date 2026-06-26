use super::*;

    #[test]
    fn au_capitals_resolve() {
        assert!(city_coords("Brisbane, QLD").is_some());
        assert!(city_coords("Sydney NSW").is_some());
        assert!(city_coords("Darwin").is_some());
    }

    #[test]
    fn regional_au_resolves() {
        assert!(city_coords("Lockyer Valley").is_some());
        assert!(city_coords("Gatton, QLD").is_some());
        assert!(city_coords("Newcastle NSW").is_some());
    }

    #[test]
    fn international_resolves() {
        assert!(city_coords("Philadelphia").is_some());
        assert!(city_coords("Auckland").is_some());
        assert!(city_coords("London").is_some());
    }

    #[test]
    fn no_match_returns_none() {
        assert!(city_coords("Clobberville").is_none());
    }

    #[test]
    fn bare_postcode_resolves() {
        // Capital-city postcodes resolve via the fallback table.
        let (lat, lon) = city_coords("4000").unwrap();
        assert!((lat - -27.4698).abs() < 0.01);
        assert!((lon - 153.0251).abs() < 0.01);
        assert!(city_coords("3000").is_some());
        assert!(city_coords("2000").is_some());
    }

    #[test]
    fn unknown_postcode_returns_none() {
        assert!(city_coords("9999").is_none());
        assert!(postcode_coords("9999").is_none());
    }

    #[test]
    fn region_geocoder_covers_the_whole_au_postcode_space() {
        use crate::util::geohash::haversine_km;
        // The QLD family postcodes that aren't in the exact table still resolve to
        // their region — and to the RIGHT region relative to the subject's fix
        // near Woodford QLD (-26.82, 152.81).
        let (subj_lat, subj_lon) = (-26.815_f64, 152.814_f64);
        let near = |pc: &str| {
            let (la, lo) = au_postcode_region(pc).expect("AU postcode resolves to a region");
            haversine_km(la, lo, subj_lat, subj_lon)
        };
        // Sunshine Coast / Brisbane / Ipswich family → within ~150 km of subject.
        assert!(near("4518") < 150.0, "Beerwah (45xx) is in the subject's area");
        assert!(near("4169") < 150.0, "East Brisbane (41xx) is in the subject's area");
        assert!(near("4311") < 150.0, "Lower Lockyer (43xx) is in the subject's area");
        // Far North QLD and interstate are correctly far.
        assert!(near("4870") > 800.0, "Cairns (48xx) is far from the subject");
        assert!(near("2076") > 700.0, "Sydney (20xx) is interstate / far");

        // Every state prefix resolves; malformed input does not.
        for pc in ["2000", "3000", "5000", "6000", "7000", "0800"] {
            assert!(au_postcode_region(pc).is_some(), "{pc} resolves");
        }
        assert!(au_postcode_region("12").is_none());
        assert!(au_postcode_region("abcd").is_none());
    }

    #[test]
    fn postcode_in_address_string_also_resolves() {
        // When city_coords is called with "Brisbane, QLD 4000" the city name
        // matches before postcode fallback even fires.
        assert!(city_coords("Brisbane, QLD 4000").is_some());
    }

    #[test]
    fn embedded_postcode_resolves_when_suburb_is_untabulated() {
        use crate::util::geohash::haversine_km;
        // Maleny is NOT in CITIES, but its postcode 4552 IS in the exact table.
        // A full address string must still earn the suburb centroid offline.
        let (lat, lon) = city_coords("12 Smith St, Maleny QLD 4552")
            .expect("a postcode-bearing AU address resolves offline");
        // ~Maleny / Sunshine Coast hinterland (4552 centroid).
        assert!(haversine_km(lat, lon, -26.729, 152.7554) < 5.0);
    }

    #[test]
    fn trailing_street_number_is_not_mistaken_for_the_postcode() {
        // A 4-digit STREET number leads, the postcode trails. The last valid
        // token (4217 = Gold Coast) must win over the first (4000 = Brisbane).
        // Suburb deliberately untabulated so the postcode path is exercised.
        use crate::util::geohash::haversine_km;
        let (lat, lon) = city_coords("4000 Pacific Hwy, Tugun-Vista QLD 4217")
            .expect("address with a leading 4-digit street number still resolves");
        // Gold Coast region (42xx ≈ -28.01,153.40), NOT Brisbane (40xx ≈ -27.47).
        assert!(
            haversine_km(lat, lon, -28.01, 153.40) < haversine_km(lat, lon, -27.47, 153.03),
            "resolved to the trailing postcode 4217 (Gold Coast), not the street number 4000"
        );
    }

    #[test]
    fn embedded_long_tail_postcode_falls_back_to_region() {
        // A NSW north-coast suburb absent from CITIES and from the exact postcode
        // table still resolves to its REGION centroid via the leading two digits,
        // so it never silently drops out of the geo footprint.
        let (lat, _lon) = city_coords("3 Ocean Ave, Smalltown NSW 2470")
            .expect("an untabulated AU address still resolves at region grain");
        // 24xx → NSW north coast band (negative latitude, well south of the equator).
        assert!(lat < 0.0, "an AU region centroid is in the southern hemisphere");
    }

    #[test]
    fn non_au_address_with_no_postcode_still_none() {
        // No AU postcode, no tabulated city → still a clean miss (no false fix).
        assert!(city_coords("221B Baker Street, Clobberville").is_none());
    }

    #[test]
    fn consolidated_gazetteer_widens_exact_postcode_coverage() {
        use crate::util::geohash::haversine_km;
        // 7250 (Launceston) was NOT in the old 22-entry city_coords table, so it
        // used to resolve only to the coarse 72xx region centroid (~70 km away).
        // After delegating to the shared ground-truth gazetteer it resolves to
        // the EXACT Launceston centroid — proving the wider table is now in use.
        let (lat, lon) = postcode_coords("7250").expect("7250 is in the shared gazetteer");
        assert!(
            haversine_km(lat, lon, -41.4388, 147.1347) < 2.0,
            "7250 resolves to exact Launceston, not the region centroid"
        );
        // And it is meaningfully tighter than the region fallback for 72xx.
        let (rlat, rlon) = au_postcode_region("7250").unwrap();
        assert!(
            haversine_km(lat, lon, -41.4388, 147.1347)
                < haversine_km(rlat, rlon, -41.4388, 147.1347),
            "exact centroid beats the region centroid for a tabulated postcode"
        );
    }
