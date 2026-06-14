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
    fn postcode_in_address_string_also_resolves() {
        // When city_coords is called with "Brisbane, QLD 4000" the city name
        // matches before postcode fallback even fires.
        assert!(city_coords("Brisbane, QLD 4000").is_some());
    }
