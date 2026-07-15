use super::*;

    #[test]
    fn swedish_surname() {
        let geo = detect_locale_from_local_part("erik.johansson").unwrap();
        assert!(geo.region.contains("Scandinavia"));
    }

    #[test]
    fn polish_surname() {
        let geo = detect_locale_from_local_part("jan.kowalczyk").unwrap();
        assert!(geo.region.contains("Poland"));
    }

    #[test]
    fn french_given_name() {
        let geo = detect_locale_from_local_part("guillaume.martin").unwrap();
        assert!(geo.region.contains("France"));
    }

    #[test]
    fn detection_is_case_insensitive() {
        // Local-part case isn't significant; a capitalised name (the common
        // `First.Last@` form) or an all-caps address must match the same as the
        // lowercase form — not silently miss.
        assert!(
            detect_locale_from_local_part("Guillaume.Martin")
                .unwrap()
                .region
                .contains("France")
        );
        assert!(
            detect_locale_from_local_part("ERIK.JOHANSSON")
                .unwrap()
                .region
                .contains("Scandinavia")
        );
    }

    #[test]
    fn generic_name_returns_none() {
        assert!(detect_locale_from_local_part("john.smith").is_none());
    }

    #[test]
    fn no_dot_returns_none() {
        assert!(detect_locale_from_local_part("johndoe").is_none());
    }

    #[test]
    fn ambiguous_cctld_locales_get_their_own_country_centroid() {
        // `es-mx`, `es-ar`, and `pt-br` are unambiguous ccTLD-derived signals
        // (.mx/.ar/.br) and must each resolve to their OWN national capital, not
        // be folded into the "parent language" country's centroid (Madrid /
        // Lisbon) — Mexico City is not Madrid, Buenos Aires is not Madrid, and
        // Brasília is not Lisbon.
        let (mx_lat, mx_lon) = locale_centroid("es-mx").unwrap();
        let (es_lat, es_lon) = locale_centroid("es").unwrap();
        assert!(
            (mx_lat - es_lat).abs() > 1.0 || (mx_lon - es_lon).abs() > 1.0,
            "es-mx must not resolve to Spain's centroid: got ({mx_lat}, {mx_lon})"
        );
        assert!(
            (mx_lat - 19.4326).abs() < 0.01 && (mx_lon - (-99.1332)).abs() < 0.01,
            "es-mx must resolve to Mexico City: got ({mx_lat}, {mx_lon})"
        );

        let (ar_lat, ar_lon) = locale_centroid("es-ar").unwrap();
        assert!(
            (ar_lat - es_lat).abs() > 1.0 || (ar_lon - es_lon).abs() > 1.0,
            "es-ar must not resolve to Spain's centroid: got ({ar_lat}, {ar_lon})"
        );
        assert!(
            (ar_lat - (-34.6037)).abs() < 0.01 && (ar_lon - (-58.3816)).abs() < 0.01,
            "es-ar must resolve to Buenos Aires: got ({ar_lat}, {ar_lon})"
        );

        let (br_lat, br_lon) = locale_centroid("pt-br").unwrap();
        let (pt_lat, pt_lon) = locale_centroid("pt").unwrap();
        assert!(
            (br_lat - pt_lat).abs() > 1.0 || (br_lon - pt_lon).abs() > 1.0,
            "pt-br must not resolve to Portugal's centroid: got ({br_lat}, {br_lon})"
        );
        assert!(
            (br_lat - (-15.7939)).abs() < 0.01 && (br_lon - (-47.8827)).abs() < 0.01,
            "pt-br must resolve to Brasília: got ({br_lat}, {br_lon})"
        );
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = EmailLocale;
        assert!(m.is_passive());
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Phone, "+61400000000")));
    }
