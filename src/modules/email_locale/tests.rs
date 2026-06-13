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

    #[tokio::test]
    async fn module_metadata() {
        let m = EmailLocale;
        assert!(m.is_passive());
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Phone, "+61400000000")));
    }
