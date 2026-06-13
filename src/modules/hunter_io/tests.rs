use super::*;

    #[test]
    fn accepts_domain_only() {
        let m = HunterIo;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn cost_is_key_gated() {
        assert_eq!(HunterIo.cost(), ModuleCost::KeyGated);
    }

    #[test]
    fn category_is_email() {
        assert!(matches!(HunterIo.category(), ModuleCategory::Email));
    }

    #[test]
    fn description_is_non_empty() {
        assert!(!HunterIo.description().is_empty());
    }

    #[test]
    fn produces_email_person_organisation() {
        let kinds = HunterIo.produces();
        assert!(kinds.contains(&EntityKind::Email));
        assert!(kinds.contains(&EntityKind::Person));
        assert!(kinds.contains(&EntityKind::Organisation));
    }

    #[test]
    fn confidence_mapping_for_hunter_confidence_score() {
        // Drive the public helper so the test catches threshold drift
        // (previously the test re-implemented the match arms and
        // asserted against its own copy).
        let cases: [(Option<u8>, f64); 7] = [
            (Some(95), 0.85),
            (Some(75), 0.70),
            (Some(50), 0.55),
            (Some(20), 0.45),
            (Some(1), 0.45),
            (Some(0), 0.50), // explicit 0 collapses to unknown floor
            (None, 0.50),
        ];
        for (input, expected) in cases {
            let got = confidence_from_hunter_score(input);
            assert!(
                (got - expected).abs() < f64::EPSILON,
                "confidence {input:?} → {got} (expected {expected})"
            );
        }
    }
