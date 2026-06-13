use super::*;

    #[test]
    fn accepts_email_only() {
        assert!(DisposableCheck.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(!DisposableCheck.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }

    #[test]
    fn cost_is_free() {
        assert!(matches!(
            DisposableCheck.cost(),
            crate::core::module::ModuleCost::Free
        ));
    }

    #[test]
    fn deser_keeps_stringly_typed_verdict() {
        let r: Resp = serde_json::from_str(r#"{"disposable":"true"}"#).unwrap();
        assert_eq!(r.disposable, "true");
    }

    #[test]
    fn verdict_parsing_is_affirmative_only_and_lenient() {
        assert!(is_disposable("true"));
        assert!(is_disposable("  TRUE \n"));
        assert!(is_disposable("True"));
        assert!(!is_disposable("false"));
        // Fail-open: an unexpected/garbage verdict is NOT branded disposable.
        assert!(!is_disposable(""));
        assert!(!is_disposable("yes"));
        assert!(!is_disposable("1"));
    }

    #[test]
    fn disposable_verdict_tags_and_collapses_confidence() {
        let e = build_email_entity("burner@mailinator.com", true, "s");
        assert_eq!(e.kind, EntityKind::Email);
        assert!(e.has_tag("email-validated") && e.has_tag("disposable"));
        assert!((e.confidence - DISPOSABLE_CONFIDENCE).abs() < 1e-9);
        let ev = &e.evidence[0];
        assert_eq!(
            ev.attributes.get("disposable").map(String::as_str),
            Some("true")
        );
        assert!(ev.summary.contains("disposable/throwaway"));
    }

    #[test]
    fn legit_verdict_validates_without_disposable_tag() {
        let e = build_email_entity("person@gmail.com", false, "s");
        assert!(e.has_tag("email-validated") && !e.has_tag("disposable"));
        assert!((e.confidence - LEGIT_CONFIDENCE).abs() < 1e-9);
        assert_eq!(
            e.evidence[0]
                .attributes
                .get("disposable")
                .map(String::as_str),
            Some("false")
        );
    }

    #[test]
    fn disposable_is_far_lower_confidence_than_legit() {
        // The whole point: a throwaway must not out-weigh a real address.
        let disp = build_email_entity("x@guerrillamail.com", true, "s");
        let legit = build_email_entity("x@outlook.com", false, "s");
        assert!(disp.confidence < legit.confidence);
    }
