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

    fn data(json: &str) -> HunterData {
        serde_json::from_str(json).expect("valid HunterData JSON")
    }

    fn emails_of(es: &[Entity], kind: EntityKind) -> Vec<&str> {
        es.iter()
            .filter(|e| e.kind == kind)
            .map(|e| e.value.as_str())
            .collect()
    }

    #[test]
    fn apply_email_pattern_renders_token_forms() {
        // Full-name + initial token combinations, with separators preserved.
        assert_eq!(
            apply_email_pattern("{first}.{last}", "Jane", "Doe", "acme.com").as_deref(),
            Some("jane.doe@acme.com")
        );
        assert_eq!(
            apply_email_pattern("{f}{last}", "Jane", "Doe", "acme.com").as_deref(),
            Some("jdoe@acme.com")
        );
        assert_eq!(
            apply_email_pattern("{first}{l}", "Jane", "Doe", "acme.com").as_deref(),
            Some("janed@acme.com")
        );
        assert_eq!(
            apply_email_pattern("{f}.{l}", "Jane", "Doe", "acme.com").as_deref(),
            Some("j.d@acme.com")
        );
        assert_eq!(
            apply_email_pattern("{first}", "Jane", "Doe", "acme.com").as_deref(),
            Some("jane@acme.com")
        );
        // A leading "@" on the domain is tolerated.
        assert_eq!(
            apply_email_pattern("{first}_{last}", "Jane", "Doe", "@acme.com").as_deref(),
            Some("jane_doe@acme.com")
        );
    }

    #[test]
    fn apply_email_pattern_refuses_when_a_required_part_is_missing() {
        // Pattern needs a last name we don't have → no malformed "jane.@...".
        assert_eq!(apply_email_pattern("{first}.{last}", "Jane", "", "acme.com"), None);
        // Needs a first initial we don't have.
        assert_eq!(apply_email_pattern("{f}{last}", "", "Doe", "acme.com"), None);
        // Empty domain or empty pattern.
        assert_eq!(apply_email_pattern("{first}", "Jane", "Doe", ""), None);
        assert_eq!(apply_email_pattern("", "Jane", "Doe", "acme.com"), None);
        // A pattern needing only the first name still renders when last is absent.
        assert_eq!(
            apply_email_pattern("{first}", "Jane", "", "acme.com").as_deref(),
            Some("jane@acme.com")
        );
    }

    #[test]
    fn build_entities_real_email_maps_value_and_person() {
        let d = data(
            r#"{
                "organization": "Acme",
                "country": "US",
                "pattern": "{first}.{last}",
                "emails": [
                    {"value": "jane.doe@acme.com", "confidence": 95,
                     "first_name": "Jane", "last_name": "Doe", "position": "CTO"}
                ]
            }"#,
        );
        let es = build_entities(&d, "acme.com", "t");
        // Verified address keeps its mapped (high) confidence and is NOT a weak lead.
        let email = es
            .iter()
            .find(|e| e.kind == EntityKind::Email)
            .expect("email entity");
        assert_eq!(email.value, "jane.doe@acme.com");
        assert!((email.confidence - 0.85).abs() < f64::EPSILON);
        assert!(!email.tags.iter().any(|t| t == "email-pattern-synthesised"));
        // Person co-located.
        assert!(emails_of(&es, EntityKind::Person).contains(&"Jane Doe"));
        // Organisation surfaced.
        assert!(emails_of(&es, EntityKind::Organisation).contains(&"Acme"));
    }

    #[test]
    fn build_entities_surfaces_canonical_domain_pivot() {
        let d = data(r#"{ "domain": "acme.io", "organization": "Acme" }"#);
        let es = build_entities(&d, "acme.com", "t");
        let dom = es
            .iter()
            .find(|e| e.kind == EntityKind::Domain)
            .expect("canonical domain entity");
        assert_eq!(dom.value, "acme.io");
        assert!(dom.tags.iter().any(|t| t == "org-domain"));
    }

    #[test]
    fn build_entities_emits_all_source_pivots() {
        let d = data(
            r#"{
                "emails": [{
                    "value": "j@acme.com", "confidence": 80,
                    "sources": [
                        {"uri": "https://a.example/team", "domain": "a.example"},
                        {"uri": "https://b.example/about", "domain": "b.example"}
                    ]
                }]
            }"#,
        );
        let es = build_entities(&d, "acme.com", "t");
        let urls = emails_of(&es, EntityKind::Url);
        // BOTH sources surface as Url pivots — not just the first.
        assert!(urls.contains(&"https://a.example/team"));
        assert!(urls.contains(&"https://b.example/about"));
        let doms = emails_of(&es, EntityKind::Domain);
        assert!(doms.contains(&"a.example"));
        assert!(doms.contains(&"b.example"));
    }

    #[test]
    fn build_entities_synthesises_email_when_value_missing() {
        let d = data(
            r#"{
                "domain": "acme.io",
                "pattern": "{first}.{last}",
                "emails": [
                    {"first_name": "Mary", "last_name": "Sue", "position": "VP"}
                ]
            }"#,
        );
        let es = build_entities(&d, "acme.com", "t");
        let email = es
            .iter()
            .find(|e| e.kind == EntityKind::Email)
            .expect("synthesised email");
        // Synthesised against Hunter's CANONICAL domain, low confidence, weak lead.
        assert_eq!(email.value, "mary.sue@acme.io");
        assert!((email.confidence - 0.40).abs() < f64::EPSILON);
        assert!(email.tags.iter().any(|t| t == "email-pattern-synthesised"));
        assert!(email.tags.iter().any(|t| t == "weak-lead"));
        // Still attributes the person.
        assert!(emails_of(&es, EntityKind::Person).contains(&"Mary Sue"));
    }

    #[test]
    fn build_entities_no_synthesis_without_pattern_or_name() {
        // Name present but no pattern → nothing to synthesise from.
        let d = data(r#"{ "emails": [{"first_name": "Mary", "last_name": "Sue"}] }"#);
        let es = build_entities(&d, "acme.com", "t");
        assert!(emails_of(&es, EntityKind::Email).is_empty());
    }

    #[test]
    fn build_entities_dedups_repeated_sources() {
        let d = data(
            r#"{
                "emails": [
                    {"value": "a@acme.com", "sources": [{"uri": "https://x.example", "domain": "x.example"}]},
                    {"value": "b@acme.com", "sources": [{"uri": "https://x.example", "domain": "x.example"}]}
                ]
            }"#,
        );
        let es = build_entities(&d, "acme.com", "t");
        // The shared source URL/domain is emitted once, not per email.
        assert_eq!(emails_of(&es, EntityKind::Url).len(), 1);
        assert_eq!(
            emails_of(&es, EntityKind::Domain)
                .iter()
                .filter(|d| **d == "x.example")
                .count(),
            1
        );
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
