use super::*;

    fn fixture() -> FcResp {
        let json = serde_json::json!({
            "fullName": "Jordan Avery",
            "location": "Brisbane, Queensland, Australia",
            "title": "Engineer",
            "organization": "Acme Pty Ltd",
            "details": {
                "locations": [{ "formatted": "Brisbane, QLD, AU" }],
                "employment": [{ "name": "Acme Pty Ltd" }, { "name": "Globex" }],
                "profiles": {
                    "twitter": { "username": "mattd", "url": "https://twitter.com/mattd" },
                    "linkedin": { "username": "matthew-avery", "url": "https://linkedin.com/in/matthew-avery" }
                }
            }
        });
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn build_entities_resolves_the_identity_graph() {
        let r = fixture();
        let es = build_entities(&r, "scan");
        let has = |k: EntityKind, v: &str| es.iter().any(|e| e.kind == k && e.value == v);
        assert!(has(EntityKind::Person, "Jordan Avery"));
        assert!(has(EntityKind::Organisation, "Acme Pty Ltd"));
        assert!(has(EntityKind::Organisation, "Globex"));
        assert!(has(EntityKind::Address, "Brisbane, Queensland, Australia"));
        assert!(has(EntityKind::Username, "twitter:mattd"));
        assert!(has(EntityKind::Username, "linkedin:matthew-avery"));
        assert!(has(
            EntityKind::Url,
            "https://linkedin.com/in/matthew-avery"
        ));
        // Every entity carries the source tag.
        assert!(es.iter().all(|e| e.has_tag("fullcontact")));
        // Current employer outranks historical.
        let acme = es.iter().find(|e| e.value == "Acme Pty Ltd").unwrap();
        let globex = es.iter().find(|e| e.value == "Globex").unwrap();
        assert!(acme.confidence > globex.confidence);
    }

    #[test]
    fn build_entities_is_quiet_on_empty_response() {
        assert!(build_entities(&FcResp::default(), "scan").is_empty());
    }

    #[test]
    fn metadata_is_keygated_people() {
        let m = FullContact;
        assert_eq!(m.cost(), ModuleCost::KeyGated);
        assert_eq!(m.category(), ModuleCategory::People);
        assert!(m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(m.accepts(&Target::new(TargetKind::Phone, "+61400000000")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }
