use super::*;

    #[test]
    fn accepts_domain_only() {
        let m = WhoisXml;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn cost_is_key_gated() {
        assert_eq!(WhoisXml.cost(), ModuleCost::KeyGated);
    }

    #[test]
    fn category_is_dns_recon() {
        assert!(matches!(WhoisXml.category(), ModuleCategory::DnsRecon));
    }

    #[test]
    fn description_is_non_empty() {
        assert!(!WhoisXml.description().is_empty());
    }

    #[test]
    fn produces_includes_registrant_kinds() {
        let kinds = WhoisXml.produces();
        assert!(kinds.contains(&EntityKind::Email));
        assert!(kinds.contains(&EntityKind::Person));
        assert!(kinds.contains(&EntityKind::Organisation));
        assert!(kinds.contains(&EntityKind::Domain));
        assert!(kinds.contains(&EntityKind::Address));
    }

    fn record(json: &str) -> WhoisRecord {
        serde_json::from_str(json).expect("valid WhoisRecord JSON")
    }

    fn values(es: &[Entity], kind: EntityKind) -> Vec<&str> {
        es.iter()
            .filter(|e| e.kind == kind)
            .map(|e| e.value.as_str())
            .collect()
    }

    #[test]
    fn build_entities_dedups_identical_contacts_across_roles() {
        // The common case: registrant == admin == technical (one privacy proxy).
        let rec = record(
            r#"{
                "registrant":            {"name": "Jane Roe", "organization": "Acme Pty Ltd", "email": "jane@acme.com"},
                "administrativeContact": {"name": "Jane Roe", "organization": "Acme Pty Ltd", "email": "jane@acme.com"},
                "technicalContact":      {"name": "Jane Roe", "organization": "Acme Pty Ltd", "email": "jane@acme.com"}
            }"#,
        );
        let es = build_entities(&rec, "acme.com", "t");
        // One node each, not three.
        assert_eq!(values(&es, EntityKind::Person), vec!["Jane Roe"]);
        assert_eq!(values(&es, EntityKind::Organisation), vec!["Acme Pty Ltd"]);
        assert_eq!(values(&es, EntityKind::Email), vec!["jane@acme.com"]);
        // The kept node carries the highest-priority role (registrant).
        let person = es.iter().find(|e| e.kind == EntityKind::Person).unwrap();
        assert!(person.tags.iter().any(|t| t == "whois-registrant"));
    }

    #[test]
    fn build_entities_surfaces_registered_domain_pivot_when_it_differs() {
        let rec = record(r#"{ "domainName": "acme.com" }"#);
        // Queried a subdomain; registry holds the parent → pivot.
        let es = build_entities(&rec, "shop.acme.com", "t");
        assert_eq!(values(&es, EntityKind::Domain), vec!["acme.com"]);
        let dom = es.iter().find(|e| e.kind == EntityKind::Domain).unwrap();
        assert!(dom.tags.iter().any(|t| t == "registered-domain"));
    }

    #[test]
    fn build_entities_no_domain_pivot_when_registered_equals_queried() {
        // Case-insensitive + trailing-dot tolerant: no redundant self-pivot.
        let rec = record(r#"{ "domainName": "ACME.com." }"#);
        let es = build_entities(&rec, "acme.com", "t");
        assert!(values(&es, EntityKind::Domain).is_empty());
    }

    #[test]
    fn build_entities_emits_registrant_location_geo_hint() {
        let rec = record(
            r#"{ "registrant": {"name": "Jane Roe", "state": "Queensland", "country": "Australia"} }"#,
        );
        let es = build_entities(&rec, "acme.com", "t");
        let addr = es
            .iter()
            .find(|e| e.kind == EntityKind::Address)
            .expect("address geo-hint");
        assert_eq!(addr.value, "Queensland, Australia");
        assert!(addr.tags.iter().any(|t| t == "geo-hint"));
    }

    #[test]
    fn build_entities_emits_nameservers_deduped() {
        let rec = record(
            r#"{ "nameServers": {"hostNames": ["ns1.acme.com", "NS1.ACME.COM.", "ns2.acme.com"]} }"#,
        );
        let es = build_entities(&rec, "acme.com", "t");
        let ns: Vec<&str> = es
            .iter()
            .filter(|e| e.kind == EntityKind::Domain && e.tags.iter().any(|t| t == "nameserver"))
            .map(|e| e.value.as_str())
            .collect();
        assert_eq!(ns, vec!["ns1.acme.com", "ns2.acme.com"]);
    }

    #[test]
    fn build_entities_skips_redacted_empty_contacts() {
        // All-empty contact fields produce no entities (no blank nodes).
        let rec = record(r#"{ "registrant": {"name": "", "organization": "  ", "email": ""} }"#);
        let es = build_entities(&rec, "acme.com", "t");
        assert!(es.is_empty());
    }

    #[test]
    fn nonempty_trims_and_drops_blank() {
        assert_eq!(nonempty(&Some("x".to_string())).as_deref(), Some("x"));
        // Surrounding whitespace is trimmed off.
        assert_eq!(
            nonempty(&Some("  hi  ".to_string())).as_deref(),
            Some("hi")
        );
        // Empty / whitespace-only → None.
        assert_eq!(nonempty(&Some(String::new())), None);
        assert_eq!(nonempty(&Some("   ".to_string())), None);
        // None → None.
        assert_eq!(nonempty(&None), None);
    }

    #[test]
    fn contact_location_composes_state_and_country() {
        // State + country → "State, Country".
        let both = Contact {
            state: Some("Queensland".to_string()),
            country: Some("Australia".to_string()),
            ..Default::default()
        };
        assert_eq!(
            contact_location(&both).as_deref(),
            Some("Queensland, Australia")
        );
        // Country only → "Country".
        let country_only = Contact {
            country: Some("Australia".to_string()),
            ..Default::default()
        };
        assert_eq!(contact_location(&country_only).as_deref(), Some("Australia"));
        // State only → "State".
        let state_only = Contact {
            state: Some("Queensland".to_string()),
            ..Default::default()
        };
        assert_eq!(contact_location(&state_only).as_deref(), Some("Queensland"));
        // Neither (and blanks are dropped by nonempty) → None.
        let neither = Contact {
            state: Some("  ".to_string()),
            ..Default::default()
        };
        assert_eq!(contact_location(&neither), None);
        assert_eq!(contact_location(&Contact::default()), None);
    }
