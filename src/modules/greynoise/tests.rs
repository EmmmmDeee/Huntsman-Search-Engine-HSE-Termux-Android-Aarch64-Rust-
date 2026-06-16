use super::*;

    #[test]
    fn accepts_ip_only() {
        let m = GreyNoise;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Username, "user")));
    }

    #[test]
    fn module_metadata() {
        let m = GreyNoise;
        assert_eq!(m.name(), "greynoise");
        assert_eq!(m.priority(), 30);
        assert_eq!(
            m.description(),
            "GreyNoise IP reputation: internet noise and RIOT classification"
        );
        // Free, community tier — no API key required.
        assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    }

    #[test]
    fn response_deserialization_full() {
        let json = r#"{
            "ip": "8.8.8.8",
            "noise": true,
            "riot": true,
            "classification": "benign",
            "name": "Google Public DNS",
            "link": "https://viz.greynoise.io/ip/8.8.8.8",
            "message": "Success"
        }"#;
        let resp: CommunityResp = serde_json::from_str(json).unwrap();
        assert_eq!(resp.ip.as_deref(), Some("8.8.8.8"));
        assert!(resp.noise);
        assert!(resp.riot);
        assert_eq!(resp.classification.as_deref(), Some("benign"));
        assert_eq!(resp.name.as_deref(), Some("Google Public DNS"));
        assert_eq!(
            resp.link.as_deref(),
            Some("https://viz.greynoise.io/ip/8.8.8.8")
        );
    }

    #[test]
    fn response_deserialization_minimal() {
        // GreyNoise returns a minimal body for IPs not in its dataset.
        let json = r#"{
            "ip": "192.168.1.1",
            "noise": false,
            "riot": false,
            "message": "IP not observed scanning the internet or contained in RIOT data set."
        }"#;
        let resp: CommunityResp = serde_json::from_str(json).unwrap();
        assert!(!resp.noise);
        assert!(!resp.riot);
        assert!(resp.classification.is_none());
        assert!(resp.name.is_none());
        assert!(resp.link.is_none());
    }

    #[test]
    fn response_deserialization_malicious() {
        let json = r#"{
            "ip": "71.6.135.131",
            "noise": true,
            "riot": false,
            "classification": "malicious",
            "name": "unknown",
            "link": "https://viz.greynoise.io/ip/71.6.135.131"
        }"#;
        let resp: CommunityResp = serde_json::from_str(json).unwrap();
        assert!(resp.noise);
        assert!(!resp.riot);
        assert_eq!(resp.classification.as_deref(), Some("malicious"));
    }

    // ── build_entities tests ──────────────────────────────────────

    #[test]
    fn build_entities_benign_with_operator() {
        let data = CommunityResp {
            ip: Some("8.8.8.8".into()),
            noise: true,
            riot: true,
            classification: Some("benign".into()),
            name: Some("Google Public DNS".into()),
            link: Some("https://viz.greynoise.io/ip/8.8.8.8".into()),
            message: Some("Success".into()),
        };
        let entities = build_entities(&data, "8.8.8.8", "scan-1");

        // Should produce IpAddress + Organisation.
        assert_eq!(entities.len(), 2);

        let ip_ent = &entities[0];
        assert_eq!(ip_ent.kind, EntityKind::IpAddress);
        assert_eq!(ip_ent.value, "8.8.8.8");
        assert!((ip_ent.confidence - 0.70).abs() < f64::EPSILON);
        assert!(ip_ent.tags.iter().any(|t| t == "greynoise-noise"));
        assert!(ip_ent.tags.iter().any(|t| t == "greynoise-riot"));
        assert!(ip_ent.tags.iter().any(|t| t == "greynoise-benign"));

        // Evidence should contain queried_ip, link, and message.
        let ev = &ip_ent.evidence[0];
        assert_eq!(
            ev.attributes.get("queried_ip").map(String::as_str),
            Some("8.8.8.8")
        );
        assert_eq!(
            ev.attributes.get("link").map(String::as_str),
            Some("https://viz.greynoise.io/ip/8.8.8.8")
        );
        assert_eq!(
            ev.attributes.get("message").map(String::as_str),
            Some("Success")
        );

        let org = &entities[1];
        assert_eq!(org.kind, EntityKind::Organisation);
        assert_eq!(org.value, "Google Public DNS");
        assert!(org.tags.iter().any(|t| t == "ip-operator"));
    }

    #[test]
    fn build_entities_malicious_no_org_for_unknown_name() {
        let data = CommunityResp {
            ip: Some("71.6.135.131".into()),
            noise: true,
            riot: false,
            classification: Some("malicious".into()),
            name: Some("unknown".into()),
            link: Some("https://viz.greynoise.io/ip/71.6.135.131".into()),
            message: None,
        };
        let entities = build_entities(&data, "71.6.135.131", "scan-2");

        // "unknown" name must not produce an Organisation pivot.
        assert_eq!(entities.len(), 1);
        let ip_ent = &entities[0];
        assert_eq!(ip_ent.kind, EntityKind::IpAddress);
        assert!((ip_ent.confidence - 0.80).abs() < f64::EPSILON);
        assert!(ip_ent.tags.iter().any(|t| t == "malicious"));
        assert!(ip_ent.tags.iter().any(|t| t == "greynoise-malicious"));
        assert!(ip_ent.tags.iter().any(|t| t == "greynoise-noise"));
    }

    #[test]
    fn build_entities_unknown_classification() {
        let data = CommunityResp {
            ip: None,
            noise: false,
            riot: false,
            classification: Some("unknown".into()),
            name: None,
            link: None,
            message: Some("No data".into()),
        };
        let entities = build_entities(&data, "1.2.3.4", "scan-3");

        assert_eq!(entities.len(), 1);
        let ip_ent = &entities[0];
        assert!((ip_ent.confidence - 0.55).abs() < f64::EPSILON);
        assert!(ip_ent.tags.iter().any(|t| t == "greynoise-unknown"));

        // message should still appear in evidence; queried_ip absent when None.
        let ev = &ip_ent.evidence[0];
        assert_eq!(
            ev.attributes.get("message").map(String::as_str),
            Some("No data")
        );
        assert!(!ev.attributes.contains_key("queried_ip"));
    }
