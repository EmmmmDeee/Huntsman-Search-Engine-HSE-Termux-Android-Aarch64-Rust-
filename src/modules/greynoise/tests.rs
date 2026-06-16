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
        assert!(resp.noise);
        assert!(resp.riot);
        assert_eq!(resp.classification.as_deref(), Some("benign"));
        assert_eq!(resp.name.as_deref(), Some("Google Public DNS"));
        assert_eq!(
            resp.link.as_deref(),
            Some("https://viz.greynoise.io/ip/8.8.8.8")
        );
        assert_eq!(resp.message.as_deref(), Some("Success"));
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
