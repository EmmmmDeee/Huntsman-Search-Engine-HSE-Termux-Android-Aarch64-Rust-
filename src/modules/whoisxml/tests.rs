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
    }
