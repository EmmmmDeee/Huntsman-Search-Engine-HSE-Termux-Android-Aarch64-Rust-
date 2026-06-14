use super::*;

    #[test]
    fn au_telstra_prefix() {
        let c = identify_carrier("61412345678").unwrap();
        assert_eq!(c.carrier, "Telstra");
        assert_eq!(c.country, "Australia");
    }

    #[test]
    fn au_optus_prefix() {
        let c = identify_carrier("61431234567").unwrap();
        assert_eq!(c.carrier, "Optus");
    }

    #[test]
    fn au_vodafone_prefix() {
        let c = identify_carrier("61420123456").unwrap();
        assert_eq!(c.carrier, "Vodafone");
    }

    #[test]
    fn uk_ee_prefix() {
        let c = identify_carrier("447400123456").unwrap();
        assert_eq!(c.carrier, "EE");
        assert_eq!(c.country, "United Kingdom");
    }

    #[test]
    fn unknown_prefix_returns_none() {
        assert!(identify_carrier("99912345678").is_none());
    }

    #[test]
    fn too_short_returns_none() {
        assert!(identify_carrier("6141").is_none());
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = PhoneCarrierGeo;
        assert!(m.is_passive());
        assert!(m.accepts(&Target::new(TargetKind::Phone, "+61412345678")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }
