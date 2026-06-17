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

    #[test]
    fn au_carrier_maps_prefixes_with_full_fields() {
        let telstra = au_carrier("400").unwrap();
        assert_eq!(telstra.carrier, "Telstra");
        assert_eq!(telstra.country, "Australia");
        assert_eq!(telstra.confidence, 0.42);
        assert_eq!(telstra.network_hint, "dominant_rural_regional");

        let vodafone = au_carrier("420").unwrap();
        assert_eq!(vodafone.carrier, "Vodafone");
        assert_eq!(vodafone.network_hint, "metro_only");

        let optus = au_carrier("430").unwrap();
        assert_eq!(optus.carrier, "Optus");
        assert_eq!(optus.network_hint, "metro_suburban");

        let mvno = au_carrier("450").unwrap();
        assert_eq!(mvno.carrier, "Pivotel/MVNOs");
        assert_eq!(mvno.network_hint, "mvno");
    }

    #[test]
    fn au_carrier_unknown_prefix_is_none() {
        assert!(au_carrier("999").is_none());
    }

    #[test]
    fn uk_carrier_maps_prefixes_with_full_fields() {
        let ee = uk_carrier("7400").unwrap();
        assert_eq!(ee.carrier, "EE");
        assert_eq!(ee.country, "United Kingdom");
        assert_eq!(ee.confidence, 0.40);
        assert_eq!(ee.network_hint, "mobile");

        assert_eq!(uk_carrier("7410").unwrap().carrier, "Vodafone UK");
        assert_eq!(uk_carrier("7420").unwrap().carrier, "Three UK");
        assert_eq!(uk_carrier("7450").unwrap().carrier, "O2 UK");
    }

    #[test]
    fn uk_carrier_unknown_prefix_is_none() {
        assert!(uk_carrier("9999").is_none());
    }
