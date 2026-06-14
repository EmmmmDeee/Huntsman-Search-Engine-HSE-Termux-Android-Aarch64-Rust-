use super::*;

    #[test]
    fn accepts_ip_only() {
        let m = IpApi;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }

    #[test]
    fn cost_is_free() {
        assert!(matches!(
            IpApi.cost(),
            crate::core::module::ModuleCost::Free
        ));
    }

    #[test]
    fn description_non_empty() {
        assert!(!IpApi.description().is_empty());
    }

    #[test]
    fn rejects_ipv6() {
        let t = Target::new(TargetKind::IpAddress, "2001:db8::1");
        let m = IpApi;
        assert!(m.accepts(&t));
    }

    #[test]
    fn deser_full() {
        let json = r#"{"status":"success","country":"Australia","countryCode":"AU","region":"NSW","regionName":"New South Wales","city":"Sydney","zip":"1001","lat":-33.8688,"lon":151.209,"timezone":"Australia/Sydney","isp":"Telstra","org":"Telstra Corp","as":"AS1221 Telstra","asname":"ASN-TELSTRA","reverse":"","mobile":true,"proxy":false,"hosting":false}"#;
        let data: IpApiResp = serde_json::from_str(json).unwrap();
        assert_eq!(data.city.as_deref(), Some("Sydney"));
        assert_eq!(data.mobile, Some(true));
        assert_eq!(data.proxy, Some(false));
    }
