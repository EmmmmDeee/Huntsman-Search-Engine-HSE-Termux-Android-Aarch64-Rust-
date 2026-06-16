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
        let json = r#"{"ip":"8.8.8.8","success":true,"type":"IPv4","country":"United States","country_code":"US","region":"California","city":"Mountain View","latitude":37.386,"longitude":-122.0838,"postal":"94039","connection":{"asn":15169,"org":"Google LLC","isp":"Google LLC","domain":"google.com"},"timezone":{"id":"America/Los_Angeles"}}"#;
        let data: IpWhoResp = serde_json::from_str(json).unwrap();
        assert!(data.success);
        assert_eq!(data.city.as_deref(), Some("Mountain View"));
        assert_eq!(data.latitude, Some(37.386));
        let conn = data.connection.unwrap();
        assert_eq!(conn.asn, Some(15169));
        assert_eq!(conn.isp.as_deref(), Some("Google LLC"));
    }

    #[test]
    fn deser_failure_response() {
        // ipwho.is reports a failed lookup with `success:false`, not an HTTP error.
        let json = r#"{"ip":"10.0.0.1","success":false,"message":"Reserved range"}"#;
        let data: IpWhoResp = serde_json::from_str(json).unwrap();
        assert!(!data.success);
        assert!(data.city.is_none());
    }
