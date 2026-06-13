use super::*;

    #[test]
    fn accepts_ip_only() {
        assert!(IpQuery.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
        assert!(!IpQuery.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }

    #[test]
    fn cost_is_free() {
        assert!(matches!(
            IpQuery.cost(),
            crate::core::module::ModuleCost::Free
        ));
    }

    #[test]
    fn deser() {
        let j = r#"{"ip":"8.8.8.8","isp":{"asn":"AS15169","org":"Google LLC","isp":"Google LLC"},"location":{"country":"United States","country_code":"US","city":"Mountain View","state":"California","latitude":37.41,"longitude":-122.11},"risk":{"is_mobile":false,"is_vpn":false,"is_tor":false,"is_proxy":false,"is_datacenter":true,"risk_score":0}}"#;
        let r: Resp = serde_json::from_str(j).unwrap();
        assert_eq!(r.risk.unwrap().risk_score, Some(0));
        assert_eq!(r.location.unwrap().city.as_deref(), Some("Mountain View"));
    }
