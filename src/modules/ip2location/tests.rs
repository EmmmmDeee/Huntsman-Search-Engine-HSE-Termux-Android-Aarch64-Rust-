use super::*;
    #[test]
    fn accepts_ip_only() {
        assert!(Ip2Location.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
        assert!(!Ip2Location.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }
    #[test]
    fn cost_is_free() {
        assert!(matches!(
            Ip2Location.cost(),
            crate::core::module::ModuleCost::Free
        ));
    }
    #[test]
    fn deser_gatton() {
        let j = r#"{"ip":"101.169.42.148","country_code":"AU","country_name":"Australia","region_name":"Queensland","city_name":"Gatton","zip_code":"4343","latitude":-27.55873,"longitude":152.27618,"time_zone":"+10:00","asn":"1221","as":"Telstra Limited","is_proxy":false}"#;
        let r: Resp = serde_json::from_str(j).unwrap();
        assert_eq!(r.city_name.as_deref(), Some("Gatton"));
        assert_eq!(r.region_name.as_deref(), Some("Queensland"));
        assert_eq!(r.zip_code.as_deref(), Some("4343"));
    }
