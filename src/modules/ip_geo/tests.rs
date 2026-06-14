use super::*;

    #[test]
    fn accepts_ip_only() {
        let m = IpGeo;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }

    #[test]
    fn deserialize_full_response() {
        let json = r#"{"status":"success","country":"Australia","countryCode":"AU","regionName":"Queensland","city":"Brisbane","zip":"4000","lat":-27.4679,"lon":153.0281,"timezone":"Australia/Brisbane","isp":"Telstra","org":"Telstra Corp","as":"AS1221 Telstra","mobile":false,"proxy":false,"hosting":false}"#;
        let r: IpApiResp = serde_json::from_str(json).unwrap();
        assert_eq!(r.status, "success");
        assert_eq!(r.country.as_deref(), Some("Australia"));
        assert_eq!(r.country_code.as_deref(), Some("AU"));
        assert_eq!(r.city.as_deref(), Some("Brisbane"));
        assert!((r.lat.unwrap() - (-27.4679)).abs() < 0.001);
        assert!((r.lon.unwrap() - 153.0281).abs() < 0.001);
        assert_eq!(r.isp.as_deref(), Some("Telstra"));
        assert_eq!(r.mobile, Some(false));
        assert_eq!(r.proxy, Some(false));
        assert_eq!(r.hosting, Some(false));
    }

    #[test]
    fn deserialize_fail_response() {
        let json = r#"{"status":"fail","message":"invalid query"}"#;
        let r: IpApiResp = serde_json::from_str(json).unwrap();
        assert_eq!(r.status, "fail");
        assert!(r.country.is_none());
    }

    #[test]
    fn deserialize_proxy_hosting_flags() {
        let json = r#"{"status":"success","country":"US","lat":37.7,"lon":-122.4,"mobile":false,"proxy":true,"hosting":true}"#;
        let r: IpApiResp = serde_json::from_str(json).unwrap();
        assert_eq!(r.proxy, Some(true));
        assert_eq!(r.hosting, Some(true));
    }

    #[test]
    fn deserialize_mobile_flag() {
        let json = r#"{"status":"success","country":"AU","lat":-33.8,"lon":151.2,"mobile":true,"proxy":false,"hosting":false}"#;
        let r: IpApiResp = serde_json::from_str(json).unwrap();
        assert_eq!(r.mobile, Some(true));
    }

    #[test]
    fn deserialize_missing_optional_fields() {
        let json = r#"{"status":"success"}"#;
        let r: IpApiResp = serde_json::from_str(json).unwrap();
        assert_eq!(r.status, "success");
        assert!(r.lat.is_none());
        assert!(r.lon.is_none());
        assert!(r.country.is_none());
    }

    #[test]
    fn module_metadata() {
        let m = IpGeo;
        assert_eq!(m.name(), "ip_geo");
        assert_eq!(m.priority(), 28);
        assert!(!m.description().is_empty());
    }
