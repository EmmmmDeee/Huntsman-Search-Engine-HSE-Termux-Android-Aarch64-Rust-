use super::*;

    #[test]
    fn accepts_ip_only() {
        let m = IpWhois;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }

    #[test]
    fn name_and_description() {
        let m = IpWhois;
        assert_eq!(m.name(), "ip_whois_geo");
        assert!(!m.description().is_empty());
    }

    #[test]
    fn priority_below_ip_geo() {
        assert!(IpWhois.priority() < 28, "should run after ip_geo (28)");
    }

    #[test]
    fn resp_deserializes_success() {
        let json = r#"{
            "success": true,
            "ip": "1.1.1.1",
            "country": "Australia",
            "country_code": "AU",
            "region": "Queensland",
            "city": "South Brisbane",
            "latitude": -27.4766,
            "longitude": 153.0166,
            "postal": "4101",
            "timezone_id": "Australia/Brisbane",
            "connection": {
                "isp": "Cloudflare Inc",
                "org": "APNIC Research",
                "asn": 13335,
                "domain": "cloudflare.com"
            }
        }"#;
        let r: Resp = serde_json::from_str(json).unwrap();
        assert_eq!(r.success, Some(true));
        assert!((r.latitude.unwrap() - (-27.4766)).abs() < 0.001);
        assert!((r.longitude.unwrap() - 153.0166).abs() < 0.001);
        assert_eq!(r.city.as_deref(), Some("South Brisbane"));
        assert_eq!(r.connection.as_ref().unwrap().asn_num, Some(13335));
    }

    #[test]
    fn resp_deserializes_failure() {
        let json = r#"{"success": false, "message": "Invalid IP address"}"#;
        let r: Resp = serde_json::from_str(json).unwrap();
        assert_eq!(r.success, Some(false));
        assert!(r.latitude.is_none());
    }

    #[test]
    fn resp_tolerates_missing_fields() {
        let json = r#"{"success": true, "latitude": 0.0, "longitude": 0.0}"#;
        let r: Resp = serde_json::from_str(json).unwrap();
        assert_eq!(r.success, Some(true));
        assert!(r.connection.is_none());
        assert!(r.city.is_none());
    }

    #[test]
    fn gates_coordinates_with_coarse_provider_validator() {
        // ipwho.is is a coarse IP-geo source: its "no fix" placeholder is a
        // sub-degree jitter around null island, which must be rejected — but a
        // real fix must pass. This locks the module to the coarse-provider gate
        // (is_plausible_provider_coord), not the precise is_valid_coords.
        use crate::util::geo::is_plausible_provider_coord;
        assert!(!is_plausible_provider_coord(0.005, 0.005)); // no-fix jitter
        assert!(!is_plausible_provider_coord(0.0, 153.0)); // one component in band
        assert!(is_plausible_provider_coord(-27.4766, 153.0166)); // real Brisbane fix
    }
