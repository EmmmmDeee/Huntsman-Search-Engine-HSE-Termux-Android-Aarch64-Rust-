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

    fn resp(json: &str) -> Resp {
        serde_json::from_str(json).expect("valid ipquery Resp")
    }
    fn has(es: &[Entity], k: EntityKind) -> bool {
        es.iter().any(|e| e.kind == k)
    }

    // A clean residential IP (no anonymiser flags, not a CDN edge): full geo.
    const RESIDENTIAL: &str = r#"{"isp":{"asn":"AS1221","org":"Telstra"},"location":{"country":"Australia","country_code":"AU","city":"Gatton","state":"Queensland","latitude":-27.55,"longitude":152.27,"timezone":"Australia/Brisbane"},"risk":{"is_vpn":false,"is_tor":false,"is_proxy":false,"is_datacenter":false}}"#;

    #[test]
    fn untrusted_geo_reason_flags_anonymisers_and_datacenters() {
        let dc = resp(r#"{"risk":{"is_datacenter":true}}"#);
        assert_eq!(untrusted_geo_reason("203.0.113.9", dc.risk.as_ref()), Some("datacenter"));
        let vpn = resp(r#"{"risk":{"is_vpn":true}}"#);
        assert_eq!(untrusted_geo_reason("203.0.113.9", vpn.risk.as_ref()), Some("vpn"));
        let tor = resp(r#"{"risk":{"is_tor":true}}"#);
        assert_eq!(untrusted_geo_reason("203.0.113.9", tor.risk.as_ref()), Some("tor exit"));
        // Clean residential IP → trusted (None). Mobile is NOT suppressed.
        let clean = resp(RESIDENTIAL);
        assert_eq!(untrusted_geo_reason("203.0.113.9", clean.risk.as_ref()), None);
        let mobile = resp(r#"{"risk":{"is_mobile":true}}"#);
        assert_eq!(untrusted_geo_reason("203.0.113.9", mobile.risk.as_ref()), None);
    }

    #[test]
    fn build_suppresses_geo_for_anonymiser_keeps_infrastructure() {
        let d = resp(r#"{"isp":{"asn":"AS9009","org":"M247 (VPN host)"},"location":{"country":"Netherlands","country_code":"NL","city":"Amsterdam","latitude":52.37,"longitude":4.89},"risk":{"is_vpn":true}}"#);
        let es = build_geo_isp_entities("203.0.113.9", &d, "t");
        // No subject location from a VPN exit…
        assert!(!has(&es, EntityKind::Coordinates), "VPN coords suppressed");
        assert!(!has(&es, EntityKind::Address), "VPN address suppressed");
        // …but the infrastructure (ASN/ISP) is still recorded.
        assert!(has(&es, EntityKind::Asn));
        assert!(has(&es, EntityKind::Organisation));
    }

    #[test]
    fn build_emits_geo_for_clean_ip_with_iso_timezone_and_au_tag() {
        let d = resp(RESIDENTIAL);
        let es = build_geo_isp_entities("203.0.113.9", &d, "t");
        let coords = es.iter().find(|e| e.kind == EntityKind::Coordinates).expect("coords");
        assert_eq!(coords.evidence[0].attributes.get("country_iso").map(String::as_str), Some("AU"));
        assert_eq!(
            coords.evidence[0].attributes.get("timezone").map(String::as_str),
            Some("Australia/Brisbane")
        );
        let addr = es.iter().find(|e| e.kind == EntityKind::Address).expect("address");
        assert!(addr.tags.iter().any(|t| t == "country:AU"));
        assert_eq!(addr.value, "Gatton, Queensland, Australia");
    }
