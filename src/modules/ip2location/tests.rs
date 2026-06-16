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

    const GATTON_JSON: &str = r#"{"ip":"101.169.42.148","country_code":"AU","country_name":"Australia","region_name":"Queensland","city_name":"Gatton","zip_code":"4343","latitude":-27.55873,"longitude":152.27618,"time_zone":"+10:00","asn":"1221","as":"Telstra Limited","is_proxy":false}"#;

    fn entity(es: &[Entity], k: EntityKind) -> Option<&Entity> {
        es.iter().find(|e| e.kind == k)
    }

    #[test]
    fn build_entities_surfaces_timezone_and_country_iso_on_geo() {
        let r: Resp = serde_json::from_str(GATTON_JSON).unwrap();
        let es = build_entities(&r, "101.169.42.148", false, "t");

        // Coordinates carry the previously-discarded timezone + ISO country.
        let coords = entity(&es, EntityKind::Coordinates).expect("coordinates");
        assert_eq!(
            coords.evidence[0].attributes.get("timezone").map(String::as_str),
            Some("+10:00")
        );
        assert_eq!(
            coords.evidence[0].attributes.get("country_iso").map(String::as_str),
            Some("AU")
        );

        // Address is country:AU-tagged directly from the country code, and the
        // composed value keeps suburb precision.
        let addr = entity(&es, EntityKind::Address).expect("address");
        assert_eq!(addr.value, "Gatton, Queensland 4343, Australia");
        assert!(addr.tags.iter().any(|t| t == "country:AU"));
    }

    #[test]
    fn build_entities_emits_asn_and_isp() {
        let r: Resp = serde_json::from_str(GATTON_JSON).unwrap();
        let es = build_entities(&r, "101.169.42.148", false, "t");
        assert_eq!(entity(&es, EntityKind::Asn).map(|e| e.value.as_str()), Some("AS1221"));
        assert_eq!(
            entity(&es, EntityKind::Organisation).map(|e| e.value.as_str()),
            Some("Telstra Limited")
        );
    }

    #[test]
    fn build_entities_skip_geo_drops_location_keeps_infrastructure() {
        // A CDN/anycast edge IP: no Coordinates/Address, but ASN/ISP still emit.
        let r: Resp = serde_json::from_str(GATTON_JSON).unwrap();
        let es = build_entities(&r, "101.169.42.148", true, "t");
        assert!(entity(&es, EntityKind::Coordinates).is_none());
        assert!(entity(&es, EntityKind::Address).is_none());
        assert!(entity(&es, EntityKind::Asn).is_some());
        assert!(entity(&es, EntityKind::Organisation).is_some());
    }

    #[test]
    fn build_entities_non_au_address_not_tagged_au() {
        let j = r#"{"country_code":"US","country_name":"United States","region_name":"California","city_name":"Mountain View","zip_code":"94043","latitude":37.4,"longitude":-122.08,"asn":"15169","as":"Google LLC"}"#;
        let r: Resp = serde_json::from_str(j).unwrap();
        let es = build_entities(&r, "8.8.8.8", false, "t");
        let addr = entity(&es, EntityKind::Address).expect("address");
        assert!(!addr.tags.iter().any(|t| t == "country:AU"));
    }
