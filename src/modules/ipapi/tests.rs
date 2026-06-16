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

    // ── build_entities (pure extraction) ───────────────────────────────

    fn resp(json: &str) -> IpWhoResp {
        serde_json::from_str(json).expect("fixture is valid IpWhoResp JSON")
    }
    fn of_kind(ents: &[Entity], kind: EntityKind) -> Option<&Entity> {
        ents.iter().find(|e| e.kind == kind)
    }

    #[test]
    fn full_record_yields_coords_address_asn_and_org() {
        let body = resp(
            r#"{"success":true,"country":"United States","region":"California",
                "city":"Mountain View","latitude":37.386,"longitude":-122.0838,
                "connection":{"asn":15169,"org":"Google LLC","isp":"Google LLC"},
                "timezone":{"id":"America/Los_Angeles"}}"#,
        );
        let ents = build_entities(&body, "8.8.8.8", "s");
        assert_eq!(ents.len(), 4);

        let coords = of_kind(&ents, EntityKind::Coordinates).expect("Coordinates entity");
        // coarse_provider_coords formats raw to 4dp; Entity::new normalises
        // Coordinates to 6dp for the canonical `value`.
        assert_eq!(coords.value, "37.386000,-122.083800");
        assert!(coords.has_tag("geoint"));
        // North-America fix → off-region for an AU-focused scan.
        assert!(coords.has_tag("off-region"));
        let attr = |k: &str| coords.evidence[0].attributes.get(k).map(String::as_str);
        assert_eq!(attr("ip"), Some("8.8.8.8"));
        assert_eq!(attr("city"), Some("Mountain View"));
        assert_eq!(attr("region"), Some("California"));
        assert_eq!(attr("country"), Some("United States"));
        assert_eq!(attr("isp"), Some("Google LLC"));
        assert_eq!(attr("asn"), Some("AS15169"));
        assert_eq!(attr("org"), Some("Google LLC"));
        assert_eq!(attr("timezone"), Some("America/Los_Angeles"));

        let addr = of_kind(&ents, EntityKind::Address).expect("Address entity");
        assert_eq!(addr.value, "Mountain View, California, United States");
        assert!(addr.has_tag("geoint"));

        assert_eq!(of_kind(&ents, EntityKind::Asn).unwrap().value, "AS15169");
        assert_eq!(
            of_kind(&ents, EntityKind::Organisation).unwrap().value,
            "Google LLC"
        );
    }

    #[test]
    fn unsuccessful_lookup_yields_nothing() {
        let body = resp(r#"{"success":false,"city":"Nowhere","latitude":1.0,"longitude":1.0}"#);
        assert!(build_entities(&body, "10.0.0.1", "s").is_empty());
    }

    #[test]
    fn cdn_edge_ip_is_skipped_entirely() {
        // 104.16.0.1 is in Cloudflare's 104.16/13 range — its geo is the
        // datacenter's, not the subject's, so the whole emit block is skipped.
        let body = resp(
            r#"{"success":true,"city":"Sydney","country":"Australia",
                "latitude":-33.8,"longitude":151.2,"connection":{"asn":13335}}"#,
        );
        assert!(build_entities(&body, "104.16.0.1", "s").is_empty());
    }

    #[test]
    fn null_island_coords_skipped_but_other_entities_survive() {
        // A sub-degree null-island fix is rejected by coarse_provider_coords,
        // yet the Address/ASN/Org still emit.
        let body = resp(
            r#"{"success":true,"city":"Accra","country":"Ghana",
                "latitude":0.005,"longitude":0.005,"connection":{"asn":30986,"org":"Some ISP"}}"#,
        );
        let ents = build_entities(&body, "8.8.4.4", "s");
        assert!(
            of_kind(&ents, EntityKind::Coordinates).is_none(),
            "null-island jitter must not become a Coordinates entity"
        );
        assert!(of_kind(&ents, EntityKind::Address).is_some());
        assert_eq!(of_kind(&ents, EntityKind::Asn).unwrap().value, "AS30986");
        assert_eq!(
            of_kind(&ents, EntityKind::Organisation).unwrap().value,
            "Some ISP"
        );
    }

    #[test]
    fn city_only_address_uses_bare_city() {
        // No region/country → the Address is just the city.
        let body = resp(r#"{"success":true,"city":"Brisbane"}"#);
        let ents = build_entities(&body, "1.2.3.4", "s");
        let addr = of_kind(&ents, EntityKind::Address).expect("Address entity");
        assert_eq!(addr.value, "Brisbane");
    }

    #[test]
    fn short_org_yields_no_organisation_entity() {
        // org of <3 chars is below the Organisation threshold (but still an attr).
        let body = resp(r#"{"success":true,"connection":{"org":"GO"}}"#);
        let ents = build_entities(&body, "1.2.3.4", "s");
        assert!(of_kind(&ents, EntityKind::Organisation).is_none());
    }

    #[test]
    fn blank_scalar_fields_skipped_in_evidence() {
        // Empty city/region/country/isp/org/timezone strings must not become
        // attributes; only the always-present `ip` remains.
        let body = resp(
            r#"{"success":true,"city":"","region":"","country":"","latitude":-27.47,
                "longitude":153.02,"connection":{"isp":"","org":""},"timezone":{"id":""}}"#,
        );
        let coords = build_entities(&body, "1.2.3.4", "s")
            .into_iter()
            .find(|e| e.kind == EntityKind::Coordinates)
            .expect("Coordinates entity");
        let attrs = &coords.evidence[0].attributes;
        for k in ["city", "region", "country", "isp", "org", "timezone"] {
            assert!(!attrs.contains_key(k), "blank `{k}` must be skipped");
        }
        assert_eq!(attrs.get("ip").map(String::as_str), Some("1.2.3.4"));
    }
