use super::*;
    #[test]
    fn accepts_ip_only() {
        assert!(IpInfo.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
        assert!(!IpInfo.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }
    #[test]
    fn cost_is_free() {
        assert!(matches!(
            IpInfo.cost(),
            crate::core::module::ModuleCost::Free
        ));
    }
    #[test]
    fn deser() {
        let j = r#"{"ip":"8.8.8.8","hostname":"dns.google","city":"Mountain View","region":"California","country":"US","loc":"37.4056,-122.0775","org":"AS15169 Google LLC","postal":"94043","timezone":"America/Los_Angeles"}"#;
        let r: IpInfoResp = serde_json::from_str(j).unwrap();
        assert_eq!(r.city.as_deref(), Some("Mountain View"));
        assert_eq!(r.org.as_deref(), Some("AS15169 Google LLC"));
    }

    fn data(json: &str) -> IpInfoResp {
        serde_json::from_str(json).unwrap()
    }

    fn one(ents: &[Entity], kind: EntityKind) -> Option<&Entity> {
        ents.iter().find(|e| e.kind == kind)
    }

    #[test]
    fn full_record_yields_all_five_entities() {
        let d = data(
            r#"{"ip":"8.8.8.8","hostname":"dns.google","city":"Mountain View",
                "region":"California","country":"US","loc":"37.4056,-122.0775",
                "org":"AS15169 Google LLC"}"#,
        );
        let ents = build_entities("8.8.8.8", &d, "s");
        assert_eq!(ents.len(), 5);

        let coords = one(&ents, EntityKind::Coordinates).unwrap();
        // Entity::new normalises Coordinates to 6-decimal lat,lon.
        assert_eq!(coords.value, "37.405600,-122.077500");
        assert!(coords.has_tag(tags::GEOINT) && coords.has_tag("ipinfo"));
        assert_eq!(
            coords.evidence[0]
                .attributes
                .get("city")
                .map(String::as_str),
            Some("Mountain View")
        );

        assert_eq!(
            one(&ents, EntityKind::Address).unwrap().value,
            "Mountain View, California, US"
        );
        assert_eq!(
            one(&ents, EntityKind::Organisation).unwrap().value,
            "AS15169 Google LLC"
        );
        let asn = one(&ents, EntityKind::Asn).unwrap();
        assert_eq!(asn.value, "AS15169");
        assert!((asn.confidence - 0.80).abs() < 1e-9);
        let dom = one(&ents, EntityKind::Domain).unwrap();
        assert_eq!(dom.value, "dns.google");
        assert!(dom.has_tag(tags::PTR));
    }

    #[test]
    fn cdn_edge_ip_yields_no_entities() {
        // A Cloudflare anycast edge IP (104.16.0.0/13) geolocates to whichever
        // datacenter answered — never the subject. ipinfo drops the whole record
        // (the city/coords/org all describe infrastructure) rather than seed a
        // false subject location into identity-location correlation.
        let d = data(
            r#"{"ip":"104.16.1.1","hostname":"edge.cloudflare.example",
                "city":"San Francisco","region":"California","country":"US",
                "loc":"37.7749,-122.4194","org":"AS13335 Cloudflare, Inc."}"#,
        );
        let ents = build_entities("104.16.1.1", &d, "s");
        assert!(
            ents.is_empty(),
            "CDN-edge IP must yield no entities, got {ents:?}"
        );
        // Sanity: the same record on a non-CDN IP DOES produce entities.
        assert!(!build_entities("8.8.8.8", &d, "s").is_empty());
    }

    #[test]
    fn null_island_loc_is_dropped() {
        // 0,0 (and sub-threshold magnitudes) is a placeholder, not a location.
        let ents = build_entities("1.2.3.4", &data(r#"{"loc":"0,0"}"#), "s");
        assert!(one(&ents, EntityKind::Coordinates).is_none());
        let ents = build_entities("1.2.3.4", &data(r#"{"loc":"0.001,0.001"}"#), "s");
        assert!(one(&ents, EntityKind::Coordinates).is_none());
    }

    #[test]
    fn address_omits_region_when_absent() {
        let ents = build_entities("1.2.3.4", &data(r#"{"city":"Sydney","country":"AU"}"#), "s");
        assert_eq!(one(&ents, EntityKind::Address).unwrap().value, "Sydney, AU");
    }

    #[test]
    fn org_without_as_prefix_yields_no_asn() {
        let ents = build_entities("1.2.3.4", &data(r#"{"org":"Cloudflare Inc"}"#), "s");
        assert!(one(&ents, EntityKind::Organisation).is_some());
        assert!(one(&ents, EntityKind::Asn).is_none());
    }

    #[test]
    fn dotless_hostname_is_not_a_domain() {
        let ents = build_entities("1.2.3.4", &data(r#"{"hostname":"localhost"}"#), "s");
        assert!(one(&ents, EntityKind::Domain).is_none());
    }
