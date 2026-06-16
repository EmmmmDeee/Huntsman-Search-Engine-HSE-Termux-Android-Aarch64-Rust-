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

    fn all(ents: &[Entity], kind: EntityKind) -> Vec<&Entity> {
        ents.iter().filter(|e| e.kind == kind).collect()
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
    fn anycast_flag_yields_no_entities() {
        // When ipinfo.io itself sets anycast=true, the IP is infrastructure —
        // skip all entities regardless of the range-based check.
        let d = data(
            r#"{"ip":"1.2.3.4","anycast":true,"city":"Sydney","region":"NSW",
                "country":"AU","loc":"-33.8688,151.2093","org":"AS13335 Cloudflare"}"#,
        );
        let ents = build_entities("1.2.3.4", &d, "s");
        assert!(
            ents.is_empty(),
            "anycast=true must yield no entities, got {ents:?}"
        );
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

    #[test]
    fn postal_and_timezone_surfaced_in_evidence() {
        let d = data(
            r#"{"city":"Melbourne","region":"Victoria","country":"AU",
                "loc":"-37.8136,144.9631","postal":"3000","timezone":"Australia/Melbourne"}"#,
        );
        let ents = build_entities("1.2.3.4", &d, "s");

        // Coordinates evidence includes postal + timezone.
        let coords = one(&ents, EntityKind::Coordinates).unwrap();
        assert_eq!(
            coords.evidence[0].attributes.get("postal").map(String::as_str),
            Some("3000")
        );
        assert_eq!(
            coords.evidence[0].attributes.get("timezone").map(String::as_str),
            Some("Australia/Melbourne")
        );

        // Address evidence also includes postal + timezone.
        let addr = one(&ents, EntityKind::Address).unwrap();
        assert_eq!(
            addr.evidence[0].attributes.get("postal").map(String::as_str),
            Some("3000")
        );
        assert_eq!(
            addr.evidence[0].attributes.get("timezone").map(String::as_str),
            Some("Australia/Melbourne")
        );
    }

    #[test]
    fn privacy_vpn_tags_org_and_asn() {
        let d = data(
            r#"{"org":"AS9009 M247 Europe SRL",
                "privacy":{"vpn":true,"proxy":false,"tor":false,"relay":false,"hosting":false}}"#,
        );
        let ents = build_entities("1.2.3.4", &d, "s");

        let org = one(&ents, EntityKind::Organisation).unwrap();
        assert!(org.has_tag("vpn"), "org should be tagged vpn");
        assert!(!org.has_tag("proxy"), "org should not be tagged proxy");

        let asn = one(&ents, EntityKind::Asn).unwrap();
        assert!(asn.has_tag("vpn"), "asn should be tagged vpn");

        // Evidence attrs must include the flag values.
        let ev = &org.evidence[0];
        assert_eq!(ev.attributes.get("vpn").map(String::as_str), Some("true"));
        assert_eq!(ev.attributes.get("proxy").map(String::as_str), Some("false"));
    }

    #[test]
    fn privacy_tor_proxy_hosting_relay_tags() {
        let d = data(
            r#"{"org":"AS1234 Example ISP",
                "privacy":{"vpn":false,"proxy":true,"tor":true,"relay":true,"hosting":true,
                           "service":"Mullvad"}}"#,
        );
        let ents = build_entities("1.2.3.4", &d, "s");
        let org = one(&ents, EntityKind::Organisation).unwrap();
        for tag in &["proxy", "tor", "relay", "hosting"] {
            assert!(org.has_tag(tag), "expected tag {tag} on org");
        }
        let ev = &org.evidence[0];
        assert_eq!(
            ev.attributes.get("privacy_service").map(String::as_str),
            Some("Mullvad")
        );
    }

    #[test]
    fn abuse_contact_fields_in_evidence() {
        let d = data(
            r#"{"org":"AS1234 Example ISP",
                "abuse":{"name":"Network Abuse","email":"abuse@example.com",
                         "phone":"+1-555-0100","address":"123 Main St",
                         "country":"US","network":"1.2.3.0/24"}}"#,
        );
        let ents = build_entities("1.2.3.4", &d, "s");
        let org = one(&ents, EntityKind::Organisation).unwrap();
        let ev = &org.evidence[0];
        assert_eq!(
            ev.attributes.get("abuse_email").map(String::as_str),
            Some("abuse@example.com")
        );
        assert_eq!(
            ev.attributes.get("abuse_name").map(String::as_str),
            Some("Network Abuse")
        );
        assert_eq!(
            ev.attributes.get("abuse_network").map(String::as_str),
            Some("1.2.3.0/24")
        );
    }

    #[test]
    fn domains_block_yields_domain_entities() {
        let d = data(
            r#"{"org":"AS1234 Example",
                "domains":{"total":3,"domains":["example.com","foo.net","bar.org"]}}"#,
        );
        let ents = build_entities("1.2.3.4", &d, "s");
        let domains = all(&ents, EntityKind::Domain);
        assert_eq!(domains.len(), 3);
        let vals: Vec<&str> = domains.iter().map(|e| e.value.as_str()).collect();
        assert!(vals.contains(&"example.com"));
        assert!(vals.contains(&"foo.net"));
        assert!(vals.contains(&"bar.org"));
        // Check hosted-domain tag.
        assert!(domains[0].has_tag("hosted-domain"));
        // total_domains attribute in evidence.
        assert_eq!(
            domains[0].evidence[0].attributes.get("total_domains").map(String::as_str),
            Some("3")
        );
    }

    #[test]
    fn domains_block_deduplicates_ptr_hostname() {
        // If the PTR hostname also appears in the domains list, it should not
        // produce a second Domain entity.
        let d = data(
            r#"{"hostname":"dns.google",
                "domains":{"total":2,"domains":["dns.google","other.example.com"]}}"#,
        );
        let ents = build_entities("1.2.3.4", &d, "s");
        let domains = all(&ents, EntityKind::Domain);
        assert_eq!(domains.len(), 2, "dns.google should not be duplicated");
        let ptr = domains.iter().find(|e| e.value == "dns.google").unwrap();
        assert!(ptr.has_tag(tags::PTR));
        let hosted = domains.iter().find(|e| e.value == "other.example.com").unwrap();
        assert!(hosted.has_tag("hosted-domain"));
    }
