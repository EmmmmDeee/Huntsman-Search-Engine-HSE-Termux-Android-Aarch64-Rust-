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
        assert_eq!(r.postal.as_deref(), Some("94043"));
        assert_eq!(r.timezone.as_deref(), Some("America/Los_Angeles"));
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
                "org":"AS15169 Google LLC","postal":"94043",
                "timezone":"America/Los_Angeles"}"#,
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
            coords.evidence[0]
                .attributes
                .get("timezone")
                .map(String::as_str),
            Some("America/Los_Angeles")
        );

        let address = one(&ents, EntityKind::Address).unwrap();
        assert_eq!(address.value, "Mountain View, California, US");
        assert_eq!(
            address.evidence[0]
                .attributes
                .get("postal")
                .map(String::as_str),
            Some("94043")
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
    fn coordinates_carry_the_originating_ip_for_login_ip_recognition() {
        // Like `ip_geo`, this module's Coordinates fix passes the shared
        // "is this actually the subject" trust gate (CDN/anycast edges are
        // dropped entirely, see `cdn_edge_ip_yields_no_entities`) and uses the
        // same recalibrated-confidence `coarse_provider_coords` helper — a
        // sibling in the same IP-geolocation family. The correlator's shared
        // `person_login_ip_coords` (used by `best_au_location_estimate` and
        // `au_location_corroboration`) only recognises a Coordinates fix as
        // tied to a subject's breach/stealer login IP when its evidence
        // carries an `ip` attribute equal to that IP.
        let d = data(r#"{"loc":"37.4056,-122.0775","city":"Mountain View"}"#);
        let ents = build_entities("8.8.8.8", &d, "s");
        let coords = one(&ents, EntityKind::Coordinates).unwrap();
        assert_eq!(
            coords.evidence[0].attributes.get("ip").map(String::as_str),
            Some("8.8.8.8"),
            "Coordinates evidence must carry the originating IP so \
             person_login_ip_coords can recognise this as a login-IP fix"
        );
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
        // Sanity: the same record on a non-CDN IP DOES produce the geo entities
        // the CDN gate suppressed — a Coordinates (from `loc`) and an Address
        // (from city/region). Asserting the kinds, not just non-emptiness, makes
        // this a real counter-case: if the trust gate ever over-fired and
        // dropped a legitimate IP's geo, this fails instead of passing silently.
        let ok = build_entities("8.8.8.8", &d, "s");
        assert!(
            ok.iter().any(|e| e.kind == EntityKind::Coordinates),
            "non-CDN IP must yield Coordinates from loc, got {ok:?}"
        );
        assert!(
            ok.iter()
                .any(|e| e.kind == EntityKind::Address && e.value.contains("San Francisco")),
            "non-CDN IP must yield the city Address, got {ok:?}"
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
