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

    // ── build_entities (pure extraction) ───────────────────────────────

    fn resp(json: &str) -> Resp {
        serde_json::from_str(json).expect("fixture is valid Resp JSON")
    }
    fn of_kind(ents: &[Entity], kind: EntityKind) -> Option<&Entity> {
        ents.iter().find(|e| e.kind == kind)
    }

    #[test]
    fn full_au_record_yields_coords_address_org_and_asn() {
        let body = resp(
            r#"{
                "success": true, "country": "Australia", "country_code": "AU",
                "region": "Queensland", "city": "South Brisbane",
                "latitude": -27.4766, "longitude": 153.0166, "postal": "4101",
                "timezone_id": "Australia/Brisbane",
                "connection": { "isp": "Cloudflare Inc", "org": "APNIC Research", "asn": 13335 }
            }"#,
        );
        let ents = build_entities(&body, "1.1.1.1", "s");
        assert_eq!(ents.len(), 4);

        let coords = of_kind(&ents, EntityKind::Coordinates).expect("Coordinates entity");
        // ip_whois_geo formats coords to 6 dp directly.
        assert_eq!(coords.value, "-27.476600,153.016600");
        assert!((coords.confidence - confidence::MEDIUM_HIGH).abs() < 1e-9);
        assert!(coords.has_tag("geoint"));
        assert!(coords.has_tag("country:AU"), "country code is uppercased");
        assert!(coords.has_tag("au-state:QLD"), "Brisbane → QLD box");
        let attr = |k: &str| coords.evidence[0].attributes.get(k).map(String::as_str);
        assert_eq!(attr("source"), Some("ipwho.is"));
        assert_eq!(attr("country"), Some("Australia"));
        assert_eq!(attr("country_code"), Some("AU"));
        assert_eq!(attr("region"), Some("Queensland"));
        assert_eq!(attr("city"), Some("South Brisbane"));
        assert_eq!(attr("postal"), Some("4101"));
        assert_eq!(attr("timezone"), Some("Australia/Brisbane"));
        assert_eq!(attr("isp"), Some("Cloudflare Inc"));
        assert_eq!(attr("asn"), Some("AS13335"));
        assert_eq!(attr("org"), Some("APNIC Research"));

        let addr = of_kind(&ents, EntityKind::Address).expect("derived Address");
        assert_eq!(addr.value, "South Brisbane, Queensland, Australia");
        assert!(addr.has_tag("geoint") && addr.has_tag("derived"));

        let org = of_kind(&ents, EntityKind::Organisation).expect("Organisation");
        assert_eq!(org.value, "APNIC Research");
        let oattr = |k: &str| org.evidence[0].attributes.get(k).map(String::as_str);
        assert_eq!(oattr("asn"), Some("AS13335"));
        assert_eq!(oattr("isp"), Some("Cloudflare Inc"));

        let asn = of_kind(&ents, EntityKind::Asn).expect("Asn");
        assert_eq!(asn.value, "AS13335");
        assert!(asn.has_tag("ip-whois"));
    }

    #[test]
    fn surfaces_region_code_and_isp_domain_previously_dropped() {
        let body = resp(
            r#"{
                "success": true, "country": "Australia", "country_code": "AU",
                "region": "Queensland", "region_code": "QLD", "city": "South Brisbane",
                "latitude": -27.4766, "longitude": 153.0166,
                "connection": { "isp": "Telstra", "org": "Telstra Corporation", "asn": 1221, "domain": "telstra.com" }
            }"#,
        );
        let ents = build_entities(&body, "203.0.113.9", "s");
        let coords = of_kind(&ents, EntityKind::Coordinates).expect("Coordinates");
        let attr = |k: &str| coords.evidence[0].attributes.get(k).map(String::as_str);
        assert_eq!(attr("region_code"), Some("QLD"));
        assert_eq!(attr("isp_domain"), Some("telstra.com"));
        // The ISP domain is also stamped on the Organisation attribution.
        let org = of_kind(&ents, EntityKind::Organisation).expect("Organisation");
        assert_eq!(
            org.evidence[0].attributes.get("isp_domain").map(String::as_str),
            Some("telstra.com")
        );
    }

    #[test]
    fn coordinates_carry_the_originating_ip_for_login_ip_recognition() {
        // The module's own doc comment frames it as `ip_geo`'s "second-source"
        // corroborating partner, and `build_entities` explicitly filters CDN/
        // anycast edge IPs because "its geo is the datacenter's, not the
        // subject's" — this module's coordinate fix is meant to represent the
        // SUBJECT's location, exactly like `ip_geo`'s. The correlator's shared
        // `person_login_ip_coords` definition (used by both
        // `best_au_location_estimate` and `au_location_corroboration`) only
        // recognises a Coordinates fix as tied to a breach/stealer login IP when
        // its evidence carries an `ip` attribute equal to that IP — `ip_geo`
        // stamps it, but this module previously did not, so an ipwho.is fix on
        // the exact same login IP silently never counted as person-location
        // corroboration despite being eligible (not hosting/proxy/platform-infra
        // tagged). The attribute must equal the input IP verbatim.
        let body = resp(
            r#"{"success": true, "country_code": "AU", "latitude": -33.8688, "longitude": 151.2093}"#,
        );
        let ents = build_entities(&body, "203.0.113.7", "s");
        let coords = of_kind(&ents, EntityKind::Coordinates).expect("Coordinates entity");
        assert_eq!(
            coords.evidence[0].attributes.get("ip").map(String::as_str),
            Some("203.0.113.7"),
            "Coordinates evidence must carry the originating IP so \
             person_login_ip_coords can recognise this as a login-IP fix"
        );
    }

    #[test]
    fn unsuccessful_lookup_yields_nothing() {
        let body = resp(r#"{"success": false, "latitude": 1.0, "longitude": 1.0}"#);
        assert!(build_entities(&body, "1.2.3.4", "s").is_empty());
    }

    #[test]
    fn cdn_edge_ip_is_skipped_entirely() {
        // 104.16.0.1 ∈ Cloudflare 104.16/13 — geo belongs to the datacenter.
        let body = resp(
            r#"{"success": true, "country": "United States", "city": "San Francisco",
                "latitude": 37.77, "longitude": -122.42, "connection": {"asn": 13335}}"#,
        );
        assert!(build_entities(&body, "104.16.0.1", "s").is_empty());
    }

    #[test]
    fn null_island_coords_reject_drops_the_whole_record() {
        // Sub-degree null-island jitter fails the coarse-provider gate, which
        // returns early from the builder. That gate precedes the Organisation/ASN
        // construction, so an implausible fix drops the ENTIRE record — matching
        // the pre-refactor process(), whose early `return` exited the function.
        let body = resp(
            r#"{"success": true, "country": "Ghana", "region": "Greater Accra",
                "city": "Accra", "latitude": 0.005, "longitude": 0.005,
                "connection": {"org": "Some ISP", "asn": 30986}}"#,
        );
        assert!(
            build_entities(&body, "8.8.4.4", "s").is_empty(),
            "an implausible provider coord returns early, emitting nothing"
        );
    }

    #[test]
    fn blank_country_code_adds_no_country_tag() {
        let body = resp(
            r#"{"success": true, "country_code": "", "latitude": -27.4766, "longitude": 153.0166}"#,
        );
        let coords = build_entities(&body, "1.1.1.1", "s")
            .into_iter()
            .find(|e| e.kind == EntityKind::Coordinates)
            .expect("Coordinates entity");
        assert!(
            !coords.tags.iter().any(|t| t.starts_with("country:")),
            "a blank country code adds no country tag"
        );
        assert!(!coords.evidence[0].attributes.contains_key("country_code"));
    }

    #[test]
    fn non_au_fix_gets_no_au_state_tag() {
        let body = resp(
            r#"{"success": true, "country_code": "US",
                "latitude": 37.77, "longitude": -122.42}"#,
        );
        let coords = build_entities(&body, "9.9.9.9", "s")
            .into_iter()
            .find(|e| e.kind == EntityKind::Coordinates)
            .expect("Coordinates entity");
        assert!(coords.has_tag("country:US"));
        assert!(!coords.tags.iter().any(|t| t.starts_with("au-state:")));
    }

    #[test]
    fn one_part_address_is_not_emitted() {
        // Only city present (region/country absent) → <2 parts → no Address.
        let body = resp(
            r#"{"success": true, "city": "Brisbane",
                "latitude": -27.4766, "longitude": 153.0166}"#,
        );
        let ents = build_entities(&body, "1.1.1.1", "s");
        assert!(of_kind(&ents, EntityKind::Coordinates).is_some());
        assert!(
            of_kind(&ents, EntityKind::Address).is_none(),
            "a single locality part must not synthesise an Address"
        );
    }

    #[test]
    fn connection_domain_yields_a_domain_entity() {
        // connection.domain (the ASN/ISP's own registered domain, e.g.
        // "cloudflare.com" for AS13335) has no struct field prior to this
        // fix, so serde silently drops it and it never becomes an entity —
        // even though the sibling connection.org field on the exact same
        // object is turned into an Organisation a few lines below. Locks in
        // that a populated connection.domain now surfaces as its own Domain
        // entity, distinct from (and in addition to) the Organisation.
        let body = resp(
            r#"{
                "success": true, "country": "Australia", "country_code": "AU",
                "region": "Queensland", "city": "South Brisbane",
                "latitude": -27.4766, "longitude": 153.0166, "postal": "4101",
                "timezone_id": "Australia/Brisbane",
                "connection": {
                    "isp": "Cloudflare Inc", "org": "APNIC Research",
                    "asn": 13335, "domain": "cloudflare.com"
                }
            }"#,
        );
        let ents = build_entities(&body, "1.1.1.1", "s");
        assert_eq!(
            ents.len(),
            5,
            "coords + address + org + asn + the new domain entity"
        );

        let dom = of_kind(&ents, EntityKind::Domain).expect("Domain entity from connection.domain");
        assert_eq!(dom.value, "cloudflare.com");
        assert!((dom.confidence - confidence::MEDIUM_HIGH).abs() < 1e-9);
        assert!(dom.has_tag("geoint"));
        assert!(dom.has_tag("derived"));
        assert!(dom.has_tag("ip-whois"));
        assert_eq!(
            dom.evidence[0].attributes.get("domain").map(String::as_str),
            Some("cloudflare.com")
        );

        // The sibling Organisation is still built independently from the
        // same connection object — this fix must not alter it.
        let org = of_kind(&ents, EntityKind::Organisation).expect("Organisation");
        assert_eq!(org.value, "APNIC Research");
    }

    #[test]
    fn absent_connection_domain_yields_no_domain_entity() {
        // Most fixtures (e.g. full_au_record_yields_coords_address_org_and_asn)
        // have no "domain" key in connection at all — must deserialize fine
        // (#[serde(default)]) and simply not emit a Domain entity.
        let body = resp(
            r#"{"success": true, "latitude": -27.4766, "longitude": 153.0166,
                "connection": { "isp": "Cloudflare Inc", "org": "APNIC Research", "asn": 13335 }}"#,
        );
        assert!(body.connection.as_ref().unwrap().domain.is_none());
        let ents = build_entities(&body, "1.1.1.1", "s");
        assert!(of_kind(&ents, EntityKind::Domain).is_none());
    }

    #[test]
    fn blank_connection_domain_yields_no_domain_entity() {
        let body = resp(
            r#"{"success": true, "latitude": -27.4766, "longitude": 153.0166,
                "connection": { "org": "APNIC Research", "asn": 13335, "domain": "" }}"#,
        );
        let ents = build_entities(&body, "1.1.1.1", "s");
        assert!(of_kind(&ents, EntityKind::Domain).is_none());
    }

    #[test]
    fn no_coords_still_yields_org_and_asn() {
        // No lat/lon at all: the coords block is skipped, but the connection
        // still produces Organisation + ASN entities.
        let body = resp(r#"{"success": true, "connection": {"org": "Telstra", "asn": 1221}}"#);
        let ents = build_entities(&body, "1.2.3.4", "s");
        assert!(of_kind(&ents, EntityKind::Coordinates).is_none());
        assert_eq!(
            of_kind(&ents, EntityKind::Organisation).unwrap().value,
            "Telstra"
        );
        assert_eq!(of_kind(&ents, EntityKind::Asn).unwrap().value, "AS1221");
    }
