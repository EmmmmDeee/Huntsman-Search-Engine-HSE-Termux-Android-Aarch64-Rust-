use crate::core::confidence;
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
        let r: IpApiResp = serde_json::from_str(json).expect("should succeed");
        assert_eq!(r.status, "success");
        assert_eq!(r.country.as_deref(), Some("Australia"));
        assert_eq!(r.country_code.as_deref(), Some("AU"));
        assert_eq!(r.city.as_deref(), Some("Brisbane"));
        assert!((r.lat.expect("should succeed") - (-27.4679)).abs() < 0.001);
        assert!((r.lon.expect("should succeed") - 153.0281).abs() < 0.001);
        assert_eq!(r.isp.as_deref(), Some("Telstra"));
        assert_eq!(r.mobile, Some(false));
        assert_eq!(r.proxy, Some(false));
        assert_eq!(r.hosting, Some(false));
    }

    #[test]
    fn deserialize_fail_response() {
        let json = r#"{"status":"fail","message":"invalid query"}"#;
        let r: IpApiResp = serde_json::from_str(json).expect("should succeed");
        assert_eq!(r.status, "fail");
        assert!(r.country.is_none());
    }

    #[test]
    fn deserialize_proxy_hosting_flags() {
        let json = r#"{"status":"success","country":"US","lat":37.7,"lon":-122.4,"mobile":false,"proxy":true,"hosting":true}"#;
        let r: IpApiResp = serde_json::from_str(json).expect("should succeed");
        assert_eq!(r.proxy, Some(true));
        assert_eq!(r.hosting, Some(true));
    }

    #[test]
    fn deserialize_mobile_flag() {
        let json = r#"{"status":"success","country":"AU","lat":-33.8,"lon":151.2,"mobile":true,"proxy":false,"hosting":false}"#;
        let r: IpApiResp = serde_json::from_str(json).expect("should succeed");
        assert_eq!(r.mobile, Some(true));
    }

    #[test]
    fn deserialize_missing_optional_fields() {
        let json = r#"{"status":"success"}"#;
        let r: IpApiResp = serde_json::from_str(json).expect("should succeed");
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

    // ── build_entities (pure extraction) ───────────────────────────────

    fn resp(json: &str) -> IpApiResp {
        serde_json::from_str(json).expect("fixture is valid IpApiResp JSON")
    }
    fn of_kind(ents: &[Entity], kind: EntityKind) -> Option<&Entity> {
        ents.iter().find(|e| e.kind == kind)
    }

    #[test]
    fn full_residential_record_yields_coords_address_asn_and_org() {
        let body = resp(
            r#"{"status":"success","country":"Australia","countryCode":"AU",
                "regionName":"Queensland","city":"Brisbane","zip":"4000",
                "lat":-27.4679,"lon":153.0281,"timezone":"Australia/Brisbane",
                "isp":"Telstra","org":"Telstra Corp","as":"AS1221 Telstra",
                "mobile":false,"proxy":false,"hosting":false}"#,
        );
        let ents = build_entities(&body, "1.2.3.4", "s");
        assert_eq!(ents.len(), 4);

        let coords = of_kind(&ents, EntityKind::Coordinates).expect("Coordinates entity");
        // coarse_provider_coords formats raw to 4 dp; Entity::new normalises to 6.
        assert_eq!(coords.value, "-27.467900,153.028100");
        // Residential (no proxy/hosting/mobile) → confidence::MEDIUM_PLUS.
        assert!((coords.confidence - confidence::MEDIUM_PLUS).abs() < 1e-9);
        assert!(coords.has_tag("geoint"));
        assert!(coords.has_tag("country:AU"));
        assert!(coords.has_tag("au-relevant"), "shared coarse builder tags AU box");
        assert!(coords.has_tag("au-state:QLD"));
        assert!(!coords.has_tag("proxy") && !coords.has_tag("hosting"));
        let attr = |k: &str| coords.evidence[0].attributes.get(k).map(String::as_str);
        assert_eq!(attr("country"), Some("Australia"));
        assert_eq!(attr("region"), Some("Queensland"));
        assert_eq!(attr("city"), Some("Brisbane"));
        assert_eq!(attr("country_code"), Some("AU"));
        assert_eq!(attr("zip"), Some("4000"));
        assert_eq!(attr("timezone"), Some("Australia/Brisbane"));
        assert_eq!(attr("isp"), Some("Telstra"));
        assert_eq!(attr("asn"), Some("AS1221 Telstra"));
        assert_eq!(attr("is_proxy"), Some("false"));
        assert_eq!(attr("source"), Some("ip-api.com"));

        let addr = of_kind(&ents, EntityKind::Address).expect("Address entity");
        assert_eq!(addr.value, "Brisbane, Queensland, Australia");
        assert!(addr.has_tag("geoint"));

        assert_eq!(of_kind(&ents, EntityKind::Asn).expect("should succeed").value, "AS1221 Telstra");

        let org = of_kind(&ents, EntityKind::Organisation).expect("Organisation");
        assert_eq!(org.value, "Telstra Corp");
        let oattr = |k: &str| org.evidence[0].attributes.get(k).map(String::as_str);
        assert_eq!(oattr("asn"), Some("AS1221 Telstra"));
        assert_eq!(oattr("isp"), Some("Telstra"));
        assert_eq!(oattr("country_code"), Some("AU"));
    }

    #[test]
    fn non_success_status_yields_nothing() {
        let body = resp(r#"{"status":"fail","message":"invalid query","lat":1.0,"lon":1.0}"#);
        assert!(build_entities(&body, "1.2.3.4", "s").is_empty());
    }

    #[test]
    fn cdn_edge_ip_is_skipped_entirely() {
        // 151.101.0.1 ∈ Fastly 151.101.0.0/16 — geo belongs to the datacenter.
        let body = resp(
            r#"{"status":"success","country":"United States","city":"San Francisco",
                "lat":37.77,"lon":-122.42,"as":"AS54113 Fastly"}"#,
        );
        assert!(build_entities(&body, "151.101.0.1", "s").is_empty());
    }

    #[test]
    fn datacenter_ip_emits_coords_but_suppresses_address() {
        // proxy/hosting → lower confidence and NO Address (the server's, not
        // the subject's), but the coords/ASN/org still emit.
        let body = resp(
            r#"{"status":"success","country":"United States","regionName":"California",
                "city":"San Francisco","lat":37.7749,"lon":-122.4194,
                "as":"AS13335 Cloudflare","org":"Cloudflare Inc",
                "mobile":false,"proxy":true,"hosting":true}"#,
        );
        let ents = build_entities(&body, "203.confidence::MEDIUM_HIGH.55", "s");

        let coords = of_kind(&ents, EntityKind::Coordinates).expect("Coordinates entity");
        // hosting/proxy → 0.35.
        assert!((coords.confidence - 0.35).abs() < 1e-9);
        assert!(coords.has_tag("proxy") && coords.has_tag("hosting"));
        assert!(coords.has_tag("off-region"), "US fix → off-region");

        assert!(
            of_kind(&ents, EntityKind::Address).is_none(),
            "a datacenter/proxy IP must not synthesise a subject Address"
        );
        assert!(of_kind(&ents, EntityKind::Asn).is_some());
        assert!(of_kind(&ents, EntityKind::Organisation).is_some());
    }

    #[test]
    fn mobile_ip_scores_mid_band() {
        let body = resp(
            r#"{"status":"success","country":"AU","countryCode":"AU","city":"Sydney",
                "lat":-33.8688,"lon":151.2093,"mobile":true,"proxy":false,"hosting":false}"#,
        );
        let coords = build_entities(&body, "1.2.3.4", "s")
            .into_iter()
            .find(|e| e.kind == EntityKind::Coordinates)
            .expect("Coordinates entity");
        // mobile → confidence::MEDIUM.
        assert!((coords.confidence - confidence::MEDIUM).abs() < 1e-9);
        assert!(coords.has_tag("mobile"));
        assert!(coords.has_tag("au-state:NSW"), "Sydney → NSW box");
    }

    #[test]
    fn null_island_coords_dropped_but_other_entities_survive() {
        // Implausible (null-island) fix → no Coordinates, yet a residential
        // record still emits its Address/ASN/org.
        let body = resp(
            r#"{"status":"success","country":"Ghana","regionName":"Greater Accra",
                "city":"Accra","lat":0.0,"lon":0.0,"as":"AS30986",
                "org":"Some ISP","mobile":false,"proxy":false,"hosting":false}"#,
        );
        let ents = build_entities(&body, "8.8.4.4", "s");
        assert!(
            of_kind(&ents, EntityKind::Coordinates).is_none(),
            "Null Island must not become Coordinates"
        );
        let addr = of_kind(&ents, EntityKind::Address).expect("Address survives");
        assert_eq!(addr.value, "Accra, Greater Accra, Ghana");
        assert_eq!(of_kind(&ents, EntityKind::Asn).expect("should succeed").value, "AS30986");
        assert!(of_kind(&ents, EntityKind::Organisation).is_some());
    }

    #[test]
    fn address_without_region_uses_city_country() {
        let body = resp(
            r#"{"status":"success","country":"Australia","city":"Brisbane",
                "mobile":false,"proxy":false,"hosting":false}"#,
        );
        let ents = build_entities(&body, "1.2.3.4", "s");
        let addr = of_kind(&ents, EntityKind::Address).expect("Address entity");
        assert_eq!(addr.value, "Brisbane, Australia");
    }

    #[test]
    fn blank_org_evidence_fields_skipped() {
        // Empty isp/country_code must not become attributes on the org evidence;
        // the always-present `asn` placeholder stays.
        let body = resp(
            r#"{"status":"success","org":"Telstra Corp","isp":"","countryCode":"",
                "mobile":false,"proxy":false,"hosting":false}"#,
        );
        let org = build_entities(&body, "1.2.3.4", "s")
            .into_iter()
            .find(|e| e.kind == EntityKind::Organisation)
            .expect("Organisation entity");
        let attrs = &org.evidence[0].attributes;
        assert!(!attrs.contains_key("isp"), "blank isp must be skipped");
        assert!(
            !attrs.contains_key("country_code"),
            "blank country_code must be skipped"
        );
        // The ASN placeholder is always written (no asn → "-").
        assert_eq!(attrs.get("asn").map(String::as_str), Some("-"));
    }
