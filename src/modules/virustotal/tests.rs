use super::*;
    use crate::core::entity::EntityKind;

    fn build_all(target: &Target, json: &str) -> Vec<Entity> {
        let r: VtResponse = serde_json::from_str(json).unwrap();
        let attrs = r.data.unwrap().attributes.unwrap();
        build_entities(target, &attrs, "s")
    }

    /// The scanned entity is always element 0.
    fn build(json: &str) -> Entity {
        let target = Target::new(TargetKind::Domain, "evil.example");
        build_all(&target, json).into_iter().next().unwrap()
    }

    #[test]
    fn module_metadata() {
        let m = VirusTotal;
        assert_eq!(m.name(), "virustotal");
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(matches!(m.cost(), ModuleCost::KeyGated));
        // produces() must declare every kind the builder can emit.
        for k in [
            EntityKind::Domain,
            EntityKind::IpAddress,
            EntityKind::Asn,
            EntityKind::Organisation,
            EntityKind::Address,
        ] {
            assert!(m.produces().contains(&k), "produces() missing {k:?}");
        }
    }

    #[test]
    fn malicious_detections_tag_and_scale_confidence() {
        let e = build(
            r#"{"data":{"attributes":{"last_analysis_stats":
                {"malicious":9,"suspicious":1,"undetected":80,"harmless":10},"reputation":5}}}"#,
        );
        assert_eq!(e.kind, EntityKind::Domain);
        assert!(e.has_tag("malicious") && e.has_tag("threat-intel") && e.has_tag("virustotal"));
        assert!(e.has_tag("suspicious")); // surfaced even alongside malicious
        // confidence = 0.50 + (9/100)*0.45 = 0.5405
        assert!((e.confidence - 0.5405).abs() < 1e-6);
        let ev = &e.evidence[0];
        assert_eq!(
            ev.attributes.get("malicious").map(String::as_str),
            Some("9")
        );
        assert_eq!(
            ev.attributes.get("total_engines").map(String::as_str),
            Some("100")
        );
        // The full breakdown the old code discarded:
        assert_eq!(
            ev.attributes.get("suspicious").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            ev.attributes.get("undetected").map(String::as_str),
            Some("80")
        );
        assert_eq!(
            ev.attributes.get("harmless").map(String::as_str),
            Some("10")
        );
        assert_eq!(
            ev.attributes.get("reputation").map(String::as_str),
            Some("5")
        );
    }

    #[test]
    fn suspicious_only_is_flagged_without_malicious() {
        // The exact case the old `if malicious > 0` gate silently dropped.
        let e = build(
            r#"{"data":{"attributes":{"last_analysis_stats":
                {"malicious":0,"suspicious":4,"undetected":90,"harmless":6}}}}"#,
        );
        assert!(e.has_tag("suspicious"));
        assert!(!e.has_tag("malicious") && !e.has_tag("threat-intel"));
        assert!((e.confidence - 0.50).abs() < 1e-6); // no malicious → baseline
    }

    #[test]
    fn strongly_negative_reputation_is_tagged() {
        let bad = build(r#"{"data":{"attributes":{"reputation":-42}}}"#);
        assert!(bad.has_tag("low-reputation"));
        let ok = build(r#"{"data":{"attributes":{"reputation":-3}}}"#);
        assert!(!ok.has_tag("low-reputation"));
    }

    #[test]
    fn clean_entity_carries_only_the_source_tag() {
        let e = build(
            r#"{"data":{"attributes":{"last_analysis_stats":
                {"malicious":0,"suspicious":0,"undetected":95,"harmless":5},"reputation":10}}}"#,
        );
        assert!(e.has_tag("virustotal"));
        for t in ["malicious", "threat-intel", "suspicious", "low-reputation"] {
            assert!(!e.has_tag(t), "clean entity must not be tagged {t}");
        }
    }

    #[test]
    fn empty_attributes_stay_at_baseline_without_phantom_reputation() {
        let target = Target::new(TargetKind::Domain, "evil.example");
        let entities = build_all(&target, r#"{"data":{"attributes":{}}}"#);
        // No network/DNS fields → only the scanned entity, no phantom pivots.
        assert_eq!(entities.len(), 1);
        let e = &entities[0];
        assert!((e.confidence - 0.50).abs() < 1e-6);
        let ev = &e.evidence[0];
        assert_eq!(
            ev.attributes.get("total_engines").map(String::as_str),
            Some("0")
        );
        // No stats → no breakdown attrs; absent reputation → no phantom "0".
        assert!(!ev.attributes.contains_key("undetected"));
        assert!(!ev.attributes.contains_key("reputation"));
        assert!(!ev.attributes.contains_key("asn"));
    }

    #[test]
    fn ip_record_surfaces_owner_asn_and_country_pivots() {
        let target = Target::new(TargetKind::IpAddress, "1.1.1.1");
        let entities = build_all(
            &target,
            r#"{"data":{"attributes":{
                "last_analysis_stats":{"malicious":0,"suspicious":0,"undetected":90,"harmless":4},
                "as_owner":"CLOUDFLARENET","asn":13335,"network":"1.1.1.0/24","country":"us"}}}"#,
        );
        // Scanned IP carries the ownership attrs as evidence + a country tag.
        let scanned = &entities[0];
        assert_eq!(scanned.kind, EntityKind::IpAddress);
        assert!(scanned.has_tag("country:US"));
        let ev = &scanned.evidence[0];
        assert_eq!(
            ev.attributes.get("as_owner").map(String::as_str),
            Some("CLOUDFLARENET")
        );
        assert_eq!(ev.attributes.get("asn").map(String::as_str), Some("13335"));
        assert_eq!(
            ev.attributes.get("network").map(String::as_str),
            Some("1.1.1.0/24")
        );
        assert_eq!(ev.attributes.get("country").map(String::as_str), Some("us"));

        // Organisation pivot.
        let org = entities
            .iter()
            .find(|e| e.kind == EntityKind::Organisation)
            .expect("Organisation pivot");
        assert_eq!(org.value, "CLOUDFLARENET");
        assert!(org.has_tag("hosting") && org.has_tag("virustotal"));

        // Asn pivot, normalised to AS-prefixed label, carrying network.
        let asn = entities
            .iter()
            .find(|e| e.kind == EntityKind::Asn)
            .expect("Asn pivot");
        assert_eq!(asn.value, "AS13335");
        assert_eq!(
            asn.evidence[0].attributes.get("network").map(String::as_str),
            Some("1.1.1.0/24")
        );

        // Address pivot from country, uppercased + coarse geoint.
        let addr = entities
            .iter()
            .find(|e| e.kind == EntityKind::Address)
            .expect("Address pivot");
        assert_eq!(addr.value, "US");
        assert!(addr.has_tag("geoint") && addr.has_tag("coarse"));
    }

    #[test]
    fn passive_dns_records_become_ip_and_domain_pivots() {
        let target = Target::new(TargetKind::Domain, "evil.example");
        let entities = build_all(
            &target,
            r#"{"data":{"attributes":{"last_dns_records":[
                {"type":"A","value":"203.0.113.5"},
                {"type":"AAAA","value":"2001:db8::1"},
                {"type":"MX","value":"10 mail.evil.example."},
                {"type":"NS","value":"ns1.evil.example"},
                {"type":"CNAME","value":"cdn.example.net"},
                {"type":"TXT","value":"v=spf1 -all"},
                {"type":"A","value":"not-an-ip"}
            ]}}}"#,
        );
        let ips: Vec<&str> = entities
            .iter()
            .filter(|e| e.kind == EntityKind::IpAddress)
            .map(|e| e.value.as_str())
            .collect();
        assert!(ips.contains(&"203.0.113.5") && ips.contains(&"2001:db8::1"));
        assert!(!ips.contains(&"not-an-ip")); // non-parseable A rejected

        // Skip element 0 (the scanned target, itself a Domain).
        let pivots: Vec<&Entity> = entities[1..]
            .iter()
            .filter(|e| e.kind == EntityKind::Domain)
            .collect();
        let domains: Vec<&str> = pivots.iter().map(|e| e.value.as_str()).collect();
        // MX hostname extracted from "10 mail.evil.example".
        assert!(domains.contains(&"mail.evil.example"));
        assert!(domains.contains(&"ns1.evil.example"));
        assert!(domains.contains(&"cdn.example.net"));

        for e in &pivots {
            assert!(e.has_tag("passive-dns"));
        }
        for e in entities.iter().filter(|e| e.kind == EntityKind::IpAddress) {
            assert!(e.has_tag("resolved"));
        }
    }

    #[test]
    fn crowd_tags_and_categories_surface() {
        let e = build(
            r#"{"data":{"attributes":{
                "tags":["phishing","malware"],
                "categories":{"BitDefender":"malware","Forcepoint":"phishing","X":"malware"}}}}"#,
        );
        assert!(e.has_tag("vt:phishing") && e.has_tag("vt:malware"));
        let ev = &e.evidence[0];
        assert_eq!(
            ev.attributes.get("tags").map(String::as_str),
            Some("phishing,malware")
        );
        // Distinct, sorted category values.
        assert_eq!(
            ev.attributes.get("categories").map(String::as_str),
            Some("malware,phishing")
        );
    }
