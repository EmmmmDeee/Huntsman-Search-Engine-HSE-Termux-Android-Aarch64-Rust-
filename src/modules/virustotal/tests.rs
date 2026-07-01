use super::*;
    use crate::core::entity::EntityKind;

    fn build(json: &str) -> Entity {
        let r: VtResponse = serde_json::from_str(json).unwrap();
        let attrs = r.data.unwrap().attributes.unwrap();
        build_entity(
            &Target::new(TargetKind::Domain, "evil.example"),
            &attrs,
            "s",
        )
    }

    #[test]
    fn module_metadata() {
        let m = VirusTotal;
        assert_eq!(m.name(), "virustotal");
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(matches!(m.cost(), ModuleCost::KeyGated));
    }

    #[test]
    fn malicious_detections_tag_and_scale_confidence() {
        let e = build(
            r#"{"data":{"attributes":{"last_analysis_stats":
                {"malicious":9,"suspicious":1,"undetected":80,"harmless":10},"reputation":5}}}"#,
        );
        assert_eq!(e.kind, EntityKind::Domain);
        assert!(
            e.has_tag(crate::core::tags::MALICIOUS)
                && e.has_tag(crate::core::tags::THREAT_INTEL)
                && e.has_tag("virustotal")
        );
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
        assert!(
            !e.has_tag(crate::core::tags::MALICIOUS)
                && !e.has_tag(crate::core::tags::THREAT_INTEL)
        );
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
        for t in [
            crate::core::tags::MALICIOUS,
            crate::core::tags::THREAT_INTEL,
            "suspicious",
            "low-reputation",
        ] {
            assert!(!e.has_tag(t), "clean entity must not be tagged {t}");
        }
    }

    #[test]
    fn empty_attributes_stay_at_baseline_without_phantom_reputation() {
        let e = build(r#"{"data":{"attributes":{}}}"#);
        assert!((e.confidence - 0.50).abs() < 1e-6);
        let ev = &e.evidence[0];
        assert_eq!(
            ev.attributes.get("total_engines").map(String::as_str),
            Some("0")
        );
        // No stats → no breakdown attrs; absent reputation → no phantom "0".
        assert!(!ev.attributes.contains_key("undetected"));
        assert!(!ev.attributes.contains_key("reputation"));
    }
