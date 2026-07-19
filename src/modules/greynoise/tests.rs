use super::*;

    #[test]
    fn accepts_ip_only() {
        let m = GreyNoise;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Username, "user")));
    }

    #[test]
    fn module_metadata() {
        let m = GreyNoise;
        assert_eq!(m.name(), "greynoise");
        assert_eq!(m.priority(), 30);
        assert_eq!(
            m.description(),
            "GreyNoise IP reputation — classifies internet noise and RIOT status (paid v3/ip lookup when keyed)"
        );
        // Free by default (Community tier); a configured key upgrades to the
        // paid v3/ip lookup instead of gating the module off entirely.
        assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    }

    #[test]
    fn response_deserialization_full() {
        let json = r#"{
            "ip": "8.8.8.8",
            "noise": true,
            "riot": true,
            "classification": "benign",
            "name": "Google Public DNS",
            "link": "https://viz.greynoise.io/ip/8.8.8.8",
            "message": "Success"
        }"#;
        let resp: CommunityResp = serde_json::from_str(json).unwrap();
        assert!(resp.noise);
        assert!(resp.riot);
        assert_eq!(resp.classification.as_deref(), Some("benign"));
        assert_eq!(resp.name.as_deref(), Some("Google Public DNS"));
        assert_eq!(
            resp.link.as_deref(),
            Some("https://viz.greynoise.io/ip/8.8.8.8")
        );
        assert_eq!(resp.message.as_deref(), Some("Success"));
    }

    #[test]
    fn response_deserialization_minimal() {
        // GreyNoise returns a minimal body for IPs not in its dataset.
        let json = r#"{
            "ip": "192.168.1.1",
            "noise": false,
            "riot": false,
            "message": "IP not observed scanning the internet or contained in RIOT data set."
        }"#;
        let resp: CommunityResp = serde_json::from_str(json).unwrap();
        assert!(!resp.noise);
        assert!(!resp.riot);
        assert!(resp.classification.is_none());
        assert!(resp.name.is_none());
        assert!(resp.link.is_none());
    }

    #[test]
    fn response_deserialization_malicious() {
        let json = r#"{
            "ip": "71.6.135.131",
            "noise": true,
            "riot": false,
            "classification": "malicious",
            "name": "unknown",
            "link": "https://viz.greynoise.io/ip/71.6.135.131"
        }"#;
        let resp: CommunityResp = serde_json::from_str(json).unwrap();
        assert!(resp.noise);
        assert!(!resp.riot);
        assert_eq!(resp.classification.as_deref(), Some("malicious"));
    }

    // ── build_entities (pure extraction) ───────────────────────────────

    fn resp(json: &str) -> CommunityResp {
        serde_json::from_str(json).expect("fixture is valid CommunityResp JSON")
    }
    fn of_kind(ents: &[Entity], kind: EntityKind) -> Option<&Entity> {
        ents.iter().find(|e| e.kind == kind)
    }

    #[test]
    fn benign_riot_record_yields_subject_and_operator() {
        let body = resp(
            r#"{
                "noise": true, "riot": true, "classification": "benign",
                "name": "Google Public DNS",
                "link": "https://viz.greynoise.io/ip/8.8.8.8",
                "message": "Success"
            }"#,
        );
        let ents = build_entities(&body, "8.8.8.8", "s");
        assert_eq!(ents.len(), 2);

        let subject = of_kind(&ents, EntityKind::IpAddress).expect("subject IP entity");
        // benign → 0.70
        assert!((subject.confidence - 0.70).abs() < 1e-9);
        assert!(subject.has_tag("greynoise-noise"));
        assert!(subject.has_tag("greynoise-riot"));
        assert!(subject.has_tag("greynoise-benign"));
        assert!(!subject.has_tag(crate::core::tags::MALICIOUS));

        let ev = &subject.evidence[0];
        let attr = |k: &str| ev.attributes.get(k).map(String::as_str);
        assert_eq!(attr("classification"), Some("benign"));
        assert_eq!(attr("noise"), Some("true"));
        assert_eq!(attr("riot"), Some("true"));
        assert_eq!(attr("name"), Some("Google Public DNS"));
        assert_eq!(attr("link"), Some("https://viz.greynoise.io/ip/8.8.8.8"));
        assert_eq!(attr("message"), Some("Success"));

        let org = of_kind(&ents, EntityKind::Organisation).expect("operator Organisation");
        assert_eq!(org.value, "Google Public DNS");
        assert!(org.has_tag("greynoise") && org.has_tag("ip-operator"));
        assert_eq!(
            org.evidence[0].attributes.get("ip").map(String::as_str),
            Some("8.8.8.8")
        );
    }

    #[test]
    fn malicious_record_tags_malicious_and_scores_high() {
        let body = resp(
            r#"{ "noise": true, "riot": false, "classification": "malicious" }"#,
        );
        let subject = build_entities(&body, "71.6.135.131", "s").remove(0);
        // malicious → 0.80
        assert!((subject.confidence - 0.80).abs() < 1e-9);
        assert!(subject.has_tag(crate::core::tags::MALICIOUS));
        assert!(subject.has_tag("greynoise-malicious"));
        assert!(subject.has_tag("greynoise-noise"));
        assert!(!subject.has_tag("greynoise-riot"));
    }

    #[test]
    fn no_finding_record_yields_nothing() {
        // 200 with only a message (IP not in the dataset) → empty.
        let body = resp(
            r#"{ "noise": false, "riot": false,
                 "message": "IP not observed scanning the internet or contained in RIOT data set." }"#,
        );
        assert!(build_entities(&body, "192.168.1.1", "s").is_empty());
    }

    #[test]
    fn noise_only_without_classification_is_unknown_band() {
        let body = resp(r#"{ "noise": true, "riot": false }"#);
        let subject = build_entities(&body, "1.2.3.4", "s").remove(0);
        // No classification → 0.55 and the unknown tag.
        assert!((subject.confidence - 0.55).abs() < 1e-9);
        assert!(subject.has_tag("greynoise-noise"));
        assert!(subject.has_tag("greynoise-unknown"));
        // Evidence falls back to the literal "unknown" classification.
        assert_eq!(
            subject.evidence[0]
                .attributes
                .get("classification")
                .map(String::as_str),
            Some("unknown")
        );
    }

    #[test]
    fn unknown_operator_name_yields_no_organisation() {
        // name == "unknown" (case-insensitively) must not become an Organisation.
        let body = resp(
            r#"{ "noise": true, "riot": false, "classification": "malicious", "name": "Unknown" }"#,
        );
        let ents = build_entities(&body, "71.6.135.131", "s");
        assert!(
            of_kind(&ents, EntityKind::Organisation).is_none(),
            "an \"unknown\" operator name must not become an Organisation pivot"
        );
    }

    #[test]
    fn short_operator_name_yields_no_organisation() {
        // A 1-char name is below the >=2 usable-name threshold.
        let body = resp(r#"{ "riot": true, "name": "X" }"#);
        let ents = build_entities(&body, "9.9.9.9", "s");
        assert!(of_kind(&ents, EntityKind::Organisation).is_none());
    }

    #[test]
    fn blank_evidence_fields_are_skipped() {
        // Empty name/link/message strings must not become evidence attributes.
        let body = resp(
            r#"{ "noise": true, "riot": false, "classification": "benign",
                 "name": "", "link": "", "message": "" }"#,
        );
        let subject = build_entities(&body, "1.2.3.4", "s").remove(0);
        let ev = &subject.evidence[0];
        assert!(!ev.attributes.contains_key("name"));
        assert!(!ev.attributes.contains_key("link"));
        assert!(!ev.attributes.contains_key("message"));
        // The core booleans/classification attrs are still present.
        assert_eq!(
            ev.attributes.get("classification").map(String::as_str),
            Some("benign")
        );
    }

    // ── Paid v3/ip path (regression: the configured key used to be
    // completely unused — the module always called the free Community
    // endpoint regardless) ──────────────────────────────────────────

    #[test]
    fn paid_response_deserialization() {
        // Same field shape `api_key_probe`'s own GreyNoise probe confirms this
        // endpoint returns (`ip` + `seen` alongside the community fields).
        let json = r#"{
            "ip": "71.6.135.131",
            "seen": true,
            "noise": true,
            "riot": false,
            "classification": "malicious",
            "name": "unknown",
            "link": "https://viz.greynoise.io/ip/71.6.135.131"
        }"#;
        let resp: PaidResp = serde_json::from_str(json).unwrap();
        assert!(resp.seen);
        assert!(resp.noise);
        assert!(!resp.riot);
        assert_eq!(resp.classification.as_deref(), Some("malicious"));
    }

    fn paid_resp(json: &str) -> PaidResp {
        serde_json::from_str(json).expect("fixture is valid PaidResp JSON")
    }

    #[test]
    fn paid_path_tags_seen_in_addition_to_the_shared_signal() {
        let body = paid_resp(
            r#"{ "seen": true, "noise": true, "riot": false, "classification": "malicious" }"#,
        );
        let subject = build_paid_entities(&body, "71.6.135.131", "s").remove(0);
        assert!((subject.confidence - 0.80).abs() < 1e-9);
        assert!(subject.has_tag("greynoise-seen"));
        assert!(subject.has_tag("greynoise-malicious"));
        assert!(subject.has_tag(crate::core::tags::MALICIOUS));
    }

    #[test]
    fn paid_path_surfaces_a_seen_but_otherwise_unclassified_ip() {
        // The community tier would gate this to nothing (no noise/riot/
        // classification) — the paid tier's confirmed `seen` is its own
        // positive signal, so the record must still surface.
        let body = paid_resp(r#"{ "seen": true, "noise": false, "riot": false }"#);
        let ents = build_paid_entities(&body, "9.9.9.9", "s");
        assert_eq!(ents.len(), 1, "a seen-only record must still surface: {ents:?}");
        let subject = &ents[0];
        // No classification → 0.55 unknown band, same as the community path.
        assert!((subject.confidence - 0.55).abs() < 1e-9);
        assert!(subject.has_tag("greynoise-seen"));
        assert!(subject.has_tag("greynoise-unknown"));
    }

    #[test]
    fn paid_path_no_signal_at_all_yields_nothing() {
        let body = paid_resp(r#"{ "seen": false, "noise": false, "riot": false }"#);
        assert!(build_paid_entities(&body, "192.168.1.1", "s").is_empty());
    }

    #[test]
    fn paid_path_still_yields_the_operator_organisation_pivot() {
        let body = paid_resp(
            r#"{ "seen": true, "noise": true, "riot": true, "classification": "benign",
                 "name": "Google Public DNS" }"#,
        );
        let ents = build_paid_entities(&body, "8.8.8.8", "s");
        let org = ents
            .iter()
            .find(|e| e.kind == EntityKind::Organisation)
            .expect("operator Organisation");
        assert_eq!(org.value, "Google Public DNS");
    }
