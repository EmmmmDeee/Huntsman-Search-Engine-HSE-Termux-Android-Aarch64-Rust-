use super::*;

    fn phone(v: &str) -> Target {
        Target::new(TargetKind::Phone, v)
    }

    #[test]
    fn build_entity_emits_region_with_carrier_evidence() {
        let r = NvResp {
            valid: true,
            country_code: Some("AU".into()),
            country_name: Some("Australia".into()),
            location: Some("Queensland".into()),
            carrier: Some("Telstra".into()),
            line_type: Some("mobile".into()),
            international_format: Some("+61400000000".into()),
            ..Default::default()
        };
        let entities = build_entities(&r, &phone("+61400000000"), "scan");
        let e = entities.iter().find(|e| e.kind == EntityKind::Address).expect("should succeed");
        assert_eq!(e.value, "Queensland, Australia");
        assert!(
            e.has_tag("phone-region") && e.has_tag("carrier-known") && e.has_tag("line:mobile")
        );
        let attr = |k: &str| e.evidence[0].attributes.get(k).cloned().unwrap_or_default();
        assert_eq!(attr("carrier"), "Telstra");
        assert_eq!(attr("line_type"), "mobile");
        assert_eq!(attr("country_code"), "AU");
        // Carrier Organisation entity should also be emitted.
        let org = entities.iter().find(|e| e.kind == EntityKind::Organisation).expect("should succeed");
        assert_eq!(org.value, "Telstra");
        assert!(org.has_tag("carrier"));
    }

    #[test]
    fn invalid_number_yields_nothing() {
        let r = NvResp {
            valid: false,
            ..Default::default()
        };
        assert!(build_entities(&r, &phone("+61400000000"), "scan").is_empty());
        // A body without `valid` is not a confirmed-valid number either.
        let silent: NvResp = serde_json::from_str("{}").expect("an empty object decodes");
        assert!(build_entities(&silent, &phone("+61400000000"), "scan").is_empty());
    }

    #[test]
    fn country_only_still_geolocates() {
        let r = NvResp {
            valid: true,
            country_name: Some("Australia".into()),
            ..Default::default()
        };
        let entities = build_entities(&r, &phone("+61400000000"), "scan");
        let e = entities.iter().find(|e| e.kind == EntityKind::Address).expect("should succeed");
        assert_eq!(e.value, "Australia");
    }

    #[test]
    fn metadata_is_keygated_phone() {
        let m = NumVerify;
        assert_eq!(m.cost(), ModuleCost::KeyGated);
        assert_eq!(m.category(), ModuleCategory::Phone);
        assert!(m.accepts(&Target::new(TargetKind::Phone, "+61400000000")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }

    #[test]
    fn module_metadata_full() {
        let m = NumVerify;
        assert_eq!(m.name(), "numverify");
        assert!(!m.description().is_empty());
        assert_eq!(m.max_timeout_ms(), 8_000);
        assert!(!m.attack_techniques().is_empty());
        assert!(m.produces().contains(&EntityKind::Address));
        assert!(m.produces().contains(&EntityKind::Organisation));
        // REQ-CRED-001: the validated subject Phone is minted here now, so the
        // capability map must say so (`contact_enrich` no longer declares it).
        assert!(m.produces().contains(&EntityKind::Phone));
    }

    #[test]
    fn build_entity_line_type_tag() {
        for lt in ["mobile", "landline", "voip"] {
            let r = NvResp {
                valid: true,
                country_name: Some("Australia".into()),
                location: Some("Queensland".into()),
                line_type: Some(lt.to_string()),
                ..Default::default()
            };
            let entities = build_entities(&r, &phone("+61400000000"), "s");
            let e = entities.iter().find(|e| e.kind == EntityKind::Address).expect("should succeed");
            assert!(e.has_tag(&format!("line:{lt}")), "missing line:{lt} tag");
        }
    }

    // ── REQ-CRED-001: the one Numverify caller ─────────────────────────────────

    /// The gateway's documented `/validate` sample response, verbatim from the
    /// vendor's API reference
    /// (marketplace.apilayer.com/code/response?service_name=number_verification&method=get&endpoint=/validate,
    /// read 2026-09-23). The same ten fields the legacy host returned, which is
    /// what lets this module mint everything `contact_enrich` used to.
    const GATEWAY_SAMPLE: &str = r#"{
  "carrier": "AT&T Mobility LLC",
  "country_code": "US",
  "country_name": "United States of America",
  "country_prefix": "+1",
  "international_format": "+14158586273",
  "line_type": "mobile",
  "local_format": "4158586273",
  "location": "Novato",
  "number": "14158586273",
  "valid": true
}"#;

    fn loopback_ctx() -> ModuleContext {
        let (bus, _rx) = tokio::sync::broadcast::channel(1);
        ModuleContext {
            scan_id: "s".into(),
            bus,
            // A plain client: `build_client()` filters loopback by design.
            http: reqwest::Client::new(),
            keys: std::collections::HashMap::new(),
            cancel: crate::core::cancel::CancelHandle::new(),
        }
    }

    /// REQ-CRED-001. A valid number confirms the subject `Phone` itself. This
    /// entity used to come from `contact_enrich`'s legacy-host leg, which was
    /// removed, so it must come from here or the capability is lost. No
    /// `transport:` tag or attribute: the only transport is HTTPS.
    #[test]
    fn a_valid_answer_confirms_the_subject_phone() {
        let r: NvResp = serde_json::from_str(GATEWAY_SAMPLE).expect("the vendor sample decodes");
        let ents = build_entities(&r, &phone("+14158586273"), "s");
        let p = ents
            .iter()
            .find(|e| e.kind == EntityKind::Phone)
            .expect("a valid answer confirms the subject phone");
        assert_eq!(p.value, "+14158586273", "the subject, as scanned");
        assert!((p.confidence - confidence::EXPERT).abs() < f64::EPSILON);
        assert!(p.has_tag("numverify") && p.has_tag("validated"));
        assert!(p.has_tag("country:US") && p.has_tag("line:mobile"));
        assert!(
            !p.tags.iter().any(|t| t.starts_with("transport:")),
            "HTTPS is the only transport; a transport tag can only mislead: {:?}",
            p.tags
        );
        let ev = &p.evidence[0];
        assert_eq!(ev.source, SRC);
        assert_eq!(ev.summary, "Numverify confirmed valid phone +14158586273");
        let attr = |k: &str| ev.attributes.get(k).map(String::as_str);
        assert_eq!(attr("normalised"), Some("14158586273"));
        assert_eq!(attr("international"), Some("+14158586273"));
        assert_eq!(attr("local"), Some("4158586273"));
        assert_eq!(attr("country_prefix"), Some("+1"));
        assert_eq!(attr("country"), Some("United States of America"));
        assert_eq!(attr("location"), Some("Novato"));
        assert_eq!(attr("carrier"), Some("AT&T Mobility LLC"));
        assert_eq!(attr("line_type"), Some("mobile"));
        assert_eq!(attr("transport"), None);
        // The region entities still follow the phone.
        let addr = ents
            .iter()
            .find(|e| e.kind == EntityKind::Address)
            .expect("region address");
        assert_eq!(addr.value, "Novato, United States of America");
    }

    /// REQ-CRED-001. A lower-cased country code is tagged upper-cased, and blank
    /// fields add no tag and no attribute. A valid answer with no region still
    /// confirms the phone.
    #[test]
    fn blank_fields_add_nothing_and_a_regionless_answer_still_confirms_the_phone() {
        let r: NvResp = serde_json::from_str(
            r#"{"valid":true,"country_code":"","line_type":"","carrier":"","number":""}"#,
        )
        .expect("decodes");
        let ents = build_entities(&r, &phone("+61400000000"), "s");
        assert_eq!(ents.len(), 1, "only the phone: no region, no carrier: {ents:?}");
        let p = &ents[0];
        assert_eq!(p.kind, EntityKind::Phone);
        assert!(!p.tags.iter().any(|t| t.starts_with("country:")));
        assert!(!p.tags.iter().any(|t| t.starts_with("line:")));
        assert!(
            p.evidence[0].attributes.is_empty(),
            "blank optional fields are dropped: {:?}",
            p.evidence[0].attributes
        );

        let lower: NvResp =
            serde_json::from_str(r#"{"valid":true,"country_code":"au"}"#).expect("decodes");
        let p = &build_entities(&lower, &phone("+61400000000"), "s")[0];
        assert!(p.has_tag("country:AU"), "country code is upper-cased: {:?}", p.tags);
    }

    /// Every entity minted from a Numverify answer names Numverify: one answer
    /// is one source (SOURCE COUNT ≠ SOURCE INDEPENDENCE). Moved here from
    /// `contact_enrich` with the phone entity (REQ-CRED-001).
    #[test]
    fn every_entity_minted_from_an_answer_is_attributed_to_numverify() {
        let r: NvResp = serde_json::from_str(GATEWAY_SAMPLE).expect("decodes");
        let ents = build_entities(&r, &phone("+14158586273"), "s");
        assert!(ents.len() >= 3, "phone, address and carrier at least: {ents:?}");
        for e in &ents {
            for ev in &e.evidence {
                assert_eq!(ev.source, SRC, "{:?} {} names `{}`", e.kind, e.value, ev.source);
            }
        }
    }

    /// REQ-CRED-001, on the real request path. The key travels in the `apikey`
    /// header and appears nowhere else in the request: not in the request line,
    /// not as `access_key=`. `contact_enrich` built
    /// `/api/validate?access_key=<KEY>&number=…`, a URL proxies and access logs
    /// record, and then resent it over plaintext.
    #[tokio::test]
    async fn the_key_travels_in_the_apikey_header_and_never_in_the_url() {
        use crate::util::http::test_server::{Canned, serve_recording};
        let (base, requests) = serve_recording(vec![Canned::json(200, GATEWAY_SAMPLE)]).await;
        let r = validate(&loopback_ctx(), &base, "nv-SECRET-key", "+14158586273")
            .await
            .expect("a 200 is an answer")
            .expect("a 200 is not the clean miss");
        assert!(r.valid, "the sample is a valid number");

        let heads = requests.lock().expect("request log").clone();
        assert_eq!(heads.len(), 1, "one request per validation: {heads:?}");
        let head = &heads[0];
        let request_line = head.lines().next().unwrap_or_default();
        assert_eq!(
            request_line, "GET /validate?number=%2B14158586273 HTTP/1.1",
            "the URL carries the number and nothing else"
        );
        assert!(
            head.to_ascii_lowercase().contains("\r\napikey: nv-secret-key\r\n"),
            "the key must travel in the `apikey` header: {head}"
        );
        assert_eq!(
            head.matches("nv-SECRET-key").count(),
            1,
            "the key appears once, in its header, and nowhere else: {head}"
        );
    }

    /// REQ-CRED-001. A failure is final: one request, and the error is
    /// returned. The removed `contact_enrich` leg answered ANY failure by
    /// resending the request elsewhere (plaintext `http://`). A 404 is the
    /// shared verdict's clean miss. A 200 `valid:false` is an answer that
    /// confirms nothing (the over-correction guard: a refusal to answer is not
    /// the only non-error outcome).
    #[tokio::test]
    async fn a_failure_is_never_retried_and_a_miss_or_invalid_number_is_an_answer() {
        use crate::util::http::test_server::{Canned, serve_recording};
        // A 5xx, not a 401/403/429: those would also burn the key in the
        // process-global pool, which `keyed_ok_or_404`'s own tests cover.
        let (base, requests) = serve_recording(vec![
            Canned::json(500, r#"{"message":"Internal Server Error"}"#),
            Canned::json(404, r#"{"message":"not found"}"#),
            Canned::json(200, r#"{"valid":false,"number":"61400000000"}"#),
        ])
        .await;
        let ctx = loopback_ctx();

        let err = validate(&ctx, &base, "k", "+61400000000")
            .await
            .expect_err("an outage is an error, not an answer");
        assert!(err.to_string().contains("500"), "{err}");
        assert_eq!(
            requests.lock().expect("request log").len(),
            1,
            "a failure must not be retried anywhere"
        );

        assert!(
            validate(&ctx, &base, "k", "+61400000000")
                .await
                .expect("a 404 is the clean miss")
                .is_none()
        );

        let invalid = validate(&ctx, &base, "k", "+61400000000")
            .await
            .expect("a 200 is an answer")
            .expect("a 200 is not the clean miss");
        assert!(!invalid.valid);
        assert!(build_entities(&invalid, &phone("+61400000000"), "s").is_empty());
        assert_eq!(requests.lock().expect("request log").len(), 3);
    }

    /// REQ-CRED-001. The one host is the HTTPS gateway: the host the `numverify`
    /// `ServiceDef` validates the key against, over the only scheme the vendor
    /// serves.
    #[test]
    fn the_one_numverify_host_is_the_https_gateway() {
        assert_eq!(API_BASE, "https://api.apilayer.com/number_verification");
        let def = crate::util::service_defs::find_service("numverify").expect("numverify def");
        assert!(
            def.test_url.starts_with(API_BASE),
            "the module and its ServiceDef must share one host: {}",
            def.test_url
        );
    }
