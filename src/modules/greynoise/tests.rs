use crate::core::confidence;
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
        let resp: CommunityResp = serde_json::from_str(json).expect("should succeed");
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
        let resp: CommunityResp = serde_json::from_str(json).expect("should succeed");
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
        let resp: CommunityResp = serde_json::from_str(json).expect("should succeed");
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
        // benign → confidence::HIGH_PLUS
        assert!((subject.confidence - confidence::HIGH_PLUS).abs() < 1e-9);
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
        // malicious → confidence::HIGH_PLUSPLUS
        assert!((subject.confidence - confidence::HIGH_PLUSPLUS).abs() < 1e-9);
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
        // No classification → confidence::MEDIUM_HIGH and the unknown tag.
        assert!((subject.confidence - confidence::MEDIUM_HIGH).abs() < 1e-9);
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
        let resp: PaidResp = serde_json::from_str(json).expect("should succeed");
        assert_eq!(resp.seen, Some(true));
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
        assert!((subject.confidence - confidence::HIGH_PLUSPLUS).abs() < 1e-9);
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
        // No classification → confidence::MEDIUM_HIGH unknown band, same as the community path.
        assert!((subject.confidence - confidence::MEDIUM_HIGH).abs() < 1e-9);
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

#[test]
fn last_seen_recency_flows_into_evidence() {
    let body = resp(
        r#"{
            "ip": "9.9.9.9",
            "noise": true,
            "riot": false,
            "classification": "malicious",
            "last_seen": "2026-01-02"
        }"#,
    );
    let ents = build_entities(&body, "9.9.9.9", "s");
    let subject = of_kind(&ents, EntityKind::IpAddress).expect("subject IP entity");
    let ev = &subject.evidence[0];
    assert_eq!(
        ev.attributes.get("last_seen").map(String::as_str),
        Some("2026-01-02"),
        "GreyNoise last_seen recency must surface in evidence"
    );
}

    #[test]
    fn an_unrecognised_paid_response_shape_is_a_failed_lookup_never_an_unobserved_ip() {
        // Backlog #22: every PaidResp field is defaulted, so a nested envelope
        // decoded to an all-false record and read as "never observed".
        let nested: PaidResp = serde_json::from_str(
            r#"{"ip":"8.8.8.8","business_service_intelligence":{"found":true,"name":"Google"},"internet_scanner_intelligence":{"found":false}}"#,
        )
        .expect("decodes to a defaulted record");
        let err = recognised(&nested).expect_err("no `seen`: the shape is not the one modelled");
        assert!(err.to_string().contains("does not recognise"), "{err}");
        assert!(
            build_paid_entities(&nested, "8.8.8.8", "s").is_empty(),
            "the old reading: an empty result, i.e. a clean negative"
        );
        let flat = paid_resp(r#"{"ip":"8.8.8.8","seen":false,"noise":false,"riot":true}"#);
        recognised(&flat).expect("the flat shape is recognised");
    }

// ── REQ-KEYFLOOR-001: a configured key never leaves the module worse than keyless ──

/// A loopback-only context holding a fresh key as the GreyNoise key, pooled
/// under `greynoise` so the refusal's burn is observable. Returns the key too.
fn keyed_ctx(tag: &str) -> (ModuleContext, String) {
    let key = format!(
        "keyfloor-greynoise-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    );
    assert!(
        crate::util::key_pool::global_pool()
            .add("greynoise", crate::util::key_pool::KeyEntry::new(key.clone())),
        "fixture: {key} must be new to the greynoise pool"
    );
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "s".into(),
        bus,
        http: reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("client"),
        keys: std::collections::HashMap::from([(KEY_ENV.to_string(), key.clone())]),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    (ctx, key)
}

const COMMUNITY_HIT: &str = r#"{"ip":"1.2.3.4","noise":true,"riot":false,"classification":"malicious","name":"unknown","link":"https://viz.greynoise.io/ip/1.2.3.4","last_seen":"2026-09-01","message":"Success"}"#;

/// REQ-KEYFLOOR-001. The keyed branch returned before the Community path, so
/// a key GreyNoise refused (live, `v3/ip` answers a bad key
/// `401 {"message":"unauthorized"}`) turned a working keyless lookup into a
/// module error. Now the refusal is reported to the pool (the key reads
/// `Invalid`) and the module answers from `v3/community`, which sends no key.
/// Real request path on loopback; one run per refusal status.
#[tokio::test]
async fn a_refused_key_still_gets_the_keyless_community_answer() {
    use crate::util::http::test_server::{Canned, serve_recording};
    for status in [401u16, 403] {
        let (base, seen) = serve_recording(vec![
            Canned::json(status, r#"{"message":"unauthorized"}"#),
            Canned::json(200, COMMUNITY_HIT),
        ])
        .await;
        let (ctx, key) = keyed_ctx(&status.to_string());

        let result = GreyNoise
            .lookup(&base, "1.2.3.4", &ctx)
            .await
            .unwrap_or_else(|e| {
                panic!("a refused key ({status}) must not cost the keyless answer: {e}")
            });

        let heads = seen.lock().expect("log").clone();
        assert_eq!(heads.len(), 2, "the key was tried, then the Community API");
        assert!(heads[0].starts_with("GET /v3/ip/1.2.3.4 "), "{}", heads[0]);
        assert!(heads[1].starts_with("GET /v3/community/1.2.3.4 "), "{}", heads[1]);
        assert!(
            !heads[1].contains(&key),
            "the keyless path sends no key: {}",
            heads[1]
        );
        let ip = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::IpAddress)
            .expect("the Community verdict is returned");
        assert!(ip.has_tag("greynoise-malicious"), "the Community verdict is used");
        assert!(!ip.has_tag("greynoise-seen"), "and it is the Community record, not a paid one");
        assert_eq!(
            crate::util::key_pool::global_pool().entry_status("greynoise", &key),
            Some(crate::util::key_pool::KeyStatus::Invalid),
            "the refused key is still reported to the pool ({status})"
        );
    }
}

/// REQ-KEYFLOOR-001, the other side of the floor: only a key REFUSAL falls
/// back. A throttle on `v3/ip` is the module's error (typed `RateLimited`) and
/// the Community API is not asked; an accepted key is answered by the paid
/// record alone; a paid `404` is a clean miss with no second request.
#[tokio::test]
async fn only_a_key_refusal_falls_back_to_the_community_api() {
    use crate::util::http::test_server::{Canned, serve_recording};

    let (base, seen) = serve_recording(vec![
        Canned::json(429, r#"{"message":"rate limit"}"#),
        Canned::json(200, COMMUNITY_HIT),
    ])
    .await;
    let (ctx, _) = keyed_ctx("429");
    let err = GreyNoise
        .lookup(&base, "1.2.3.4", &ctx)
        .await
        .expect_err("a throttled key is a failed lookup, not a fallback");
    assert!(matches!(err, Error::RateLimited(_)), "{err:?}");
    assert_eq!(seen.lock().expect("log").len(), 1, "no fallback on 429");

    let (base, seen) = serve_recording(vec![
        Canned::json(
            200,
            r#"{"ip":"1.2.3.4","seen":true,"noise":false,"riot":false,"classification":"benign","name":"Example Scanner"}"#,
        ),
        Canned::json(200, COMMUNITY_HIT),
    ])
    .await;
    let (ctx, _) = keyed_ctx("200");
    let result = GreyNoise
        .lookup(&base, "1.2.3.4", &ctx)
        .await
        .expect("an accepted key answers");
    let ip = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress)
        .expect("the paid verdict is returned");
    assert!(ip.has_tag("greynoise-seen") && ip.has_tag("greynoise-benign"), "the paid record is used");
    assert_eq!(seen.lock().expect("log").len(), 1, "Community not asked");

    let (base, seen) = serve_recording(vec![
        Canned::json(404, r#"{"message":"not found"}"#),
        Canned::json(200, COMMUNITY_HIT),
    ])
    .await;
    let (ctx, _) = keyed_ctx("404");
    let result = GreyNoise
        .lookup(&base, "1.2.3.4", &ctx)
        .await
        .expect("a paid 404 is a clean miss");
    assert!(result.is_empty(), "the clean miss adds nothing");
    assert_eq!(seen.lock().expect("log").len(), 1, "Community not asked");
}
