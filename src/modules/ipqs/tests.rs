use super::*;
#[test]
fn accepts_three_kinds() {
    let m = IpQs;
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(m.accepts(&Target::new(TargetKind::Phone, "+1")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
}
#[test]
fn cost_is_key_gated() {
    assert!(matches!(IpQs.cost(), ModuleCost::KeyGated));
}
#[test]
fn attack_techniques_covers_the_organisation_pivot() {
    // Regression: process() emits Organisation from the ISP, `organization`,
    // and phone-carrier fields, but attack_techniques() omitted T1591.002
    // (Business Relationships) — the same pivot every sibling Infrastructure
    // module with an ISP/ASN-operator Organisation declares.
    let ids = IpQs.attack_techniques();
    assert!(
        ids.contains(&"T1591.002"),
        "must declare T1591.002 for the ISP/organization/carrier Organisation pivot: {ids:?}"
    );
    assert!(IpQs.produces().contains(&EntityKind::Organisation));
}

fn parse(json: &str) -> Common {
    serde_json::from_str(json).expect("should succeed")
}

fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
    e.evidence[0].attributes.get(k).map(String::as_str)
}

#[test]
fn high_fraud_ip_tags_high_risk_and_network_signals() {
    let b = parse(
        r#"{"success":true,"fraud_score":92,"proxy":true,"vpn":true,"tor":false,
            "recent_abuse":true,"isp":"Acme","asn":64500,"country_code":"ru"}"#,
    );
    let e = build_reputation_entity(EntityKind::IpAddress, "ip", "1.2.3.4", &b, "s");
    assert_eq!(e.kind, EntityKind::IpAddress);
    assert!(e.has_tag("ipqs") && e.has_tag("high-risk"));
    assert!(!e.has_tag("elevated-risk")); // mutually exclusive band
    assert!(e.has_tag("proxy") && e.has_tag("vpn") && e.has_tag("recent-abuse"));
    assert!(!e.has_tag("tor")); // explicit false → no tag
    assert!(e.has_tag("country:RU")); // upper-cased
    assert_eq!(attr(&e, "fraud_score"), Some("92"));
    assert_eq!(attr(&e, "endpoint"), Some("ip"));
    assert_eq!(attr(&e, "asn"), Some("64500"));
    assert_eq!(attr(&e, "isp"), Some("Acme"));
}

#[test]
fn risk_band_is_threshold_exact() {
    let elevated = build_reputation_entity(
        EntityKind::IpAddress,
        "ip",
        "x",
        &parse(&format!(r#"{{"fraud_score":{ELEVATED_RISK_SCORE}}}"#)),
        "s",
    );
    assert!(elevated.has_tag("elevated-risk") && !elevated.has_tag("high-risk"));

    let clean = build_reputation_entity(
        EntityKind::IpAddress,
        "ip",
        "x",
        &parse(&format!(r#"{{"fraud_score":{}}}"#, ELEVATED_RISK_SCORE - 1)),
        "s",
    );
    assert!(!clean.has_tag("elevated-risk") && !clean.has_tag("high-risk"));

    let high = build_reputation_entity(
        EntityKind::IpAddress,
        "ip",
        "x",
        &parse(&format!(r#"{{"fraud_score":{HIGH_RISK_SCORE}}}"#)),
        "s",
    );
    assert!(high.has_tag("high-risk") && !high.has_tag("elevated-risk"));
}

#[test]
fn email_endpoint_surfaces_email_fields_and_tags() {
    let b = parse(
        r#"{"success":true,"fraud_score":10,"disposable":true,"leaked":true,
            "valid":true,"deliverability":"high","smtp_score":3,
            "first_seen":{"human":"2 years ago"}}"#,
    );
    let e = build_reputation_entity(EntityKind::Email, "email", "a@b.com", &b, "s");
    assert_eq!(e.kind, EntityKind::Email);
    assert!(e.has_tag("disposable") && e.has_tag("leaked"));
    assert!(!e.has_tag("high-risk") && !e.has_tag("elevated-risk")); // low score
    assert_eq!(attr(&e, "deliverability"), Some("high"));
    assert_eq!(attr(&e, "smtp_score"), Some("3"));
    assert_eq!(attr(&e, "valid"), Some("true"));
    assert_eq!(attr(&e, "first_seen"), Some("2 years ago"));
}

#[test]
fn missing_fraud_score_defaults_to_clean_and_omits_optionals() {
    let e = build_reputation_entity(
        EntityKind::Phone,
        "phone",
        "+15555550100",
        &parse(r#"{"success":true,"line_type":"Wireless","carrier":"Telco","active":true}"#),
        "s",
    );
    assert_eq!(attr(&e, "fraud_score"), Some("0")); // unwrap_or(0)
    assert!(!e.has_tag("high-risk") && !e.has_tag("elevated-risk"));
    assert_eq!(attr(&e, "line_type"), Some("Wireless"));
    assert_eq!(attr(&e, "carrier"), Some("Telco"));
    assert_eq!(attr(&e, "active"), Some("true"));
    // IP-only fields absent on a phone response → omitted.
    assert_eq!(attr(&e, "isp"), None);
    assert_eq!(attr(&e, "first_seen"), None);
}

// The key/quota-message classifier this module's verdict closure calls
// (`crate::util::http::is_key_or_quota_message`) moved to `util::http::fetch`
// and is unit-tested there — it is a shared primitive with two other callers
// now (stolen_tax, niamonx), not an ipqs-local concern.

#[test]
fn a_non_key_provider_failure_is_never_a_clean_miss() {
    use crate::util::http::BodyVerdict;
    for j in [
        r#"{"success":false}"#,
        r#"{"success":false,"message":"An internal error occurred. Please try again later."}"#,
        r#"{"success":false,"message":"Your subscription is not valid for this IP API."}"#,
    ] {
        assert!(
            !matches!(body_verdict(&parse(j)), BodyVerdict::Absent),
            "must not be a clean miss: {j}"
        );
        let err = accepted(parse(j)).err().expect("must fail closed");
        assert!(err.to_string().contains("success=false"), "{err}");
    }
}

#[test]
fn an_unverified_refusal_text_fails_closed_and_a_dead_key_is_still_key_shaped() {
    use crate::util::http::BodyVerdict;
    // No refusal wording is trusted as "IPQS holds nothing": the vendor's docs
    // name none, so an invalid-target-looking message is reported with IPQS's
    // own words rather than read as a clean negative.
    for m in [
        "Invalid IPv4 address, IPv6 address or hostname. Please check the IP/Hostname and try again.",
        "Invalid email address. Please check the email and try again.",
    ] {
        let j = serde_json::json!({ "success": false, "message": m }).to_string();
        assert!(!matches!(body_verdict(&parse(&j)), BodyVerdict::Absent), "{m}");
        let err = accepted(parse(&j)).err().expect("fails closed");
        assert!(err.to_string().contains(m), "{err}");
    }
    assert!(matches!(
        body_verdict(&parse(r#"{"success":false,"message":"Invalid API Key."}"#)),
        BodyVerdict::KeyFailure { .. }
    ));
    let ok = parse(r#"{"success":true,"fraud_score":12}"#);
    assert!(matches!(body_verdict(&ok), BodyVerdict::Accept));
    assert!(accepted(ok).is_ok());
    // A body with no `success` flag at all is an answer, not a failure.
    assert!(accepted(parse(r#"{"fraud_score":3}"#)).is_ok());
}

#[tokio::test]
async fn a_provider_failure_on_the_real_request_path_is_an_error_not_a_miss() {
    // REQ-IPQS-001: the module's real request path against a loopback. A
    // non-key `success:false` came back `Ok(empty)` — coverage's "IPQS holds
    // nothing" — for a query IPQS failed.
    use crate::util::http::test_server::{Canned, serve};
    let base = serve(vec![
        Canned::json(200, r#"{"success":false,"message":"An internal error occurred."}"#),
        Canned::json(200, r#"{"success":true,"fraud_score":12}"#),
    ])
    .await;
    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    let ctx = ModuleContext {
        scan_id: "s".into(),
        bus,
        http: crate::util::http::build_client(),
        keys: Default::default(),
        cancel: Default::default(),
    };
    let client = reqwest::Client::new();
    let err = query(&ctx, &client, &base, "ip", "8.8.8.8", "k")
        .await
        .err()
        .expect("a provider failure fails closed");
    assert!(err.to_string().contains("An internal error occurred."), "{err}");
    let ok = query(&ctx, &client, &base, "ip", "8.8.8.8", "k").await.expect("answers");
    assert!(ok.is_some(), "a real answer is still an answer");
}

/// REQ-IPQS-001: the rotation half of the verdict, on the module's real
/// request path. IPQS reports a dead key in-body on an HTTP 200, so the
/// classifier test above cannot show that the cascade acts on it: a `query`
/// that dropped the verdict, or read the key failure as an answer, would
/// still pass there. Here the first key's in-body failure must retire it in
/// the pool and the next pooled key must be asked, whose answer is returned.
///
/// The pool is the process-global one (`fofa`'s lock explains why that is
/// safe in tests: `huntsman_dir_path()` is pid-scoped under `cfg(test)`); key
/// VALUES are pid-unique so parallel tests cannot collide.
#[tokio::test]
async fn a_dead_key_on_the_real_request_path_rotates_to_the_next_pooled_key() {
    use crate::util::http::test_server::{Canned, serve};
    use crate::util::key_pool::{KeyEntry, KeyStatus, global_pool};
    let pool = global_pool();
    let dead = format!("ipqs-req-ipqs-001-dead-{}", std::process::id());
    let live = format!("ipqs-req-ipqs-001-live-{}", std::process::id());
    assert!(pool.add(SRC, KeyEntry::new(dead.clone())), "fixture: `ipqs` is poolable");
    assert!(pool.add(SRC, KeyEntry::new(live.clone())), "fixture");
    let base = serve(vec![
        Canned::json(200, r#"{"success":false,"message":"Invalid API Key."}"#),
        Canned::json(200, r#"{"success":true,"fraud_score":12}"#),
    ])
    .await;
    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    let ctx = ModuleContext {
        scan_id: "s".into(),
        bus,
        http: crate::util::http::build_client(),
        keys: Default::default(),
        cancel: Default::default(),
    };
    let body = query(&ctx, &reqwest::Client::new(), &base, "ip", "8.8.8.8", &dead)
        .await
        .expect("the next pooled key answers")
        .expect("an answer, not a miss");
    assert_eq!(body.fraud_score, Some(12));
    assert_eq!(
        pool.entry_status(SRC, &dead),
        Some(KeyStatus::Invalid),
        "the in-body key failure must retire the key that sent it"
    );
}
