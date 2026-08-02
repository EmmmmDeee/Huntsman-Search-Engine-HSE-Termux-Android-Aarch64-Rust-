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

#[test]
fn key_or_quota_failure_messages_are_classified_but_bad_targets_are_not() {
    // A success:false message naming a key/quota problem must surface (→ report
    // + Err), not be swallowed as an empty result.
    for m in [
        "You have insufficient credits to make this query",
        "Invalid API Key.",
        "You have exceeded your request quota",
        "You do not have permission to access this endpoint",
        "Unauthorized",
    ] {
        assert!(is_key_or_quota_failure(m), "must classify key/quota: {m:?}");
    }
    // A merely-invalid target stays a clean empty result (NOT a key failure).
    for m in [
        "Please enter a valid IP address.",
        "Please enter a valid email address.",
        "",
    ] {
        assert!(
            !is_key_or_quota_failure(m),
            "an invalid-target message must not be treated as a key failure: {m:?}"
        );
    }
}
