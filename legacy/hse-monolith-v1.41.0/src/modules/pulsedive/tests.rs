use super::*;

#[test]
fn accepts_ip_domain_and_url_but_not_email() {
    let m = Pulsedive;
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
    assert!(m.accepts(&Target::new(TargetKind::Domain, "evil.test")));
    assert!(m.accepts(&Target::new(TargetKind::Url, "https://evil.test/x")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

#[test]
fn cost_is_key_gated() {
    // A free Pulsedive account (no payment) is required for a usable daily
    // quota — https://blog.pulsedive.com/pulsedive-plan-updates-2024/.
    assert!(matches!(Pulsedive.cost(), ModuleCost::KeyGated));
}

fn body(json: &str) -> InfoResp {
    serde_json::from_str(json).expect("should succeed")
}

fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
    e.evidence[0].attributes.get(k).map(String::as_str)
}

#[test]
fn risk_confidence_follows_the_documented_ladder() {
    assert!((risk_confidence("critical") - confidence::HIGH_PLUSPLUS_PLUS).abs() < 1e-9);
    assert!((risk_confidence("high") - confidence::HIGH_PLUSPLUS).abs() < 1e-9);
    assert!((risk_confidence("medium") - confidence::HIGH_PLUS).abs() < 1e-9);
    assert!((risk_confidence("low") - confidence::MEDIUM_PLUS).abs() < 1e-9);
    assert!((risk_confidence("none") - confidence::MEDIUM).abs() < 1e-9);
    // Case-insensitive.
    assert!((risk_confidence("HIGH") - confidence::HIGH_PLUSPLUS).abs() < 1e-9);
    // Unrecognised falls to the neutral middle rather than panicking.
    assert!((risk_confidence("unknown") - confidence::MEDIUM_HIGH).abs() < 1e-9);
}

#[test]
fn populated_high_risk_response_builds_malicious_entity_with_full_evidence() {
    let b = body(
        r#"{
          "iid": 12345,
          "risk": "high",
          "risk_recommended": "high",
          "submissions": 42,
          "stamp_added": "2024-01-01 00:00:00",
          "stamp_updated": "2024-06-01 00:00:00",
          "stamp_seen": "2024-06-02 00:00:00",
          "riskfactors": [
            {"description": "found in threat feeds"},
            {"description": "recently registered domain"}
          ],
          "threats": [
            {"name": "Zeus", "category": "malware"},
            {"name": "Zeus", "category": "malware"}
          ],
          "feeds": [
            {"name": "Zeus Bad Domains"}
          ],
          "properties": {
            "geo": {
              "country": "United States of America",
              "region": "CA",
              "city": "San Francisco",
              "org": "Example Hosting Inc"
            }
          }
        }"#,
    );
    let entities = build_entities(EntityKind::Domain, "evil.test", &b, "s");
    // Subject + Address + Organisation.
    assert_eq!(entities.len(), 3);

    let subject = &entities[0];
    assert_eq!(subject.kind, EntityKind::Domain);
    assert!((subject.confidence - confidence::HIGH_PLUSPLUS).abs() < 1e-9);
    assert!(
        subject.has_tag("pulsedive")
            && subject.has_tag(crate::core::tags::THREAT_INTEL)
            && subject.has_tag(crate::core::tags::MALICIOUS)
    );
    assert_eq!(attr(subject, "risk"), Some("high"));
    // Identical to `risk` — must be omitted, not duplicated.
    assert_eq!(attr(subject, "risk_recommended"), None);
    assert_eq!(attr(subject, "submissions"), Some("42"));
    assert_eq!(attr(subject, "threat_count"), Some("2"));
    // Deduplicated + frequency-ranked by the shared `freq::top_n`.
    assert_eq!(attr(subject, "threat_names"), Some("Zeus\u{d7}2"));
    assert_eq!(attr(subject, "threat_categories"), Some("malware\u{d7}2"));
    assert_eq!(attr(subject, "feed_count"), Some("1"));
    assert_eq!(attr(subject, "feed_names"), Some("Zeus Bad Domains\u{d7}1"));
    assert!(attr(subject, "risk_factors").is_some());
    assert_eq!(attr(subject, "first_added"), Some("2024-01-01 00:00:00"));
    assert_eq!(attr(subject, "last_updated"), Some("2024-06-01 00:00:00"));
    assert_eq!(attr(subject, "last_seen"), Some("2024-06-02 00:00:00"));
    assert_eq!(
        attr(subject, "pulsedive_url"),
        Some("https://pulsedive.com/indicator/?iid=12345")
    );

    let addr = &entities[1];
    assert_eq!(addr.kind, EntityKind::Address);
    assert_eq!(addr.value, "San Francisco, CA, United States of America");
    assert!(addr.has_tag("pulsedive") && addr.has_tag(crate::core::tags::GEOINT));

    let org = &entities[2];
    assert_eq!(org.kind, EntityKind::Organisation);
    assert_eq!(org.value, "Example Hosting Inc");
    assert!(org.has_tag("pulsedive"));
}

#[test]
fn unknown_risk_with_no_threats_or_riskfactors_yields_no_findings() {
    // The shape Pulsedive answers with the FIRST time it ever sees an
    // indicator: risk not yet assessed, nothing linked. Must not be
    // fabricated into a finding.
    let b = body(r#"{"iid": 999, "risk": "unknown"}"#);
    assert!(build_entities(EntityKind::IpAddress, "1.2.3.4", &b, "s").is_empty());

    // Same outcome when `risk` is entirely absent.
    let b = body(r#"{"iid": 999}"#);
    assert!(build_entities(EntityKind::IpAddress, "1.2.3.4", &b, "s").is_empty());
}

#[test]
fn unknown_risk_with_a_linked_threat_still_surfaces() {
    // Defensive edge case: even an "unknown"-risk record is a real finding if
    // Pulsedive has linked at least one threat to it.
    let b = body(r#"{"risk": "unknown", "threats": [{"name": "Emotet"}]}"#);
    let entities = build_entities(EntityKind::Domain, "x.test", &b, "s");
    assert_eq!(entities.len(), 1);
    assert!(entities[0].has_tag(crate::core::tags::MALICIOUS));
}

#[test]
fn benign_none_risk_is_reported_at_medium_confidence_without_malicious_tag() {
    let b = body(r#"{"risk": "none", "riskfactors": [{"description": "clean"}]}"#);
    let entities = build_entities(EntityKind::IpAddress, "8.8.8.8", &b, "s");
    assert_eq!(entities.len(), 1);
    let e = &entities[0];
    assert!((e.confidence - confidence::MEDIUM).abs() < 1e-9);
    assert!(!e.has_tag(crate::core::tags::MALICIOUS));
    assert!(e.has_tag("pulsedive"));
}

#[test]
fn missing_geo_fields_omit_address_and_organisation() {
    // Pulsedive's own worked example ships an empty `geo: {}` for most
    // domain/URL indicators — no city/country/org must mean no pivot, not a
    // half-populated one.
    let b = body(r#"{"risk": "low", "properties": {"geo": {}}}"#);
    let entities = build_entities(EntityKind::Domain, "x.test", &b, "s");
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, EntityKind::Domain);
}

#[test]
fn threat_and_feed_name_lists_are_capped() {
    let threats: Vec<String> = (0..20)
        .map(|i| format!(r#"{{"name":"threat{i:02}"}}"#))
        .collect();
    let b = body(&format!(
        r#"{{"risk":"high","threats":[{}]}}"#,
        threats.join(",")
    ));
    let entities = build_entities(EntityKind::Domain, "x.test", &b, "s");
    let names = attr(&entities[0], "threat_names").expect("should succeed");
    assert_eq!(names.split(", ").count(), MAX_NAMES);
}
