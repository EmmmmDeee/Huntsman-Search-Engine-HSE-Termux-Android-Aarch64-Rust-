use super::*;

#[test]
fn accepts_phone_and_email() {
    let m = ContactEnrich;
    assert!(m.accepts(&Target::new(TargetKind::Phone, "+1")));
    assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "x")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
}

#[test]
fn cost_is_free() {
    assert!(matches!(ContactEnrich.cost(), ModuleCost::Free));
}

#[test]
fn priority_and_timeout() {
    let m = ContactEnrich;
    assert_eq!(m.priority(), 85);
    assert_eq!(m.max_timeout_ms(), 6_000);
}

#[test]
fn parse_numverify_response() {
    let raw = r#"{
      "valid": true,
      "number": "14158586273",
      "local_format": "4158586273",
      "international_format": "+14158586273",
      "country_prefix": "+1",
      "country_code": "US",
      "country_name": "United States of America",
      "location": "Novato",
      "carrier": "AT&T Mobility LLC",
      "line_type": "mobile"
    }"#;
    let r: NumverifyResp = serde_json::from_str(raw).unwrap();
    assert_eq!(r.valid, Some(true));
    assert_eq!(r.country_code.as_deref(), Some("US"));
    assert_eq!(r.carrier.as_deref(), Some("AT&T Mobility LLC"));
    assert_eq!(r.line_type.as_deref(), Some("mobile"));
}

#[test]
fn parse_gravatar_response() {
    let raw = r#"{
      "entry": [{
        "displayName": "John Doe",
        "preferredUsername": "johndoe",
        "name": {"formatted": "John Doe"},
        "urls": [{"value": "https://example.com", "title": "Blog"}],
        "currentLocation": "NYC",
        "aboutMe": "dev",
        "photos": [{"value": "https://gravatar.com/avatar/abc"}]
      }]
    }"#;
    let r: ProfileResp = serde_json::from_str(raw).unwrap();
    assert_eq!(r.entry.len(), 1);
    let e = &r.entry[0];
    assert_eq!(e.display_name.as_deref(), Some("John Doe"));
    assert_eq!(e.location.as_deref(), Some("NYC"));
}
