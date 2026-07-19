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
    assert_eq!(e.current_location.as_deref(), Some("NYC"));
}

// ── build_phone_entities (pure extraction) ─────────────────────────

fn numverify(json: &str) -> NumverifyResp {
    serde_json::from_str(json).expect("fixture is valid NumverifyResp JSON")
}
fn phone_target(v: &str) -> Target {
    Target::new(TargetKind::Phone, v)
}

#[test]
fn valid_phone_yields_tagged_entity_with_evidence() {
    let body = numverify(
        r#"{
            "valid": true, "number": "14158586273", "local_format": "4158586273",
            "international_format": "+14158586273", "country_prefix": "+1",
            "country_code": "us", "country_name": "United States of America",
            "location": "Novato", "carrier": "AT&T Mobility LLC", "line_type": "mobile"
        }"#,
    );
    let ents = build_phone_entities(&body, &phone_target("+14158586273"), "https", "s");
    assert_eq!(ents.len(), 1);
    let e = &ents[0];
    assert_eq!(e.kind, EntityKind::Phone);
    assert!(e.has_tag("numverify") && e.has_tag("validated"));
    assert!(e.has_tag("transport:https"));
    assert!(e.has_tag("country:US"), "country code is uppercased");
    assert!(e.has_tag("line:mobile"));

    let attr = |k: &str| e.evidence[0].attributes.get(k).map(String::as_str);
    assert_eq!(attr("transport"), Some("https"));
    assert_eq!(attr("normalised"), Some("14158586273"));
    assert_eq!(attr("international"), Some("+14158586273"));
    assert_eq!(attr("country"), Some("United States of America"));
    assert_eq!(attr("carrier"), Some("AT&T Mobility LLC"));
    assert_eq!(attr("line_type"), Some("mobile"));
}

#[test]
fn invalid_phone_yields_nothing() {
    assert!(
        build_phone_entities(
            &numverify(r#"{"valid":false}"#),
            &phone_target("+1"),
            "https",
            "s"
        )
        .is_empty()
    );
    // A missing `valid` field is also not a confirmed-valid number.
    assert!(build_phone_entities(&numverify(r#"{}"#), &phone_target("+1"), "http", "s").is_empty());
}

#[test]
fn phone_blank_fields_skipped_and_transport_recorded() {
    // Blank country_code/line_type add no tags; blank evidence fields skipped;
    // the transport reflects the http fallback.
    let body =
        numverify(r#"{ "valid": true, "country_code": "", "line_type": "", "carrier": "" }"#);
    let e = &build_phone_entities(&body, &phone_target("+61400000000"), "http", "s")[0];
    assert!(!e.tags.iter().any(|t| t.starts_with("country:")));
    assert!(!e.tags.iter().any(|t| t.starts_with("line:")));
    assert!(e.has_tag("transport:http"));
    // Only the transport attribute survives; blank optional fields are dropped.
    assert_eq!(
        e.evidence[0]
            .attributes
            .get("transport")
            .map(String::as_str),
        Some("http")
    );
    assert!(!e.evidence[0].attributes.contains_key("carrier"));
    assert!(!e.evidence[0].attributes.contains_key("line_type"));
}

// ── build_email_entities (pure extraction) ─────────────────────────

fn gravatar(json: &str) -> ProfileEntry {
    let r: ProfileResp = serde_json::from_str(json).expect("fixture is valid ProfileResp JSON");
    r.entry
        .into_iter()
        .next()
        .expect("fixture carries an entry")
}
fn email_target(v: &str) -> Target {
    Target::new(TargetKind::Email, v)
}
fn of_kind(ents: &[Entity], kind: EntityKind) -> Option<&Entity> {
    ents.iter().find(|e| e.kind == kind)
}

#[test]
fn full_gravatar_yields_email_person_username_address_and_urls() {
    let entry = gravatar(
        r#"{ "entry": [{
            "displayName": "John Doe", "preferredUsername": "johndoe",
            "name": {"formatted": "John Doe"},
            "urls": [
                {"value": "https://example.com", "title": "Blog"},
                {"value": "ftp://nope", "title": "Bad"}
            ],
            "currentLocation": "Sydney NSW", "aboutMe": "dev",
            "photos": [{"value": "https://gravatar.com/avatar/abc"}]
        }] }"#,
    );
    let ents = build_email_entities(
        &entry,
        &email_target("x@example.com"),
        "x@example.com",
        "abc123",
        "s",
    );

    let email = of_kind(&ents, EntityKind::Email).expect("subject email");
    assert!(email.has_tag("gravatar"));
    let attr = |k: &str| email.evidence[0].attributes.get(k).map(String::as_str);
    assert_eq!(attr("md5"), Some("abc123"));
    assert_eq!(attr("profile_url"), Some("https://www.gravatar.com/abc123"));
    assert_eq!(attr("display_name"), Some("John Doe"));
    assert_eq!(attr("preferred_username"), Some("johndoe"));
    assert_eq!(attr("name"), Some("John Doe"));
    assert_eq!(attr("bio"), Some("dev"));
    assert_eq!(attr("avatar_url"), Some("https://gravatar.com/avatar/abc"));
    // The urls evidence string folds every entry with a value (title-prefixed).
    assert_eq!(
        attr("urls"),
        Some("Blog: https://example.com | Bad: ftp://nope")
    );

    let person = of_kind(&ents, EntityKind::Person).expect("person");
    assert_eq!(person.value, "John Doe");
    let user = of_kind(&ents, EntityKind::Username).expect("username");
    assert_eq!(user.value, "johndoe");

    let addr = of_kind(&ents, EntityKind::Address).expect("address");
    assert_eq!(addr.value, "Sydney NSW");
    assert!(addr.has_tag("geoint"));
    // The AU state token is recognised and tags the address as AU.
    assert!(addr.has_tag("au-state:NSW") && addr.has_tag("country:AU"));

    // Only the http(s) URL becomes a Url entity; the ftp link is dropped.
    let urls: Vec<&str> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Url)
        .map(|e| e.value.as_str())
        .collect();
    assert_eq!(urls, vec!["https://example.com"]);
}

#[test]
fn minimal_gravatar_yields_only_the_email() {
    // An entry with nothing usable still produces the subject email entity.
    let entry = gravatar(r#"{ "entry": [{}] }"#);
    let ents = build_email_entities(&entry, &email_target("x@y.com"), "x@y.com", "h", "s");
    assert_eq!(ents.len(), 1);
    assert_eq!(ents[0].kind, EntityKind::Email);
    // Only md5 + profile_url evidence — no optional profile attributes.
    let keys: Vec<&str> = ents[0].evidence[0]
        .attributes
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, vec!["md5", "profile_url"]);
}

#[test]
fn single_word_or_short_name_yields_no_person() {
    // A formatted name without a space is not split into a Person.
    let entry = gravatar(r#"{ "entry": [{ "name": {"formatted": "Cher"} }] }"#);
    let ents = build_email_entities(&entry, &email_target("x@y.com"), "x@y.com", "h", "s");
    assert!(of_kind(&ents, EntityKind::Person).is_none());
    // ...but it is still recorded as the `name` attribute on the email evidence.
    assert_eq!(
        ents[0].evidence[0]
            .attributes
            .get("name")
            .map(String::as_str),
        Some("Cher")
    );
}

#[test]
fn short_username_and_location_are_skipped() {
    // preferredUsername < 3 chars and location < 3 chars are both dropped.
    let entry =
        gravatar(r#"{ "entry": [{ "preferredUsername": "ab", "currentLocation": "NY" }] }"#);
    let ents = build_email_entities(&entry, &email_target("x@y.com"), "x@y.com", "h", "s");
    assert!(of_kind(&ents, EntityKind::Username).is_none());
    assert!(of_kind(&ents, EntityKind::Address).is_none());
}

#[test]
fn non_au_location_yields_address_without_state_tags() {
    let entry = gravatar(r#"{ "entry": [{ "currentLocation": "Berlin, Germany" }] }"#);
    let ents = build_email_entities(&entry, &email_target("x@y.com"), "x@y.com", "h", "s");
    let addr = of_kind(&ents, EntityKind::Address).expect("address");
    assert_eq!(addr.value, "Berlin, Germany");
    assert!(!addr.tags.iter().any(|t| t.starts_with("au-state:")));
    assert!(!addr.has_tag("country:AU"));
}

#[test]
fn gravatar_hash_normalises_email_per_spec() {
    // The official gravatar.com example: a trailing space + mixed case MUST be
    // trimmed and lowercased before MD5, yielding the documented hash. Hashing
    // the raw value (the bug) gives a different, never-resolving hash.
    assert_eq!(
        gravatar_hash("MyEmailAddress@example.com "),
        "0bc83cb571cd1c50ba6f3e8a78ef1346"
    );
    // Case + whitespace variants of the same address converge to one hash.
    assert_eq!(
        gravatar_hash("  myemailaddress@EXAMPLE.com"),
        "0bc83cb571cd1c50ba6f3e8a78ef1346"
    );
}
