use super::*;

fn make_user(
    name: &str,
    display_name: Option<&str>,
    url: Option<&str>,
    about: Option<&str>,
    location: Option<&str>,
) -> SfUser {
    SfUser {
        name: name.to_string(),
        display_name: display_name.map(str::to_string),
        url: url.map(str::to_string),
        about: about.map(str::to_string),
        location: location.map(str::to_string),
    }
}

#[test]
fn emits_username_and_profile_url_from_url_field() {
    let user = make_user(
        "sfdev",
        None,
        Some("https://sourceforge.net/u/sfdev/"),
        None,
        None,
    );
    let ents = build_entities(user, "scan-sf-001");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "sfdev")
    );
    // trailing slash must be stripped
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://sourceforge.net/u/sfdev")
    );
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .unwrap();
    assert!(u.has_tag("sourceforge") && u.has_tag("public-profile"));
    assert!((u.confidence - 0.86).abs() < 0.01);
}

#[test]
fn falls_back_to_constructed_url_when_url_absent() {
    let user = make_user("sfdev", None, None, None, None);
    let ents = build_entities(user, "scan-sf-002");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://sourceforge.net/u/sfdev")
    );
}

#[test]
fn emits_person_from_multi_word_display_name() {
    let user = make_user("sfdev", Some("Source Forge Developer"), None, None, None);
    let ents = build_entities(user, "scan-sf-003");
    let p = ents.iter().find(|e| e.kind == EntityKind::Person);
    assert!(p.is_some(), "must emit Person from multi-word display_name");
    assert_eq!(p.unwrap().value, "Source Forge Developer");
    assert!(p.unwrap().has_tag("sourceforge"));
}

#[test]
fn single_word_display_name_does_not_emit_person() {
    let user = make_user("sfdev", Some("SfDev"), None, None, None);
    let ents = build_entities(user, "scan-sf-004");
    assert!(ents.iter().all(|e| e.kind != EntityKind::Person));
}

#[test]
fn emits_address_from_location() {
    let user = make_user("sfdev", None, None, None, Some("Tokyo, Japan"));
    let ents = build_entities(user, "scan-sf-005");
    let a = ents.iter().find(|e| e.kind == EntityKind::Address);
    assert!(a.is_some(), "must emit Address from location");
    assert_eq!(a.unwrap().value, "Tokyo, Japan");
    assert!(a.unwrap().has_tag("self-asserted"));
}

#[test]
fn extracts_email_from_bio() {
    let user = make_user(
        "sfdev",
        None,
        None,
        Some("Contact me at sfdev@example.net"),
        None,
    );
    let ents = build_entities(user, "scan-sf-006");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Email && e.value == "sfdev@example.net")
    );
}

#[test]
fn empty_name_returns_no_entities() {
    let user = make_user("", None, None, None, None);
    assert!(build_entities(user, "scan-sf-007").is_empty());
}
