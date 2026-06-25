use super::*;

fn make_user(username: &str, name: Option<&str>, clan: Option<&str>, city: Option<&str>) -> CwUser {
    CwUser {
        username: username.to_string(),
        name: name.map(str::to_string),
        clan: clan.map(str::to_string),
        city: city.map(str::to_string),
    }
}

#[test]
fn emits_username_and_profile_url() {
    let user = make_user("kata_warrior", None, None, None);
    let ents = build_entities(user, "scan-cw-001");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "kata_warrior")
    );
    assert!(
        ents.iter().any(|e| e.kind == EntityKind::Url
            && e.value == "https://www.codewars.com/users/kata_warrior")
    );
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .unwrap();
    assert!(u.has_tag("codewars") && u.has_tag("public-profile"));
    assert!((u.confidence - 0.84).abs() < 0.01);
}

#[test]
fn emits_person_from_multi_word_name() {
    let user = make_user("k_dev", Some("Kim Developer"), None, None);
    let ents = build_entities(user, "scan-cw-002");
    let p = ents.iter().find(|e| e.kind == EntityKind::Person);
    assert!(p.is_some(), "must emit Person from multi-word name");
    assert_eq!(p.unwrap().value, "Kim Developer");
    assert!(p.unwrap().has_tag("codewars"));
    assert!((p.unwrap().confidence - 0.68).abs() < 0.01);
}

#[test]
fn single_word_name_does_not_emit_person() {
    let user = make_user("k_dev", Some("Kim"), None, None);
    let ents = build_entities(user, "scan-cw-003");
    assert!(ents.iter().all(|e| e.kind != EntityKind::Person));
}

#[test]
fn emits_organisation_from_clan() {
    let user = make_user("coder99", None, Some("Hack The Planet"), None);
    let ents = build_entities(user, "scan-cw-004");
    let o = ents.iter().find(|e| e.kind == EntityKind::Organisation);
    assert!(o.is_some(), "must emit Organisation from clan field");
    assert_eq!(o.unwrap().value, "Hack The Planet");
    assert!(o.unwrap().has_tag("self-asserted") && o.unwrap().has_tag("codewars"));
    assert!((o.unwrap().confidence - 0.48).abs() < 0.01);
}

#[test]
fn emits_address_from_city() {
    let user = make_user("coder99", None, None, Some("Tokyo"));
    let ents = build_entities(user, "scan-cw-005");
    let a = ents.iter().find(|e| e.kind == EntityKind::Address);
    assert!(a.is_some(), "must emit Address from city field");
    assert_eq!(a.unwrap().value, "Tokyo");
    assert!(a.unwrap().has_tag("self-asserted"));
}

#[test]
fn empty_clan_and_city_emit_no_org_or_address() {
    let user = make_user("coder99", None, Some(""), Some(""));
    let ents = build_entities(user, "scan-cw-006");
    assert!(ents.iter().all(|e| e.kind != EntityKind::Organisation));
    assert!(ents.iter().all(|e| e.kind != EntityKind::Address));
}

#[test]
fn empty_username_returns_no_entities() {
    let user = make_user("", None, None, None);
    assert!(build_entities(user, "scan-cw-007").is_empty());
}
