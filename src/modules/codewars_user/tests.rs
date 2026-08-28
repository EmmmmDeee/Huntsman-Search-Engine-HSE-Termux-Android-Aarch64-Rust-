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
        .expect("should succeed");
    assert!(u.has_tag("codewars") && u.has_tag("public-profile"));
    assert!((u.confidence - 0.84).abs() < 0.01);
}

#[test]
fn emits_person_from_multi_word_name() {
    let user = make_user("k_dev", Some("Kim Developer"), None, None);
    let ents = build_entities(user, "scan-cw-002");
    let p = ents.iter().find(|e| e.kind == EntityKind::Person);
    assert!(p.is_some(), "must emit Person from multi-word name");
    assert_eq!(p.expect("should succeed").value, "Kim Developer");
    assert!(p.expect("should succeed").has_tag("codewars"));
    assert!((p.expect("should succeed").confidence - 0.68).abs() < 0.01);
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
    assert_eq!(o.expect("should succeed").value, "Hack The Planet");
    assert!(
        o.expect("should succeed").has_tag("self-asserted")
            && o.expect("should succeed").has_tag("codewars")
    );
    assert!((o.expect("should succeed").confidence - 0.48).abs() < 0.01);
}

#[test]
fn emits_address_from_city() {
    let user = make_user("coder99", None, None, Some("Tokyo"));
    let ents = build_entities(user, "scan-cw-005");
    let a = ents.iter().find(|e| e.kind == EntityKind::Address);
    assert!(a.is_some(), "must emit Address from city field");
    assert_eq!(a.expect("should succeed").value, "Tokyo");
    assert!(a.expect("should succeed").has_tag("self-asserted"));
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

#[test]
fn attack_techniques_covers_every_entity_kind_this_module_produces() {
    // Mirrors the github_user/dockerhub_user regression: the override must
    // not replace the whole category default with a single technique when
    // the module's own `build_entities` constructs Person/Organisation/
    // Address/Coordinates in addition to the Username the Code Repositories
    // technique covers — every admitted entity's `attack:<ID>` provenance
    // tag is sourced directly from this list (core::engine::dispatch).
    let techniques = CodewarsUser.attack_techniques();
    assert!(
        techniques.contains(&"T1593.003"),
        "Code Repositories: the module's own username discovery mechanism"
    );
    assert!(
        techniques.contains(&"T1589.003"),
        "Employee Names: the real `name` field becomes a Person entity"
    );
    assert!(
        techniques.contains(&"T1591.001"),
        "Determine Physical Locations: `city` becomes Address/Coordinates"
    );
    assert!(
        techniques.contains(&"T1591.002"),
        "Business Relationships: `clan` becomes an Organisation entity"
    );
    for &id in techniques {
        assert!(
            crate::core::attack::technique(id).is_some(),
            "{id} must be a catalogued Reconnaissance technique"
        );
    }
}
