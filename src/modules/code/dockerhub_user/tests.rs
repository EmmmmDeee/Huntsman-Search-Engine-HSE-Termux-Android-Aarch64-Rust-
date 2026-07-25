use super::*;

fn make_user(
    username: &str,
    full_name: Option<&str>,
    company: Option<&str>,
    location: Option<&str>,
    profile_url: Option<&str>,
    gravatar_email: Option<&str>,
) -> DhUser {
    DhUser {
        username: username.to_string(),
        full_name: full_name.map(str::to_string),
        company: company.map(str::to_string),
        location: location.map(str::to_string),
        profile_url: profile_url.map(str::to_string),
        gravatar_email: gravatar_email.map(str::to_string),
    }
}

#[test]
fn emits_username_and_profile_url() {
    let user = make_user("bob", None, None, None, None, None);
    let ents = build_entities(user, "scan-dh-001");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "bob")
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://hub.docker.com/u/bob")
    );
    let uname = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .unwrap();
    assert!(uname.has_tag("dockerhub") && uname.has_tag("public-profile"));
}

#[test]
fn emits_person_from_multi_word_name() {
    let user = make_user("bob", Some("Bob Smith"), None, None, None, None);
    let ents = build_entities(user, "scan-dh-002");
    let p = ents.iter().find(|e| e.kind == EntityKind::Person);
    assert!(p.is_some(), "must emit Person from multi-word full_name");
    assert_eq!(p.unwrap().value, "Bob Smith");
}

#[test]
fn single_word_name_does_not_emit_person() {
    let user = make_user("bob", Some("Bob"), None, None, None, None);
    let ents = build_entities(user, "scan-dh-003");
    assert!(ents.iter().all(|e| e.kind != EntityKind::Person));
}

#[test]
fn emits_organisation_from_company() {
    let user = make_user("bob", None, Some("Acme Corp"), None, None, None);
    let ents = build_entities(user, "scan-dh-004");
    let o = ents.iter().find(|e| e.kind == EntityKind::Organisation);
    assert!(o.is_some(), "must emit Organisation from company field");
    assert_eq!(o.unwrap().value, "Acme Corp");
    assert!(o.unwrap().has_tag("self-asserted"));
}

#[test]
fn emits_address_from_location() {
    let user = make_user("bob", None, None, Some("San Francisco, CA"), None, None);
    let ents = build_entities(user, "scan-dh-005");
    let a = ents.iter().find(|e| e.kind == EntityKind::Address);
    assert!(a.is_some(), "must emit Address from location field");
    assert_eq!(a.unwrap().value, "San Francisco, CA");
}

#[test]
fn emits_website_url_and_domain_from_profile_url() {
    let user = make_user("bob", None, None, None, Some("https://bob.dev"), None);
    let ents = build_entities(user, "scan-dh-006");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://bob.dev")
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "bob.dev")
    );
}

#[test]
fn emits_email_from_gravatar_email_when_present() {
    let user = make_user("bob", None, None, None, None, Some("bob@example.com"));
    let ents = build_entities(user, "scan-dh-007");
    let em = ents.iter().find(|e| e.kind == EntityKind::Email);
    assert!(em.is_some(), "must emit Email when gravatar_email is set");
    assert_eq!(em.unwrap().value, "bob@example.com");
    assert!(em.unwrap().has_tag("gravatar"));
}

#[test]
fn empty_username_returns_no_entities() {
    let user = make_user("", None, None, None, None, None);
    assert!(build_entities(user, "scan-dh-008").is_empty());
}

#[test]
fn attack_techniques_covers_every_entity_kind_this_module_produces() {
    // Mirrors the github_user regression: the override must not replace the
    // whole category default with a single technique when the module's own
    // `build_entities` constructs Person/Organisation/Address/Coordinates/
    // Email in addition to the Username the Code Repositories technique
    // covers — every admitted entity's `attack:<ID>` provenance tag is
    // sourced directly from this list (core::engine::dispatch).
    let techniques = DockerhubUser.attack_techniques();
    assert!(
        techniques.contains(&"T1593.003"),
        "Code Repositories: the module's own username discovery mechanism"
    );
    assert!(
        techniques.contains(&"T1589.002"),
        "Email Addresses: gravatar_email becomes an Email entity"
    );
    assert!(
        techniques.contains(&"T1589.003"),
        "Employee Names: full_name becomes a Person entity"
    );
    assert!(
        techniques.contains(&"T1591.001"),
        "Determine Physical Locations: location becomes Address/Coordinates"
    );
    assert!(
        techniques.contains(&"T1591.002"),
        "Business Relationships: company becomes an Organisation entity"
    );
    for &id in techniques {
        assert!(
            crate::core::attack::technique(id).is_some(),
            "{id} must be a catalogued Reconnaissance technique"
        );
    }
}
