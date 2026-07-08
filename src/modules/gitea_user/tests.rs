use super::*;

fn make_user(
    login: &str,
    full_name: Option<&str>,
    email: Option<&str>,
    website: Option<&str>,
    location: Option<&str>,
    description: Option<&str>,
) -> GtUser {
    GtUser {
        login: login.to_string(),
        full_name: full_name.map(str::to_string),
        email: email.map(str::to_string),
        website: website.map(str::to_string),
        location: location.map(str::to_string),
        description: description.map(str::to_string),
        html_url: Some(format!("https://gitea.com/{login}")),
        created: Some("2020-01-01T00:00:00Z".to_string()),
    }
}

#[test]
fn emits_username_and_profile_url() {
    let user = make_user("gdev", None, None, None, None, None);
    let ents = build_entities(user, "scan-gt-001");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "gdev")
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://gitea.com/gdev")
    );
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .unwrap();
    assert!(u.has_tag("gitea") && u.has_tag("public-profile"));
}

#[test]
fn emits_person_from_multi_word_full_name() {
    let user = make_user("gdev", Some("Gitea Developer"), None, None, None, None);
    let ents = build_entities(user, "scan-gt-002");
    let p = ents.iter().find(|e| e.kind == EntityKind::Person);
    assert!(p.is_some(), "must emit Person from multi-word full_name");
    assert_eq!(p.unwrap().value, "Gitea Developer");
    assert!(p.unwrap().has_tag("gitea"));
}

#[test]
fn emits_public_email() {
    let user = make_user("gdev", None, Some("gdev@example.com"), None, None, None);
    let ents = build_entities(user, "scan-gt-003");
    let em = ents.iter().find(|e| e.kind == EntityKind::Email);
    assert!(em.is_some(), "must emit Email from public email field");
    assert_eq!(em.unwrap().value, "gdev@example.com");
    assert!(em.unwrap().has_tag("gitea"));
}

#[test]
fn emits_website_url_and_domain() {
    let user = make_user("gdev", None, None, Some("https://gdev.io"), None, None);
    let ents = build_entities(user, "scan-gt-004");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://gdev.io")
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "gdev.io")
    );
}

#[test]
fn emits_address_from_location() {
    let user = make_user("gdev", None, None, None, Some("Berlin, Germany"), None);
    let ents = build_entities(user, "scan-gt-005");
    let a = ents.iter().find(|e| e.kind == EntityKind::Address);
    assert!(a.is_some(), "must emit Address from location");
    assert_eq!(a.unwrap().value, "Berlin, Germany");
    assert!(a.unwrap().has_tag("self-asserted"));
}

#[test]
fn extracts_email_from_bio() {
    let user = make_user(
        "gdev",
        None,
        None,
        None,
        None,
        Some("Reach me at gitdev@mail.com"),
    );
    let ents = build_entities(user, "scan-gt-006");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Email && e.value == "gitdev@mail.com")
    );
}

#[test]
fn attack_techniques_covers_every_entity_kind_this_module_produces() {
    // build_entities constructs a Person (full_name) and an
    // Address/Coordinates (location) in addition to the Email/Username the
    // override already credits — the same under-declared-coverage gap
    // already fixed for the sibling "profile lookup" modules
    // (github_user/dockerhub_user/codewars_user/mastodon_user/
    // sourceforge_user/bitbucket_user/rubygems_user/gitlab_user/cpan_user).
    let techniques = GiteaUser.attack_techniques();
    assert!(
        techniques.contains(&"T1589.002"),
        "Email Addresses: public email + bio-extracted emails"
    );
    assert!(
        techniques.contains(&"T1589.003"),
        "Employee Names: Person from the real `full_name` field"
    );
    assert!(
        techniques.contains(&"T1591.001"),
        "Determine Physical Locations: Address/Coordinates from `location`"
    );
    assert!(
        techniques.contains(&"T1593.003"),
        "Code Repositories: the Username via the Gitea.com profile itself"
    );
    for id in techniques {
        assert!(
            crate::core::attack::technique(id).is_some(),
            "declared technique {id} must exist in the Reconnaissance catalogue"
        );
    }
}

#[test]
fn empty_login_returns_no_entities() {
    let user = GtUser {
        login: String::new(),
        full_name: None,
        email: None,
        website: None,
        location: None,
        description: None,
        html_url: None,
        created: None,
    };
    assert!(build_entities(user, "scan-gt-007").is_empty());
}
