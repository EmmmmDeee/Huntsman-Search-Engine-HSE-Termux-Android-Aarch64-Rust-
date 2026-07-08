use super::*;

fn make_user(
    nickname: &str,
    display_name: Option<&str>,
    account_status: Option<&str>,
    location: Option<&str>,
    website: Option<&str>,
    profile_href: Option<&str>,
) -> BbUser {
    BbUser {
        nickname: nickname.to_string(),
        display_name: display_name.map(str::to_string),
        account_status: account_status.map(str::to_string),
        location: location.map(str::to_string),
        website: website.map(str::to_string),
        links: profile_href.map(|href| BbLinks {
            html: Some(BbLink {
                href: Some(href.to_string()),
            }),
        }),
    }
}

#[test]
fn emits_username_and_profile_url_from_links() {
    let user = make_user(
        "jdev",
        None,
        Some("active"),
        None,
        None,
        Some("https://bitbucket.org/jdev"),
    );
    let ents = build_entities(user, "scan-bb-001");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "jdev")
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://bitbucket.org/jdev")
    );
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .unwrap();
    assert!(u.has_tag("bitbucket") && u.has_tag("public-profile"));
    assert!((u.confidence - 0.86).abs() < 0.01);
}

#[test]
fn falls_back_to_constructed_profile_url_when_links_absent() {
    let user = make_user("jdev", None, Some("active"), None, None, None);
    let ents = build_entities(user, "scan-bb-002");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://bitbucket.org/jdev")
    );
}

#[test]
fn emits_person_from_multi_word_display_name() {
    let user = make_user(
        "jdev",
        Some("Jane Developer"),
        Some("active"),
        None,
        None,
        None,
    );
    let ents = build_entities(user, "scan-bb-003");
    let p = ents.iter().find(|e| e.kind == EntityKind::Person);
    assert!(p.is_some(), "must emit Person from multi-word display_name");
    assert_eq!(p.unwrap().value, "Jane Developer");
    assert!(p.unwrap().has_tag("bitbucket"));
    assert!((p.unwrap().confidence - 0.70).abs() < 0.01);
}

#[test]
fn single_word_display_name_does_not_emit_person() {
    let user = make_user("jdev", Some("Jane"), Some("active"), None, None, None);
    let ents = build_entities(user, "scan-bb-004");
    assert!(ents.iter().all(|e| e.kind != EntityKind::Person));
}

#[test]
fn emits_website_url_and_domain() {
    let user = make_user(
        "jdev",
        None,
        Some("active"),
        None,
        Some("https://jane.dev"),
        None,
    );
    let ents = build_entities(user, "scan-bb-005");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://jane.dev")
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "jane.dev")
    );
}

#[test]
fn emits_address_from_location() {
    let user = make_user(
        "jdev",
        None,
        Some("active"),
        Some("Sydney, Australia"),
        None,
        None,
    );
    let ents = build_entities(user, "scan-bb-006");
    let a = ents.iter().find(|e| e.kind == EntityKind::Address);
    assert!(a.is_some(), "must emit Address from location");
    assert_eq!(a.unwrap().value, "Sydney, Australia");
    assert!(a.unwrap().has_tag("self-asserted"));
}

#[test]
fn inactive_account_returns_no_entities() {
    let user = make_user(
        "jdev",
        Some("Jane Developer"),
        Some("closed"),
        Some("Sydney"),
        None,
        None,
    );
    assert!(build_entities(user, "scan-bb-007").is_empty());
}

#[test]
fn empty_nickname_returns_no_entities() {
    let user = make_user("", None, None, None, None, None);
    assert!(build_entities(user, "scan-bb-008").is_empty());
}

#[test]
fn attack_techniques_covers_every_entity_kind_this_module_produces() {
    // Mirrors the github_user/dockerhub_user/codewars_user/mastodon_user/
    // sourceforge_user regression: the override must not omit coverage for
    // entity kinds `build_entities` actually constructs — every admitted
    // entity's `attack:<ID>` provenance tag is sourced directly from this
    // list (core::engine::dispatch). Also asserts T1589.002 is explicitly
    // ABSENT: unlike those siblings, Bitbucket's API returns no bio/email
    // field, so no `EntityKind::Email` is ever built here.
    let techniques = BitbucketUser.attack_techniques();
    assert!(
        techniques.contains(&"T1593.003"),
        "Code Repositories: the module's own username discovery mechanism"
    );
    assert!(
        techniques.contains(&"T1589.003"),
        "Employee Names: display_name becomes a Person entity"
    );
    assert!(
        techniques.contains(&"T1591.001"),
        "Determine Physical Locations: location becomes Address/Coordinates"
    );
    assert!(
        !techniques.contains(&"T1589.002"),
        "Email Addresses must not be claimed: no email field exists anywhere in BbUser"
    );
    for &id in techniques {
        assert!(
            crate::core::attack::technique(id).is_some(),
            "{id} must be a catalogued Reconnaissance technique"
        );
    }
}
