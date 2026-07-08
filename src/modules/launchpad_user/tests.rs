use super::*;

fn make_person(
    name: &str,
    display_name: Option<&str>,
    web_link: Option<&str>,
    homepage_content: Option<&str>,
    is_valid: bool,
) -> LpPerson {
    LpPerson {
        name: name.to_string(),
        display_name: display_name.map(str::to_string),
        web_link: web_link.map(str::to_string),
        homepage_content: homepage_content.map(str::to_string),
        is_valid,
    }
}

#[test]
fn emits_username_and_profile_url_from_web_link() {
    let p = make_person(
        "alice",
        None,
        Some("https://launchpad.net/~alice"),
        None,
        true,
    );
    let ents = build_entities(p, "scan-lp-001");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "alice")
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://launchpad.net/~alice")
    );
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .unwrap();
    assert!(u.has_tag("launchpad") && u.has_tag("public-profile"));
    assert!((u.confidence - 0.85).abs() < 0.01);
}

#[test]
fn falls_back_to_constructed_url_when_web_link_absent() {
    let p = make_person("alice", None, None, None, true);
    let ents = build_entities(p, "scan-lp-002");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://launchpad.net/~alice")
    );
}

#[test]
fn emits_person_from_multi_word_display_name() {
    let p = make_person("alice", Some("Alice Ubuntu Developer"), None, None, true);
    let ents = build_entities(p, "scan-lp-003");
    let pe = ents.iter().find(|e| e.kind == EntityKind::Person);
    assert!(
        pe.is_some(),
        "must emit Person from multi-word display_name"
    );
    assert_eq!(pe.unwrap().value, "Alice Ubuntu Developer");
    assert!(pe.unwrap().has_tag("launchpad"));
}

#[test]
fn single_word_display_name_does_not_emit_person() {
    let p = make_person("alice", Some("Alice"), None, None, true);
    let ents = build_entities(p, "scan-lp-004");
    assert!(ents.iter().all(|e| e.kind != EntityKind::Person));
}

#[test]
fn extracts_email_from_bio() {
    let p = make_person(
        "alice",
        None,
        None,
        Some("Contact me at alice@ubuntu.com for packaging help."),
        true,
    );
    let ents = build_entities(p, "scan-lp-005");
    let em = ents.iter().find(|e| e.kind == EntityKind::Email);
    assert!(em.is_some(), "must extract email from bio");
    assert_eq!(em.unwrap().value, "alice@ubuntu.com");
    assert!(em.unwrap().has_tag("launchpad"));
}

#[test]
fn invalid_account_returns_no_entities() {
    let p = make_person("alice", Some("Alice Dev"), None, None, false);
    assert!(build_entities(p, "scan-lp-006").is_empty());
}

#[test]
fn attack_techniques_covers_every_entity_kind_this_module_produces() {
    // build_entities constructs a Person from the multi-word
    // display_name in addition to the Email/Username the override
    // already credits — the same under-declared-coverage gap already
    // fixed for the sibling "profile lookup" modules (github_user/
    // dockerhub_user/codewars_user/mastodon_user/sourceforge_user/
    // bitbucket_user/rubygems_user/gitlab_user/cpan_user/gitea_user/
    // codeberg_user/huggingface_user/hexpm_user/devto/crates_io/
    // npm_author/stackoverflow_user/steam_profile). No location field
    // exists on `LpPerson`, so T1591.001 does not apply here; no
    // Organisation entities are built either, so T1591.002 does not
    // apply.
    let techniques = LaunchpadUser.attack_techniques();
    assert!(
        techniques.contains(&"T1589.002"),
        "Email Addresses: emails extracted from the bio"
    );
    assert!(
        techniques.contains(&"T1589.003"),
        "Employee Names: Person from the multi-word `display_name` field"
    );
    assert!(
        techniques.contains(&"T1593.003"),
        "Code Repositories: the Username via the Launchpad profile itself"
    );
    for id in techniques {
        assert!(
            crate::core::attack::technique(id).is_some(),
            "declared technique {id} must exist in the Reconnaissance catalogue"
        );
    }
}

#[test]
fn empty_name_returns_no_entities() {
    let p = make_person("", None, None, None, true);
    assert!(build_entities(p, "scan-lp-007").is_empty());
}
