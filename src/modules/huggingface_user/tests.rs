use super::*;

fn make_user(
    username: &str,
    fullname: Option<&str>,
    email: Option<&str>,
    website: Option<&str>,
    twitter: Option<&str>,
    orgs: Vec<(&str, Option<&str>)>,
) -> HfUser {
    HfUser {
        username: username.to_string(),
        fullname: fullname.map(str::to_string),
        email: email.map(str::to_string),
        website: website.map(str::to_string),
        twitter: twitter.map(str::to_string),
        orgs: orgs
            .into_iter()
            .map(|(n, f)| HfOrg {
                name: n.to_string(),
                fullname: f.map(str::to_string),
            })
            .collect(),
    }
}

#[test]
fn emits_username_and_profile_url() {
    let user = make_user("alice", None, None, None, None, vec![]);
    let ents = build_entities(user, "scan-hf-001");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "alice")
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://huggingface.co/alice")
    );
}

#[test]
fn emits_person_from_multi_word_fullname() {
    let user = make_user("alice", Some("Alice Smith"), None, None, None, vec![]);
    let ents = build_entities(user, "scan-hf-002");
    let p = ents.iter().find(|e| e.kind == EntityKind::Person);
    assert!(p.is_some(), "must emit Person from two-word fullname");
    assert_eq!(p.unwrap().value, "Alice Smith");
    assert!(p.unwrap().has_tag("huggingface"));
}

#[test]
fn single_word_fullname_does_not_emit_person() {
    let user = make_user("alice", Some("Alice"), None, None, None, vec![]);
    let ents = build_entities(user, "scan-hf-003");
    assert!(ents.iter().all(|e| e.kind != EntityKind::Person));
}

#[test]
fn emits_email_when_public() {
    let user = make_user("alice", None, Some("alice@example.com"), None, None, vec![]);
    let ents = build_entities(user, "scan-hf-004");
    let em = ents.iter().find(|e| e.kind == EntityKind::Email);
    assert!(em.is_some(), "must emit Email entity when email is set");
    assert_eq!(em.unwrap().value, "alice@example.com");
    assert!(em.unwrap().has_tag("huggingface"));
}

#[test]
fn emits_website_url_and_domain() {
    let user = make_user("alice", None, None, Some("https://alice.dev"), None, vec![]);
    let ents = build_entities(user, "scan-hf-005");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://alice.dev")
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "alice.dev")
    );
}

#[test]
fn emits_twitter_username_with_at_stripped() {
    let user = make_user("alice", None, None, None, Some("@aliceml"), vec![]);
    let ents = build_entities(user, "scan-hf-006");
    let tw = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "aliceml");
    assert!(
        tw.is_some(),
        "twitter handle must be emitted with @ stripped"
    );
    assert!(tw.unwrap().has_tag("twitter"));
}

#[test]
fn emits_org_using_fullname_when_available() {
    let user = make_user(
        "alice",
        None,
        None,
        None,
        None,
        vec![("huggingface", Some("Hugging Face Inc."))],
    );
    let ents = build_entities(user, "scan-hf-007");
    let org = ents.iter().find(|e| e.kind == EntityKind::Organisation);
    assert!(org.is_some(), "must emit Organisation for org membership");
    assert_eq!(org.unwrap().value, "Hugging Face Inc.");
    assert!(org.unwrap().has_tag("org-member"));
}

#[test]
fn attack_techniques_covers_every_entity_kind_this_module_produces() {
    // build_entities constructs a Person (fullname), an Email (email), and
    // an Organisation (orgs[]) in addition to the Username the override
    // already credits — the same under-declared-coverage gap already
    // fixed for the sibling "profile lookup" modules
    // (github_user/dockerhub_user/codewars_user/mastodon_user/
    // sourceforge_user/bitbucket_user/rubygems_user/gitlab_user/
    // cpan_user/gitea_user/codeberg_user). No `location` field exists on
    // `HfUser`, so T1591.001 does not apply here.
    let techniques = HuggingfaceUser.attack_techniques();
    assert!(
        techniques.contains(&"T1589.002"),
        "Email Addresses: Email from the public `email` field"
    );
    assert!(
        techniques.contains(&"T1589.003"),
        "Employee Names: Person from the real `fullname` field"
    );
    assert!(
        techniques.contains(&"T1591.002"),
        "Business Relationships: Organisation from `orgs[]` membership"
    );
    assert!(
        techniques.contains(&"T1593.003"),
        "Code Repositories: the Username via the Hugging Face profile itself"
    );
    for id in techniques {
        assert!(
            crate::core::attack::technique(id).is_some(),
            "declared technique {id} must exist in the Reconnaissance catalogue"
        );
    }
}

#[test]
fn empty_username_returns_no_entities() {
    let user = make_user("", None, None, None, None, vec![]);
    assert!(build_entities(user, "scan-hf-008").is_empty());
}
