use super::*;

fn make_user(username: &str, full_name: Option<&str>, handles: Vec<(&str, &str)>) -> HexUser {
    HexUser {
        username: username.to_string(),
        full_name: full_name.map(str::to_string),
        handles: handles
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    }
}

#[test]
fn emits_username_and_profile_url() {
    let user = make_user("ecto_dev", None, vec![]);
    let ents = build_entities(user, "scan-hx-001");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "ecto_dev")
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://hex.pm/users/ecto_dev")
    );
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "ecto_dev")
        .unwrap();
    assert!(u.has_tag("hexpm") && u.has_tag("public-profile"));
}

#[test]
fn emits_person_from_multi_word_full_name() {
    let user = make_user("chrismccord", Some("Chris McCord"), vec![]);
    let ents = build_entities(user, "scan-hx-002");
    let p = ents.iter().find(|e| e.kind == EntityKind::Person);
    assert!(p.is_some(), "must emit Person from two-word full_name");
    assert_eq!(p.unwrap().value, "Chris McCord");
    assert!(p.unwrap().has_tag("hexpm"));
}

#[test]
fn single_word_full_name_does_not_emit_person() {
    let user = make_user("chrismccord", Some("Chris"), vec![]);
    let ents = build_entities(user, "scan-hx-003");
    assert!(ents.iter().all(|e| e.kind != EntityKind::Person));
}

#[test]
fn emits_github_handle_from_handles_map() {
    let user = make_user("elixirlang", None, vec![("github", "elixir-lang")]);
    let ents = build_entities(user, "scan-hx-004");
    let gh = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "elixir-lang");
    assert!(gh.is_some(), "must emit Username for github handle");
    assert!(
        gh.unwrap().has_tag("github") && gh.unwrap().has_tag("hexpm"),
        "github entity must carry both hexpm and github tags"
    );
    assert!((gh.unwrap().confidence - 0.72).abs() < 0.01);
}

#[test]
fn emits_twitter_handle_with_at_stripped() {
    // Use a twitter handle different from the username to avoid a collision
    // between the confirmed-username entity and the cross-platform pivot.
    let user = make_user("hex_dev", None, vec![("twitter", "@hex_dev_tw")]);
    let ents = build_entities(user, "scan-hx-005");
    let tw = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "hex_dev_tw");
    assert!(
        tw.is_some(),
        "must emit Username for twitter handle with @ stripped"
    );
    assert!(tw.unwrap().has_tag("twitter"));
    assert!((tw.unwrap().confidence - 0.62).abs() < 0.01);
}

#[test]
fn unknown_platform_handle_not_emitted() {
    let user = make_user(
        "foo",
        None,
        vec![("elixirforum", "foo_dev"), ("discord", "foo#1234")],
    );
    let ents = build_entities(user, "scan-hx-006");
    // Only github and twitter handles are emitted; elixirforum/discord are dropped.
    assert!(
        ents.iter()
            .filter(|e| e.kind == EntityKind::Username && e.value != "foo")
            .count()
            == 0,
        "unknown platform handles must not be emitted"
    );
}

#[test]
fn empty_username_returns_no_entities() {
    let user = make_user("", None, vec![]);
    assert!(build_entities(user, "scan-hx-007").is_empty());
}
