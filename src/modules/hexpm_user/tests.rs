use super::*;

/// Build a `HexUser` in the REAL hex.pm shape: `handles` keyed by display name
/// (`"GitHub"`, `"X.com"`) with full profile-URL values.
fn make_user(
    username: &str,
    full_name: Option<&str>,
    email: Option<&str>,
    inserted_at: Option<&str>,
    handles: Vec<(&str, &str)>,
) -> HexUser {
    HexUser {
        username: username.to_string(),
        full_name: full_name.map(str::to_string),
        email: email.map(str::to_string),
        inserted_at: inserted_at.map(str::to_string),
        handles: handles
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    }
}

#[test]
fn handle_from_link_extracts_the_profile_segment() {
    assert_eq!(
        handle_from_link("https://github.com/wojtekmach").as_deref(),
        Some("wojtekmach")
    );
    assert_eq!(
        handle_from_link("https://x.com/wojtekmach/").as_deref(),
        Some("wojtekmach")
    );
    // A rare bare handle is used verbatim (with a leading @ stripped).
    assert_eq!(handle_from_link("@josevalim").as_deref(), Some("josevalim"));
    // A host-only URL has no profile segment — must NOT yield the host.
    assert_eq!(handle_from_link("https://github.com"), None);
    assert_eq!(handle_from_link("  "), None);
}

#[test]
fn emits_username_and_profile_url() {
    let user = make_user("ecto_dev", None, None, None, vec![]);
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
        .expect("should succeed");
    assert!(u.has_tag("hexpm") && u.has_tag("public-profile"));
}

#[test]
fn emits_person_from_multi_word_full_name() {
    let user = make_user("chrismccord", Some("Chris McCord"), None, None, vec![]);
    let ents = build_entities(user, "scan-hx-002");
    let p = ents.iter().find(|e| e.kind == EntityKind::Person);
    assert!(p.is_some(), "must emit Person from two-word full_name");
    assert_eq!(p.expect("should succeed").value, "Chris McCord");
    assert!(p.expect("should succeed").has_tag("hexpm"));
}

#[test]
fn single_word_full_name_does_not_emit_person() {
    let user = make_user("chrismccord", Some("Chris"), None, None, vec![]);
    let ents = build_entities(user, "scan-hx-003");
    assert!(ents.iter().all(|e| e.kind != EntityKind::Person));
}

#[test]
fn emits_email_when_published() {
    // The top-level `email` is the highest-value field; it was never
    // deserialised pre-fix, so it was silently dropped on every scan.
    let user = make_user("jv", None, Some("jose.valim@gmail.com"), None, vec![]);
    let ents = build_entities(user, "scan-hx-004");
    let em = ents.iter().find(|e| e.kind == EntityKind::Email);
    assert!(
        em.is_some(),
        "must emit Email from the published email field"
    );
    assert_eq!(em.expect("should succeed").value, "jose.valim@gmail.com");
    assert!(em.expect("should succeed").has_tag("hexpm"));
}

#[test]
fn emits_github_handle_from_display_key_and_url_value() {
    // REAL shape: key is the display name "GitHub", value is a full URL.
    let user = make_user(
        "elixirlang",
        None,
        None,
        None,
        vec![("GitHub", "https://github.com/elixir-lang")],
    );
    let ents = build_entities(user, "scan-hx-005");
    let gh = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "elixir-lang");
    assert!(gh.is_some(), "must emit Username for the GitHub URL handle");
<<<<<<< HEAD
    assert!(gh.expect("should succeed").has_tag("github") && gh.expect("should succeed").has_tag("hexpm"));
=======
    assert!(
        gh.expect("should succeed").has_tag("github")
            && gh.expect("should succeed").has_tag("hexpm")
    );
>>>>>>> origin/main
    assert!((gh.expect("should succeed").confidence - 0.72).abs() < 0.01);
}

#[test]
fn emits_twitter_handle_from_x_com_display_key() {
    let user = make_user(
        "hex_dev",
        None,
        None,
        None,
        vec![("X.com", "https://x.com/hex_dev_tw")],
    );
    let ents = build_entities(user, "scan-hx-006");
    let tw = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "hex_dev_tw");
    assert!(tw.is_some(), "must emit Username for the X.com URL handle");
    assert!(tw.expect("should succeed").has_tag("twitter"));
    assert!((tw.expect("should succeed").confidence - 0.62).abs() < 0.01);
}

#[test]
fn unknown_platform_handle_not_emitted() {
    let user = make_user(
        "foo",
        None,
        None,
        None,
        vec![
            ("Elixir Forum", "https://elixirforum.com/u/foo"),
            ("Slack", "https://elixir-slack.community"),
            ("Libera", "irc://irc.libera.chat/elixir"),
        ],
    );
    let ents = build_entities(user, "scan-hx-007");
    assert_eq!(
        ents.iter()
            .filter(|e| e.kind == EntityKind::Username && e.value != "foo")
            .count(),
        0,
        "only GitHub / X handles are pivots; forum/slack/irc must be dropped"
    );
}

#[test]
fn account_created_date_travels_as_evidence() {
    let user = make_user(
        "jv",
        None,
        None,
        Some("2015-12-23T15:07:53.627945Z"),
        vec![],
    );
    let ents = build_entities(user, "scan-hx-008");
    let un = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .expect("username entity present");
    assert_eq!(
        un.evidence[0]
            .attributes
            .get("account_created")
            .map(String::as_str),
        Some("2015-12-23T15:07:53.627945Z")
    );
}

#[test]
fn empty_username_returns_no_entities() {
    let user = make_user("", None, None, None, vec![]);
    assert!(build_entities(user, "scan-hx-009").is_empty());
}

#[test]
fn deserialises_the_real_hexpm_response_shape() {
    // Regression for the live-shape mismatch: the pre-fix `HexUser` had no
    // `email`/`inserted_at` and matched `handles` on lowercase keys with
    // bare-handle values — so against the REAL response (display-name keys,
    // full-URL values, a top-level email) it dropped the email AND every
    // cross-platform pivot. This body is trimmed verbatim from a real
    // `GET https://hex.pm/api/users/wojtekmach` response.
    let body = r#"{
        "username": "wojtekmach",
        "full_name": "Wojtek Mach",
        "email": "wojtek@wojtekmach.pl",
        "inserted_at": "2015-12-23T15:07:53.627945Z",
        "handles": {
            "GitHub": "https://github.com/wojtekmach",
            "X.com": "https://x.com/wojtekmach",
            "Elixir Forum": "https://elixirforum.com/u/wojtekmach",
            "Slack": "https://elixir-slack.community"
        }
    }"#;
    let user: HexUser = serde_json::from_str(body).expect("real hex.pm body must deserialise");
    assert_eq!(user.email.as_deref(), Some("wojtek@wojtekmach.pl"));

    let ents = build_entities(user, "scan-hx-real");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Email && e.value == "wojtek@wojtekmach.pl"),
        "the real published email must be recovered"
    );
    assert!(
        ents.iter().any(|e| e.kind == EntityKind::Username
            && e.value == "wojtekmach"
            && e.has_tag("github")),
        "the GitHub cross-platform pivot must be recovered from the URL value"
    );
    assert!(
        ents.iter().any(|e| e.kind == EntityKind::Username
            && e.value == "wojtekmach"
            && e.has_tag("twitter")),
        "the X.com cross-platform pivot must be recovered from the URL value"
    );
    // Forum/Slack are not pivot platforms — no spurious usernames from them.
    assert!(
        !ents
            .iter()
            .any(|e| e.kind == EntityKind::Username && e.value.contains("slack")),
        "non-pivot platforms must not leak entities"
    );
}
