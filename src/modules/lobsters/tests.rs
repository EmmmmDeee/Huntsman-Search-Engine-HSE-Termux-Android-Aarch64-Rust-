use super::*;

fn make_user(
    username: &str,
    karma: i64,
    github: Option<&str>,
    twitter: Option<&str>,
    about: Option<&str>,
) -> LobstersUser {
    LobstersUser {
        username: username.to_string(),
        created_at: Some("2015-03-01T00:00:00Z".to_string()),
        karma: Some(karma),
        about: about.map(str::to_string),
        is_moderator: Some(false),
        github_username: github.map(str::to_string),
        twitter_username: twitter.map(str::to_string),
        mastodon_username: None,
        invited_by_user: None,
    }
}

fn user_with_mastodon(username: &str, mastodon: &str) -> LobstersUser {
    let mut u = make_user(username, 100, None, None, None);
    u.mastodon_username = Some(mastodon.to_string());
    u
}

#[test]
fn accepts_username_only() {
    let m = Lobsters;
    assert!(m.accepts(&Target::new(TargetKind::Username, "pushcx")));
    // Lobste.rs exposes no email or domain lookup — routing either kind here
    // would spend a scan slot on a request that can only 404.
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "lobste.rs")));
}

#[test]
fn module_metadata() {
    assert_eq!(Lobsters.name(), "lobsters");
    assert_eq!(Lobsters.priority(), 104);
    assert_eq!(Lobsters.max_timeout_ms(), 8_000);
    assert!(!Lobsters.description().is_empty());
}

// ── LobstersUser deserialization (the wire contract) ───────────────

#[test]
fn parses_live_shaped_account_json() {
    // Shape of a real `GET https://lobste.rs/~{user}.json` body. Pins that the
    // live cross-platform pivot fields (`github_username`, `mastodon_username`,
    // `invited_by_user`) survive deserialization — they are what makes this
    // module worth a round-trip, and a silent rename upstream would otherwise
    // degrade to a bare Username with no test noticing.
    let raw = r#"{
        "username": "pushcx",
        "created_at": "2012-05-01T00:00:00.000-06:00",
        "is_admin": true,
        "about": "Lobsters admin. Reach me at pushcx@example.com",
        "is_moderator": true,
        "karma": 12345,
        "avatar_url": "/avatars/pushcx-100.png",
        "invited_by_user": "jcs",
        "github_username": "pushcx",
        "mastodon_username": "pushcx@hachyderm.io"
    }"#;
    let u: LobstersUser = serde_json::from_str(raw).expect("live-shaped body must deserialize");
    assert_eq!(u.username, "pushcx");
    assert_eq!(u.karma, Some(12345));
    assert_eq!(u.is_moderator, Some(true));
    assert_eq!(u.github_username.as_deref(), Some("pushcx"));
    assert_eq!(u.mastodon_username.as_deref(), Some("pushcx@hachyderm.io"));
    assert_eq!(u.invited_by_user.as_deref(), Some("jcs"));
    // Unknown/new server fields (is_admin, avatar_url) must not fail the parse.
    assert!(u.created_at.is_some());
    // Dormant legacy field: the live API stopped returning it, so it must
    // default rather than being a required key.
    assert_eq!(u.twitter_username, None);
}

#[test]
fn deserialization_rejects_malformed_and_incomplete_bodies() {
    // `username` is the one non-defaulted field: a body without it is not a
    // Lobste.rs account, and must surface as Err rather than an entity built
    // on an empty handle.
    let missing_username = serde_json::from_str::<LobstersUser>(r#"{"karma": 10}"#);
    assert!(missing_username.is_err(), "missing username must be Err");

    // An empty body (some proxies return one on error) and a wrong-shaped
    // payload must both be errors, never a panic.
    assert!(serde_json::from_str::<LobstersUser>("").is_err());
    assert!(serde_json::from_str::<LobstersUser>("[]").is_err());
    assert!(serde_json::from_str::<LobstersUser>(r#"{"username": 42}"#).is_err());
}

// ── build_entities (pure account→entity mapping) ───────────────────

#[test]
fn builds_username_entity_with_correct_confidence() {
    let user = make_user("devuser", 500, None, None, None);
    let entities = build_entities(user, "scan-lob-001");
    let u = entities
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "devuser");
    assert!(u.is_some(), "must emit Username entity for the account");
    assert!((u.expect("should succeed").confidence - confidence::VERY_HIGH_PLUS).abs() < 0.01);
}

#[test]
fn emits_github_username_pivot() {
    let user = make_user("devuser", 500, Some("devuser-gh"), None, None);
    let entities = build_entities(user, "scan-lob-002");
    let gh = entities
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "devuser-gh");
    assert!(gh.is_some(), "must emit GitHub username pivot");
    assert!(
        gh.expect("should succeed").has_tag("github"),
        "pivot entity must carry 'github' tag"
    );
}

#[test]
fn emits_invited_by_username_pivot() {
    let mut user = make_user("devuser", 500, None, None, None);
    user.invited_by_user = Some("founder".to_string());
    let entities = build_entities(user, "scan-lob-006");
    let inv = entities
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "founder")
        .expect("must emit invited-by username pivot");
    assert!(
        inv.has_tag("lobsters-invited-by"),
        "pivot entity must carry 'lobsters-invited-by' tag"
    );
    // A vouching relationship is NOT a cross-service identity claim; tagging it
    // "lobsters-pivot" would let downstream consumers treat the inviter as the
    // same person as the target.
    assert!(
        !inv.has_tag("lobsters-pivot"),
        "invited-by must not be labelled a cross-platform pivot"
    );
}

#[test]
fn emits_twitter_username_pivot_stripping_at_prefix() {
    let user = make_user("devuser", 200, None, Some("@twitterhandle"), None);
    let entities = build_entities(user, "scan-lob-003");
    let tw = entities
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "twitterhandle");
    assert!(tw.is_some(), "must strip @ and emit Twitter username");
}

#[test]
fn emits_bare_mastodon_username_pivot() {
    // The live shape for most accounts: a bare fediverse handle (no server).
    let entities = build_entities(user_with_mastodon("pushcx", "lobsters"), "scan-lob-md1");
    let m = entities
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "lobsters")
        .expect("must emit the mastodon username pivot");
    assert!(m.has_tag("mastodon") && m.has_tag("fediverse") && m.has_tag("lobsters-pivot"));
    // No server → no homeserver Domain entity.
    assert!(!entities.iter().any(|e| e.kind == EntityKind::Domain));
}

#[test]
fn emits_qualified_mastodon_handle_and_homeserver_domain() {
    // A fully-qualified `@user@server` handle → Username(local) + Domain(server).
    let entities = build_entities(
        user_with_mastodon("dev", "@alice@fosstodon.org"),
        "scan-lob-md2",
    );
    let m = entities
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "alice")
        .expect("local part → Username");
    assert!(m.has_tag("mastodon"));
    assert_eq!(
        m.evidence[0]
            .attributes
            .get("homeserver")
            .map(String::as_str),
        Some("fosstodon.org")
    );
    let d = entities
        .iter()
        .find(|e| e.kind == EntityKind::Domain && e.value == "fosstodon.org")
        .expect("homeserver → Domain pivot");
    assert!(d.has_tag("mastodon-homeserver"));
}

#[test]
fn degenerate_pivot_field_values_emit_no_entities() {
    // Empty/punctuation-only field values are the realistic garbage a
    // user-editable profile yields. Each guard below exists to stop an empty or
    // dotless value becoming a bogus pivot entity that pollutes correlation.
    let mut user = make_user("quietuser", 10, Some(""), Some("@"), Some("no links here"));
    user.invited_by_user = Some("   ".to_string());
    user.mastodon_username = Some("@".to_string());
    let entities = build_entities(user, "scan-lob-007");
    assert_eq!(
        entities.len(),
        1,
        "only the subject Username may survive degenerate field values, got: {:?}",
        entities.iter().map(|e| &e.value).collect::<Vec<_>>()
    );
    assert_eq!(entities[0].value, "quietuser");

    // A dotless homeserver (e.g. an intranet host) is not a resolvable domain,
    // so it must not be minted as a Domain lead.
    let entities = build_entities(user_with_mastodon("dev", "alice@localhost"), "scan-lob-008");
    assert!(
        !entities.iter().any(|e| e.kind == EntityKind::Domain),
        "dotless homeserver must not become a Domain entity"
    );
}

#[test]
fn extracts_email_and_url_from_bio() {
    let about = "contact me at dev@example.com or visit https://example.com/about";
    let user = make_user("devuser", 100, None, None, Some(about));
    let entities = build_entities(user, "scan-lob-004");
    assert!(
        entities
            .iter()
            .any(|e| e.kind == EntityKind::Email && e.value == "dev@example.com"),
        "must extract email from bio"
    );
    assert!(
        entities.iter().any(|e| e.kind == EntityKind::Url),
        "must extract URL from bio"
    );
    assert!(
        entities
            .iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "example.com"),
        "must emit Domain entity from bio URL"
    );
}

#[test]
fn no_entities_for_empty_optional_fields() {
    let user = make_user("quietuser", 10, None, None, None);
    let entities = build_entities(user, "scan-lob-005");
    assert_eq!(
        entities.len(),
        1,
        "only the Username entity when no pivots or bio"
    );
    assert_eq!(entities[0].kind, EntityKind::Username);
}

#[test]
fn every_built_entity_kind_is_declared_in_produces() {
    // Local guard for the same invariant `tests/architecture.rs`'s
    // `every_literal_constructed_entity_kind_is_declared_in_produces` enforces
    // crate-wide — but asserted on entities actually built, so a new emission
    // path fails here with the module's own fixture rather than in a global scan.
    let mut user = make_user(
        "devuser",
        900,
        Some("devuser-gh"),
        Some("@devtweets"),
        Some("mail dev@example.com or https://example.com/about"),
    );
    user.invited_by_user = Some("jcs".to_string());
    user.mastodon_username = Some("@alice@fosstodon.org".to_string());
    let entities = build_entities(user, "scan-lob-produces");

    let declared = Lobsters.produces();
    for e in &entities {
        assert!(
            declared.contains(&e.kind),
            "built {:?} ({}) is absent from produces()",
            e.kind,
            e.value
        );
    }
    // Coverage floor: keeps the assertion above from passing vacuously if a
    // fixture change stops exercising a branch.
    for kind in declared {
        assert!(
            entities.iter().any(|e| &e.kind == kind),
            "maximal fixture never exercised declared kind {kind:?}"
        );
    }
}
