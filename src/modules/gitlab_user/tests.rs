use super::*;

fn make_user(
    username: &str,
    name: Option<&str>,
    twitter: Option<&str>,
    website: Option<&str>,
    location: Option<&str>,
    org: Option<&str>,
) -> GlUser {
    GlUser {
        username: username.to_string(),
        name: name.map(str::to_string),
        public_email: None,
        bio: None,
        website_url: website.map(str::to_string),
        location: location.map(str::to_string),
        organization: org.map(str::to_string),
        twitter: twitter.map(str::to_string),
        linkedin: None,
        created_at: Some("2019-01-01T00:00:00Z".to_string()),
    }
}

#[test]
fn accepts_username_only() {
    let m = GitlabUser;
    assert!(m.accepts(&Target::new(TargetKind::Username, "alice")));
    // GitLab's `/users?username=` endpoint is handle-keyed only — an email or a
    // domain seed has no query form here, so dispatching them would burn a
    // request per scan for a guaranteed miss.
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Alice Smith")));
}

#[test]
fn module_metadata() {
    assert_eq!(GitlabUser.name(), "gitlab_user");
    assert_eq!(GitlabUser.priority(), 106);
    assert_eq!(GitlabUser.max_timeout_ms(), 8_000);
    assert!(!GitlabUser.description().is_empty());
}

#[test]
fn parses_keyless_users_array_response() {
    // Exact shape of the UNAUTHENTICATED `/api/v4/users?username=` reply: a JSON
    // ARRAY of the basic public view. Deserialising into a bare object (rather
    // than `Vec<_>`) would fail every real lookup, so the array wrapper is the
    // load-bearing part of this fixture. Unknown/keyed-only fields present in
    // the live body (`id`, `state`, `avatar_url`, `web_url`) must be tolerated.
    let raw = r#"[
        {"id": 1234, "username": "alice", "name": "Alice Smith",
         "state": "active", "locked": false,
         "avatar_url": "https://secure.gravatar.com/avatar/abc",
         "web_url": "https://gitlab.com/alice",
         "public_email": "alice@example.com"}
    ]"#;
    let users: Vec<GlUser> = serde_json::from_str(raw).expect("keyless array body should parse");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].username, "alice");
    assert_eq!(users[0].name.as_deref(), Some("Alice Smith"));
    assert_eq!(users[0].public_email.as_deref(), Some("alice@example.com"));
    // Keyed-only fields are absent from the keyless body and must default to
    // None rather than failing the whole parse.
    assert!(users[0].bio.is_none());
    assert!(users[0].location.is_none());
    assert!(users[0].created_at.is_none());
}

#[test]
fn malformed_response_bodies_are_rejected_not_panicked() {
    // "No such user" is a 200 carrying an empty array — it must deserialise
    // cleanly to zero users so `process` reports a clean miss, not an error.
    let empty: Vec<GlUser> =
        serde_json::from_str("[]").expect("empty array is a valid 'no match' body");
    assert!(empty.is_empty());

    // `username` is the one non-defaulted field: a record without it is not a
    // usable account record and must surface as Err, never a silent placeholder.
    assert!(serde_json::from_str::<Vec<GlUser>>(r#"[{"name": "Alice Smith"}]"#).is_err());
    // Wrong shape (object where the API returns an array) and truncated bodies
    // must also be Err rather than a panic.
    assert!(serde_json::from_str::<Vec<GlUser>>(r#"{"username": "alice"}"#).is_err());
    assert!(serde_json::from_str::<Vec<GlUser>>(r#"[{"username": "ali"#).is_err());
    assert!(serde_json::from_str::<Vec<GlUser>>("").is_err());
}

#[test]
fn build_entities_minimal_account_emits_only_the_username() {
    // The keyless endpoint routinely returns username-only records; that alone
    // is still a confirmed-account pivot, and must not drag along empty extras.
    let ents = build_entities(
        make_user("quietuser", None, None, None, None, None),
        "scan-gl",
    );
    assert_eq!(ents.len(), 1, "only Username when no optional fields");
    let u = &ents[0];
    assert_eq!(u.kind, EntityKind::Username);
    assert_eq!(u.value, "quietuser");
    assert!(u.has_tag("gitlab") && u.has_tag("code"));
    assert!((u.confidence - confidence::VERY_HIGH_PLUS).abs() < 0.01);
    assert_eq!(
        u.evidence[0]
            .attributes
            .get("profile_url")
            .map(String::as_str),
        Some("https://gitlab.com/quietuser")
    );
    // `created_at` is keyed-only; when present it rides on the Username evidence.
    assert_eq!(
        u.evidence[0]
            .attributes
            .get("created_at")
            .map(String::as_str),
        Some("2019-01-01T00:00:00Z")
    );
}

#[test]
fn build_entities_full_profile_emits_every_pivot_and_only_declared_kinds() {
    let mut user = make_user(
        "gluser",
        Some("Alice Coder"),
        Some("@alicetw"),
        Some("https://alice.dev"),
        Some("Sydney, NSW"),
        Some("Acme Corp"),
    );
    user.public_email = Some("dev@example.com".to_string());
    user.linkedin = Some("alice-coder".to_string());
    user.bio = Some("reach me at bio@alice.dev".to_string());
    let ents = build_entities(user, "scan-gl-full");
    let has = |k: EntityKind, v: &str| ents.iter().any(|e| e.kind == k && e.value == v);

    assert!(has(EntityKind::Username, "gluser"));
    assert!(has(EntityKind::Email, "dev@example.com"));
    assert!(has(EntityKind::Person, "Alice Coder"));
    assert!(has(EntityKind::Organisation, "Acme Corp"));
    // The `@` prefix GitLab stores in the twitter field is not part of the
    // handle — leaving it in produces a username that pivots to nothing.
    assert!(has(EntityKind::Username, "alicetw"));
    // A bare LinkedIn handle is expanded to the canonical profile URL; only an
    // already-absolute value is passed through untouched.
    assert!(has(
        EntityKind::Url,
        "https://www.linkedin.com/in/alice-coder"
    ));
    assert!(has(EntityKind::Url, "https://alice.dev"));
    assert!(has(EntityKind::Domain, "alice.dev"));
    let a = ents
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("self-reported location → Address");
    assert_eq!(a.value, "Sydney, NSW");
    assert!(a.has_tag("self-asserted") && a.has_tag("geo-hint"));
    // A geocodable location also yields the derived Coordinates pivot.
    assert!(ents.iter().any(|e| e.kind == EntityKind::Coordinates));
    // Bio-mined contact address, distinct from `public_email`.
    assert!(has(EntityKind::Email, "bio@alice.dev"));

    // Every kind minted here must be declared by produces(), the invariant
    // tests/architecture.rs::every_literal_constructed_entity_kind_is_declared_in_produces
    // enforces repo-wide.
    let declared = GitlabUser.produces();
    for e in &ents {
        assert!(
            declared.contains(&e.kind),
            "{:?} emitted but not declared in produces()",
            e.kind
        );
    }
}

#[test]
fn build_entities_ignores_blank_and_malformed_optional_fields() {
    // Every optional field present but junk: the module must emit the Username
    // and nothing else rather than minting empty-valued or unpivotable entities.
    let mut user = make_user(
        "gluser",
        // Single token is a handle, not a real name → no Person.
        Some("alice"),
        // Bare "@" strips to the empty string → no Twitter pivot.
        Some("@"),
        // Not an absolute http(s) URL → no Url and no derived Domain.
        Some("alice.dev"),
        // >100 chars is a bio mis-filed as a location → no Address/Coordinates.
        Some(&"x".repeat(101)),
        // Whitespace-only organisation → no Organisation.
        Some("   "),
    );
    user.bio = Some("no contact details here".to_string());
    let ents = build_entities(user, "scan-gl-junk");
    assert_eq!(
        ents.len(),
        1,
        "junk optional fields must not mint entities, got {:?}",
        ents.iter().map(|e| (&e.kind, &e.value)).collect::<Vec<_>>()
    );
    assert_eq!(ents[0].kind, EntityKind::Username);
}

#[test]
fn build_entities_public_email_must_look_like_an_address() {
    // `public_email` is the one rich field the keyless endpoint returns, so it
    // is surfaced at high confidence — but GitLab also returns it as "" for
    // accounts that publish no address, which must not become an Email entity.
    let mut user = make_user("gluser", None, None, None, None, None);
    user.public_email = Some("  dev@example.com  ".to_string());
    let ents = build_entities(user, "scan-gl-email");
    let em = ents
        .iter()
        .find(|e| e.kind == EntityKind::Email)
        .expect("public_email → Email entity");
    assert_eq!(em.value, "dev@example.com", "surrounding space trimmed");
    assert!(em.has_tag("gitlab") && em.has_tag("public-profile"));
    assert!((em.confidence - confidence::HIGH_PLUSPLUS_PLUS).abs() < 0.01);

    for junk in ["", "   ", "not-an-email", "a@b"] {
        let mut u = make_user("gluser", None, None, None, None, None);
        u.public_email = Some(junk.to_string());
        assert!(
            build_entities(u, "scan-gl-email-neg")
                .iter()
                .all(|e| e.kind != EntityKind::Email),
            "malformed public_email {junk:?} must not become an Email entity"
        );
    }
}
