use super::*;

/// Sparse `DevUser` builder — every optional field defaults to absent so each
/// test opts in to exactly the profile fields whose branch it exercises.
fn user(username: &str) -> DevUser {
    DevUser {
        username: username.to_string(),
        name: None,
        summary: None,
        twitter_username: None,
        github_username: None,
        website_url: None,
        location: None,
        joined_at: None,
    }
}

#[test]
fn accepts_username_only() {
    let m = DevTo;
    assert!(m.accepts(&Target::new(TargetKind::Username, "alice")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "alice@example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "dev.to")));
}

#[test]
fn module_metadata() {
    assert_eq!(DevTo.name(), "devto");
    assert_eq!(DevTo.priority(), 103);
    assert_eq!(DevTo.max_timeout_ms(), 8_000);
    assert!(!DevTo.description().is_empty());
}

// ── DevUser deserialization (the wire contract) ────────────────────

#[test]
fn parse_profile_json_extracts_every_pivot_field() {
    // Shape of a real `GET /api/users/by_username` body, including the
    // `type_of`/`id`/`profile_image` fields the struct does not model: the
    // response carries far more keys than we consume, so this pins that no
    // `deny_unknown_fields` creeps in and silently fails every live lookup.
    let raw = r#"{
        "type_of": "user",
        "id": 12345,
        "username": "alice",
        "name": "Alice Smith",
        "summary": "Rust and embedded systems.",
        "twitter_username": "alicetw",
        "github_username": "alice-gh",
        "website_url": "https://alice.dev",
        "location": "Sydney, NSW",
        "joined_at": "Jan 1, 2019",
        "profile_image": "https://media.dev.to/alice.png"
    }"#;
    let u: DevUser = serde_json::from_str(raw).expect("realistic dev.to profile body must parse");
    assert_eq!(u.username, "alice");
    assert_eq!(u.name.as_deref(), Some("Alice Smith"));
    assert_eq!(u.twitter_username.as_deref(), Some("alicetw"));
    assert_eq!(u.github_username.as_deref(), Some("alice-gh"));
    assert_eq!(u.website_url.as_deref(), Some("https://alice.dev"));
    assert_eq!(u.location.as_deref(), Some("Sydney, NSW"));
    assert_eq!(u.joined_at.as_deref(), Some("Jan 1, 2019"));

    // Dev.to sends JSON `null` (not an absent key) for unset optional profile
    // fields, so `#[serde(default)]` alone would not save us — `Option<T>`
    // must absorb the null rather than erroring the whole lookup.
    let nulls = r#"{"username":"bob","name":null,"summary":null,"twitter_username":null,
                    "github_username":null,"website_url":null,"location":null,"joined_at":null}"#;
    let b: DevUser = serde_json::from_str(nulls).expect("null-valued optional fields must parse");
    assert_eq!(b.username, "bob");
    assert!(b.name.is_none() && b.website_url.is_none());
}

#[test]
fn parse_rejects_body_missing_required_username() {
    // `username` is the one non-defaulted field: everything downstream keys the
    // profile URL and evidence off it, so a body without it must be an Err the
    // caller propagates, never a silently empty-named account entity.
    assert!(serde_json::from_str::<DevUser>(r#"{"name":"Alice Smith","id":1}"#).is_err());
    assert!(serde_json::from_str::<DevUser>("{}").is_err());
    // Wrong shape / truncated body: an error, not a panic.
    assert!(serde_json::from_str::<DevUser>("[]").is_err());
    assert!(serde_json::from_str::<DevUser>(r#"{"username":"alice""#).is_err());
    assert!(serde_json::from_str::<DevUser>("").is_err());
}

// ── build_entities (pure account→entity mapping) ───────────────────

#[test]
fn build_entities_full_profile_emits_all_declared_pivots() {
    let mut u = user("alice");
    u.name = Some("Alice Smith".to_string());
    u.github_username = Some("alice-gh".to_string());
    // Dev.to stores the handle bare, but users routinely type the `@` in; the
    // pivot must be the handle alone or every downstream username lookup 404s.
    u.twitter_username = Some("@alicetw".to_string());
    u.website_url = Some("https://alice.dev".to_string());
    u.location = Some("Sydney, NSW".to_string());
    u.joined_at = Some("Jan 1, 2019".to_string());

    let ents = build_entities(u, "scan-dt");
    let find = |k: EntityKind, v: &str| ents.iter().find(|e| e.kind == k && e.value == v);

    // Subject account: confirmed-on-dev.to, with the profile URL folded in.
    let acct = find(EntityKind::Username, "alice").expect("subject username entity");
    assert!(acct.has_tag("devto"));
    assert!((acct.confidence - confidence::EXPERT).abs() < f64::EPSILON);
    let attr = |k: &str| acct.evidence[0].attributes.get(k).map(String::as_str);
    assert_eq!(attr("profile_url"), Some("https://dev.to/alice"));
    assert_eq!(attr("joined_at"), Some("Jan 1, 2019"));

    assert!(find(EntityKind::Person, "Alice Smith").is_some());

    let gh = find(EntityKind::Username, "alice-gh").expect("github pivot");
    assert!(gh.has_tag("github") && gh.has_tag("devto-pivot"));

    let tw = find(EntityKind::Username, "alicetw").expect("twitter pivot with '@' stripped");
    assert!(tw.has_tag("twitter"));

    let site = find(EntityKind::Url, "https://alice.dev").expect("personal site url");
    assert!(site.has_tag("personal-site"));
    let dom = find(EntityKind::Domain, "alice.dev").expect("domain derived from website");
    assert!(dom.has_tag("derived"));

    let addr = find(EntityKind::Address, "Sydney, NSW").expect("self-reported location");
    assert!(addr.has_tag("self-asserted") && addr.has_tag("geo-hint"));
    // A tabulated city geocodes offline, so the Address is accompanied by
    // Coordinates — the pair is what puts the account on the geo footprint.
    let coords = ents
        .iter()
        .find(|e| e.kind == EntityKind::Coordinates)
        .expect("geocoded coordinates for a tabulated city");
    assert!(coords.has_tag("devto") && coords.has_tag("addr-derived"));

    // `every_literal_constructed_entity_kind_is_declared_in_produces` enforces
    // this statically; assert it on real output too so a future branch that
    // emits an undeclared kind fails here with the offending kind named.
    let declared = DevTo.produces();
    for e in &ents {
        assert!(
            declared.contains(&e.kind),
            "emitted {:?} is not declared in produces()",
            e.kind
        );
    }
}

#[test]
fn build_entities_extracts_emails_and_links_from_bio() {
    let mut u = user("alice");
    u.summary =
        Some("Rust dev. Contact alice@example.com or read https://alice.dev/blog for more.".into());
    let ents = build_entities(u, "scan-dt");

    // extract::emails lowercases and dedupes; the bio is the only place a
    // contact address surfaces on dev.to, so losing it loses the pivot.
    let em = ents
        .iter()
        .find(|e| e.kind == EntityKind::Email)
        .expect("email mined from bio");
    assert_eq!(em.value, "alice@example.com");
    assert!(em.has_tag("public-profile"));

    // The trailing sentence period must not be swallowed into the URL.
    let link = ents
        .iter()
        .find(|e| e.kind == EntityKind::Url)
        .expect("link mined from bio");
    assert_eq!(link.value, "https://alice.dev/blog");
}

#[test]
fn build_entities_minimal_profile_emits_only_the_username() {
    // Empty-string pivot fields are what dev.to returns for "never filled in",
    // and a single-token `name` is the handle echoed back — neither is a real
    // pivot, so an unguarded mapping would emit junk Username/Person entities.
    let mut u = user("alice");
    u.name = Some("alice".to_string());
    u.github_username = Some(String::new());
    u.twitter_username = Some(String::new());

    let ents = build_entities(u, "scan-dt");
    assert_eq!(ents.len(), 1, "only the subject account is a real finding");
    assert_eq!(ents[0].kind, EntityKind::Username);
    assert_eq!(ents[0].value, "alice");
}

#[test]
fn build_entities_skips_schemeless_website_and_ungeocodable_location() {
    // `website_url` is free text: users type a bare host. Without a scheme it
    // is not a resolvable URL, so neither the Url nor the derived Domain may be
    // fabricated from it.
    let mut u = user("alice");
    u.website_url = Some("alice.dev".to_string());
    u.location = Some("Freedonia".to_string());

    let ents = build_entities(u, "scan-dt");
    assert!(
        !ents
            .iter()
            .any(|e| matches!(e.kind, EntityKind::Url | EntityKind::Domain)),
        "a schemeless website must yield no Url/Domain"
    );
    // The location is still recorded as a coarse self-asserted Address, but an
    // unrecognised place must not borrow a coordinate from anywhere.
    assert!(ents.iter().any(|e| e.kind == EntityKind::Address));
    assert!(
        !ents.iter().any(|e| e.kind == EntityKind::Coordinates),
        "an unrecognised place must not be geocoded"
    );
}
