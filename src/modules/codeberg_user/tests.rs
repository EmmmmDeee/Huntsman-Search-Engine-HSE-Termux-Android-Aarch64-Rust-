use super::*;

fn make_user(
    login: &str,
    full_name: Option<&str>,
    description: Option<&str>,
    website: Option<&str>,
    location: Option<&str>,
) -> CbUser {
    CbUser {
        login: login.to_string(),
        full_name: full_name.map(str::to_string),
        email: None,
        description: description.map(str::to_string),
        location: location.map(str::to_string),
        website: website.map(str::to_string),
        html_url: Some(format!("https://codeberg.org/{login}")),
        created: Some("2021-03-15T00:00:00Z".to_string()),
    }
}

// ── Module contract ────────────────────────────────────────────────

#[test]
fn accepts_username_only() {
    let m = CodebergUser;
    assert!(m.accepts(&Target::new(TargetKind::Username, "alice")));
    // Codeberg's `/users/{name}` endpoint is handle-keyed only — there is no
    // email or domain lookup, so those targets must not be routed here.
    assert!(!m.accepts(&Target::new(TargetKind::Email, "alice@example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Alice Dev")));
}

#[test]
fn module_metadata() {
    assert_eq!(CodebergUser.name(), "codeberg_user");
    assert_eq!(CodebergUser.priority(), 105);
    assert_eq!(CodebergUser.max_timeout_ms(), 8_000);
    assert!(!CodebergUser.description().is_empty());
}

#[test]
fn every_emitted_kind_is_declared_in_produces() {
    // Mirrors the repo-wide architecture invariant
    // `every_literal_constructed_entity_kind_is_declared_in_produces`, but at
    // the level of what a maximal record actually emits: a field added to
    // `build_entities` without extending `produces()` fails here with the
    // offending kind named, rather than as an opaque whole-crate assertion.
    let mut user = make_user(
        "alice",
        Some("Alice Dev"),
        Some("Reach me at bio@example.com"),
        Some("https://alice.dev"),
        Some("Brisbane, QLD"),
    );
    user.email = Some("alice@alice.dev".to_string());
    let ents = build_entities(user, "scan-cb-produces");
    let declared = CodebergUser.produces();
    for e in &ents {
        assert!(
            declared.contains(&e.kind),
            "emitted {:?} is not declared in produces()",
            e.kind
        );
    }
    // Guard against the assertion passing vacuously on an empty result.
    assert!(ents.len() >= 7, "maximal record must exercise every branch");
}

// ── CbUser deserialisation (provider response shape) ───────────────

#[test]
fn deserialises_real_codeberg_shape_including_top_level_email() {
    // Regression for the dropped field: the pre-fix `CbUser` had no `email`,
    // so a real published address in the top-level field was lost.
    let body = r#"{
        "login": "alice",
        "full_name": "Alice Dev",
        "email": "alice@alice.dev",
        "description": "FOSS developer",
        "website": "https://alice.dev",
        "html_url": "https://codeberg.org/alice",
        "created": "2021-03-15T00:00:00Z"
    }"#;
    let user: CbUser = serde_json::from_str(body).expect("real codeberg body must deserialise");
    assert_eq!(user.email.as_deref(), Some("alice@alice.dev"));
    let ents = build_entities(user, "scan-cb-real");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Email && e.value == "alice@alice.dev"),
        "the real published email must be recovered from the top-level field"
    );
}

#[test]
fn deserialises_sparse_body_with_only_login() {
    // Forgejo omits unset profile fields entirely rather than sending nulls.
    // Every field but `login` carries `#[serde(default)]`, so a bare account
    // must still parse — losing that would make every minimal profile a hard
    // fetch error instead of a thin-but-valid result.
    let user: CbUser =
        serde_json::from_str(r#"{"id":1,"login":"alice"}"#).expect("sparse body must deserialise");
    assert_eq!(user.login, "alice");
    assert!(user.full_name.is_none() && user.html_url.is_none());
}

#[test]
fn rejects_body_missing_login_and_malformed_json() {
    // `login` is the one non-optional field — it keys the whole record and the
    // `process` handle-match guard. A body without it must be an Err, never a
    // silently empty-named user.
    assert!(
        serde_json::from_str::<CbUser>(r#"{"full_name":"Alice Dev"}"#).is_err(),
        "a body missing the required `login` must not deserialise"
    );
    // Truncated/garbage payloads (proxy interception, HTML error page) must
    // surface as Err rather than panicking inside the parser.
    assert!(serde_json::from_str::<CbUser>("{\"login\":").is_err());
    assert!(serde_json::from_str::<CbUser>("<html>404</html>").is_err());
    // Wrong shape: the endpoint returns an object, not an array of users.
    assert!(serde_json::from_str::<CbUser>(r#"[{"login":"alice"}]"#).is_err());
}

// ── build_entities (pure account→entity mapping) ───────────────────

#[test]
fn builds_username_entity_confirmed_on_codeberg() {
    let user = make_user("alice", None, None, None, None);
    let ents = build_entities(user, "scan-cb-001");
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "alice")
        .expect("must emit Username entity");
    assert!((u.confidence - confidence::EXPERT).abs() < 0.01);
    assert!(u.has_tag("codeberg") && u.has_tag("code"));
    assert_eq!(
        u.evidence[0]
            .attributes
            .get("profile_url")
            .map(String::as_str),
        Some("https://codeberg.org/alice")
    );
    assert_eq!(
        u.evidence[0]
            .attributes
            .get("created_at")
            .map(String::as_str),
        Some("2021-03-15T00:00:00Z")
    );
}

#[test]
fn minimal_account_emits_only_username_and_profile_url() {
    // A profile with every optional field unset is the common case for a
    // fresh Codeberg account. It must still yield the two facts that are
    // always true — the handle exists, and where it lives — and nothing
    // speculative on top.
    let user = CbUser {
        login: "alice".to_string(),
        full_name: None,
        email: None,
        description: None,
        location: None,
        website: None,
        html_url: None,
        created: None,
    };
    let ents = build_entities(user, "scan-cb-minimal");
    assert_eq!(ents.len(), 2, "minimal account must not invent entities");
    assert_eq!(ents[0].kind, EntityKind::Username);
    // `html_url` absent → the profile URL is constructed from the login rather
    // than left empty, so the Url entity is never a bare "".
    assert_eq!(ents[1].kind, EntityKind::Url);
    assert_eq!(ents[1].value, "https://codeberg.org/alice");
    assert_eq!(
        ents[0].evidence[0]
            .attributes
            .get("profile_url")
            .map(String::as_str),
        Some("https://codeberg.org/alice")
    );
}

#[test]
fn emits_person_from_full_name() {
    let user = make_user("alice", Some("Alice Developer"), None, None, None);
    let ents = build_entities(user, "scan-cb-002");
    let p = ents
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("must emit Person from multi-word full name");
    assert_eq!(p.value, "Alice Developer");
}

#[test]
fn no_person_from_single_token_name() {
    // Forgejo defaults `full_name` to the handle when unset, so a single token
    // is a username echo, not a real name.
    let user = make_user("alice", Some("alice"), None, None, None);
    let ents = build_entities(user, "scan-cb-006");
    assert!(
        ents.iter().all(|e| e.kind != EntityKind::Person),
        "single-token full_name must not emit a Person"
    );
}

#[test]
fn emits_public_email_from_top_level_field() {
    // The top-level `email` field the sibling gitea_user harvests but this
    // module used to drop.
    let mut user = make_user("alice", None, None, None, None);
    user.email = Some("alice@personal.dev".to_string());
    let ents = build_entities(user, "scan-cb-email");
    let em = ents
        .iter()
        .find(|e| e.kind == EntityKind::Email)
        .expect("must emit Email from the top-level email field");
    assert_eq!(em.value, "alice@personal.dev");
    assert!(em.has_tag("codeberg"));
}

#[test]
fn skips_forge_noreply_masking_email() {
    // A `@noreply.codeberg.org` masking address is a privacy placeholder,
    // not a real contact — it must NOT become an Email finding (and both
    // Forgejo siblings must agree on this).
    let mut user = make_user("alice", None, None, None, None);
    user.email = Some("alice@noreply.codeberg.org".to_string());
    let ents = build_entities(user, "scan-cb-noreply");
    assert!(
        ents.iter().all(|e| e.kind != EntityKind::Email),
        "a forge no-reply masking address must not seed an Email finding"
    );
}

#[test]
fn emits_website_url_and_domain() {
    let user = make_user("alice", None, None, Some("https://alice.dev"), None);
    let ents = build_entities(user, "scan-cb-003");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://alice.dev"),
        "must emit website URL"
    );
    let d = ents
        .iter()
        .find(|e| e.kind == EntityKind::Domain)
        .expect("must emit domain from website");
    assert_eq!(d.value, "alice.dev");
    assert!(
        d.has_tag("derived"),
        "derived Domain must be tagged as such"
    );
}

#[test]
fn platform_host_website_yields_no_derived_domain() {
    // A profile whose website points at another forge is an account pointer,
    // not personal infrastructure: promoting `github.com` to a Domain would
    // seed correlation on shared platform infrastructure. Only the Url and the
    // two always-present entities survive.
    let user = make_user("alice", None, None, Some("https://github.com/alice"), None);
    let ents = build_entities(user, "scan-cb-platform");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://github.com/alice"),
        "the platform link is still a legitimate Url pivot"
    );
    assert!(
        ents.iter().all(|e| e.kind != EntityKind::Domain),
        "a platform host must never be promoted to a Domain"
    );
}

#[test]
fn non_absolute_website_emits_no_url_or_domain() {
    // Users routinely type a bare host into the website field. Without an
    // `http(s)` scheme it is not a fetchable URL, so neither a Url nor a
    // derived Domain may be fabricated from it.
    let user = make_user("alice", None, None, Some("alice.dev"), None);
    let ents = build_entities(user, "scan-cb-scheme");
    assert!(ents.iter().all(|e| e.kind != EntityKind::Domain));
    // Only the always-present profile Url remains.
    assert_eq!(
        ents.iter().filter(|e| e.kind == EntityKind::Url).count(),
        1,
        "a scheme-less website must not add a second Url"
    );
}

#[test]
fn emits_address_from_location() {
    let user = make_user("alice", None, None, None, Some("Berlin, DE"));
    let ents = build_entities(user, "scan-cb-004");
    let a = ents
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("must emit Address from location");
    assert_eq!(a.value, "Berlin, DE");
    assert!(a.has_tag("self-asserted") && a.has_tag("geo-hint"));
    // Berlin is not in the offline gazetteer — an unknown place must earn no
    // coordinate rather than borrow a nearby one.
    assert!(ents.iter().all(|e| e.kind != EntityKind::Coordinates));
}

#[test]
fn tabulated_location_also_emits_coordinates() {
    // A gazetteer hit adds the inline geocode alongside the Address; the
    // Coordinates entity is declared in produces() and must actually be
    // reachable, otherwise the geo footprint silently loses Codeberg.
    let user = make_user("alice", None, None, None, Some("Brisbane, QLD"));
    let ents = build_entities(user, "scan-cb-geo");
    let c = ents
        .iter()
        .find(|e| e.kind == EntityKind::Coordinates)
        .expect("tabulated city must geocode to Coordinates");
    assert!(c.has_tag("codeberg") && c.has_tag("addr-derived") && c.has_tag("geoint"));
    // Coordinates are calibrated below the Address they derive from.
    let a = ents
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("address entity");
    assert!(c.confidence < a.confidence);
}

#[test]
fn empty_location_emits_no_address_or_coordinates() {
    // Forgejo sends `""` for a cleared location field rather than omitting it.
    let user = make_user("alice", None, None, None, Some("   "));
    let ents = build_entities(user, "scan-cb-emptyloc");
    assert!(
        ents.iter()
            .all(|e| !matches!(e.kind, EntityKind::Address | EntityKind::Coordinates)),
        "a blank location must not seed a geo finding"
    );
}

#[test]
fn emits_email_from_bio() {
    let user = make_user(
        "alice",
        None,
        Some("Contact me at alice@example.com"),
        None,
        None,
    );
    let ents = build_entities(user, "scan-cb-005");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Email && e.value == "alice@example.com"),
        "must extract email from bio"
    );
}

#[test]
fn bio_without_an_email_emits_nothing_extra() {
    // The bio is free text; the extractor must stay quiet on prose rather than
    // guessing at handles or `at`-spelled addresses.
    let user = make_user("alice", None, Some("FOSS developer, she/her"), None, None);
    let ents = build_entities(user, "scan-cb-bio-none");
    assert!(ents.iter().all(|e| e.kind != EntityKind::Email));
    assert_eq!(ents.len(), 2, "a plain bio adds no entities");
}
