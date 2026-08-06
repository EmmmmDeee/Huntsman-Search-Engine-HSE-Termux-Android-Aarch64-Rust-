use super::*;

fn make_profile(
    handle: &str,
    display_name: Option<&str>,
    description: Option<&str>,
) -> BskyProfile {
    BskyProfile {
        handle: handle.to_string(),
        display_name: display_name.map(str::to_string),
        description: description.map(str::to_string),
        did: Some("did:plc:abc123".to_string()),
        created_at: None,
    }
}

// ── module surface ─────────────────────────────────────────────────

#[test]
fn accepts_username_only() {
    let m = BlueskyUser;
    assert!(m.accepts(&Target::new(TargetKind::Username, "alice")));
    // A Bluesky handle can *look* like a domain, but the module is seeded from
    // the username band alone. Accepting Domain would re-probe every domain a
    // scan touches against an actor endpoint that 400s for nearly all of them.
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "alice.dev")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "alice@example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Alice Example")));
}

#[test]
fn module_metadata() {
    assert_eq!(BlueskyUser.name(), "bluesky_user");
    assert_eq!(BlueskyUser.priority(), 104);
    assert_eq!(BlueskyUser.max_timeout_ms(), 8_000);
    assert!(!BlueskyUser.description().is_empty());
}

// ── wire format (`app.bsky.actor.getProfile`) ──────────────────────

#[test]
fn deserialises_the_camel_case_fields_of_a_real_getprofile_body() {
    // Body shape captured from `app.bsky.actor.getProfile`. Every mapping test
    // below builds `BskyProfile` by hand, so nothing pinned the two
    // `#[serde(rename)]`s: dropping either leaves the struct compiling and all
    // hand-built fixtures green while the live module silently loses the display
    // name and the account-age signal on every real lookup. The unknown fields
    // (avatar, counts, labels) must also stay ignored rather than failing the
    // parse — the AppView adds response fields without notice.
    let raw = r#"{
        "did": "did:plc:z72i7hdynmk6r22z27h6tvur",
        "handle": "alice.bsky.social",
        "displayName": "Alice Example",
        "description": "Dev. Reach me at alice@example.com",
        "avatar": "https://cdn.bsky.app/img/avatar/plain/abc/def@jpeg",
        "followersCount": 1234,
        "followsCount": 56,
        "postsCount": 789,
        "indexedAt": "2024-06-01T12:00:00.000Z",
        "createdAt": "2023-04-12T04:53:57.057Z",
        "labels": []
    }"#;
    let p: BskyProfile = serde_json::from_str(raw).expect("realistic getProfile body must parse");
    assert_eq!(p.handle, "alice.bsky.social");
    assert_eq!(
        p.display_name.as_deref(),
        Some("Alice Example"),
        "`displayName` must arrive through the serde rename"
    );
    assert_eq!(
        p.created_at.as_deref(),
        Some("2023-04-12T04:53:57.057Z"),
        "`createdAt` must arrive through the serde rename"
    );
    assert_eq!(p.did.as_deref(), Some("did:plc:z72i7hdynmk6r22z27h6tvur"));

    // and the parsed body drives the same mapping the hand-built fixtures do.
    let ents = build_entities(p, "scan-bsky-016");
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "alice")
        .expect("username entity");
    assert!(u.has_tag("account-age"));
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Person && e.value == "Alice Example")
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Email && e.value == "alice@example.com")
    );
}

#[test]
fn a_minimal_profile_omitting_every_optional_field_parses() {
    // getProfile omits displayName/description/createdAt entirely for a bare
    // account. Each optional field carries `#[serde(default)]`, so absence must
    // read as None rather than a parse failure that would drop a real account.
    let p: BskyProfile = serde_json::from_str(r#"{"handle": "quiet.bsky.social"}"#)
        .expect("minimal body must parse");
    assert_eq!(p.handle, "quiet.bsky.social");
    assert!(
        p.display_name.is_none()
            && p.description.is_none()
            && p.created_at.is_none()
            && p.did.is_none()
    );
    let ents = build_entities(p, "scan-bsky-017");
    assert_eq!(ents.len(), 2, "username + profile URL only");
}

#[test]
fn a_body_without_a_handle_fails_to_parse_rather_than_defaulting() {
    // `handle` is the one non-`default` field, and deliberately so: it is the
    // identity the whole mapping keys off (bare username, profile URL, domain
    // grading). A body lacking it must be an Err the caller treats as a miss,
    // never a profile silently keyed on an empty handle.
    assert!(
        serde_json::from_str::<BskyProfile>(r#"{"did": "did:plc:abc", "displayName": "Alice"}"#)
            .is_err(),
        "a profile without `handle` must not deserialise"
    );
}

#[test]
fn malformed_and_empty_bodies_are_errors_not_panics() {
    // `fetch_json_or_absent` turns each of these into a clean miss; what matters
    // here is that the shape is rejected at the serde boundary instead of
    // unwinding inside a module task.
    for raw in [
        "",
        "not json at all",
        "{",
        "[]",
        "null",
        r#"{"handle": 12345}"#,
    ] {
        assert!(
            serde_json::from_str::<BskyProfile>(raw).is_err(),
            "{raw:?} must deserialise to Err"
        );
    }
}

// ── build_entities (pure profile→entity mapping) ───────────────────

#[test]
fn constructed_entity_kinds_are_all_declared_in_produces() {
    // Runtime dual of the architecture guard
    // `every_literal_constructed_entity_kind_is_declared_in_produces`, which
    // reads the source for literal `Entity::new(EntityKind::X, …)`. Here one
    // profile exercises every emitting branch at once, so a branch that starts
    // minting an undeclared kind fails with the offending value in hand.
    let mut p = make_profile(
        "alice.dev",
        Some("Alice Example"),
        Some("mail alice@example.com blog https://notes.example.org/x"),
    );
    p.created_at = Some("2023-04-01T00:00:00.000Z".to_string());
    let ents = build_entities(p, "scan-bsky-015");
    let declared = BlueskyUser.produces();

    for e in &ents {
        // `Other(_)` is the documented exception — it owns a String and so
        // cannot sit in the `const` produces() slice.
        if matches!(e.kind, EntityKind::Other(_)) {
            continue;
        }
        assert!(
            declared.contains(&e.kind),
            "{:?} (value {:?}) is emitted but not declared in produces()",
            e.kind,
            e.value
        );
    }

    // Coverage floor: without it the loop above passes vacuously the moment the
    // fixture stops reaching a branch.
    for k in [
        EntityKind::Username,
        EntityKind::Person,
        EntityKind::Email,
        EntityKind::Url,
        EntityKind::Domain,
    ] {
        assert!(
            ents.iter().any(|e| e.kind == k),
            "fixture must exercise the {k:?} branch"
        );
    }
}

#[test]
fn builds_username_strips_bsky_social_suffix() {
    let p = make_profile("alice.bsky.social", None, None);
    let ents = build_entities(p, "scan-bsky-001");
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "alice");
    assert!(
        u.is_some(),
        "must strip .bsky.social and emit bare username"
    );
    assert!((u.expect("should succeed").confidence - confidence::HIGH_PLUSPLUS_PLUS).abs() < 0.01);
    assert!(u.expect("should succeed").has_tag("bluesky"));
}

#[test]
fn emits_person_from_multi_word_display_name() {
    let p = make_profile("alice.bsky.social", Some("Alice Example"), None);
    let ents = build_entities(p, "scan-bsky-003");
    let person = ents.iter().find(|e| e.kind == EntityKind::Person);
    assert!(
        person.is_some(),
        "must emit Person from multi-word display name"
    );
    assert_eq!(person.expect("should succeed").value, "Alice Example");
}

#[test]
fn no_person_for_single_word_name() {
    let p = make_profile("alice.bsky.social", Some("alice"), None);
    let ents = build_entities(p, "scan-bsky-004");
    assert!(
        ents.iter().all(|e| e.kind != EntityKind::Person),
        "single-token display name must not produce a Person entity"
    );
}

#[test]
fn emits_email_and_url_from_bio() {
    let p = make_profile(
        "alice.bsky.social",
        None,
        Some("Contact: alice@example.com | Blog: https://alice.dev/blog"),
    );
    let ents = build_entities(p, "scan-bsky-005");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Email && e.value == "alice@example.com"),
        "must extract email from bio"
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value.contains("alice.dev/blog")),
        "must extract URL from bio"
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "alice.dev"),
        "must extract domain from bio URL"
    );
}

#[test]
fn emits_profile_url() {
    let p = make_profile("alice.bsky.social", None, None);
    let ents = build_entities(p, "scan-bsky-006");
    assert!(
        ents.iter().any(|e| e.kind == EntityKind::Url
            && e.value == "https://bsky.app/profile/alice.bsky.social"),
        "must emit canonical bsky.app profile URL"
    );
}

#[test]
fn did_is_promoted_to_its_own_other_kind_entity() {
    let p = make_profile("alice.bsky.social", None, None);
    let ents = build_entities(p, "scan-bsky-010");
    let d = ents
        .iter()
        .find(|e| e.kind == EntityKind::Other("bluesky-did".into()) && e.value == "did:plc:abc123");
    assert!(
        d.is_some(),
        "DID must be promoted to its own Other(\"bluesky-did\") entity, not just folded into evidence"
    );
    assert!(d.expect("should succeed").has_tag("bluesky"));
    assert!(d.expect("should succeed").has_tag("did"));
    // Must not be emitted as Username — a raw DID fed into username
    // enumeration modules would produce noisy, doomed lookups.
    assert!(
        !ents
            .iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "did:plc:abc123"),
        "DID must never be emitted as a Username entity"
    );
}

#[test]
fn no_did_entity_when_did_absent() {
    let mut p = make_profile("alice.bsky.social", None, None);
    p.did = None;
    let ents = build_entities(p, "scan-bsky-011");
    assert!(
        ents.iter()
            .all(|e| e.kind != EntityKind::Other("bluesky-did".into())),
        "no DID entity when did is absent from the profile"
    );
}

#[test]
fn no_entities_beyond_username_and_profile_url_for_empty_profile() {
    let p = make_profile("quiet.bsky.social", None, None);
    let ents = build_entities(p, "scan-bsky-007");
    assert_eq!(
        ents.len(),
        3,
        "username + did + profile URL only when no optional fields"
    );
}

#[test]
fn created_at_dates_the_account_as_age_evidence() {
    let mut p = make_profile("alice.bsky.social", None, None);
    p.created_at = Some("2023-04-01T00:00:00.000Z".to_string());
    let ents = build_entities(p, "scan-bsky-008");
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "alice")
        .expect("username entity");
    // The account-age tag flags it as a creation-date signal,
    assert!(
        u.has_tag("account-age"),
        "created account must be tagged account-age"
    );
    // and the ISO timestamp is reduced to its UTC date in evidence.
    assert!(
        u.evidence.iter().any(|ev| ev
            .attributes
            .get("created_at")
            .is_some_and(|v| v.as_str() == "2023-04-01")),
        "creation date must be carried as `created_at` evidence (YYYY-MM-DD)"
    );
}

#[test]
fn no_account_age_tag_without_created_at() {
    let p = make_profile("alice.bsky.social", None, None);
    let ents = build_entities(p, "scan-bsky-009");
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "alice")
        .expect("username entity");
    assert!(
        !u.has_tag("account-age"),
        "no account-age tag when createdAt is absent"
    );
}

#[test]
fn a_platform_handle_outside_bsky_social_still_collapses_to_the_bare_name() {
    // Staff (`.bsky.team`) and bridged (`.brid.gy`, `.translate.goog`)
    // accounts carry names the platform issued, exactly like `.bsky.social`.
    // While only `.bsky.social` was stripped here, `bnewbold.bsky.team` was
    // emitted whole and so could never meet the `bnewbold` that
    // `plc_directory` and the rest of the social band emit for the same
    // person. The shared namespace list is what closes that.
    for (handle, bare) in [
        ("bnewbold.bsky.team", "bnewbold"),
        ("someone.brid.gy", "someone"),
        ("retr0-id.translate.goog", "retr0-id"),
    ] {
        let ents = build_entities(make_profile(handle, None, None), "scan-bsky-012");
        assert!(
            ents.iter()
                .any(|e| e.kind == EntityKind::Username && e.value == bare),
            "{handle} must collapse to the bare username {bare}"
        );
    }
}

#[test]
fn a_platform_issued_handle_never_becomes_a_domain() {
    // Emitting one of these as the subject's Domain would attribute
    // Bluesky's, Bridgy's or Google's infrastructure to an individual — the
    // confident wrong finding the shared namespace list exists to prevent.
    for handle in [
        "alice.bsky.social",
        "bnewbold.bsky.team",
        "someone.brid.gy",
        "retr0-id.translate.goog",
    ] {
        let ents = build_entities(make_profile(handle, None, None), "scan-bsky-013");
        assert!(
            ents.iter().all(|e| e.kind != EntityKind::Domain),
            "{handle} is a platform-issued name and must not become a Domain"
        );
    }
}

#[test]
fn a_domain_handle_carries_what_it_proves_and_what_it_does_not() {
    let ents = build_entities(make_profile("alice.dev", None, None), "scan-bsky-002");
    let d = ents
        .iter()
        .find(|e| e.kind == EntityKind::Domain && e.value == "alice.dev")
        .expect("a custom-domain handle must emit a Domain entity");
    assert!(d.has_tag("custom-handle"));
    // Graded by the shared function rather than by a literal, so this module
    // and `plc_directory` cannot hand noisy-OR two different grades for one
    // fact.
    assert!(
        (d.confidence - handle_domain_confidence(true, "alice.dev")).abs() < f64::EPSILON,
        "domain confidence must come from the shared grading, not a local constant"
    );
    let ev = d.evidence.first().expect("domain evidence");
    assert_eq!(
        ev.attributes.get("attribution").map(String::as_str),
        Some(DOMAIN_HANDLE_ATTRIBUTION),
        "the dossier must state what a domain handle demonstrates"
    );
    assert_eq!(
        ev.attributes.get("coverage").map(String::as_str),
        Some(DOMAIN_HANDLE_CAVEAT),
        "and what it does not — verified control is not registration ownership"
    );
}

#[test]
fn a_handle_issued_out_of_someone_elses_domain_is_graded_below_an_apex_one() {
    // The platform list cannot enumerate every provider that hands out
    // subdomain handles, so label depth covers the tail: the domain is still
    // reported, and it does not arrive with an apex handle's authority.
    let ents = build_entities(
        make_profile("alice.pds.example.org", None, None),
        "scan-bsky-014",
    );
    let d = ents
        .iter()
        .find(|e| e.kind == EntityKind::Domain && e.value == "alice.pds.example.org")
        .expect("a non-platform handle is still infrastructure worth reporting");
    assert!(
        d.confidence < handle_domain_confidence(true, "alice.dev"),
        "a subdomain handle must not grade as a registrable domain the subject obtained"
    );
}

#[test]
fn only_probes_that_can_succeed_are_issued() {
    // The gate in `process`, stated as the pairing it enforces. `alice` can
    // only ever be `alice.bsky.social`; `alice.dev` can only ever be itself;
    // and `_ryno_23` — the exact case from a live scan — is neither shape, so
    // no request is issued for it at all rather than two guaranteed 400s.
    assert!(is_dns_label("alice") && !is_handle("alice"));
    assert!(!is_dns_label("alice.dev") && is_handle("alice.dev"));
    assert!(!is_dns_label("_ryno_23") && !is_handle("_ryno_23"));
}
