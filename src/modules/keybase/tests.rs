use super::*;

#[test]
fn accepts_username_only() {
    let m = Keybase;
    assert!(m.accepts(&Target::new(TargetKind::Username, "alice")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
}

#[test]
fn module_metadata() {
    assert_eq!(Keybase.name(), "keybase");
    assert_eq!(Keybase.priority(), 100);
    assert_eq!(Keybase.max_timeout_ms(), 4_000);
    assert!(!Keybase.description().is_empty());
}

#[test]
fn parse_response() {
    // `them` is a single OBJECT (the singular ?username= endpoint), not an
    // array — this pins the shape that a `Vec<KbUser>` used to reject with
    // "invalid type: map, expected a sequence" on every real lookup.
    let raw = r#"{
        "status": {"code": 0, "name": "OK"},
        "them": {
            "id": "abc123",
            "basics": {"username": "alice", "ctime": 1500000000},
            "profile": {"full_name": "Alice Smith", "location": "Sydney, AU", "bio": "dev"},
            "proofs_summary": {
                "all": [
                    {"proof_type": "twitter", "nametag": "alice_s", "state": 1},
                    {"proof_type": "github", "nametag": "alicesmith", "state": 1},
                    {"proof_type": "dns", "nametag": "alice.dev", "state": 1}
                ]
            }
        }
    }"#;
    let r: KbResp = serde_json::from_str(raw).unwrap();
    assert_eq!(r.status.unwrap().code, Some(0));
    let user = r.them.unwrap();
    assert_eq!(
        user.basics.as_ref().unwrap().username.as_deref(),
        Some("alice")
    );
    assert_eq!(
        user.profile.as_ref().unwrap().full_name.as_deref(),
        Some("Alice Smith")
    );
    assert_eq!(user.proofs_summary.as_ref().unwrap().all.len(), 3);
}

#[test]
fn extract_proofs_maps_verified_links_and_urls() {
    // Shape captured from the live keybase.io lookup for `chris`.
    let proofs: Vec<KbProof> = serde_json::from_str(
        r#"[
            {"proof_type":"twitter","nametag":"malgorithms","state":1,"service_url":"https://twitter.com/malgorithms"},
            {"proof_type":"github","nametag":"malgorithms","state":1,"service_url":"https://github.com/malgorithms"},
            {"proof_type":"gitlab","nametag":"mal","state":1,"service_url":"https://gitlab.com/mal"},
            {"proof_type":"dns","nametag":"chriscoyne.com","state":1,"service_url":"http://chriscoyne.com"},
            {"proof_type":"twitter","nametag":"revoked","state":2,"service_url":"https://twitter.com/revoked"}
        ]"#,
    )
    .unwrap();
    let mut r = ModuleResult::new();
    extract_proofs(&proofs, "chris", "scan", &mut r);
    let has = |k: EntityKind, v: &str| r.entities.iter().any(|e| e.kind == k && e.value == v);

    // Cross-platform handles (incl. the newly-supported gitlab).
    assert!(has(EntityKind::Username, "malgorithms"));
    assert!(
        has(EntityKind::Username, "mal"),
        "gitlab proof now supported"
    );
    // Verified service_url surfaced as a first-class profile link.
    assert!(has(EntityKind::Url, "https://github.com/malgorithms"));
    // DNS proof → owned domain.
    assert!(has(EntityKind::Domain, "chriscoyne.com"));
    // Revoked (state != 1) proof dropped entirely.
    assert!(!has(EntityKind::Username, "revoked"));
    assert!(!has(EntityKind::Url, "https://twitter.com/revoked"));
    // Verified handles carry the `verified` tag.
    let gh = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "malgorithms")
        .unwrap();
    assert!(gh.has_tag("verified") && gh.has_tag("keybase"));
}

// ── build_entities (pure profile→entity mapping) ───────────────────

fn kb(raw: &str) -> KbResp {
    serde_json::from_str(raw).expect("valid KbResp fixture")
}

#[test]
fn build_entities_full_au_profile_emits_username_person_address_coords() {
    let body = kb(r#"{
        "status": {"code": 0},
        "them": {
            "id": "abc123",
            "basics": {"username": "alice", "ctime": 1500000000},
            "profile": {"full_name": "Alice Smith", "location": "Sydney, NSW", "bio": "dev"},
            "proofs_summary": {"all": []}
        }
    }"#);
    let ents = build_entities(body, "alice", "scan");
    let find = |k: EntityKind, v: &str| ents.iter().find(|e| e.kind == k && e.value == v);

    // Subject Username carries the folded profile evidence.
    let u = find(EntityKind::Username, "alice").expect("username entity");
    assert!(u.has_tag("keybase"));
    let attr = |k: &str| u.evidence[0].attributes.get(k).map(String::as_str);
    assert_eq!(attr("profile_url"), Some("https://keybase.io/alice"));
    assert_eq!(attr("proof_count"), Some("0"));
    assert_eq!(attr("full_name"), Some("Alice Smith"));
    assert_eq!(attr("location"), Some("Sydney, NSW"));
    assert_eq!(attr("keybase_id"), Some("abc123"));
    assert_eq!(attr("created_at_unix"), Some("1500000000"));

    // full_name (≥3 chars, has a space) → Person pivot.
    assert!(find(EntityKind::Person, "Alice Smith").is_some());

    // Self-reported AU location → Address tagged with state + country.
    let a = find(EntityKind::Address, "Sydney, NSW").expect("address entity");
    assert!(a.has_tag("self-reported") && a.has_tag("geoint"));
    assert!(a.has_tag("au-state:NSW") && a.has_tag("country:AU"));

    // Inline geocode → Coordinates carrying the same AU tags.
    let c = ents
        .iter()
        .find(|e| e.kind == EntityKind::Coordinates)
        .expect("coords entity");
    assert!(c.has_tag("addr-derived") && c.has_tag("keybase"));
    assert!(c.has_tag("au-state:NSW") && c.has_tag("country:AU"));
}

#[test]
fn build_entities_non_au_location_has_no_state_or_coords() {
    let body = kb(r#"{
        "status": {"code": 0},
        "them": {
            "basics": {"username": "bob"},
            "profile": {"location": "Berlin, Germany"}
        }
    }"#);
    let ents = build_entities(body, "bob", "scan");

    let a = ents
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("address entity");
    assert!(a.has_tag("self-reported"));
    assert!(
        !a.has_tag("country:AU"),
        "non-AU location must not be AU-tagged"
    );
    // No AU city match → no derived Coordinates.
    assert!(!ents.iter().any(|e| e.kind == EntityKind::Coordinates));
}

#[test]
fn build_entities_status_not_ok_is_empty() {
    // A non-existent user is a 200 with status.code != 0 and no `them`.
    let body = kb(r#"{"status": {"code": 1}}"#);
    assert!(build_entities(body, "alice", "scan").is_empty());
}

#[test]
fn build_entities_absent_them_is_empty() {
    // status ok but no subject object present → nothing to emit.
    let body = kb(r#"{"status": {"code": 0}}"#);
    assert!(build_entities(body, "alice", "scan").is_empty());
}

#[test]
fn build_entities_name_without_space_emits_no_person() {
    let body = kb(r#"{
        "status": {"code": 0},
        "them": {"basics": {"username": "bob"}, "profile": {"full_name": "Bob"}}
    }"#);
    let ents = build_entities(body, "bob", "scan");
    assert!(!ents.iter().any(|e| e.kind == EntityKind::Person));
    // Only the subject Username survives.
    assert_eq!(ents.len(), 1);
    assert_eq!(ents[0].kind, EntityKind::Username);
}

#[test]
fn build_entities_short_location_is_skipped() {
    let body = kb(r#"{
        "status": {"code": 0},
        "them": {"basics": {"username": "bob"}, "profile": {"location": "Hi"}}
    }"#);
    let ents = build_entities(body, "bob", "scan");
    assert!(
        !ents
            .iter()
            .any(|e| matches!(e.kind, EntityKind::Address | EntityKind::Coordinates))
    );
    assert_eq!(ents.len(), 1);
}

#[test]
fn build_entities_falls_back_to_query_username_when_basics_absent() {
    let body = kb(r#"{"status": {"code": 0}, "them": {"id": "x"}}"#);
    let ents = build_entities(body, "fallback", "scan");
    let u = &ents[0];
    assert_eq!(u.kind, EntityKind::Username);
    assert_eq!(u.value, "fallback");
    assert_eq!(
        u.evidence[0]
            .attributes
            .get("profile_url")
            .map(String::as_str),
        Some("https://keybase.io/fallback")
    );
}
