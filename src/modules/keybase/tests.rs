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
    let r: KbResp = serde_json::from_str(raw).expect("should succeed");
    assert_eq!(r.status.expect("should succeed").code, Some(0));
    let user = r.them.expect("should succeed");
    assert_eq!(
        user.basics
            .as_ref()
            .expect("should succeed")
            .username
            .as_deref(),
        Some("alice")
    );
    assert_eq!(
        user.profile
            .as_ref()
            .expect("should succeed")
            .full_name
            .as_deref(),
        Some("Alice Smith")
    );
    assert_eq!(
        user.proofs_summary
            .as_ref()
            .expect("should succeed")
            .all
            .len(),
        3
    );
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
    .expect("should succeed");
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
        .expect("should succeed");
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

#[test]
fn build_entities_rejects_a_returned_username_that_does_not_match_the_query() {
    // Defensive parity with codeberg_user/hexpm_user/devto: verify the
    // record's own username before trusting it, rather than attributing a
    // different account's data to the queried handle.
    let body = kb(r#"{"status": {"code": 0}, "them": {"id": "x",
            "basics": {"username": "someone_else"}}}"#);
    assert!(build_entities(body, "alice", "scan").is_empty());
}

#[test]
fn build_entities_case_insensitive_username_match_is_accepted() {
    let body = kb(r#"{"status": {"code": 0}, "them": {"id": "x",
            "basics": {"username": "Alice"}}}"#);
    let ents = build_entities(body, "alice", "scan");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "alice")
    );
}

/// `profile_kit::location_address` / `location_coordinates` are the shared
/// authority six sibling profile modules already use (`steam_profile`,
/// `codewars_user`, `gitlab_user`, `stackoverflow_user`, `codeberg_user`,
/// `dockerhub_user`), and both refuse a value over 100 characters because —
/// in the helper's own words — "a longer value is a bio mis-mapped to the
/// location field, not a place."
///
/// `keybase` built both entities inline and checked only `loc.len() >= 3`, so
/// a bio sitting in the location field became an `Address` **valued on the
/// whole bio** plus a person-anchored `Coordinates` at `confidence::MEDIUM` —
/// which is exactly the noisy-OR expansion floor, so it pivots. `city_coords`
/// matches whole tokens anywhere in the string, so any city named in passing
/// anchors the subject to it (REQ-KEYBASE-001).
#[test]
fn a_bio_in_the_location_field_is_not_a_place() {
    let bio = "Software engineer and occasional speaker. Previously at ACME in \
               Sydney, now mostly travelling. Opinions my own, DMs open.";
    assert!(bio.len() > 100, "the fixture must exceed the shared cap");

    let body = kb(&format!(
        r#"{{
        "status": {{"code": 0}},
        "them": {{
            "basics": {{"username": "carol"}},
            "profile": {{"location": "{bio}"}},
            "proofs_summary": {{"all": []}}
        }}
    }}"#
    ));
    let ents = build_entities(body, "carol", "scan");

    assert!(
        !ents
            .iter()
            .any(|e| e.kind == EntityKind::Address && e.value == bio),
        "a 140-character bio is not an Address"
    );
    assert!(
        !ents.iter().any(|e| e.kind == EntityKind::Coordinates),
        "a city merely NAMED in a bio must not anchor the subject to it; got {:?}",
        ents.iter()
            .filter(|e| e.kind == EntityKind::Coordinates)
            .map(|e| (e.value.clone(), e.confidence))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_real_location_still_yields_an_address_and_a_coordinate() {
    // CONTROL — passes on the baseline AND the fix. The cap must reject bios,
    // never ordinary places.
    let body = kb(r#"{
        "status": {"code": 0},
        "them": {
            "basics": {"username": "dave"},
            "profile": {"location": "Melbourne, VIC"},
            "proofs_summary": {"all": []}
        }
    }"#);
    let ents = build_entities(body, "dave", "scan");
    let a = ents
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("a real place is still an Address");
    assert_eq!(a.value, "Melbourne, VIC");
    assert!(a.has_tag("au-state:VIC") && a.has_tag("country:AU"));
    let c = ents
        .iter()
        .find(|e| e.kind == EntityKind::Coordinates)
        .expect("a real place is still geocoded");
    assert!(c.has_tag("addr-derived") && c.has_tag("keybase"));
    assert!(c.has_tag("au-state:VIC") && c.has_tag("country:AU"));
}

#[test]
fn a_location_exactly_at_the_cap_is_still_a_place() {
    // CONTROL and boundary: the shared helper rejects `> 100`, not `>= 100`.
    // Pinning it here stops the consolidation from quietly tightening the
    // contract the six sibling modules already depend on.
    //
    // The padding must survive `trim()`, which the helper applies BEFORE
    // measuring. The first cut of this test padded with spaces, so the value
    // collapsed to 6 characters and the assertion held for the wrong reason —
    // a mutation tightening the cap to `>= 100` sailed straight past it.
    let loc = format!("Sydney, New South Wales, Australia{}", "-x".repeat(33));
    assert_eq!(loc.len(), 100);
    assert_eq!(loc.trim().len(), 100, "the fixture must survive trimming");
    let body = kb(&format!(
        r#"{{
        "status": {{"code": 0}},
        "them": {{
            "basics": {{"username": "erin"}},
            "profile": {{"location": "{loc}"}},
            "proofs_summary": {{"all": []}}
        }}
    }}"#
    ));
    let ents = build_entities(body, "erin", "scan");
    assert!(
        ents.iter().any(|e| e.kind == EntityKind::Coordinates),
        "a 100-character location is within the shared cap"
    );
}
