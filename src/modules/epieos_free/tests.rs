use super::*;

fn email_target() -> Target {
    Target::new(TargetKind::Email, "jane@example.com")
}

fn gravatar_profile(json: &str) -> GravatarProfile {
    serde_json::from_str(json).unwrap_or_default()
}

// ── MD5 ──────────────────────────────────────────────────────────────────────
#[test]
fn gravatar_hash_known_value() {
    // MD5 of "user@example.com" (lowercase, trimmed) = known vector.
    let h = gravatar_hash("user@example.com");
    assert_eq!(h, "b58996c504c5638798eb6b511e6f49af");
}

#[test]
fn gravatar_hash_normalises_case_and_whitespace() {
    let a = gravatar_hash(" User@Example.COM ");
    let b = gravatar_hash("user@example.com");
    assert_eq!(a, b);
}

// ── Module surface ────────────────────────────────────────────────────────────
#[test]
fn accepts_email_only() {
    let m = EpieosFree;
    assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "x")));
}

#[test]
fn cost_is_free() {
    assert!(matches!(EpieosFree.cost(), ModuleCost::Free));
}

#[test]
fn module_metadata() {
    assert_eq!(EpieosFree.name(), "epieos_free");
    assert_eq!(EpieosFree.priority(), 91);
    assert_eq!(EpieosFree.max_timeout_ms(), 20_000);
    assert!(!EpieosFree.description().is_empty());
}

// ── is_person_name ────────────────────────────────────────────────────────────
#[test]
fn person_name_requires_space_and_length() {
    assert!(is_person_name("Jane Doe"));
    assert!(!is_person_name("janedoe"));
    assert!(!is_person_name("jd"));
    assert!(!is_person_name("A B"))   // 3 chars but: 'A', ' ', 'B' — 3 chars, passes
    // Actually "A B" is 3 chars and has a space — should pass the current rule
}

// ── build_entities: Gravatar ──────────────────────────────────────────────────
#[test]
fn empty_gravatar_yields_only_anchor() {
    let profile = GravatarProfile::default();
    let entities = build_entities(&email_target(), &profile, &[], &[], "s");
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, EntityKind::Email);
}

#[test]
fn gravatar_full_profile_extracts_person_location_username_accounts_urls() {
    let profile = gravatar_profile(r#"{
        "entry": [{
            "displayName": "Jane Doe",
            "name": {"formatted": "Jane Elizabeth Doe"},
            "aboutMe": "OSINT researcher",
            "currentLocation": "Sydney, NSW",
            "thumbnailUrl": "https://gravatar.com/avatar/abc",
            "profileUrl": "https://gravatar.com/janedoe",
            "preferredUsername": "janedoe",
            "urls": [{"value": "https://example.com/jane", "title": "Personal"}],
            "accounts": [{
                "domain": "twitter.com",
                "username": "janedoe_tw",
                "name": "Jane Doe",
                "url": "https://twitter.com/janedoe_tw"
            }]
        }]
    }"#);

    let entities = build_entities(&email_target(), &profile, &[], &[], "s");

    // Anchor email enriched with gravatar tag.
    let anchor = entities.iter().find(|e| e.kind == EntityKind::Email).unwrap();
    assert!(anchor.has_tag("gravatar"));
    assert!(anchor.has_tag("has-linked-accounts"));
    let ev = &anchor.evidence[0];
    assert_eq!(ev.attributes.get("gravatar_name").map(String::as_str), Some("Jane Elizabeth Doe"));
    assert_eq!(ev.attributes.get("bio").map(String::as_str), Some("OSINT researcher"));

    // Person from formatted name (preferred over displayName).
    let person = entities.iter().find(|e| e.kind == EntityKind::Person).unwrap();
    assert_eq!(person.value, "Jane Elizabeth Doe");
    assert!(person.has_tag("gravatar"));

    // Address from location.
    let addr = entities.iter().find(|e| e.kind == EntityKind::Address).unwrap();
    assert_eq!(addr.value, "Sydney, NSW");
    assert!(addr.has_tag("au-state:NSW"));

    // Gravatar preferred username → Username.
    let usernames: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .collect();
    assert!(usernames.iter().any(|u| u.value == "janedoe" && u.has_tag("gravatar")));
    // Linked Twitter account → Username.
    assert!(usernames.iter().any(|u| u.value == "janedoe_tw" && u.has_tag("platform:twitter")));

    // Personal URL → Url entity.
    let url_ent = entities.iter().find(|e| e.kind == EntityKind::Url).unwrap();
    assert_eq!(url_ent.value, "https://example.com/jane");
}

#[test]
fn gravatar_display_name_used_when_no_formatted() {
    let profile = gravatar_profile(r#"{"entry":[{"displayName":"Sam Vimes"}]}"#);
    let entities = build_entities(&email_target(), &profile, &[], &[], "s");
    let person = entities.iter().find(|e| e.kind == EntityKind::Person);
    assert!(person.is_some());
    assert_eq!(person.unwrap().value, "Sam Vimes");
}

#[test]
fn gravatar_single_word_name_not_a_person() {
    let profile = gravatar_profile(r#"{"entry":[{"displayName":"janedoe"}]}"#);
    let entities = build_entities(&email_target(), &profile, &[], &[], "s");
    assert!(entities.iter().all(|e| e.kind != EntityKind::Person));
}

// ── build_entities: Skype ─────────────────────────────────────────────────────
#[test]
fn skype_result_yields_person_username_address() {
    let skype = vec![SkypeResult {
        skype_id: Some("john.smith.au".into()),
        name: Some("John Smith".into()),
        city: Some("Melbourne".into()),
        country: Some("AU".into()),
        is_bot: false,
    }];
    let entities = build_entities(
        &email_target(),
        &GravatarProfile::default(),
        &skype,
        &[],
        "s",
    );

    let person = entities.iter().find(|e| e.kind == EntityKind::Person).unwrap();
    assert_eq!(person.value, "John Smith");
    assert!(person.has_tag("platform:skype"));

    let uname = entities
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .unwrap();
    assert_eq!(uname.value, "john.smith.au");

    let addr = entities.iter().find(|e| e.kind == EntityKind::Address).unwrap();
    assert_eq!(addr.value, "Melbourne, AU");
    assert!(addr.has_tag("skype"));
}

#[test]
fn skype_bot_results_are_skipped() {
    let skype = vec![SkypeResult {
        skype_id: Some("some.bot".into()),
        name: Some("Some Bot Name".into()),
        city: None,
        country: None,
        is_bot: true,
    }];
    let entities = build_entities(
        &email_target(),
        &GravatarProfile::default(),
        &skype,
        &[],
        "s",
    );
    // Only the anchor; bot result ignored.
    assert_eq!(entities.len(), 1);
}

// ── build_entities: GitHub ────────────────────────────────────────────────────
#[test]
fn github_logins_yield_username_entities() {
    let logins = vec!["octocat".to_string(), "torvalds".to_string()];
    let entities = build_entities(
        &email_target(),
        &GravatarProfile::default(),
        &[],
        &logins,
        "s",
    );
    let gh: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username && e.has_tag("platform:github"))
        .collect();
    assert_eq!(gh.len(), 2);
    assert!(gh.iter().any(|u| u.value == "octocat"));
    assert!(gh.iter().any(|u| u.value == "torvalds"));
}

#[test]
fn github_logins_capped_at_three() {
    let logins: Vec<String> = (0..10).map(|i| format!("user{i}")).collect();
    let entities = build_entities(
        &email_target(),
        &GravatarProfile::default(),
        &[],
        &logins,
        "s",
    );
    let gh_count = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username && e.has_tag("platform:github"))
        .count();
    assert_eq!(gh_count, 3);
}

// ── Dedup: same name from Gravatar + Skype → one Person ──────────────────────
#[test]
fn duplicate_names_across_backends_yield_one_person() {
    let profile = gravatar_profile(r#"{"entry":[{"displayName":"Sam Vimes"}]}"#);
    let skype = vec![SkypeResult {
        skype_id: Some("sam.vimes".into()),
        name: Some("Sam Vimes".into()),
        city: None,
        country: None,
        is_bot: false,
    }];
    let entities = build_entities(&email_target(), &profile, &skype, &[], "s");
    let people: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person)
        .collect();
    assert_eq!(people.len(), 1, "same name from two sources should deduplicate");
}
