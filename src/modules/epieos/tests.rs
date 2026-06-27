use super::*;

fn email_target() -> Target {
    Target::new(TargetKind::Email, "jane@example.com")
}

fn build(json: &str) -> Vec<Entity> {
    let body: EpieosResp = serde_json::from_str(json).unwrap();
    build_entities(&email_target(), &body, "s")
}

// ── Module surface ──────────────────────────────────────────────────
#[test]
fn accepts_email_only() {
    let m = Epieos;
    assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "x")));
}

#[test]
fn cost_is_key_gated() {
    assert!(matches!(Epieos.cost(), ModuleCost::KeyGated));
}

#[test]
fn module_metadata() {
    assert_eq!(Epieos.name(), "epieos");
    assert_eq!(Epieos.priority(), 92);
    assert_eq!(Epieos.max_timeout_ms(), 15_000);
    assert!(!Epieos.description().is_empty());
}

#[test]
fn parse_response() {
    let raw = r#"{"google_id":"123","name":"John Smith",
        "maps_reviews":[{"place_name":"Sydney Opera House","rating":5.0,"date":"2024-01-15"}],
        "skype":{"handle":"john.smith.au","name":"John Smith","city":"Sydney","country":"AU"}}"#;
    let r: EpieosResp = serde_json::from_str(raw).unwrap();
    assert_eq!(r.name.as_deref(), Some("John Smith"));
    assert_eq!(r.maps_reviews.unwrap().len(), 1);
}

// ── Core: full extraction incl. the recovered fields ─────────────────
#[test]
fn extracts_full_profile_with_review_rating_and_text() {
    let es = build(
        r#"{
            "google_id":"1234567890","name":"Jane Doe",
            "profile_picture":"https://lh3.googleusercontent.com/p",
            "maps_reviews":[
                {"place_name":"Sydney Opera House","rating":5.0,"text":"Stunning, came with family.","date":"2024-01-15"}
            ],
            "skype":{"handle":"jane.doe","name":"Jane Q Doe","city":"Sydney","country":"AU"},
            "calendar":{"name":"Jane Doe"}
        }"#,
    );

    // Enriched email anchor carries the Skype name (previously discarded).
    let anchor = es.iter().find(|e| e.kind == EntityKind::Email).unwrap();
    let ev = &anchor.evidence[0];
    assert!(
        anchor.has_tag("google-account")
            && anchor.has_tag("skype")
            && anchor.has_tag("has-maps-reviews")
    );
    assert_eq!(
        ev.attributes.get("skype_name").map(String::as_str),
        Some("Jane Q Doe")
    );
    assert_eq!(
        ev.attributes.get("skype_handle").map(String::as_str),
        Some("jane.doe")
    );

    // Two DISTINCT Person leads (Google "Jane Doe" + Skype "Jane Q Doe").
    let people: Vec<&Entity> = es.iter().filter(|e| e.kind == EntityKind::Person).collect();
    assert_eq!(people.len(), 2);
    assert!(
        people
            .iter()
            .any(|p| p.value == "Jane Doe" && p.has_tag("google"))
    );
    assert!(
        people
            .iter()
            .any(|p| p.value == "Jane Q Doe" && p.has_tag("platform:skype"))
    );

    // Skype handle → Username.
    let users: Vec<&Entity> = es
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .collect();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].value, "jane.doe");

    // Addresses: the Skype location + the reviewed place (with rating + text).
    let addrs: Vec<&Entity> = es
        .iter()
        .filter(|e| e.kind == EntityKind::Address)
        .collect();
    let skype_loc = addrs.iter().find(|a| a.value == "Sydney, AU").unwrap();
    assert!(skype_loc.has_tag("skype"));
    let place = addrs
        .iter()
        .find(|a| a.value == "Sydney Opera House")
        .unwrap();
    assert!(place.has_tag("google-maps"));
    let pev = &place.evidence[0];
    assert_eq!(
        pev.attributes.get("rating").map(String::as_str),
        Some("5.0")
    );
    assert_eq!(
        pev.attributes.get("review_text").map(String::as_str),
        Some("Stunning, came with family.")
    );
    assert_eq!(
        pev.attributes.get("review_date").map(String::as_str),
        Some("2024-01-15")
    );
}

#[test]
fn identical_google_and_skype_names_yield_one_person() {
    let es = build(r#"{"name":"Sam Vimes","skype":{"name":"Sam Vimes"}}"#);
    assert_eq!(
        es.iter().filter(|e| e.kind == EntityKind::Person).count(),
        1
    );
}

#[test]
fn handle_like_names_are_not_persons() {
    // "janedoe" (no space) and a short skype name must not become Person.
    let es = build(r#"{"name":"janedoe","skype":{"name":"jd"}}"#);
    assert!(es.iter().all(|e| e.kind != EntityKind::Person));
}

#[test]
fn review_text_is_preserved_verbatim() {
    // Full-fidelity policy: a discovered review is stored exactly as returned,
    // never truncated — the operator must see the authentic result in full, even
    // a long one. (The non-ASCII place name also guards against any byte-vs-char
    // mishandling now that no length cap is applied.)
    let long = "x".repeat(400);
    let es = build(&format!(
        r#"{{"maps_reviews":[{{"place_name":"Café ☕","text":"{long}"}}]}}"#
    ));
    let place = es.iter().find(|e| e.value == "Café ☕").unwrap();
    let text = place.evidence[0].attributes.get("review_text").unwrap();
    assert_eq!(text, &long);
}

#[test]
fn empty_response_yields_only_the_anchor() {
    let es = build("{}");
    assert_eq!(es.len(), 1);
    assert_eq!(es[0].kind, EntityKind::Email);
}

#[test]
fn is_person_name_requires_min_len_and_a_space() {
    assert!(is_person_name("Jane Doe"));
    assert!(is_person_name("a b"));
    assert!(is_person_name("  Jane Doe  "));
    assert!(!is_person_name("ab"));
    assert!(!is_person_name("janedoe"));
    assert!(!is_person_name("  "));
    assert!(!is_person_name(""));
}
