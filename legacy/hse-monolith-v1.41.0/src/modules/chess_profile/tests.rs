use super::*;

#[test]
fn accepts_only_username_targets() {
    let m = ChessProfile;
    assert!(m.accepts(&Target::new(TargetKind::Username, "hikaru")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Jane Doe")));
}

#[test]
fn accepts_value_admits_handles_and_rejects_junk() {
    assert!(accepts_value("erik"));
    assert!(accepts_value("magnus-c"));
    assert!(accepts_value("DrNykterstein"));
    assert!(!accepts_value("a")); // too short
    assert!(!accepts_value(&"x".repeat(31))); // too long
    assert!(!accepts_value("123456")); // no letter
    assert!(!accepts_value("with space")); // illegal char
    assert!(!accepts_value("dot.name")); // dot not allowed
}

// Real capture: GET https://api.chess.com/pub/player/erik
const CHESSCOM_ERIK: &str = r#"{"avatar":"https://images.chesscomfiles.com/uploads/v1/user/41.jpeg","player_id":41,"@id":"https://api.chess.com/pub/player/erik","url":"https://www.chess.com/member/erik","name":"Erik","username":"erik","followers":10033,"country":"https://api.chess.com/pub/country/US","location":"Bay Area, CA","last_online":1784744478,"joined":1178556600,"status":"staff","verified":false}"#;

#[test]
fn chesscom_hit_mints_handle_and_url_with_country_and_location_evidence() {
    let p: ChessComProfile = serde_json::from_str(CHESSCOM_ERIK).unwrap();
    let ents = parse_chesscom(&p, "erik", "scan-1");
    let usernames: Vec<_> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .collect();
    let urls: Vec<_> = ents.iter().filter(|e| e.kind == EntityKind::Url).collect();
    let persons: Vec<_> = ents.iter().filter(|e| e.kind == EntityKind::Person).collect();
    assert_eq!(usernames.len(), 1);
    assert_eq!(usernames[0].value, "erik");
    assert!((usernames[0].confidence - HANDLE_CONF).abs() < 1e-9);
    assert_eq!(urls.len(), 1);
    assert_eq!(urls[0].value, "https://www.chess.com/member/erik");
    // `name` == "Erik" echoes the handle (case-insensitive) → NO fabricated Person.
    assert!(
        persons.is_empty(),
        "a name that only echoes the handle must not mint a Person"
    );
    let ev = &usernames[0].evidence[0];
    assert_eq!(ev.attributes.get("country").map(String::as_str), Some("US"));
    assert_eq!(
        ev.attributes.get("location").map(String::as_str),
        Some("Bay Area, CA")
    );
}

#[test]
fn chesscom_off_target_response_is_rejected() {
    // A response whose canonical handle doesn't match the query must not mint an
    // off-target account (defends against redirects / unexpected upstream shape).
    let p: ChessComProfile = serde_json::from_str(CHESSCOM_ERIK).unwrap();
    assert!(parse_chesscom(&p, "someone_else", "scan-1").is_empty());
}

#[test]
fn chesscom_emits_candidate_person_when_name_differs_from_handle() {
    let json = r#"{"username":"gmhikaru","url":"https://www.chess.com/member/gmhikaru","name":"Hikaru Nakamura","country":"https://api.chess.com/pub/country/US","verified":true}"#;
    let p: ChessComProfile = serde_json::from_str(json).unwrap();
    let ents = parse_chesscom(&p, "gmhikaru", "scan-1");
    let person = ents
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("self-asserted name → Person");
    assert_eq!(person.value, "Hikaru Nakamura");
    assert!((person.confidence - NAME_CONF).abs() < 1e-9);
    assert!(
        person.has_tag(tags::CANDIDATE),
        "self-asserted name is candidate-quarantined (a lead, never verified)"
    );
    assert!(person.has_tag("self-reported"));
}

// Real capture: GET https://lichess.org/api/user/thibault
const LICHESS_THIBAULT: &str = r#"{"id":"thibault","username":"thibault","url":"https://lichess.org/@/thibault","createdAt":1290415680000,"seenAt":1784747833649,"profile":{"bio":"I turn coffee into bugs.","realName":"Thibault Duplessis","links":"github.com/ornicar\r\nmas.to/@thibault"}}"#;

#[test]
fn lichess_hit_mints_handle_url_links_and_candidate_person() {
    let u: LichessUser = serde_json::from_str(LICHESS_THIBAULT).unwrap();
    let ents = parse_lichess(&u, "thibault", "scan-1");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "thibault")
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://lichess.org/@/thibault")
    );
    // Heavy-tail: each self-listed link, scheme-normalised, as a pivotable Url.
    let urls: Vec<&str> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Url)
        .map(|e| e.value.as_str())
        .collect();
    assert!(
        urls.contains(&"https://github.com/ornicar"),
        "scheme-less link must be normalised: {urls:?}"
    );
    assert!(urls.contains(&"https://mas.to/@thibault"));
    // Self-asserted realName → candidate Person.
    let person = ents
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("realName → Person");
    assert_eq!(person.value, "Thibault Duplessis");
    assert!(person.has_tag(tags::CANDIDATE));
    // Bio rides along as evidence, never as an entity.
    let handle = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .unwrap();
    assert_eq!(
        handle.evidence[0].attributes.get("bio").map(String::as_str),
        Some("I turn coffee into bugs.")
    );
}

#[test]
fn lichess_firstname_lastname_fallback() {
    let json = r#"{"id":"user","username":"user","profile":{"firstName":"Jane","lastName":"Roe"}}"#;
    let u: LichessUser = serde_json::from_str(json).unwrap();
    let ents = parse_lichess(&u, "user", "scan-1");
    let person = ents
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("firstName+lastName → Person");
    assert_eq!(person.value, "Jane Roe");
}

#[test]
fn lichess_off_target_rejected_and_no_links_is_clean() {
    let u: LichessUser = serde_json::from_str(LICHESS_THIBAULT).unwrap();
    assert!(parse_lichess(&u, "not_thibault", "scan-1").is_empty());
    // A profile with no links / no name yields just the handle + URL, nothing else.
    let bare = r#"{"id":"h","username":"h"}"#;
    let u2: LichessUser = serde_json::from_str(bare).unwrap();
    let ents = parse_lichess(&u2, "h", "scan-1");
    assert_eq!(ents.iter().filter(|e| e.kind == EntityKind::Person).count(), 0);
    assert_eq!(ents.iter().filter(|e| e.kind == EntityKind::Username).count(), 1);
}

#[test]
fn normalise_links_filters_noise_and_dedups() {
    let got = normalise_links("github.com/x  https://twitter.com/y\nnot a url\nhttps://twitter.com/y");
    assert_eq!(got, vec!["https://github.com/x", "https://twitter.com/y"]);
    assert!(normalise_links("just some bio words").is_empty());
}

#[test]
fn normalise_links_caps_output_at_max_links() {
    let raw = (0..MAX_LINKS + 15)
        .map(|i| format!("https://example.com/{i}"))
        .collect::<Vec<_>>()
        .join(" ");
    let got = normalise_links(&raw);
    assert_eq!(got.len(), MAX_LINKS, "must cap at MAX_LINKS, not unbounded");
    assert_eq!(got[0], "https://example.com/0");
    assert_eq!(got[MAX_LINKS - 1], format!("https://example.com/{}", MAX_LINKS - 1));
}

#[test]
fn iso_country_extraction() {
    assert_eq!(
        iso_country_from_url("https://api.chess.com/pub/country/US"),
        Some("US".to_string())
    );
    assert_eq!(
        iso_country_from_url("https://api.chess.com/pub/country/de"),
        Some("DE".to_string())
    );
    assert_eq!(iso_country_from_url("garbage"), None);
    assert_eq!(iso_country_from_url("https://x/country/USA"), None); // not 2-char
}
