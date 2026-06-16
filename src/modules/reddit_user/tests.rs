use super::*;

#[test]
fn accepts_only_username() {
    let m = RedditUser;
    assert!(m.accepts(&Target::new(TargetKind::Username, "spez")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
}

#[test]
fn metadata() {
    let m = RedditUser;
    assert_eq!(m.name(), "reddit_user");
    assert_eq!(m.priority(), 105);
    assert_eq!(m.max_timeout_ms(), 6_000);
    assert!(!m.description().is_empty());
    assert!(m.produces().contains(&EntityKind::Username));
    assert!(!m.attack_techniques().is_empty());
}

#[test]
fn deserializes_about_and_missing() {
    let json = r#"{"data":{"name":"spez","created_utc":1118030400.0,
        "link_karma":12,"comment_karma":34,"verified":true,"is_gold":false,
        "subreddit":{"public_description":"contact me@example.com https://example.com/me","title":"hi"}}}"#;
    let r: AboutResp = serde_json::from_str(json).unwrap();
    let d = r.data.unwrap();
    assert_eq!(d.name, "spez");
    assert_eq!(d.link_karma, Some(12));
    assert_eq!(d.verified, Some(true));
    // An empty/suspended response (no data) is a clean None.
    let empty: AboutResp = serde_json::from_str(r#"{"data":null}"#).unwrap();
    assert!(empty.data.is_none());
}

#[test]
fn bio_extracts_email_and_url() {
    let (email_re, url_re) = bio_patterns();
    let bio = "Reach Me@Example.com — https://example.com/profile.";
    assert_eq!(
        email_re.find(bio).unwrap().as_str().to_lowercase(),
        "me@example.com"
    );
    let link = url_re
        .find(bio)
        .unwrap()
        .as_str()
        .trim_end_matches(['.', ',', ')']);
    assert_eq!(link, "https://example.com/profile");
}

#[test]
fn handle_validation() {
    let valid = |s: &str| -> bool {
        s.len() >= 3
            && s.len() <= 20
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    };
    assert!(valid("spez"));
    assert!(valid("kylo4kylo"));
    assert!(!valid("ab")); // too short
    assert!(!valid("this_handle_is_way_too_long"));
    assert!(!valid("has space"));
}

// ── build_entities ───────────────────────────────────────────────────────────

fn data(name: &str, verified: bool) -> AboutData {
    AboutData {
        name: name.to_string(),
        created_utc: Some(1118030400.0),
        link_karma: Some(10),
        comment_karma: Some(20),
        verified: Some(verified),
        is_gold: Some(false),
        subreddit: None,
    }
}

#[test]
fn build_entities_emits_username_with_metadata() {
    let ents = build_entities(data("spez", false), "scan-1");
    assert_eq!(ents.len(), 1);
    let u = &ents[0];
    assert_eq!(u.kind, EntityKind::Username);
    assert_eq!(u.value, "spez");
    assert!(u.has_tag("reddit"));
    let attr = |k: &str| u.evidence[0].attributes.get(k).map(String::as_str);
    assert_eq!(attr("profile_url"), Some("https://www.reddit.com/user/spez"));
    assert_eq!(attr("link_karma"), Some("10"));
    assert_eq!(attr("comment_karma"), Some("20"));
}

#[test]
fn build_entities_verified_account_carries_tag() {
    let ents = build_entities(data("verified_user", true), "scan-2");
    assert!(ents[0].has_tag("verified"));
}

#[test]
fn build_entities_unverified_account_lacks_tag() {
    let ents = build_entities(data("plain_user", false), "scan-3");
    assert!(!ents[0].has_tag("verified"));
}

#[test]
fn build_entities_bio_email_emits_email_entity() {
    let mut d = data("alice", false);
    d.subreddit = Some(Subreddit {
        public_description: Some("Contact alice@example.com".to_string()),
        title: None,
    });
    let ents = build_entities(d, "scan-4");
    let email = ents.iter().find(|e| e.kind == EntityKind::Email).unwrap();
    assert_eq!(email.value, "alice@example.com");
    assert!(email.has_tag("reddit") && email.has_tag("public-profile"));
}

#[test]
fn build_entities_bio_url_emits_url_entity_without_trailing_punct() {
    let mut d = data("bob", false);
    d.subreddit = Some(Subreddit {
        public_description: Some("https://bob.dev/.".to_string()),
        title: None,
    });
    let ents = build_entities(d, "scan-5");
    let url = ents.iter().find(|e| e.kind == EntityKind::Url).unwrap();
    assert!(url.value.starts_with("https://"));
    assert!(!url.value.ends_with('.'), "trailing dot must be stripped");
    assert!(url.has_tag("personal-site"));
}

#[test]
fn build_entities_no_subreddit_yields_only_username() {
    let ents = build_entities(data("quiet", false), "scan-6");
    assert_eq!(ents.len(), 1);
    assert_eq!(ents[0].kind, EntityKind::Username);
}

#[test]
fn build_entities_title_field_also_mined_for_bio() {
    let mut d = data("carol", false);
    d.subreddit = Some(Subreddit {
        public_description: None,
        title: Some("contact carol@test.org".to_string()),
    });
    let ents = build_entities(d, "scan-7");
    let email = ents.iter().find(|e| e.kind == EntityKind::Email).unwrap();
    assert_eq!(email.value, "carol@test.org");
}
