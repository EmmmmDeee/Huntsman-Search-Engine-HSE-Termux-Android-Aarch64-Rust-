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
    use crate::util::extract::{EMAIL_RE, URL_RE};
    let bio = "Reach Me@Example.com — https://example.com/profile.";
    assert_eq!(
        EMAIL_RE.find(bio).unwrap().as_str().to_lowercase(),
        "me@example.com"
    );
    let link = URL_RE
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
    let pool = crate::util::key_pool::global_pool();
    let ents = build_entities(data("spez", false), "scan-1", &pool);
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
    let pool = crate::util::key_pool::global_pool();
    let ents = build_entities(data("verified_user", true), "scan-2", &pool);
    assert!(ents[0].has_tag("verified"));
}

#[test]
fn build_entities_unverified_account_lacks_tag() {
    let pool = crate::util::key_pool::global_pool();
    let ents = build_entities(data("plain_user", false), "scan-3", &pool);
    assert!(!ents[0].has_tag("verified"));
}

#[test]
fn build_entities_bio_email_emits_email_entity() {
    let mut d = data("alice", false);
    d.subreddit = Some(Subreddit {
        public_description: Some("Contact alice@example.com".to_string()),
        title: None,
    });
    let pool = crate::util::key_pool::global_pool();
    let ents = build_entities(d, "scan-4", &pool);
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
    let pool = crate::util::key_pool::global_pool();
    let ents = build_entities(d, "scan-5", &pool);
    let url = ents.iter().find(|e| e.kind == EntityKind::Url).unwrap();
    assert!(url.value.starts_with("https://"));
    assert!(!url.value.ends_with('.'), "trailing dot must be stripped");
    assert!(url.has_tag("personal-site"));
}

#[test]
fn build_entities_no_subreddit_yields_only_username() {
    let pool = crate::util::key_pool::global_pool();
    let ents = build_entities(data("quiet", false), "scan-6", &pool);
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
    let pool = crate::util::key_pool::global_pool();
    let ents = build_entities(d, "scan-7", &pool);
    let email = ents.iter().find(|e| e.kind == EntityKind::Email).unwrap();
    assert_eq!(email.value, "carol@test.org");
}

#[test]
fn submitted_entities_emits_all_distinct_subreddits_deterministically() {
    // A submitted.json body naming 12 distinct subreddits (plus a duplicate) in
    // deliberately non-alphabetical order — more than the old silent cap of 10.
    let names = [
        "rust", "python", "golang", "aww", "pics", "news", "science", "space",
        "gaming", "movies", "books", "history", "rust", // duplicate — deduped
    ];
    let body = format!(
        "[{}]",
        names
            .iter()
            .map(|s| format!(r#"{{"subreddit":"{s}"}}"#))
            .collect::<Vec<_>>()
            .join(",")
    );

    let out = submitted_entities(&body, "someuser", "s");
    // Every DISTINCT subreddit is emitted (12), none dropped by a cap.
    assert_eq!(
        out.len(),
        12,
        "all distinct subreddits emitted, not capped at 10"
    );
    // Deterministic: values emerge sorted, independent of the dedup HashSet's
    // randomised iteration order.
    let vals: Vec<&str> = out.iter().map(|e| e.value.as_str()).collect();
    let mut sorted = vals.clone();
    sorted.sort_unstable();
    assert_eq!(vals, sorted, "subreddits emerge in sorted, deterministic order");
    assert!(
        out.iter()
            .all(|e| e.kind == EntityKind::Organisation && e.has_tag("subreddit")),
        "each is a subreddit-tagged Organisation"
    );
}

// ── mine_keys_from_text ────────────────────────────────────────────────────

#[test]
fn mine_keys_from_text_pools_a_leaked_key_with_reddit_provenance() {
    // A 234-char BinaryEdge-shaped (`bp0_`-prefixed, poolable) key — the same
    // fixture shape used to prove the wayback (T2.82) and hacker_news (T2.84)
    // key-mining passes — embedded in synthetic submitted.json-shaped text,
    // proving this NEW pass reaches `pool.add` with Reddit-specific
    // provenance, not just a generic "found it" no-op.
    let leaked_key = format!(
        "bp0_{}",
        "oHBvRPOIvGrv5iFlbCBFNOgmBjMtpsiaOclRz3AwzKsbVRJN9wVGFYGW2WmQzCudiH7YFjS1on43XkMtECqOxSF2O3GYRdo1XKXWNqRs7rpEmoKiuPKdYR7osjOrU1xxDO0CzUZREN68k4tUNpfZ46pdJQIPvjiQvlb5lZXOIgfFwD3HJoKyrbmEYYmdhQj38AruHr4iwRxpVHSbKdA9u4uQgwLg6G3oT1ogmM"
    );
    let text = format!(r#"{{"selftext":"oops my config: {leaked_key}"}}"#);
    let pool = crate::util::key_pool::global_pool();
    let username = "reddit-keymine-test-user";

    mine_keys_from_text(&pool, &text, username, "submitted");

    let entry = pool
        .snapshot()
        .services
        .get("binaryedge")
        .into_iter()
        .flatten()
        .find(|e| e.value == leaked_key)
        .cloned();
    let found = entry.is_some();
    if let Some(e) = &entry {
        assert_eq!(
            e.discovered_by.as_deref(),
            Some(format!("reddit_user:{username}").as_str()),
            "provenance must name reddit_user, not a generic/wrong source"
        );
        assert!(
            e.notes.as_deref().is_some_and(|n| n.contains("submitted") && n.contains(username)),
            "notes must carry the source label + username, got {:?}",
            e.notes
        );
    }
    if found {
        pool.remove("binaryedge", &leaked_key);
    }
    assert!(
        found,
        "a leaked key in Reddit bio/submitted text must reach the key pool"
    );
}

#[test]
fn build_entities_bio_with_a_leaked_key_pools_it_with_bio_provenance() {
    // End-to-end through build_entities (not the helper directly): a bio
    // containing a leaked key must be classified with source_label "bio",
    // distinguishing it from a "submitted"-sourced hit.
    let leaked_key = format!(
        "bp0_{}",
        "zzBvRPOIvGrv5iFlbCBFNOgmBjMtpsiaOclRz3AwzKsbVRJN9wVGFYGW2WmQzCudiH7YFjS1on43XkMtECqOxSF2O3GYRdo1XKXWNqRs7rpEmoKiuPKdYR7osjOrU1xxDO0CzUZREN68k4tUNpfZ46pdJQIPvjiQvlb5lZXOIgfFwD3HJoKyrbmEYYmdhQj38AruHr4iwRxpVHSbKdA9u4uQgwLg6G3oT1ogmZ"
    );
    let mut d = data("bio-keytest", false);
    d.subreddit = Some(Subreddit {
        public_description: Some(format!("my key is {leaked_key} whoops")),
        title: None,
    });
    let pool = crate::util::key_pool::global_pool();
    build_entities(d, "scan-biokey", &pool);

    let entry = pool
        .snapshot()
        .services
        .get("binaryedge")
        .into_iter()
        .flatten()
        .find(|e| e.value == leaked_key)
        .cloned();
    let found = entry.is_some();
    if let Some(e) = &entry {
        assert!(
            e.notes.as_deref().is_some_and(|n| n.contains("bio")),
            "notes must label this a bio-sourced hit, got {:?}",
            e.notes
        );
    }
    if found {
        pool.remove("binaryedge", &leaked_key);
    }
    assert!(found, "a leaked key in the bio must reach the key pool");
}
