use super::*;

#[test]
fn accepts_only_username() {
    let m = HackerNews;
    assert!(m.accepts(&Target::new(TargetKind::Username, "pg")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "ycombinator.com")));
}

#[test]
fn metadata() {
    let m = HackerNews;
    assert_eq!(m.name(), "hacker_news");
    assert_eq!(m.priority(), 106);
    assert_eq!(m.max_timeout_ms(), 6_000);
    assert!(!m.description().is_empty());
    assert!(m.produces().contains(&EntityKind::Username));
    assert!(!m.attack_techniques().is_empty());
}

#[test]
fn deserializes_account_and_null() {
    let json = r#"{"id":"pg","created":1160418092,"karma":157222,
        "about":"Reach me at paul@example.com or https://paulgraham.com/",
        "submitted":[1,2,3]}"#;
    let u: Option<HnUser> = serde_json::from_str(json).expect("should succeed");
    let u = u.expect("should succeed");
    assert_eq!(u.id, "pg");
    assert_eq!(u.karma, Some(157222));
    assert_eq!(u.submitted.as_ref().expect("should succeed").len(), 3);
    // The literal `null` (unknown handle) is a clean None.
    let none: Option<HnUser> = serde_json::from_str("null").expect("should succeed");
    assert!(none.is_none());
}

#[test]
fn bio_extracts_email_and_url() {
    use crate::util::extract::{EMAIL_RE, URL_RE};
    let about = "Contact: Paul@Example.com — site https://paulgraham.com/bio.html.";
    assert_eq!(
        EMAIL_RE.find(about).expect("should succeed").as_str().to_lowercase(),
        "paul@example.com"
    );
    let link = URL_RE
        .find(about)
        .expect("should succeed")
        .as_str()
        .trim_end_matches(['.', ',', ')']);
    assert_eq!(link, "https://paulgraham.com/bio.html");
}

#[test]
fn handle_validation() {
    let valid = |s: &str| -> bool {
        s.len() >= 2
            && s.len() <= 15
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    };
    assert!(valid("pg"));
    assert!(valid("kylo4kylo"));
    assert!(valid("user_name-1"));
    assert!(!valid("a")); // too short
    assert!(!valid("this_handle_is_too_long"));
    assert!(!valid("has space"));
    assert!(!valid("emoji😀"));
}

// ── build_entities ───────────────────────────────────────────────────────────

fn user(id: &str) -> HnUser {
    HnUser {
        id: id.to_string(),
        created: Some(1160418092),
        karma: Some(42),
        about: None,
        submitted: Some(vec![1, 2, 3]),
    }
}

#[test]
fn build_entities_emits_username_with_metadata() {
    let pool = crate::util::key_pool::global_pool();
    let ents = build_entities(user("pg"), "scan-1", &pool);
    assert_eq!(ents.len(), 1);
    let u = &ents[0];
    assert_eq!(u.kind, EntityKind::Username);
    assert_eq!(u.value, "pg");
    assert!(u.has_tag("hacker-news"));
    let attr = |k: &str| u.evidence[0].attributes.get(k).map(String::as_str);
    assert_eq!(attr("profile_url"), Some("https://news.ycombinator.com/user?id=pg"));
    assert_eq!(attr("karma"), Some("42"));
    assert_eq!(attr("submissions"), Some("3"));
    assert_eq!(attr("created_unix"), Some("1160418092"));
}

#[test]
fn build_entities_no_submissions_defaults_to_zero() {
    let u = HnUser {
        id: "nobody".to_string(),
        created: None,
        karma: None,
        about: None,
        submitted: None,
    };
    let pool = crate::util::key_pool::global_pool();
    let ents = build_entities(u, "scan-2", &pool);
    assert_eq!(ents[0].evidence[0].attributes.get("submissions").map(String::as_str), Some("0"));
}

#[test]
fn build_entities_bio_email_emits_email_entity() {
    let u = HnUser {
        id: "alice".to_string(),
        created: None,
        karma: None,
        about: Some("Email: alice@example.com".to_string()),
        submitted: None,
    };
    let pool = crate::util::key_pool::global_pool();
    let ents = build_entities(u, "scan-3", &pool);
    let email = ents.iter().find(|e| e.kind == EntityKind::Email).expect("should succeed");
    assert_eq!(email.value, "alice@example.com");
    assert!(email.has_tag("hacker-news") && email.has_tag("public-profile"));
}

#[test]
fn build_entities_bio_url_emits_url_entity_without_trailing_punct() {
    let u = HnUser {
        id: "bob".to_string(),
        created: None,
        karma: None,
        about: Some("See https://bob.dev/.".to_string()),
        submitted: None,
    };
    let pool = crate::util::key_pool::global_pool();
    let ents = build_entities(u, "scan-4", &pool);
    let url = ents.iter().find(|e| e.kind == EntityKind::Url).expect("should succeed");
    assert!(url.value.starts_with("https://"));
    assert!(!url.value.ends_with('.'), "trailing dot must be stripped");
    assert!(url.has_tag("personal-site"));
}

#[test]
fn build_entities_no_bio_yields_only_username() {
    let pool = crate::util::key_pool::global_pool();
    let ents = build_entities(user("quiet"), "scan-5", &pool);
    assert_eq!(ents.len(), 1);
    assert_eq!(ents[0].kind, EntityKind::Username);
}

// ── algolia_domain_entities ────────────────────────────────────────────────

#[test]
fn algolia_domain_entities_emits_all_distinct_domains_deterministically() {
    // An Algolia search response naming several distinct domains (plus a
    // duplicate and a self-referential ycombinator link) in deliberately
    // non-alphabetical order.
    let urls = [
        "https://rust-lang.org/blog",
        "https://python.org/docs",
        "https://golang.org/",
        "https://aws.amazon.com/blogs/x",
        "https://rust-lang.org/other", // same domain as the first — deduped
        "https://cloudflare.com/",
        "https://news.ycombinator.com/item?id=1", // HN's own domain, still counted
    ];
    let body = format!(
        "[{}]",
        urls.iter()
            .map(|u| format!(r#"{{"url":"{u}"}}"#))
            .collect::<Vec<_>>()
            .join(",")
    );

    let out = algolia_domain_entities(&body, "someuser", "s");
    // 6 distinct domains: rust-lang.org, python.org, golang.org,
    // aws.amazon.com, cloudflare.com, news.ycombinator.com. The bio-extractor's
    // ycombinator.com/news.ycombinator.com exclusion does not apply here — this
    // path has no such exclusion.
    assert_eq!(out.len(), 6, "all distinct domains emitted: {out:?}");

    // Deterministic: values emerge sorted, independent of the dedup
    // HashSet's randomised iteration order.
    let vals: Vec<&str> = out.iter().map(|e| e.value.as_str()).collect();
    let mut sorted = vals.clone();
    sorted.sort_unstable();
    assert_eq!(vals, sorted, "domains emerge in sorted, deterministic order");
    assert!(
        out.iter()
            .all(|e| e.kind == EntityKind::Domain && e.has_tag("hn-submission")),
        "each is an hn-submission-tagged Domain"
    );
}

#[test]
fn algolia_domain_entities_no_urls_yields_nothing() {
    let body = r#"[{"title":"no url field here"}]"#;
    assert!(algolia_domain_entities(body, "someuser", "s").is_empty());
}

// ── mine_keys_from_text ────────────────────────────────────────────────────

#[test]
fn mine_keys_from_text_pools_a_leaked_key_with_hacker_news_provenance() {
    // A 234-char BinaryEdge-shaped (`bp0_`-prefixed, poolable) key — the same
    // fixture shape used to prove the wayback key-mining pass (T2.82) and the
    // web_crawler/username_search tokenizer merge (T2.80) — embedded in
    // synthetic HN comment text, proving this NEW pass reaches `pool.add`
    // with HN-specific provenance, not just a generic "found it" no-op.
    let leaked_key = format!(
        "bp0_{}",
        "oHBvRPOIvGrv5iFlbCBFNOgmBjMtpsiaOclRz3AwzKsbVRJN9wVGFYGW2WmQzCudiH7YFjS1on43XkMtECqOxSF2O3GYRdo1XKXWNqRs7rpEmoKiuPKdYR7osjOrU1xxDO0CzUZREN68k4tUNpfZ46pdJQIPvjiQvlb5lZXOIgfFwD3HJoKyrbmEYYmdhQj38AruHr4iwRxpVHSbKdA9u4uQgwLg6G3oT1ogmM"
    );
    let text = format!("Here's my config, oops: BINARYEDGE_KEY={leaked_key} — ignore that.");
    let pool = crate::util::key_pool::global_pool();
    let username = "hn-keymine-test-user";

    mine_keys_from_text(&pool, &text, username, "submissions");

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
            Some(format!("hacker_news:{username}").as_str()),
            "provenance must name hacker_news, not a generic/wrong source"
        );
        assert!(
            e.notes.as_deref().is_some_and(|n| n.contains("submissions") && n.contains(username)),
            "notes must carry the source label + username, got {:?}",
            e.notes
        );
    }
    if found {
        pool.remove("binaryedge", &leaked_key);
    }
    assert!(
        found,
        "a leaked key in HN bio/submission text must reach the key pool"
    );
}

#[test]
fn build_entities_bio_with_a_leaked_key_pools_it_with_bio_provenance() {
    // End-to-end through build_entities (not the helper directly): a bio
    // containing a leaked key must be classified with source_label "bio",
    // distinguishing it from a "submissions"-sourced hit.
    let leaked_key = format!(
        "bp0_{}",
        "zzBvRPOIvGrv5iFlbCBFNOgmBjMtpsiaOclRz3AwzKsbVRJN9wVGFYGW2WmQzCudiH7YFjS1on43XkMtECqOxSF2O3GYRdo1XKXWNqRs7rpEmoKiuPKdYR7osjOrU1xxDO0CzUZREN68k4tUNpfZ46pdJQIPvjiQvlb5lZXOIgfFwD3HJoKyrbmEYYmdhQj38AruHr4iwRxpVHSbKdA9u4uQgwLg6G3oT1ogmZ"
    );
    let u = HnUser {
        id: "biokeytest".to_string(),
        created: None,
        karma: None,
        about: Some(format!("my key is {leaked_key} whoops")),
        submitted: None,
    };
    let pool = crate::util::key_pool::global_pool();
    build_entities(u, "scan-biokey", &pool);

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
