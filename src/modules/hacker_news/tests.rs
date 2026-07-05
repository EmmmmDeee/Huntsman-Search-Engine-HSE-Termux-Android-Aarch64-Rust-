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
    let u: Option<HnUser> = serde_json::from_str(json).unwrap();
    let u = u.unwrap();
    assert_eq!(u.id, "pg");
    assert_eq!(u.karma, Some(157222));
    assert_eq!(u.submitted.as_ref().unwrap().len(), 3);
    // The literal `null` (unknown handle) is a clean None.
    let none: Option<HnUser> = serde_json::from_str("null").unwrap();
    assert!(none.is_none());
}

#[test]
fn bio_extracts_email_and_url() {
    use crate::util::extract::{EMAIL_RE, URL_RE};
    let about = "Contact: Paul@Example.com — site https://paulgraham.com/bio.html.";
    assert_eq!(
        EMAIL_RE.find(about).unwrap().as_str().to_lowercase(),
        "paul@example.com"
    );
    let link = URL_RE
        .find(about)
        .unwrap()
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
    let ents = build_entities(user("pg"), "scan-1");
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
    let ents = build_entities(u, "scan-2");
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
    let ents = build_entities(u, "scan-3");
    let email = ents.iter().find(|e| e.kind == EntityKind::Email).unwrap();
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
    let ents = build_entities(u, "scan-4");
    let url = ents.iter().find(|e| e.kind == EntityKind::Url).unwrap();
    assert!(url.value.starts_with("https://"));
    assert!(!url.value.ends_with('.'), "trailing dot must be stripped");
    assert!(url.has_tag("personal-site"));
}

#[test]
fn build_entities_no_bio_yields_only_username() {
    let ents = build_entities(user("quiet"), "scan-5");
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
