use super::*;

const FIXTURE: &str = r#"{
  "subject": "acct:Gargron@mastodon.social",
  "aliases": ["https://mastodon.social/@Gargron", "https://mastodon.social/users/Gargron"],
  "links": [
    { "rel": "http://webfinger.net/rel/profile-page", "type": "text/html", "href": "https://mastodon.social/@Gargron" },
    { "rel": "self", "type": "application/activity+json", "href": "https://mastodon.social/users/Gargron" },
    { "rel": "http://webfinger.net/rel/avatar", "type": "image/png", "href": "https://files.mastodon.social/x.png" }
  ]
}"#;

#[test]
fn extract_pulls_profile_actor_and_username() {
    let wf: WebFinger = serde_json::from_str(FIXTURE).expect("should succeed");
    let mut result = ModuleResult::new();
    extract_webfinger(&wf, "Gargron@mastodon.social", "mastodon.social", "scan", &mut result);
    let e = &result.entities;
    // Human profile page + ActivityPub actor, both as URL pivots.
    assert!(
        e.iter()
            .any(|x| x.kind == EntityKind::Url
                && x.value.to_ascii_lowercase().contains("mastodon.social/@gargron")
                && x.has_tag("fediverse"))
    );
    assert!(
        e.iter()
            .any(|x| x.kind == EntityKind::Url
                && x.value.to_ascii_lowercase().contains("mastodon.social/users/gargron"))
    );
    // The local username as a pivot.
    assert!(
        e.iter()
            .any(|x| x.kind == EntityKind::Username && x.value.eq_ignore_ascii_case("Gargron"))
    );
    // The seed email is flagged as a confirmed Fediverse identity.
    assert!(
        e.iter()
            .any(|x| x.kind == EntityKind::Email
                && x.value.eq_ignore_ascii_case("Gargron@mastodon.social")
                && x.has_tag("fediverse"))
    );
}

/// `aliases` are a distinct array from `links` — a WebFinger document can (and
/// often does, per the WebFinger spec) alias a subject to a URI that has no
/// corresponding typed `rel` link. This fixture deliberately gives the alias a
/// URI that appears nowhere in `links`, so the assertion can only pass if
/// `extract_webfinger` walks `aliases` itself rather than happening to catch
/// the value via the links-derived loop.
const ALIAS_DIVERGES_FIXTURE: &str = r#"{
  "subject": "acct:alice@example.social",
  "aliases": ["https://example.social/alias/alice-alt"],
  "links": [
    { "rel": "http://webfinger.net/rel/profile-page", "type": "text/html", "href": "https://example.social/@alice" },
    { "rel": "self", "type": "application/activity+json", "href": "https://example.social/users/alice" }
  ]
}"#;

#[test]
fn extract_emits_alias_uris_that_diverge_from_links() {
    let wf: WebFinger = serde_json::from_str(ALIAS_DIVERGES_FIXTURE).expect("should succeed");
    let mut result = ModuleResult::new();
    extract_webfinger(&wf, "alice@example.social", "example.social", "scan", &mut result);
    let e = &result.entities;
    // The alias URI, absent from `links`, is still emitted as its own URL pivot.
    assert!(
        e.iter().any(|x| x.kind == EntityKind::Url
            && x.value.eq_ignore_ascii_case("https://example.social/alias/alice-alt")
            && x.has_tag("fediverse")
            && x.has_tag("mastodon")
            && x.has_tag("webfinger-alias"))
    );
    // The links-derived profile page / actor URLs are untouched by the change.
    assert!(
        e.iter()
            .any(|x| x.kind == EntityKind::Url
                && x.value.to_ascii_lowercase().contains("example.social/@alice"))
    );
    assert!(
        e.iter()
            .any(|x| x.kind == EntityKind::Url
                && x.value.to_ascii_lowercase().contains("example.social/users/alice"))
    );
}

#[test]
fn freemail_domains_are_skipped_custom_domains_probed() {
    // Freemail providers run no WebFinger server → a certain 404, so they are not
    // probed (saves the guaranteed-miss request).
    for d in ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com"] {
        assert!(!domain_worth_probing(d), "{d} (freemail) must be skipped");
    }
    // A Fediverse instance or any custom domain might self-host WebFinger → probe.
    assert!(domain_worth_probing("mastodon.social"));
    assert!(domain_worth_probing("example.org"));
}

#[test]
fn accepts_only_emails() {
    let m = Fediverse;
    assert!(m.accepts(&Target::new(TargetKind::Email, "a@example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "alice")));
    assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    assert_eq!(m.category(), ModuleCategory::Social);
    assert!(!m.attack_techniques().is_empty());
}

/// Live end-to-end proof against the REAL Mastodon WebFinger endpoint — no mock.
/// Ignored by default (network); run with
/// `cargo test -p huntsman-search-engine fediverse_live -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "hits the live Mastodon WebFinger endpoint; run manually"]
async fn fediverse_live_resolves_a_known_handle() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    let target = Target::new(TargetKind::Email, "Gargron@mastodon.social");
    let r = Fediverse
        .process(&target, &ctx)
        .await
        .expect("live WebFinger must not error");
    eprintln!(
        "fediverse live: {} entities ({} url, {} username)",
        r.entities.len(),
        r.entities.iter().filter(|e| e.kind == EntityKind::Url).count(),
        r.entities.iter().filter(|e| e.kind == EntityKind::Username).count(),
    );
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Url && e.value.contains("mastodon.social")),
        "expected the resolved Mastodon profile URL"
    );
}
