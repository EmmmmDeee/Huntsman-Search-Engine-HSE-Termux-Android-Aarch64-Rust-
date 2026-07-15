use super::*;

const SCAN: &str = "scan-pk-001";

// ── profile_url ──────────────────────────────────────────────────────────────

#[test]
fn profile_url_prefers_absolute_api_link() {
    let u = profile_url(Some("https://gitea.com/alice"), || {
        "https://fallback/x".to_string()
    });
    assert_eq!(u, "https://gitea.com/alice");
}

#[test]
fn profile_url_trims_trailing_slash_on_api_link() {
    let u = profile_url(Some("https://sourceforge.net/u/alice/"), || {
        "https://fallback/x".to_string()
    });
    assert_eq!(u, "https://sourceforge.net/u/alice");
}

#[test]
fn profile_url_falls_back_when_link_absent() {
    let u = profile_url(None, || "https://launchpad.net/~alice".to_string());
    assert_eq!(u, "https://launchpad.net/~alice");
}

#[test]
fn profile_url_falls_back_when_link_not_http() {
    // A relative or scheme-less link is not usable — construct the fallback.
    let u = profile_url(Some("/u/alice"), || "https://x/alice".to_string());
    assert_eq!(u, "https://x/alice");
}

// ── person_from_name ─────────────────────────────────────────────────────────

#[test]
fn person_emitted_from_multi_word_name() {
    let p = person_from_name("Alice Q. Developer", 0.72, SCAN).unwrap();
    assert_eq!(p.kind, EntityKind::Person);
    assert_eq!(p.value, "Alice Q. Developer");
    assert!((p.confidence - 0.72).abs() < 1e-9);
}

#[test]
fn person_rejected_for_single_token() {
    assert!(person_from_name("alice", 0.72, SCAN).is_none());
}

#[test]
fn person_rejected_for_placeholder() {
    // Centralised placeholder filtering my newer modules previously skipped:
    // "John Doe" / "Test User" are canonical synthetic names the validation
    // layer rejects (see core::validation::placeholder::is_placeholder_person).
    assert!(person_from_name("John Doe", 0.72, SCAN).is_none());
    assert!(person_from_name("Test User", 0.72, SCAN).is_none());
}

// ── website_url_and_domain ───────────────────────────────────────────────────

#[test]
fn website_emits_url_and_domain_for_third_party_host() {
    let ents = website_url_and_domain("https://alice.dev", 0.70, 0.62, SCAN);
    assert_eq!(ents.len(), 2);
    assert_eq!(ents[0].kind, EntityKind::Url);
    assert_eq!(ents[0].value, "https://alice.dev");
    assert_eq!(ents[1].kind, EntityKind::Domain);
    assert_eq!(ents[1].value, "alice.dev");
}

#[test]
fn website_excludes_platform_host_domain_but_keeps_url() {
    // A GitHub link is a `Url` pointer, never a personal `Domain`.
    let ents = website_url_and_domain("https://github.com/alice", 0.70, 0.62, SCAN);
    assert_eq!(ents.len(), 1);
    assert_eq!(ents[0].kind, EntityKind::Url);
}

#[test]
fn website_returns_empty_for_non_http() {
    assert!(website_url_and_domain("ftp://alice.dev", 0.70, 0.62, SCAN).is_empty());
    assert!(website_url_and_domain("alice.dev", 0.70, 0.62, SCAN).is_empty());
}

// ── location_address ─────────────────────────────────────────────────────────

#[test]
fn address_emitted_for_short_location() {
    let a = location_address("Berlin, Germany", 0.36, SCAN).unwrap();
    assert_eq!(a.kind, EntityKind::Address);
    assert_eq!(a.value, "Berlin, Germany");
}

#[test]
fn address_rejected_for_empty_or_overlong() {
    assert!(location_address("   ", 0.36, SCAN).is_none());
    let long = "x".repeat(101);
    assert!(location_address(&long, 0.36, SCAN).is_none());
}

// ── bio_emails ───────────────────────────────────────────────────────────────

#[test]
fn bio_emails_extracts_every_address_uncapped() {
    // A bio listing six contact emails — all must surface. A prior take(limit)
    // (callers passed 3–5) silently dropped the extra contact-email pivots.
    let bio = "a@x.com b@x.com c@x.com d@x.com e@x.com f@x.com";
    let all = bio_emails(bio, 0.68, SCAN);
    assert_eq!(
        all.len(),
        6,
        "every distinct bio email is emitted, not capped"
    );
    assert!(all.iter().all(|e| e.kind == EntityKind::Email));
}

#[test]
fn bio_emails_empty_when_none_present() {
    assert!(bio_emails("no contact details here", 0.68, SCAN).is_empty());
}
