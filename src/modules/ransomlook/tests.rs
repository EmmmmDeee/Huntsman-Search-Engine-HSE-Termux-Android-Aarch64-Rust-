use super::{Post, RansomLook, SRC, SearchResp, build_result};
use crate::core::{
    confidence,
    entity::EntityKind,
    module::Module,
    scan::{Target, TargetKind},
};

fn post(title: &str, group: &str, link: &str) -> Post {
    Post {
        post_title: Some(title.into()),
        group_name: Some(group.into()),
        discovered: Some("2026-09-01".into()),
        link: Some(link.into()),
    }
}

#[test]
fn accepts_domain_and_org_only() {
    let m = RansomLook;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "acme.com")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Corp")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

#[test]
fn module_name_is_stable() {
    assert_eq!(RansomLook.name(), "ransomlook");
    assert_eq!(RansomLook.name(), SRC);
}

#[test]
fn org_seed_matches_title_and_emits_org_plus_absolute_url() {
    let resp = SearchResp {
        posts: vec![post("Acme Corporation", "lockbit", "/leaks/abc123")],
    };
    let target = Target::new(TargetKind::Organisation, "Acme Corporation");
    let r = build_result(&resp, &target, "s");

    let org = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .expect("victim org emitted");
    assert_eq!(org.value, "Acme Corporation");
    assert!(org.has_tag("ransomware-victim"));
    assert!(org.has_tag("group:lockbit"));

    let url = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Url)
        .expect("reference url emitted");
    // Relative link made absolute against the RansomLook base.
    assert_eq!(url.value, "https://www.ransomlook.io/leaks/abc123");
    assert!(url.has_tag("reference"));
}

#[test]
fn domain_seed_matches_full_domain_in_title() {
    let resp = SearchResp {
        posts: vec![post("acme.com (Acme Corp)", "akira", "https://x.example/p")],
    };
    let target = Target::new(TargetKind::Domain, "acme.com");
    let r = build_result(&resp, &target, "s");
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Organisation)
    );
    // Absolute link is kept as-is.
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://x.example/p")
    );
}

#[test]
fn incidental_nonmatching_post_is_dropped() {
    let resp = SearchResp {
        posts: vec![post("Totally Unrelated Ltd", "clop", "/leaks/z")],
    };
    let target = Target::new(TargetKind::Domain, "acme.com");
    let r = build_result(&resp, &target, "s");
    assert_eq!(r.entities.len(), 0);
}

#[test]
fn short_domain_label_does_not_over_match() {
    // A 3-char label must NOT match on the partial-label rule (>=4 required),
    // so "ibm.com" does not sweep in every title containing "ibm".
    let resp = SearchResp {
        posts: vec![post("Fibmarket Holdings", "play", "/leaks/q")],
    };
    let target = Target::new(TargetKind::Domain, "ibm.com");
    let r = build_result(&resp, &target, "s");
    assert_eq!(r.entities.len(), 0);
}

#[test]
fn empty_posts_is_a_clean_negative() {
    let resp = SearchResp { posts: vec![] };
    let target = Target::new(TargetKind::Organisation, "Acme");
    let r = build_result(&resp, &target, "s");
    assert_eq!(r.entities.len(), 0);
}

#[test]
fn domain_label_partial_match_is_medium_high() {
    // Domain seed whose >=4-char label ("acme") is a title token, but the FULL
    // domain ("acme.com") is not present → the Match::Partial label arm. Pins the
    // >=4 label floor AND the Partial (MEDIUM_HIGH) confidence.
    let resp = SearchResp {
        posts: vec![post("Acme Holdings", "akira", "/leaks/p")],
    };
    let target = Target::new(TargetKind::Domain, "acme.com");
    let r = build_result(&resp, &target, "s");
    let org = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .expect("partial-label victim org emitted");
    assert_eq!(org.confidence, confidence::MEDIUM_HIGH);
}

#[test]
fn domain_full_match_is_high_strong() {
    // Full domain present as a title token → Match::Strong → HIGH, pinning the
    // Strong/Partial confidence split.
    let resp = SearchResp {
        posts: vec![post("Breach at acme.com dump", "akira", "/leaks/p")],
    };
    let target = Target::new(TargetKind::Domain, "acme.com");
    let r = build_result(&resp, &target, "s");
    let org = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .expect("strong victim org emitted");
    assert_eq!(org.confidence, confidence::HIGH);
}

#[test]
fn bare_relative_link_is_resolved_against_base() {
    // A link with no leading slash and not absolute → the else-arm inserts the
    // joining slash: BASE + "/" + link.
    let resp = SearchResp {
        posts: vec![post("Acme", "clop", "leaks/q")],
    };
    let target = Target::new(TargetKind::Organisation, "Acme");
    let r = build_result(&resp, &target, "s");
    let url = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Url)
        .expect("reference url emitted");
    assert_eq!(url.value, "https://www.ransomlook.io/leaks/q");
}

#[test]
fn org_seed_substring_match_within_word_is_rejected() {
    // REQ-RANSOMWARE-001: substring containment that is NOT a whole-word boundary
    // must NOT match. An Organisation seed "acm" must not match a title "Acme Inc"
    // — the old code had (title.contains(needle) || needle.contains(&title)) which
    // would incorrectly match this. The new whole-word-token gate requires all
    // tokens in the needle to appear as complete words.
    let resp = SearchResp {
        posts: vec![post("Acme Inc", "clop", "/leaks/q")],
    };
    let target = Target::new(TargetKind::Organisation, "acm");
    let r = build_result(&resp, &target, "s");
    assert_eq!(
        r.entities.len(),
        0,
        "substring 'acm' within 'Acme' must not match"
    );

    // Reverse direction: seed is a substring of a title word, also fails.
    let resp = SearchResp {
        posts: vec![post("Acme", "clop", "/leaks/q")],
    };
    let target = Target::new(TargetKind::Organisation, "company acme");
    let r = build_result(&resp, &target, "s");
    assert_eq!(
        r.entities.len(),
        0,
        "tokens ['company', 'acme'] where 'company' is missing must not match title 'Acme'"
    );
}

#[test]
fn org_seed_whole_word_token_match_partial_succeeds() {
    // Positive control: when all tokens of the seed are present as whole words
    // in the title, the match succeeds as Partial. "Acme Holdings" as a seed matches
    // a title "Acme Holdings Inc" because both tokens "acme" and "holdings" are
    // present as whole words in the title.
    let resp = SearchResp {
        posts: vec![post("Acme Holdings Inc", "lockbit", "/leaks/abc")],
    };
    let target = Target::new(TargetKind::Organisation, "Acme Holdings");
    let r = build_result(&resp, &target, "s");
    let org = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .expect("whole-word tokens 'Acme' + 'Holdings' must match title 'Acme Holdings Inc'");
    assert_eq!(org.confidence, confidence::MEDIUM_HIGH);
}
