use super::*;
use crate::core::confidence;

fn make_person(
    name: &str,
    display_name: Option<&str>,
    web_link: Option<&str>,
    description: Option<&str>,
    is_valid: bool,
) -> LpPerson {
    LpPerson {
        name: name.to_string(),
        display_name: display_name.map(str::to_string),
        web_link: web_link.map(str::to_string),
        description: description.map(str::to_string),
        is_valid,
        time_zone: None,
    }
}

#[test]
fn surfaces_time_zone_and_coarse_au_tag_on_username() {
    let mut p = make_person("alice", None, None, None, true);
    p.time_zone = Some("Australia/Brisbane".to_string());
    let ents = build_entities(p, "scan-lp-tz");
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .expect("username");
    assert_eq!(
        u.evidence[0]
            .attributes
            .get("time_zone")
            .map(String::as_str),
        Some("Australia/Brisbane")
    );
    assert!(
        u.has_tag("country:AU"),
        "an Australia/* zone tags country:AU"
    );

    // A non-AU zone surfaces the attribute but no country:AU tag.
    let mut q = make_person("bob", None, None, None, true);
    q.time_zone = Some("Europe/Berlin".to_string());
    let ents = build_entities(q, "scan-lp-tz2");
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .expect("username");
    assert_eq!(
        u.evidence[0]
            .attributes
            .get("time_zone")
            .map(String::as_str),
        Some("Europe/Berlin")
    );
    assert!(!u.has_tag("country:AU"));
}

#[test]
fn emits_username_and_profile_url_from_web_link() {
    let p = make_person(
        "alice",
        None,
        Some("https://launchpad.net/~alice"),
        None,
        true,
    );
    let ents = build_entities(p, "scan-lp-001");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "alice")
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://launchpad.net/~alice")
    );
    let u = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .unwrap();
    assert!(u.has_tag("launchpad") && u.has_tag("public-profile"));
    assert!((u.confidence - confidence::HIGH_PLUSPLUS_PLUS).abs() < 0.01);
}

#[test]
fn falls_back_to_constructed_url_when_web_link_absent() {
    let p = make_person("alice", None, None, None, true);
    let ents = build_entities(p, "scan-lp-002");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://launchpad.net/~alice")
    );
}

#[test]
fn emits_person_from_multi_word_display_name() {
    let p = make_person("alice", Some("Alice Ubuntu Developer"), None, None, true);
    let ents = build_entities(p, "scan-lp-003");
    let pe = ents.iter().find(|e| e.kind == EntityKind::Person);
    assert!(
        pe.is_some(),
        "must emit Person from multi-word display_name"
    );
    assert_eq!(pe.unwrap().value, "Alice Ubuntu Developer");
    assert!(pe.unwrap().has_tag("launchpad"));
}

#[test]
fn single_word_display_name_does_not_emit_person() {
    let p = make_person("alice", Some("Alice"), None, None, true);
    let ents = build_entities(p, "scan-lp-004");
    assert!(ents.iter().all(|e| e.kind != EntityKind::Person));
}

#[test]
fn extracts_email_from_bio() {
    let p = make_person(
        "alice",
        None,
        None,
        Some("Contact me at alice@ubuntu.com for packaging help."),
        true,
    );
    let ents = build_entities(p, "scan-lp-005");
    let em = ents.iter().find(|e| e.kind == EntityKind::Email);
    assert!(em.is_some(), "must extract email from bio");
    assert_eq!(em.unwrap().value, "alice@ubuntu.com");
    assert!(em.unwrap().has_tag("launchpad"));
    let attr = em
        .unwrap()
        .evidence
        .iter()
        .find_map(|ev| ev.attributes.get("source_field"))
        .expect("evidence must record which field the bio came from");
    assert_eq!(
        attr, "description",
        "must attribute the bio to `description`, the field Launchpad's API actually populates"
    );
}

/// Regression for T2.105: the real Launchpad API returns `homepage_content:
/// null` on essentially every modern account (confirmed live against
/// `~cjwatson`, `~sil2100`, `~xnox`, `~kirkland`, `~stgraber` — all `None`)
/// while `description` carries the actual bio text. `LpPerson` no longer has
/// a `homepage_content` field at all — this test pins that the sole bio
/// field left (`description`) is what drives extraction, i.e. a person with
/// no `description` yields no bio-derived email even though a legacy
/// deployment might still have populated the now-dead `homepage_content`
/// field server-side.
#[test]
fn no_bio_email_when_description_absent() {
    let p = make_person("alice", None, None, None, true);
    let ents = build_entities(p, "scan-lp-008");
    assert!(
        ents.iter().all(|e| e.kind != EntityKind::Email),
        "must not fabricate a bio email when `description` is absent"
    );
}

#[test]
fn invalid_account_returns_no_entities() {
    let p = make_person("alice", Some("Alice Dev"), None, None, false);
    assert!(build_entities(p, "scan-lp-006").is_empty());
}

#[test]
fn empty_name_returns_no_entities() {
    let p = make_person("", None, None, None, true);
    assert!(build_entities(p, "scan-lp-007").is_empty());
}
