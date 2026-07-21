use crate::core::confidence;
use super::*;

const FIXTURE: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<profile>
  <steamID64>76561197960287930</steamID64>
  <steamID><![CDATA[Rabscuttle]]></steamID>
  <realname><![CDATA[Robin Walker]]></realname>
  <location><![CDATA[Seattle, Washington, United States]]></location>
  <customURL><![CDATA[rabscuttle]]></customURL>
</profile>"#;

#[test]
fn extract_tag_handles_cdata_and_plain() {
    assert_eq!(
        extract_tag("<steamID64>76561197960287930</steamID64>", "steamID64").as_deref(),
        Some("76561197960287930")
    );
    assert_eq!(
        extract_tag("<realname><![CDATA[Robin Walker]]></realname>", "realname").as_deref(),
        Some("Robin Walker")
    );
    assert_eq!(extract_tag("<realname></realname>", "realname"), None);
    assert_eq!(extract_tag("<profile></profile>", "realname"), None);
    // Entity decoding outside CDATA.
    assert_eq!(
        extract_tag("<location>Montr&amp;al</location>", "location").as_deref(),
        Some("Montr&al")
    );
}

#[test]
fn steam_lookup_url_routes_id_and_vanity() {
    // SteamID64 (public 7656119… range) → /profiles, high confidence.
    let (url, conf) = steam_lookup_url("76561197960287930").unwrap();
    assert!(url.contains("/profiles/76561197960287930?xml=1"));
    assert!((conf - confidence::HIGH_PLUSPLUS_PLUS).abs() < 1e-9);
    // `steam:`-prefixed id64 still routes to /profiles.
    assert!(
        steam_lookup_url("steam:76561197960265728")
            .unwrap()
            .0
            .contains("/profiles/")
    );
    // `steam:`-prefixed vanity → /id.
    assert!(
        steam_lookup_url("steam:gabelogannewell")
            .unwrap()
            .0
            .contains("/id/gabelogannewell")
    );
    // Bare plausible vanity → /id, moderate confidence.
    let (url, conf) = steam_lookup_url("gabelogannewell").unwrap();
    assert!(url.contains("/id/gabelogannewell"));
    assert!((conf - confidence::MEDIUM_PLUS).abs() < 1e-9);
    // A Discord snowflake (18 digits, not 7656119…) must NOT trigger a Steam
    // lookup (all-digit → not a vanity, wrong prefix → not a SteamID64).
    assert!(steam_lookup_url("175928847299117063").is_none());
    // Too short.
    assert!(steam_lookup_url("ab").is_none());
}

#[test]
fn is_vanity_shaped_gates() {
    assert!(is_vanity_shaped("gabelogannewell"));
    assert!(is_vanity_shaped("a_b-c1"));
    assert!(!is_vanity_shaped("ab")); // too short
    assert!(!is_vanity_shaped("12345")); // no letter
    assert!(!is_vanity_shaped("with space"));
}

#[test]
fn extract_profile_builds_identity_from_fixture() {
    let mut result = ModuleResult::new();
    extract_profile(FIXTURE, confidence::HIGH_PLUSPLUS_PLUS, "scan", &mut result);
    let e = &result.entities;
    assert!(
        e.iter()
            .any(|x| x.kind == EntityKind::Url
                && x.value == "https://steamcommunity.com/profiles/76561197960287930")
    );
    assert!(
        e.iter()
            .any(|x| x.kind == EntityKind::Person && x.value == "Robin Walker")
    );
    assert!(
        e.iter()
            .any(|x| x.kind == EntityKind::Address && x.value.contains("Seattle"))
    );
    assert!(
        e.iter()
            .any(|x| x.kind == EntityKind::Username && x.value == "rabscuttle")
    );
    assert!(e.iter().all(|x| x.has_tag("steam")));
}

/// T2.106 regression: `<steamID>` (persona name) matching `<customURL>`
/// case-insensitively (the fixture's own "Rabscuttle" vs "rabscuttle") must
/// NOT mint a second near-duplicate Username entity for the same handle.
#[test]
fn extract_profile_does_not_duplicate_persona_and_vanity() {
    let mut result = ModuleResult::new();
    extract_profile(FIXTURE, confidence::HIGH_PLUSPLUS_PLUS, "scan", &mut result);
    let usernames: Vec<&str> = result
        .entities
        .iter()
        .filter(|x| x.kind == EntityKind::Username)
        .map(|x| x.value.as_str())
        .collect();
    assert_eq!(usernames, vec!["rabscuttle"]);
    // And the persona shouldn't be promoted to Person either — it's a single
    // token, and the fixture's real Person is "Robin Walker".
    let persons: Vec<&str> = result
        .entities
        .iter()
        .filter(|x| x.kind == EntityKind::Person)
        .map(|x| x.value.as_str())
        .collect();
    assert_eq!(persons, vec!["Robin Walker"]);
}

/// T2.106: a multi-word persona name with no `<realname>` at all promotes to
/// a Person entity (mirroring `realname`'s policy via
/// `profile_kit::person_from_name`), previously silently dropped entirely.
#[test]
fn extract_profile_promotes_multiword_persona_to_person() {
    const FIXTURE_NO_REALNAME: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<profile>
  <steamID64>76561197960287930</steamID64>
  <steamID><![CDATA[Gabe Newell]]></steamID>
  <customURL><![CDATA[gaben]]></customURL>
</profile>"#;
    let mut result = ModuleResult::new();
    extract_profile(FIXTURE_NO_REALNAME, confidence::HIGH_PLUSPLUS_PLUS, "scan", &mut result);
    assert!(
        result
            .entities
            .iter()
            .any(|x| x.kind == EntityKind::Person && x.value == "Gabe Newell" && x.has_tag("persona"))
    );
}

/// T2.106: a single-token persona distinct from the vanity URL is a genuine
/// second handle pivot (previously dropped entirely — the field was never read).
#[test]
fn extract_profile_emits_persona_username_when_distinct_from_vanity() {
    const FIXTURE_DISTINCT: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<profile>
  <steamID64>76561197960287930</steamID64>
  <steamID><![CDATA[oldhandle]]></steamID>
  <customURL><![CDATA[newvanity]]></customURL>
</profile>"#;
    let mut result = ModuleResult::new();
    extract_profile(FIXTURE_DISTINCT, confidence::HIGH_PLUSPLUS_PLUS, "scan", &mut result);
    let usernames: std::collections::HashSet<&str> = result
        .entities
        .iter()
        .filter(|x| x.kind == EntityKind::Username)
        .map(|x| x.value.as_str())
        .collect();
    assert!(usernames.contains("oldhandle"));
    assert!(usernames.contains("newvanity"));
}

/// T2.106: `<summary>` (the free-text bio) is mined for emails/URLs exactly
/// like every sibling Social module's bio-scanning policy — previously the
/// field was never read at all.
#[test]
fn extract_profile_mines_bio_email_and_url() {
    const FIXTURE_BIO: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<profile>
  <steamID64>76561197960287930</steamID64>
  <steamID><![CDATA[Rabscuttle]]></steamID>
  <summary><![CDATA[Contact me at rabscuttle@example.com or visit https://rabscuttle.dev/about]]></summary>
</profile>"#;
    let mut result = ModuleResult::new();
    extract_profile(FIXTURE_BIO, confidence::HIGH_PLUSPLUS_PLUS, "scan", &mut result);
    let e = &result.entities;
    assert!(
        e.iter()
            .any(|x| x.kind == EntityKind::Email && x.value == "rabscuttle@example.com")
    );
    assert!(
        e.iter()
            .any(|x| x.kind == EntityKind::Url && x.value == "https://rabscuttle.dev/about")
    );
    assert!(
        e.iter()
            .any(|x| x.kind == EntityKind::Domain && x.value == "rabscuttle.dev")
    );
}

/// T2.106: a bio with no email/URL mints nothing extra — never fabricate a
/// pivot out of empty free text.
#[test]
fn extract_profile_bio_without_pivots_emits_nothing_extra() {
    const FIXTURE_PLAIN_BIO: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<profile>
  <steamID64>76561197960287930</steamID64>
  <steamID><![CDATA[Rabscuttle]]></steamID>
  <summary><![CDATA[Just here for the games.]]></summary>
</profile>"#;
    let mut result = ModuleResult::new();
    extract_profile(FIXTURE_PLAIN_BIO, confidence::HIGH_PLUSPLUS_PLUS, "scan", &mut result);
    assert!(!result.entities.iter().any(|x| x.kind == EntityKind::Email));
    assert!(
        !result
            .entities
            .iter()
            .any(|x| x.kind == EntityKind::Domain)
    );
}

#[test]
fn is_free_social_module() {
    let m = SteamProfile;
    assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    assert_eq!(m.category(), ModuleCategory::Social);
    assert!(!m.attack_techniques().is_empty());
    assert!(m.accepts(&Target::new(TargetKind::Username, "76561197960287930")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

/// Live end-to-end proof against the REAL Steam community XML — no mock.
/// Ignored by default (network + non-deterministic upstream); run with
/// `cargo test -p huntsman-search-engine steam_profile_live -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "hits the live Steam community XML endpoint; run manually"]
async fn steam_profile_live_resolves_a_public_vanity() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    // A well-known public vanity reliably resolves to a profile (the Url is
    // emitted whenever the SteamID64 is visible, regardless of privacy).
    let target = Target::new(TargetKind::Username, "gabelogannewell");
    let r = SteamProfile
        .process(&target, &ctx)
        .await
        .expect("live Steam query must not error");
    eprintln!(
        "steam_profile live: {} entities ({} url, {} person, {} address)",
        r.entities.len(),
        r.entities.iter().filter(|e| e.kind == EntityKind::Url).count(),
        r.entities.iter().filter(|e| e.kind == EntityKind::Person).count(),
        r.entities.iter().filter(|e| e.kind == EntityKind::Address).count(),
    );
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Url && e.value.contains("steamcommunity.com/profiles/")),
        "expected a resolved Steam profile URL"
    );
}
