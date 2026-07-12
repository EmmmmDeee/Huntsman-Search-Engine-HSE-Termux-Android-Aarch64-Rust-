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
    assert!((conf - 0.85).abs() < 1e-9);
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
    assert!((conf - 0.60).abs() < 1e-9);
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
    extract_profile(FIXTURE, 0.85, "scan", &mut result);
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
