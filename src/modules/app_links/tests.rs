use super::*;

/// Real-shaped Android Digital Asset Links: one signed app + two delegated web
/// targets (one of which is the queried domain itself, which must be dropped).
const ASSETLINKS: &str = r#"[
  { "relation": ["delegate_permission/common.handle_all_urls"],
    "target": { "namespace": "android_app", "package_name": "com.example.app",
      "sha256_cert_fingerprints":
        ["ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89"] } },
  { "relation": ["delegate_permission/common.get_login_creds"],
    "target": { "namespace": "web", "site": "https://login.example.org/path" } },
  { "relation": ["delegate_permission/common.get_login_creds"],
    "target": { "namespace": "web", "site": "https://example.com" } }
]"#;

/// Real-shaped AASA: `appID`, `appIDs`, and `webcredentials` (the last repeats
/// the first app, exercising dedup of both the appID and its Team ID).
const AASA: &str = r#"{
  "applinks": {
    "apps": [],
    "details": [
      { "appID": "7JMU3EK8QX.com.example.App", "paths": ["/x/*"] },
      { "appIDs": ["ABCDE12345.com.example.App2"], "components": [] }
    ]
  },
  "webcredentials": { "apps": ["7JMU3EK8QX.com.example.App"] }
}"#;

#[test]
fn assetlinks_extracts_package_cert_and_delegated_domain() {
    let mut r = ModuleResult::new();
    parse_assetlinks(ASSETLINKS, "example.com", "scan", &mut r);
    let e = &r.entities;

    assert!(
        e.iter().any(|x| x.kind == EntityKind::Other("android-app-id".into())
            && x.value == "com.example.app"
            && x.has_tag("android-app"))
    );
    // Fingerprint is surfaced upper-cased.
    assert!(
        e.iter().any(|x| x.kind == EntityKind::Other("cert-sha256".into())
            && x.value.starts_with("AB:CD:EF:")
            && x.has_tag("signing-cert"))
    );
    // The distinct delegated domain is a pivot…
    assert!(
        e.iter()
            .any(|x| x.kind == EntityKind::Domain && x.value == "login.example.org")
    );
    // …but the queried domain is never echoed back as a "delegated" pivot.
    assert!(
        e.iter()
            .all(|x| !(x.kind == EntityKind::Domain && x.value == "example.com"))
    );
}

#[test]
fn aasa_extracts_team_bundle_and_app_id() {
    let mut r = ModuleResult::new();
    parse_aasa(AASA, "example.com", "scan", &mut r);
    let e = &r.entities;

    // Apple Developer Team ID (the org identity).
    assert!(
        e.iter().any(|x| x.kind == EntityKind::Other("apple-team-id".into())
            && x.value == "7JMU3EK8QX"
            && x.has_tag("apple-team"))
    );
    // The second app's full id + bundle.
    assert!(
        e.iter().any(|x| x.kind == EntityKind::Other("apple-app-id".into())
            && x.value == "ABCDE12345.com.example.App2")
    );
    assert!(
        e.iter().any(|x| x.kind == EntityKind::Other("ios-bundle-id".into())
            && x.value == "com.example.App2")
    );
    // Team `7JMU3EK8QX` is referenced twice (details + webcredentials) but
    // deduped to a single entity.
    assert_eq!(
        e.iter()
            .filter(|x| x.kind == EntityKind::Other("apple-team-id".into())
                && x.value == "7JMU3EK8QX")
            .count(),
        1
    );
}

#[test]
fn shape_gates() {
    assert!(is_team_id("7JMU3EK8QX"));
    assert!(!is_team_id("toolongteamid")); // not 10 chars
    assert!(!is_team_id("lowercase1")); // must be upper-case alnum
    assert_eq!(
        split_app_id("7JMU3EK8QX.com.x.App"),
        Some(("7JMU3EK8QX", "com.x.App"))
    );
    assert!(split_app_id("notateam.com.x").is_none());
    assert!(is_pkg("com.example.app"));
    assert!(!is_pkg("nodot"));
    assert!(is_sha256_fp(
        "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"
    ));
    assert!(!is_sha256_fp("AB:CD")); // too few octets
    assert_eq!(host_of("https://login.example.org/x"), Some("login.example.org".into()));
    assert_eq!(host_of("ftp://nope"), None);
}

#[test]
fn malformed_bodies_are_clean_misses() {
    let mut r = ModuleResult::new();
    parse_assetlinks("not json", "example.com", "scan", &mut r);
    parse_aasa("<html>404</html>", "example.com", "scan", &mut r);
    assert!(r.entities.is_empty());
}

#[test]
fn is_free_web_module() {
    let m = AppLinks;
    assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    assert_eq!(m.category(), ModuleCategory::Web);
    // Uses the Web category's default ATT&CK mapping.
    assert!(!m.attack_techniques().is_empty());
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "alice")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

/// Live end-to-end proof against a REAL domain's AASA — no mock. Ignored by
/// default (network); run with
/// `cargo test -p huntsman-search-engine app_links_live -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "hits live well-known endpoints; run manually"]
async fn app_links_live_resolves_apple_team() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Default::default(),
    };
    let r = AppLinks
        .process(&Target::new(TargetKind::Domain, "paypal.com"), &ctx)
        .await
        .expect("live well-known fetch must not error");
    eprintln!(
        "app_links live (paypal.com): {} entities ({} team, {} ios-app, {} android, {} domain)",
        r.entities.len(),
        count_kind(&r, "apple-team-id"),
        count_kind(&r, "apple-app-id"),
        count_kind(&r, "android-app-id"),
        r.entities.iter().filter(|e| e.kind == EntityKind::Domain).count(),
    );
    // PayPal reliably serves an AASA that exposes at least one Apple Team ID.
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Other("apple-team-id".into())),
        "expected at least one Apple Team ID from the live AASA"
    );
}

#[cfg(test)]
fn count_kind(r: &ModuleResult, k: &str) -> usize {
    r.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Other(k.to_string()))
        .count()
}
