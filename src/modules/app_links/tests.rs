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
fn assetlinks_emits_every_app_and_delegated_domain_no_cap() {
    // 25 distinct signed apps (> the old APP_CAP = 24) and 13 distinct delegated
    // sibling domains (> the old SITE_CAP = 12), all from the owner's own
    // assetlinks.json. Every one is an authoritative, owner-asserted attribution,
    // so all must surface — none dropped by an arbitrary per-module cap.
    let mut statements = Vec::new();
    for i in 0..25 {
        // A distinct, well-formed 32-octet SHA-256 fingerprint per app.
        let fp: String = std::iter::once(format!("{i:02X}"))
            .chain(std::iter::repeat_n("AB".to_string(), 31))
            .collect::<Vec<_>>()
            .join(":");
        statements.push(serde_json::json!({
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {
                "namespace": "android_app",
                "package_name": format!("com.example.app{i}"),
                "sha256_cert_fingerprints": [fp]
            }
        }));
    }
    for i in 0..13 {
        statements.push(serde_json::json!({
            "relation": ["delegate_permission/common.get_login_creds"],
            "target": { "namespace": "web", "site": format!("https://s{i}.example.org") }
        }));
    }
    let body = serde_json::Value::Array(statements).to_string();
    let mut r = ModuleResult::new();
    parse_assetlinks(&body, "example.com", "scan", &mut r);

    assert_eq!(
        count_kind(&r, "android-app-id"),
        25,
        "every distinct package emitted, not capped at 24"
    );
    assert_eq!(
        count_kind(&r, "cert-sha256"),
        25,
        "every distinct signing-cert fingerprint emitted, not capped at 24"
    );
    let domains = r
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .count();
    assert_eq!(
        domains, 13,
        "every distinct delegated domain emitted, not capped at 12"
    );
}

#[test]
fn aasa_emits_every_app_id_no_cap() {
    // 25 distinct Apple appIDs (> the old APP_CAP = 24), each with its own Team
    // ID and bundle. Every owner-published app identity must surface.
    let details: Vec<serde_json::Value> = (0..25)
        .map(|i| {
            let team = format!("TEAM{i:06}"); // 10 upper-alnum chars → valid Team ID
            serde_json::json!({ "appID": format!("{team}.com.example.App{i}"), "paths": ["/*"] })
        })
        .collect();
    let body = serde_json::json!({ "applinks": { "apps": [], "details": details } }).to_string();
    let mut r = ModuleResult::new();
    parse_aasa(&body, "example.com", "scan", &mut r);

    assert_eq!(
        count_kind(&r, "apple-app-id"),
        25,
        "every distinct appID emitted, not capped at 24"
    );
    assert_eq!(
        count_kind(&r, "apple-team-id"),
        25,
        "every distinct Apple Team ID emitted"
    );
    assert_eq!(
        count_kind(&r, "ios-bundle-id"),
        25,
        "every distinct bundle ID emitted"
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

// -- fetch_text failure contract (T2.153) -----------------------------------

/// One-shot local HTTP server answering with `status` + `body`. Mirrors the
/// pgp / sanctions_ofac / chain_intel / geocode / opencellid test pattern.
async fn serve_once(status: u16, body: &'static str) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut buf = vec![0u8; 2048];
        let _ = sock.read(&mut buf).await;
        let reason = if status == 200 { "OK" } else { "Error" };
        let head = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let _ = sock.write_all(head.as_bytes()).await;
        let _ = sock.write_all(body.as_bytes()).await;
        let _ = sock.flush().await;
    });
    addr
}

fn test_ctx() -> ModuleContext {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    ModuleContext {
        scan_id: "t".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    }
}

#[tokio::test]
async fn fetch_text_reports_transport_failed_on_an_unreachable_host() {
    // T2.153 regression: a genuine transport failure (connection refused)
    // previously collapsed into the same None as an ordinary 404 — a
    // total outage on both well-knowns was indistinguishable from "this
    // domain doesn't publish app links". Port 1: connection refused.
    let ctx = test_ctx();
    let outcome = fetch_text(&ctx, "http://127.0.0.1:1/").await;
    assert!(
        matches!(outcome, FetchOutcome::TransportFailed),
        "an unreachable host must report TransportFailed"
    );
}

#[tokio::test]
async fn fetch_text_keeps_404_and_5xx_as_answered_not_transport_failed() {
    // The ordinary negative (a site that doesn't publish this well-known)
    // must stay Answered, never TransportFailed — a real HTTP answer (even
    // an error status) means the host WAS reachable.
    let ctx = test_ctx();
    let addr_404 = serve_once(404, "not found").await;
    assert!(matches!(
        fetch_text(&ctx, &format!("http://{addr_404}/")).await,
        FetchOutcome::Answered
    ));

    let addr_500 = serve_once(500, "upstream error").await;
    assert!(matches!(
        fetch_text(&ctx, &format!("http://{addr_500}/")).await,
        FetchOutcome::Answered
    ));
}

#[tokio::test]
async fn fetch_text_returns_body_on_a_real_2xx_payload() {
    let ctx = test_ctx();
    let addr = serve_once(200, "[]").await;
    let outcome = fetch_text(&ctx, &format!("http://{addr}/")).await;
    assert!(matches!(outcome, FetchOutcome::Body(ref b) if b == "[]"));
}

#[tokio::test]
async fn fetch_text_treats_empty_2xx_body_as_answered() {
    // A 2xx with an empty body is a genuine (if unusual) answer, not a
    // failure.
    let ctx = test_ctx();
    let addr = serve_once(200, "").await;
    assert!(matches!(
        fetch_text(&ctx, &format!("http://{addr}/")).await,
        FetchOutcome::Answered
    ));
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
