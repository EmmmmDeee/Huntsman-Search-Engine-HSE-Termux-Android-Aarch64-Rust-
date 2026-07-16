use super::*;

#[test]
fn accepts_only_username_targets() {
    let m = GamingProfile;
    assert!(m.accepts(&Target::new(TargetKind::Username, "alice")));
    // Gaming handles are usernames only — not emails, domains, or IPs.
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Jane Doe")));
}

#[test]
fn accepts_value_admits_handles_and_rejects_junk() {
    assert!(accepts_value("alice"));
    assert!(accepts_value("cool_guy"));
    assert!(accepts_value("abc123"));
    assert!(accepts_value("Notch"));
    // Too short / too long.
    assert!(!accepts_value("ab"));
    assert!(!accepts_value("a".repeat(21).as_str()));
    // No letter → a numeric id or shapeless token, not a gaming handle.
    assert!(!accepts_value("12345"));
    assert!(!accepts_value("____"));
    // Illegal characters for either platform's handle.
    assert!(!accepts_value("with space"));
    assert!(!accepts_value("dot.name"));
}

#[test]
fn pick_exact_roblox_is_case_insensitive_exact() {
    let data = vec![
        RobloxUserStub {
            id: 1,
            name: "Roblox".into(),
            display_name: "Roblox".into(),
            has_verified_badge: true,
        },
        RobloxUserStub {
            id: 2,
            name: "RobloxDev".into(),
            display_name: "RobloxDev".into(),
            has_verified_badge: false,
        },
    ];
    // Case-insensitive exact match wins.
    let hit = pick_exact_roblox(&data, "roblox").expect("exact match");
    assert_eq!(hit.id, 1);
    // A different handle that merely shares the root must not match — the
    // resolver is exact, never a substring.
    assert!(pick_exact_roblox(&data, "Rob").is_none());
    assert!(pick_exact_roblox(&data, "RobloxDeveloper").is_none());
}

#[test]
fn dash_uuid_formats_32_hex_only() {
    assert_eq!(
        dash_uuid("069a79f444e94726a5befca90e38aaf5").as_deref(),
        Some("069a79f4-44e9-4726-a5be-fca90e38aaf5")
    );
    // Wrong length / non-hex → None (caller falls back to the raw string).
    assert_eq!(dash_uuid("069a79f4"), None);
    assert_eq!(dash_uuid("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"), None);
}

#[test]
fn is_free_social_module() {
    let m = GamingProfile;
    assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    assert_eq!(m.category(), ModuleCategory::Social);
    // ATT&CK is the Social-category default; the architecture guard requires it
    // to be a non-empty, in-register set.
    assert!(!m.attack_techniques().is_empty());
    // Documented outputs are the profile handle and its profile URL.
    assert!(m.produces().contains(&EntityKind::Username));
    assert!(m.produces().contains(&EntityKind::Url));
}

/// Live end-to-end proof against the REAL public Roblox + Mojang APIs — no
/// mock, no fixture. Ignored by default (network + non-deterministic upstream);
/// run with
/// `cargo test -p huntsman-search-engine gaming_profile_live -- --ignored --nocapture`.
/// Asserts the module fetches and parses genuine profile data and attributes
/// only the exact-handle account.
#[tokio::test]
#[ignore = "hits the live public Roblox + Mojang APIs; run manually"]
async fn gaming_profile_live_resolves_real_accounts() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };

    // Roblox account id 1 is the canonical "Roblox" handle — a stable live hit.
    let (roblox, roblox_failure) = roblox_lookup(&ctx, "Roblox").await;
    assert!(roblox_failure.is_none(), "a live resolve must not hard-fail");
    assert!(
        roblox.iter().any(|e| e.kind == EntityKind::Username
            && e.value.eq_ignore_ascii_case("Roblox")
            && e.has_tag("roblox")),
        "expected a roblox-tagged Username entity for the exact handle"
    );
    assert!(
        roblox
            .iter()
            .any(|e| e.kind == EntityKind::Url && e.value.contains("roblox.com/users/1/")),
        "expected the first-party Roblox profile URL"
    );

    // "Notch" is the canonical original Minecraft account — a stable live hit.
    let (minecraft, minecraft_failure) = minecraft_lookup(&ctx, "Notch").await;
    assert!(minecraft_failure.is_none(), "a live resolve must not hard-fail");
    assert!(
        minecraft.iter().any(|e| e.kind == EntityKind::Username
            && e.value.eq_ignore_ascii_case("Notch")
            && e.has_tag("minecraft")),
        "expected a minecraft-tagged Username entity for the exact handle"
    );

    eprintln!(
        "gaming_profile live: roblox={} entities, minecraft={} entities",
        roblox.len(),
        minecraft.len()
    );
}

// -- roblox_lookup_at / minecraft_lookup_at failure contract (T2.157) -------

/// One-shot local HTTP server answering with `status` + `body`. Mirrors the
/// pgp / sanctions_ofac / app_links / au_seifa test pattern.
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
async fn roblox_lookup_surfaces_transport_failure_as_error() {
    // T2.157 regression: the primary exact-username resolve's transport/
    // status/parse failure previously collapsed into a bare empty Vec,
    // indistinguishable from a genuine "no such Roblox handle". Port 1:
    // connection refused.
    let ctx = test_ctx();
    let (entities, failure) = roblox_lookup_at(&ctx, "someuser", "http://127.0.0.1:1").await;
    assert!(entities.is_empty());
    assert!(
        failure.is_some(),
        "an unreachable Roblox host must report a hard failure, not a silent empty batch"
    );
}

#[tokio::test]
async fn roblox_lookup_surfaces_a_5xx_as_error() {
    let addr = serve_once(503, "upstream down").await;
    let ctx = test_ctx();
    let (entities, failure) =
        roblox_lookup_at(&ctx, "someuser", &format!("http://{addr}")).await;
    assert!(entities.is_empty());
    assert!(failure.is_some(), "a 5xx must report a hard failure");
}

#[tokio::test]
async fn roblox_lookup_keeps_the_genuine_no_match_as_a_clean_miss() {
    // The genuine negative must be preserved: a 200 with `{"data":[]}` is
    // Roblox's real "no such handle" answer, never a failure.
    let addr = serve_once(200, r#"{"data":[]}"#).await;
    let ctx = test_ctx();
    let (entities, failure) =
        roblox_lookup_at(&ctx, "someuser", &format!("http://{addr}")).await;
    assert!(entities.is_empty());
    assert!(
        failure.is_none(),
        "a genuine empty-data resolve must stay a clean miss, not a hard failure"
    );
}

#[tokio::test]
async fn minecraft_lookup_surfaces_transport_failure_as_error() {
    let ctx = test_ctx();
    let (entities, failure) = minecraft_lookup_at(&ctx, "someuser", "http://127.0.0.1:1").await;
    assert!(entities.is_empty());
    assert!(
        failure.is_some(),
        "an unreachable Mojang host must report a hard failure, not a silent empty batch"
    );
}

#[tokio::test]
async fn minecraft_lookup_surfaces_a_5xx_as_error() {
    let addr = serve_once(503, "upstream down").await;
    let ctx = test_ctx();
    let (entities, failure) =
        minecraft_lookup_at(&ctx, "someuser", &format!("http://{addr}")).await;
    assert!(entities.is_empty());
    assert!(failure.is_some(), "a 5xx must report a hard failure");
}

#[tokio::test]
async fn minecraft_lookup_keeps_a_404_as_the_clean_no_account_miss() {
    // Mojang's real "no such Java account" answer is a 404 — must stay a
    // clean miss, never a hard failure.
    let addr = serve_once(404, "not found").await;
    let ctx = test_ctx();
    let (entities, failure) =
        minecraft_lookup_at(&ctx, "someuser", &format!("http://{addr}")).await;
    assert!(entities.is_empty());
    assert!(
        failure.is_none(),
        "a genuine 404 must stay a clean miss, not a hard failure"
    );
}
