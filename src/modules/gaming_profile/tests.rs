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
    let roblox = roblox_lookup(&ctx, "Roblox").await;
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
    let minecraft = minecraft_lookup(&ctx, "Notch").await;
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
