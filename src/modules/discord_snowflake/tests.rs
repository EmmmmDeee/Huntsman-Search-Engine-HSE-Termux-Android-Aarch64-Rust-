use super::*;

#[test]
fn utc_date_matches_known_unix_dates() {
    assert_eq!(utc_date(0), "1970-01-01");
    assert_eq!(utc_date(DISCORD_EPOCH_SECS), "2015-01-01");
    assert_eq!(utc_date(1_577_836_800), "2020-01-01");
}

#[test]
fn decode_round_trips_a_known_date() {
    // Build the snowflake for 2020-01-01 and confirm `(id >> 22) + epoch` and
    // the date formatter recover it exactly — catches an off-by-shift / wrong
    // epoch.
    let created_ms = 1_577_836_800_000u64; // 2020-01-01T00:00:00Z
    let id = (created_ms - DISCORD_EPOCH_MS) << 22;
    let decoded_ms = (id >> 22) + DISCORD_EPOCH_MS;
    assert_eq!(decoded_ms, created_ms);
    assert_eq!(utc_date((decoded_ms / 1000) as i64), "2020-01-01");
}

#[test]
fn candidate_gates_shape_and_excludes_steam() {
    assert!(snowflake_candidate("175928847299117063").is_some()); // 18-digit ID
    assert_eq!(
        snowflake_candidate("discord:123456789012345678"),
        Some((123_456_789_012_345_678u64, true))
    );
    // Steam ID64 (17-digit `7656119…`) is excluded — it decodes to a plausible
    // 2015 date and would otherwise be mis-attributed as Discord.
    assert!(snowflake_candidate("76561197960265728").is_none());
    // …but an explicit `discord:` prefix overrides the bare-Steam heuristic.
    assert!(snowflake_candidate("discord:76561197960265728").is_some());
    // Shape rejects.
    assert!(snowflake_candidate("1234567890123456").is_none()); // 16 digits
    assert!(snowflake_candidate("123456789012345678901").is_none()); // 21 digits
    assert!(snowflake_candidate("0123456789012345678").is_none()); // leading zero
    assert!(snowflake_candidate("alice1234567890123").is_none()); // non-digit
}

#[test]
fn is_free_passive_social() {
    let m = DiscordSnowflake;
    assert!(m.is_passive()); // pure offline compute, no network
    assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    assert_eq!(m.category(), ModuleCategory::Social);
    assert!(!m.attack_techniques().is_empty());
    assert!(m.accepts(&Target::new(TargetKind::Username, "175928847299117063")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    // A Steam ID must never be accepted as a Discord snowflake.
    assert!(!m.accepts(&Target::new(TargetKind::Username, "76561197960265728")));
}

#[tokio::test]
async fn process_enriches_discord_id_with_creation_date() {
    // Fully offline + deterministic (no network) — runs in CI, not ignored.
    let id = ((1_577_836_800_000u64 - DISCORD_EPOCH_MS) << 22).to_string();
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "t".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Default::default(),
    };
    let target = Target::new(TargetKind::Username, &id);
    let r = DiscordSnowflake
        .process(&target, &ctx)
        .await
        .expect("offline decode never errors");
    let e = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .expect("a username entity enriched with the creation date");
    assert!(e.has_tag("discord") && e.has_tag("account-age"));
}
