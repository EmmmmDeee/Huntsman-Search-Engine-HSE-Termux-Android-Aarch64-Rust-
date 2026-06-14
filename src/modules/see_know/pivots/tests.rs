use super::*;
    use crate::core::entity::Entity;

    #[test]
    fn looks_like_discord_id_strict_heuristic() {
        // 17–20 digits, no leading zero.
        assert!(looks_like_discord_id("12345678901234567"));
        assert!(looks_like_discord_id("12345678901234567890"));
        // Too short, too long, leading-zero, non-digit — all reject.
        assert!(!looks_like_discord_id("1234567890123456")); // 16 digits
        assert!(!looks_like_discord_id("123456789012345678901")); // 21 digits
        assert!(!looks_like_discord_id("0123456789012345678")); // leading zero
        assert!(!looks_like_discord_id("alice1234567890"));
        assert!(!looks_like_discord_id(""));
    }

    #[test]
    fn discover_discord_pivots_extracts_unique_ids() {
        let mut r = ModuleResult::new();
        r.push(Entity::new(
            EntityKind::Username,
            "discord:359023095012345678",
            0.6,
            "test",
        ));
        // Duplicate ID — must be deduplicated.
        r.push(Entity::new(
            EntityKind::Username,
            "discord:359023095012345678",
            0.6,
            "test",
        ));
        // Non-Discord username — must be skipped.
        r.push(Entity::new(EntityKind::Username, "alice", 0.7, "test"));
        // Non-Username entity with `discord:` prefix — must be skipped.
        r.push(Entity::new(
            EntityKind::Email,
            "discord:foo@bar",
            0.5,
            "test",
        ));
        let ids = discover_discord_pivots(&r);
        assert_eq!(ids, vec!["359023095012345678".to_string()]);
    }

    #[test]
    fn looks_like_steam_id_strict_heuristic() {
        // Exactly 17 digits, no leading zero.
        assert!(looks_like_steam_id("76561198000000000"));
        assert!(looks_like_steam_id("76561198123456789"));
        // 16 / 18 digits, leading-zero, non-digit — all reject.
        assert!(!looks_like_steam_id("7656119800000000")); // 16
        assert!(!looks_like_steam_id("765611980000000000")); // 18
        assert!(!looks_like_steam_id("07561198000000000")); // leading zero
        assert!(!looks_like_steam_id("765611x8000000000"));
        assert!(!looks_like_steam_id(""));
    }

    #[test]
    fn discover_steam_pivots_extracts_unique_ids() {
        let mut r = ModuleResult::new();
        r.push(Entity::new(
            EntityKind::Username,
            "steam:76561198000000000",
            0.6,
            "test",
        ));
        r.push(Entity::new(
            EntityKind::Username,
            "steam:76561198000000000",
            0.6,
            "test",
        ));
        // Mixed-in discord entity — must be ignored by the steam
        // pivot collector.
        r.push(Entity::new(
            EntityKind::Username,
            "discord:359023095012345678",
            0.6,
            "test",
        ));
        let ids = discover_steam_pivots(&r);
        assert_eq!(ids, vec!["76561198000000000".to_string()]);
    }
