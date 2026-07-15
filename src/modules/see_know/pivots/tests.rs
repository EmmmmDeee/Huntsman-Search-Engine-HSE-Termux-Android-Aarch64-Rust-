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

    #[test]
    fn discover_discord_pivots_ignores_non_username_entities() {
        let mut r = ModuleResult::new();
        // Email entity with discord: prefix — must be skipped (wrong kind)
        r.push(Entity::new(EntityKind::Email, "discord:359023095012345678", 0.6, "test"));
        // Domain entity — must be skipped
        r.push(Entity::new(EntityKind::Domain, "discord.com", 0.6, "test"));
        assert!(discover_discord_pivots(&r).is_empty());
    }

    #[test]
    fn discover_steam_pivots_returns_empty_for_no_steam_entities() {
        let mut r = ModuleResult::new();
        r.push(Entity::new(EntityKind::Username, "discord:359023095012345678", 0.7, "test"));
        assert!(discover_steam_pivots(&r).is_empty());
    }

    fn ids(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("id{i}")).collect()
    }

    #[test]
    fn discord_attempt_slice_budget_one_attempts_only_the_first_id_partially() {
        // Budget=1: the first id's `discord_user` call fits, but there's no
        // slot left for its `discord_to_roblox` call, and no other id is
        // even started — exactly one id counts as "attempted".
        assert_eq!(discord_attempt_slice(&ids(3), 1), ["id0"]);
    }

    #[test]
    fn discord_attempt_slice_budget_two_attempts_only_the_first_id_fully() {
        // Budget=2: the first id consumes both its slots; the budget is
        // exhausted before a second id can even start.
        assert_eq!(discord_attempt_slice(&ids(3), 2), ["id0"]);
    }

    #[test]
    fn discord_attempt_slice_budget_three_attempts_two_ids() {
        // Budget=3: id0 takes both slots (2), id1 gets only its first slot
        // (1) before the budget runs out — two ids attempted.
        assert_eq!(discord_attempt_slice(&ids(4), 3), ["id0", "id1"]);
    }

    #[test]
    fn discord_attempt_slice_ample_budget_attempts_every_id() {
        assert_eq!(discord_attempt_slice(&ids(5), 100), ids(5).as_slice());
    }

    #[test]
    fn discord_attempt_slice_zero_budget_attempts_nothing() {
        assert!(discord_attempt_slice(&ids(3), 0).is_empty());
    }

    #[test]
    fn steam_attempt_slice_truncates_to_exactly_the_budget() {
        assert_eq!(steam_attempt_slice(&ids(5), 2), ["id0", "id1"]);
        assert_eq!(steam_attempt_slice(&ids(5), 100), ids(5).as_slice());
        assert!(steam_attempt_slice(&ids(5), 0).is_empty());
    }
