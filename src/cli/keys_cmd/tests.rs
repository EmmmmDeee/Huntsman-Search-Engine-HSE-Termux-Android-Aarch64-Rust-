
use super::{bank_row, char_prefix, mask_key, run_tsv_import};

    fn vault_entry(service: &str, key: &str, count: u32) -> crate::util::key_vault::VaultEntry {
        crate::util::key_vault::VaultEntry {
            key_value: key.to_string(),
            service: service.to_string(),
            provider: "stealer_log".to_string(),
            first_scan_id: "s1".to_string(),
            last_scan_id: "s2".to_string(),
            discovery_count: count,
            first_seen_at: 0,
            last_seen_at: 0,
        }
    }

    #[test]
    fn bank_row_marks_osint_provider_and_masks_key() {
        let row = bank_row(&vault_entry("shodan", "AKIAIOSFODNN7EXAMPLE", 3), false);
        assert!(row.contains('★'), "OSINT provider is starred: {row}");
        assert!(row.contains("attack-surface"), "category shown: {row}");
        assert!(row.contains("shodan"));
        assert!(row.contains("AKIA…MPLE"), "key masked by default: {row}");
        assert!(row.contains("×3"), "discovery count shown: {row}");
        assert!(!row.contains("AKIAIOSFODNN7EXAMPLE"), "full key hidden");
    }

    #[test]
    fn bank_row_infra_key_not_starred_and_reveal_shows_full() {
        let row = bank_row(&vault_entry("aws_access_key", "AKIAIOSFODNN7EXAMPLE", 1), true);
        assert!(!row.contains('★'), "infra provider not starred: {row}");
        assert!(row.contains("infrastructure"));
        assert!(row.contains("AKIAIOSFODNN7EXAMPLE"), "--reveal shows full key");
    }

    #[test]
    fn mask_key_short_value_fully_masked() {
        // `mask_key` now delegates to the shared `< 16` full-mask policy — the
        // old `> 8` threshold used to return an 8-char (or shorter) value
        // completely UNMASKED, and revealed 8 of 9 chars for a 9-char key.
        assert_eq!(mask_key(""), "•");
        assert_eq!(mask_key("abc"), "•••");
        assert_eq!(mask_key("abcdefgh"), "••••••••");
        assert_eq!(mask_key("abcdefghijklmno"), "•".repeat(15)); // 15 chars
    }

    #[test]
    fn mask_key_long_value_truncates() {
        assert_eq!(mask_key("AKIAIOSFODNN7EXAMPLE"), "AKIA…MPLE");
    }

    #[test]
    fn mask_key_handles_multibyte_chars() {
        // Pre-fix this byte-indexed `&v[..4]`/`&v[len-4..]` would panic
        // for a value whose 4th byte falls inside a multi-byte char.
        let v = "𝕊éCRet𝕊éCRet𝕊éCRet"; // 18 chars (≥ 16, so head+tail applies), 33 bytes
        let m = mask_key(v);
        assert!(m.contains('…'));
        assert_eq!(m.chars().count(), 9);
    }

    #[test]
    fn char_prefix_byte_safe() {
        assert_eq!(char_prefix("abcdef", 4), "abcd");
        // Multi-byte safe: 𝕊 is 4 bytes, so byte-slicing at 1 would panic.
        assert_eq!(char_prefix("𝕊abc", 2), "𝕊a");
    }

    // A Shodan-shaped key (prefix `d0a2df`, min_len 32) — a poolable OSINT
    // service. Suffix mirrors the key_harvest test fixtures' high-entropy
    // alphanumeric padding so it clears the `is_likely_real_key` gate.
    const SHODAN_KEY: &str = "d0a2dfA1b2C3d4E5f6G7h8I9j0K1l2M3";
    // A 64-char hex blob with no vendor prefix — classifies as the
    // `generic_hex` catch-all, which carries no vendor identity and is
    // deliberately excluded from `is_poolable_service`'s allowlist.
    const GENERIC_HEX_KEY: &str =
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    fn tsv_row(source: &str, field: &str, value: &str) -> String {
        format!("{source}\t{field}\ttag\t{value}\tctx")
    }

    #[test]
    fn run_tsv_import_separates_nonpoolable_from_duplicates() {
        // A non-poolable classification (generic_hex — no vendor identity)
        // must be tallied as `skipped_nonpoolable`, not folded into
        // `skipped_dup`: `pool.add` rejects both for the same underlying
        // reason ("returned false"), but they are different situations an
        // operator needs to tell apart.
        let pool = crate::util::key_pool::KeyPool::new();
        let content = format!(
            "{}\n{}\n",
            tsv_row("dump1", "password", SHODAN_KEY),
            tsv_row("dump1", "password", GENERIC_HEX_KEY),
        );
        let summary = run_tsv_import(&content, "dump1.tsv", false, &pool);
        assert_eq!(summary.imported, 1, "only the poolable shodan key imports");
        assert_eq!(
            summary.skipped_nonpoolable, 1,
            "the generic_hex value must be tallied as non-poolable"
        );
        assert_eq!(
            summary.skipped_dup, 0,
            "a non-poolable rejection must NOT be counted as a duplicate: {summary:?}",
        );
    }

    #[test]
    fn run_tsv_import_tracks_only_this_calls_additions_for_validate() {
        // Two SEPARATE `import-tsv` invocations against the same pool (e.g.
        // an operator running the command on two different dump files at
        // different times). The second call's `imported_this_run` — what
        // `--validate` iterates — must contain ONLY the key the second call
        // itself added, never the first call's key too. The previous
        // implementation instead scanned the WHOLE pool filtered by a
        // `discovered_by` string comparison that (due to comparing the row's
        // own internal source label against the CLI file path) matched every
        // entry from any prior import, re-validating historical keys.
        let pool = crate::util::key_pool::KeyPool::new();
        let first = run_tsv_import(&tsv_row("dump1", "password", SHODAN_KEY), "dump1.tsv", false, &pool);
        assert_eq!(first.imported_this_run, vec![("shodan", SHODAN_KEY.to_string())]);

        // A second distinct poolable key from a different file/run.
        const HIBP_KEY: &str = "d0a2dfZ9y8X7w6V5u4T3s2R1q0P9o8N7";
        let second = run_tsv_import(
            &tsv_row("dump2", "password", HIBP_KEY),
            "dump2.tsv",
            false,
            &pool,
        );
        assert_eq!(
            second.imported_this_run,
            vec![("shodan", HIBP_KEY.to_string())],
            "the second call's tracked set must contain only what IT added, \
             not the first call's key too: {second:?}"
        );
        // Sanity: both keys really are in the pool now (2 total), proving the
        // scoping is about what's *reported*, not what's *persisted*.
        assert_eq!(pool.total_keys(), 2);
    }
