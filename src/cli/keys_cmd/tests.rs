
use super::{bank_row, char_prefix, mask_key};

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
            verified_count: 0,
            last_verified_at: None,
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
    fn bank_row_shows_verified_duplicate_count_when_proven_live() {
        let mut e = vault_entry("shodan", "AKIAIOSFODNN7EXAMPLE", 3);
        // Unverified: a dash, never a phantom tick.
        assert!(bank_row(&e, false).contains(" - "), "unverified shows '-'");
        e.verified_count = 2;
        e.last_verified_at = Some(123);
        let row = bank_row(&e, false);
        assert!(e.is_verified());
        assert!(row.contains("✓×2"), "verified-duplicate count shown: {row}");
    }

    #[test]
    fn bank_row_infra_key_not_starred_and_reveal_shows_full() {
        let row = bank_row(&vault_entry("aws_access_key", "AKIAIOSFODNN7EXAMPLE", 1), true);
        assert!(!row.contains('★'), "infra provider not starred: {row}");
        assert!(row.contains("infrastructure"));
        assert!(row.contains("AKIAIOSFODNN7EXAMPLE"), "--reveal shows full key");
    }

    #[test]
    fn mask_key_short_value_returned_verbatim() {
        assert_eq!(mask_key(""), "");
        assert_eq!(mask_key("abc"), "abc");
        assert_eq!(mask_key("abcdefgh"), "abcdefgh");
    }

    #[test]
    fn mask_key_long_value_truncates() {
        assert_eq!(mask_key("AKIAIOSFODNN7EXAMPLE"), "AKIA…MPLE");
    }

    #[test]
    fn mask_key_handles_multibyte_chars() {
        // Pre-fix this byte-indexed `&v[..4]`/`&v[len-4..]` would panic
        // for a value whose 4th byte falls inside a multi-byte char.
        let v = "𝕊éCRet𝕊éCRet"; // 12 chars, 22 bytes
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
