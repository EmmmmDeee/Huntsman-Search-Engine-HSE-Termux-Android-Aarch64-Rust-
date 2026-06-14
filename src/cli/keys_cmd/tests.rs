use super::*;

use super::{char_prefix, mask_key};

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
