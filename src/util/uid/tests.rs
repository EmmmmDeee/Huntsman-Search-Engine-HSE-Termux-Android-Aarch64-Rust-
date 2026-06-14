use super::*;

    #[test]
    fn scan_id_is_64_hex_chars() {
        let id = scan_id("email", "x@y.com");
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
