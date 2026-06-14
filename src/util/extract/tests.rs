use super::*;

    #[test]
    fn matches_standard_address_shapes() {
        for ok in [
            "alice@example.com",
            "bob.smith+tag@sub.example.co.uk",
            "a@b.io",
            "with%percent@example.com",
        ] {
            assert!(EMAIL_RE.is_match(ok), "should match: {ok}");
        }
    }

    #[test]
    fn rejects_non_addresses() {
        for no in ["@example.com", "user@host", "user@host.123", "plainword"] {
            assert!(!EMAIL_RE.is_match(no), "should NOT match: {no}");
        }
    }

    #[test]
    fn extracts_and_lowercases_dedupes() {
        assert_eq!(emails("contact alice@example.com"), ["alice@example.com"]);
        let text = "Ping Alice@Example.COM and alice@example.com";
        assert_eq!(emails(text), ["alice@example.com"]);
    }

    #[test]
    fn phones_extracts_e164() {
        assert_eq!(phones("+61412345678"), ["+61412345678"]);
        assert_eq!(phones("call +1 (555) 123-4567"), ["+15551234567"]);
        assert!(phones("5551234567").is_empty());
    }

    #[test]
    fn page_emails_drops_asset_refs() {
        assert!(page_emails("logo@2x.png").is_empty());
        assert_eq!(page_emails("bob@example.com"), ["bob@example.com"]);
    }
