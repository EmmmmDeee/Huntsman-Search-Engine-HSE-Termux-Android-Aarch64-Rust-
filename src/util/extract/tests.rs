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
    fn url_re_matches_scheme_and_stops_at_sentence_punctuation() {
        // The bio/profile cases reddit_user + hacker_news relied on: the match
        // over-runs the trailing '.' (callers trim it) and stops at the space.
        let m = URL_RE
            .find("site https://paulgraham.com/bio.html. and more")
            .unwrap();
        assert_eq!(
            m.as_str().trim_end_matches(['.', ',', ')']),
            "https://paulgraham.com/bio.html"
        );
        assert!(URL_RE.is_match("http://x.io/p"));
        assert!(!URL_RE.is_match("no scheme here example.com"));
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
    fn phones_deduplicates_same_number() {
        let text = "+61412345678 and again +61412345678";
        assert_eq!(phones(text), vec!["+61412345678"]);
    }

    #[test]
    fn page_emails_deduplicates_case_insensitive() {
        let text = "Contact Alice@Example.com or alice@example.com";
        assert_eq!(page_emails(text), vec!["alice@example.com"]);
    }

    #[test]
    fn page_emails_drops_asset_refs() {
        assert!(page_emails("logo@2x.png").is_empty());
        assert_eq!(page_emails("bob@example.com"), ["bob@example.com"]);
    }

    #[test]
    fn page_emails_drops_script_url_fragments() {
        // URL fragments glued to `@` during HTML stripping are not mailboxes
        // (the real-scan bug `viewtopic.phprose.cl@onet.eu`); a clean address in
        // the same text still extracts. Consolidated from search_engines.
        assert!(page_emails("see viewtopic.phprose.cl@onet.eu and index.html@x.com").is_empty());
        assert_eq!(
            page_emails("real person jane.doe@onet.eu posted"),
            ["jane.doe@onet.eu"]
        );
    }

    #[test]
    fn looks_like_email_rejects_provider_field_junk() {
        // Real addresses seen in the breach `email` fields for the Ali.kareem scan.
        for good in [
            "ali.kareem95@gmail.com",
            "alik.8972@yahoo.com",
            "dr.ali.ali52@gmail.com",
        ] {
            assert!(looks_like_email(good), "{good} is a real address");
        }
        // Junk a provider echoes/mangles into an `email` field — must not become an
        // Email entity (this is the see_know `contains('@')`-only gap, now closed).
        for junk in [
            "Ali.kareem",     // username echoed into the email field (snusbase)
            "ali.kareem",
            "user@",          // no host
            "@gmail.com",     // no local part
            "user@localhost", // host has no dot
            "a b@c.com",      // embedded whitespace
            "",
        ] {
            assert!(!looks_like_email(junk), "{junk:?} must be rejected");
        }
    }
