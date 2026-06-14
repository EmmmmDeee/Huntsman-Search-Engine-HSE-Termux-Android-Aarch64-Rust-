use super::*;

use super::{source_family, text_mentions_ip};

    #[test]
    fn text_mentions_ip_is_whole_address_for_v4() {
        assert!(text_mentions_ip("seen at 1.2.3.4: Brisbane", "1.2.3.4"));
        assert!(text_mentions_ip("origin 1.2.3.4:8080", "1.2.3.4"));
        // Substring of a longer address must not match.
        assert!(!text_mentions_ip("host 11.2.3.45 responded", "1.2.3.4"));
        assert!(!text_mentions_ip("host 1.2.3.45 responded", "1.2.3.4"));
    }

    #[test]
    fn text_mentions_ip_is_whole_address_for_v6() {
        assert!(text_mentions_ip(
            "AAAA 2001:db8::1 for example.com",
            "2001:db8::1"
        ));
        // Bracketed-with-port spelling: ']' is a legitimate boundary.
        assert!(text_mentions_ip("via [2001:db8::1]:443", "2001:db8::1"));
        // Hex letters and ':' EXTEND a v6 address — these are different
        // addresses, and the v4-only boundary set falsely chained them.
        assert!(!text_mentions_ip("AAAA 2001:db8::1a for x", "2001:db8::1"));
        assert!(!text_mentions_ip("AAAA 2001:db8::12 for x", "2001:db8::1"));
        assert!(!text_mentions_ip("AAAA 2001:db8::1:2 for x", "2001:db8::1"));
        // Entity values are normalised lowercase; summaries may be uppercase.
        assert!(text_mentions_ip("AAAA 2001:DB8::1 for x", "2001:db8::1"));
    }

    #[test]
    fn source_family_covers_every_registered_coarse_geo_provider() {
        // The sibling providers of the already-listed ipinfo/ipquery/wigle —
        // these fell through to "other" and were excluded from cross-family
        // diversity counts, contrary to the classifier's stated intent.
        assert_eq!(source_family("ipapi"), "infra");
        assert_eq!(source_family("ip2location"), "infra");
        assert_eq!(source_family("mylnikov"), "infra");
    }
