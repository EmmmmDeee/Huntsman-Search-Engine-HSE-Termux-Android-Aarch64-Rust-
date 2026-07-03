use super::*;
    use crate::util::key_roi::KeyRoi;

    #[test]
    fn loaded_huntsman_keys_are_sorted_regardless_of_insertion_order() {
        // `loaded` is a HashMap, so an unsorted read would print the keys in a
        // different order on every `hse doctor` invocation against the
        // identical environment — the same determinism bug class
        // `rank_unset_keys` already guards against for the unset-keys listing.
        // Build the map via two different insertion orders and assert both
        // produce the identical sorted output.
        let mut a = std::collections::HashMap::new();
        a.insert("HUNTSMAN_WIGLE_TOKEN".to_string(), "x".to_string());
        a.insert("HUNTSMAN_HIBP_KEY".to_string(), "x".to_string());
        a.insert("HUNTSMAN_ONYPHE_KEY".to_string(), "x".to_string());
        // A non-HUNTSMAN_ key must be filtered out regardless of ordering.
        a.insert("HOME".to_string(), "/root".to_string());

        let mut b = std::collections::HashMap::new();
        b.insert("HUNTSMAN_ONYPHE_KEY".to_string(), "x".to_string());
        b.insert("HOME".to_string(), "/root".to_string());
        b.insert("HUNTSMAN_HIBP_KEY".to_string(), "x".to_string());
        b.insert("HUNTSMAN_WIGLE_TOKEN".to_string(), "x".to_string());

        let expected = vec!["HUNTSMAN_HIBP_KEY", "HUNTSMAN_ONYPHE_KEY", "HUNTSMAN_WIGLE_TOKEN"];
        assert_eq!(sorted_huntsman_keys(&a), expected);
        assert_eq!(sorted_huntsman_keys(&b), expected);
    }

    #[test]
    fn unset_keys_rank_multiplier_first_then_name() {
        // Nothing configured → every KNOWN_KEY is unset and ranked.
        let ranked = rank_unset_keys(|_| false);
        assert_eq!(ranked.len(), keys::KNOWN_KEYS.len());

        // Tiers are non-increasing across the whole list (Multiplier block,
        // then Expansion, then Terminal — never a higher tier after a lower).
        for w in ranked.windows(2) {
            assert!(
                w[0].1 >= w[1].1,
                "ROI must be non-increasing: {:?} ({:?}) before {:?} ({:?})",
                w[0].0,
                w[0].1,
                w[1].0,
                w[1].1
            );
        }
        // Within a tier, names are ascending.
        for w in ranked.windows(2) {
            if w[0].1 == w[1].1 {
                assert!(w[0].0 < w[1].0, "within-tier ties sort by name");
            }
        }

        // A known multiplier (Shodan) must outrank a known terminal
        // (IP2Location) — the whole point of the ranking.
        let pos = |env: &str| ranked.iter().position(|(k, _)| *k == env);
        if let (Some(shodan), Some(ip2)) =
            (pos("HUNTSMAN_SHODAN_KEY"), pos("HUNTSMAN_IP2LOCATION_KEY"))
        {
            assert!(
                shodan < ip2,
                "multiplier Shodan must precede terminal IP2Location"
            );
        }
        // The first entry is multiplier-tier (there are several).
        assert_eq!(ranked[0].1, KeyRoi::Multiplier);
    }

    #[test]
    fn present_keys_are_excluded_from_the_ranking() {
        let first = keys::KNOWN_KEYS[0];
        let ranked = rank_unset_keys(|k| k == first);
        assert!(
            !ranked.iter().any(|(k, _)| *k == first),
            "a configured key must not appear in the unset ranking"
        );
        assert_eq!(ranked.len(), keys::KNOWN_KEYS.len() - 1);
    }
