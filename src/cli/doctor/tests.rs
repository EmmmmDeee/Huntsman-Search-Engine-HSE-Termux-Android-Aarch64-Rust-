use super::*;
    use crate::util::key_roi::KeyRoi;

    #[test]
    fn curl_missing_message_names_every_curl_only_no_fallback_surface() {
        let msg = curl_missing_message();
        // The six curl-only (no reqwest path) modules.
        for name in [
            "search_engines",
            "social_probe",
            "see_know",
            "oathnet_pro",
            "api_key_probe",
            "abn_lookup",
        ] {
            assert!(msg.contains(name), "message must name {name}: {msg}");
        }
        // The two `hse keys` commands whose validation also shells out to curl
        // with no fallback — previously missing from this message entirely.
        assert!(msg.contains("hse keys validate"), "{msg}");
        assert!(msg.contains("hse keys import-tsv"), "{msg}");
        // `geocode` tries reqwest before ever falling back to curl, so its
        // absence only loses a fallback — it must NOT be listed here as if
        // curl's absence broke the module outright.
        assert!(
            !msg.contains("geocode"),
            "geocode has a reqwest fallback and must not be listed: {msg}"
        );
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
