use super::*;
    use crate::secrets::key_roi::KeyRoi;

    #[test]
    fn seeknow_guidance_when_doh_retry_already_ran_and_failed() {
        // curl_client's real format when the DoH retry itself also failed:
        // "curl exited 6 (after DoH resolver fallback): <stderr snippet>".
        let detail = "curl exited 6 (after DoH resolver fallback): Could not resolve host";
        let msg = seeknow_unreachable_guidance(detail);
        assert!(
            msg.contains("already ran"),
            "must state the DoH retry was already attempted: {msg}"
        );
        assert!(
            !msg.contains("did not run"),
            "must not ALSO claim it didn't run: {msg}"
        );
    }

    #[test]
    fn seeknow_guidance_when_dns_failure_but_doh_disabled() {
        // A genuine exit-6 with NO doh-retry marker — only possible if
        // HUNTSMAN_DOH_URL disabled the automatic fallback (the code
        // unconditionally attempts it otherwise).
        let detail = "curl exited 6: Could not resolve host";
        let msg = seeknow_unreachable_guidance(detail);
        assert!(
            msg.contains("did not run"),
            "must state the retry did NOT run: {msg}"
        );
        assert!(
            !msg.contains("already ran"),
            "must not falsely claim a retry was attempted: {msg}"
        );
        assert!(
            msg.contains("HUNTSMAN_DOH_URL"),
            "must point at the env var that could have disabled it: {msg}"
        );
    }

    #[test]
    fn seeknow_guidance_when_not_a_dns_failure_at_all() {
        // A regression guard for the Copilot-flagged bug: a plain timeout
        // (exit 28) or connection-refused (exit 7) must NOT claim any DoH
        // retry was attempted — the fallback only ever triggers on exit 6.
        for detail in [
            "curl exited 28: Operation timed out",
            "curl exited 7: Failed to connect",
            "curl exited 60: SSL certificate problem",
        ] {
            let msg = seeknow_unreachable_guidance(detail);
            assert!(
                !msg.contains("DoH") || msg.contains("did not run"),
                "non-DNS failure ({detail}) must not claim an unqualified DoH attempt: {msg}"
            );
            assert!(
                !msg.contains("already ran"),
                "non-DNS failure ({detail}) must not claim the retry already ran: {msg}"
            );
        }
    }

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

    use crate::core::engine::ModuleHealth;

    #[test]
    fn module_health_line_names_the_module_and_streak() {
        let h = ModuleHealth {
            name: "hackertarget",
            consecutive_failures: 3,
            last_success_at: None,
        };
        let line = format_module_health(&h);
        assert!(line.contains("hackertarget"));
        assert!(line.contains('3'));
        assert!(line.contains("never succeeded this process"));
    }

    #[test]
    fn module_health_line_singular_for_one_failure() {
        let h = ModuleHealth {
            name: "crtsh",
            consecutive_failures: 1,
            last_success_at: None,
        };
        assert!(
            format_module_health(&h).contains("1 consecutive failure "),
            "must not pluralize a single failure"
        );
    }

    #[test]
    fn module_health_line_reports_last_success_time_when_present() {
        let h = ModuleHealth {
            name: "urlscan",
            consecutive_failures: 2,
            last_success_at: Some(1_700_000_000),
        };
        let line = format_module_health(&h);
        assert!(line.contains("last succeeded"));
        assert!(!line.contains("never succeeded"));
        assert!(line.contains("20231114T221320Z"));
    }

    #[test]
    fn format_weak_findings_empty_is_a_clean_no_op_message() {
        let out = format_weak_findings(&[]);
        assert!(out.contains("no weak findings"), "{out}");
    }

    #[test]
    fn format_weak_findings_lists_each_anomaly_weakest_first() {
        let anomalies = vec![
            EvidenceAnomaly {
                entity_uid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
                module_name: "username_search".to_string(),
                confidence: 0.20,
                created_at: 0,
            },
            EvidenceAnomaly {
                entity_uid: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
                module_name: "name_intel".to_string(),
                confidence: 0.25,
                created_at: 0,
            },
        ];
        let out = format_weak_findings(&anomalies);
        assert!(out.contains("2 weak finding"), "{out}");
        assert!(out.contains("username_search"), "{out}");
        assert!(out.contains("name_intel"), "{out}");
        assert!(out.contains("0.20"), "{out}");
        assert!(out.contains("0.25"), "{out}");
        // Never the full 64-char uid — the truncated cross-reference form only.
        assert!(!out.contains(&anomalies[0].entity_uid), "{out}");
        assert!(out.contains(&anomalies[0].entity_uid[..12]), "{out}");
    }

    #[test]
    fn format_weak_findings_caps_the_printed_list_and_notes_the_remainder() {
        let anomalies: Vec<EvidenceAnomaly> = (0..25)
            .map(|i| EvidenceAnomaly {
                entity_uid: format!("{i:064}"),
                module_name: "search_engines".to_string(),
                confidence: 0.10 + (i as f64) * 0.001,
                created_at: 0,
            })
            .collect();
        let out = format_weak_findings(&anomalies);
        assert_eq!(out.matches("conf=").count(), 20, "must cap the printed rows at 20: {out}");
        assert!(out.contains("… and 5 more"), "{out}");
    }
