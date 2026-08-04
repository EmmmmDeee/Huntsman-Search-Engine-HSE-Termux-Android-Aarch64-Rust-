use super::*;
    use crate::util::key_roi::KeyRoi;

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
    fn format_weak_findings_caps_one_modules_rows_and_notes_the_remainder() {
        let anomalies: Vec<EvidenceAnomaly> = (0..25)
            .map(|i| EvidenceAnomaly {
                entity_uid: format!("{i:064}"),
                module_name: "search_engines".to_string(),
                confidence: 0.10 + (i as f64) * 0.001,
                created_at: 0,
            })
            .collect();
        let out = format_weak_findings(&anomalies);
        // A single module gets at most PER_MODULE rows, not the whole budget.
        assert_eq!(
            out.matches("conf=").count(),
            3,
            "one module must not consume the whole sample: {out}"
        );
        assert!(out.contains("… and 22 more"), "{out}");
        // The full count is still stated, both in the header and per module.
        assert!(out.contains("25 weak finding"), "{out}");
        assert!(out.contains("search_engines 25"), "{out}");
    }

    /// The reported production shape: one module emitting thousands of findings
    /// at its flat floor, and a handful of genuinely interesting ones above it.
    ///
    /// Before the per-module cap, the list was sorted weakest-first and truncated
    /// at 20 — and 0.20 is the lowest confidence any module routinely emits, so
    /// every printed row was the same module at the same confidence and the rows
    /// this section exists to surface were unreachable. An operator saw 20
    /// identical lines and "… and 1326 more".
    #[test]
    fn a_flat_floor_module_cannot_crowd_out_every_other_module() {
        let mut anomalies: Vec<EvidenceAnomaly> = (0..1340)
            .map(|i| EvidenceAnomaly {
                entity_uid: format!("{i:064}"),
                module_name: "name_intel".to_string(),
                confidence: 0.20,
                created_at: 0,
            })
            .collect();
        // The entities the section is FOR: a breach-pool near-miss and a
        // demoted registry hit, both above the flood's floor.
        anomalies.push(EvidenceAnomaly {
            entity_uid: format!("{:064}", 9001),
            module_name: "breach_pool".to_string(),
            confidence: 0.25,
            created_at: 0,
        });
        anomalies.push(EvidenceAnomaly {
            entity_uid: format!("{:064}", 9002),
            module_name: "asic_persons".to_string(),
            confidence: 0.28,
            created_at: 0,
        });
        // Weakest-first, as the store returns them.
        anomalies.sort_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap());

        let out = format_weak_findings(&anomalies);
        assert!(
            out.contains("breach_pool") && out.contains("asic_persons"),
            "the findings worth reviewing must be reachable: {out}"
        );
        assert_eq!(
            out.matches("conf=0.20").count(),
            3,
            "the flood is capped at PER_MODULE rows: {out}"
        );
        // And its scale is stated as a number rather than implied by repetition.
        assert!(out.contains("name_intel 1340"), "{out}");
    }
