use crate::api::scan_export::csv_escape;

    #[test]
    fn validated_target_accepts_good_and_prefixes_bad() {
        use super::validated_target;
        use crate::core::scan::TargetKind;
        let ok = validated_target(TargetKind::Domain, "cloudflare.com".to_string());
        assert!(ok.is_ok());
        assert_eq!(ok.unwrap().value, "cloudflare.com");
        let err = validated_target(TargetKind::Domain, "no-dot".to_string()).unwrap_err();
        assert!(
            err.starts_with("invalid target: "),
            "must carry client-facing prefix, got: {err}"
        );
    }

    #[test]
    fn aggregate_scan_stats_sums_counts_and_histograms_status() {
        use super::aggregate_scan_stats;
        use crate::core::scan::{Scan, ScanStatus, Target, TargetKind};

        let mk = |id: &str, status: ScanStatus, ents: usize, dedup: usize| {
            let mut s = Scan::new(id, Target::new(TargetKind::Email, "x@y.com"));
            s.status = status;
            s.entity_count = ents;
            s.modules_deduped = dedup;
            s
        };
        let scans = [
            mk("a", ScanStatus::Complete, 10, 2),
            mk("b", ScanStatus::Complete, 5, 1),
            mk("c", ScanStatus::Failed, 0, 0),
            mk("d", ScanStatus::Running, 3, 4),
        ];
        let agg = aggregate_scan_stats(&scans);
        assert_eq!(agg.total_entities, 18);
        assert_eq!(agg.total_deduped, 7);
        assert_eq!(agg.by_status.get("complete"), Some(&2));
        assert_eq!(agg.by_status.get("failed"), Some(&1));
        assert_eq!(agg.by_status.get("running"), Some(&1));
        assert_eq!(agg.by_status.get("pending"), None);

        // Empty input yields all-zero totals and an empty histogram.
        let empty = aggregate_scan_stats(&[]);
        assert_eq!(empty, super::ScanStatsAgg::default());
    }

    #[test]
    fn module_health_json_shapes_name_streak_and_last_success() {
        use super::module_health_json;
        use crate::core::engine::ModuleHealth;
        let unhealthy = vec![
            ModuleHealth {
                name: "hackertarget",
                consecutive_failures: 3,
                last_success_at: None,
            },
            ModuleHealth {
                name: "crtsh",
                consecutive_failures: 1,
                last_success_at: Some(1_700_000_000),
            },
        ];
        let v = module_health_json(&unhealthy);
        assert_eq!(v["count"], 2);
        let modules = v["modules"].as_array().unwrap();
        assert_eq!(modules[0]["name"], "hackertarget");
        assert_eq!(modules[0]["consecutive_failures"], 3);
        assert!(
            modules[0]["last_success_at"].is_null(),
            "never-succeeded module must serialise last_success_at as null"
        );
        assert_eq!(modules[1]["name"], "crtsh");
        assert_eq!(modules[1]["last_success_at"], 1_700_000_000);
    }

    #[test]
    fn module_health_json_is_empty_on_a_healthy_process() {
        use super::module_health_json;
        let v = module_health_json(&[]);
        assert_eq!(v["count"], 0);
        assert!(v["modules"].as_array().unwrap().is_empty());
    }

    #[test]
    fn capability_probe_json_tallies_outcomes_and_flags_canary_drift() {
        use super::capability_probe_json;
        use crate::core::scan::TargetKind;
        use crate::selftest::capability_probe::{ProbeOutcome, ProbeReport};
        // ip_geo is a curated canary → an empty parse is confirmed drift.
        // A non-canary empty is NOT drift. Alive/unreachable round out the tally.
        let reports = vec![
            ProbeReport {
                module: "ip_geo",
                kind: TargetKind::IpAddress,
                value: "8.8.8.8",
                outcome: ProbeOutcome::Empty,
            },
            ProbeReport {
                module: "certspotter",
                kind: TargetKind::Domain,
                value: "example.com",
                outcome: ProbeOutcome::Alive { found: 9 },
            },
            ProbeReport {
                module: "some_breach",
                kind: TargetKind::Email,
                value: "test@example.com",
                outcome: ProbeOutcome::Empty,
            },
            ProbeReport {
                module: "bgpview",
                kind: TargetKind::Asn,
                value: "AS15169",
                outcome: ProbeOutcome::Unreachable {
                    reason: "connect".into(),
                },
            },
        ];
        let v = capability_probe_json(&reports);
        assert_eq!(v["probed"], 4);
        assert_eq!(v["alive"], 1);
        assert_eq!(v["empty"], 2);
        assert_eq!(v["unreachable"], 1);
        // Only the ip_geo canary's empty is confirmed drift.
        assert_eq!(v["drift"].as_array().unwrap().len(), 1);
        assert_eq!(v["drift"][0], "ip_geo");
        let mods = v["modules"].as_array().unwrap();
        let ip_geo = mods.iter().find(|m| m["module"] == "ip_geo").unwrap();
        assert_eq!(ip_geo["canary"], true);
        assert_eq!(ip_geo["drift"], true);
        let breach = mods.iter().find(|m| m["module"] == "some_breach").unwrap();
        assert_eq!(breach["canary"], false);
        assert_eq!(breach["drift"], false);
        let cs = mods.iter().find(|m| m["module"] == "certspotter").unwrap();
        assert_eq!(cs["outcome"], "alive");
        assert_eq!(cs["found"], 9);
    }

    #[test]
    fn csv_escape_plain() {
        assert_eq!(csv_escape("hello"), "hello");
    }

    #[test]
    fn csv_escape_comma() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
    }

    #[test]
    fn csv_escape_quotes() {
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn csv_escape_newline() {
        assert_eq!(csv_escape("line1\nline2"), "\"line1\nline2\"");
    }

    #[test]
    fn csv_escape_cr() {
        assert_eq!(csv_escape("a\rb"), "\"a\rb\"");
    }

    #[test]
    fn csv_escape_empty() {
        assert_eq!(csv_escape(""), "");
    }

    // ── Formula-injection neutralization ─────────────────────────────

    #[test]
    fn csv_escape_neutralizes_excel_formula() {
        // Excel-style formula prefixes get a leading apostrophe
        // prepended so Excel/LibreOffice render the cell as text
        // instead of evaluating it. The apostrophe alone is enough —
        // outer quoting fires only when the body also carries CSV
        // metachars (comma, quote, CR, LF).
        assert_eq!(csv_escape("=cmd|/c calc"), "'=cmd|/c calc");
        assert_eq!(csv_escape("+1234"), "'+1234");
        assert_eq!(csv_escape("-SUM(A1:A2)"), "'-SUM(A1:A2)");
        assert_eq!(csv_escape("@evil"), "'@evil");
        // Tab and CR are also formula triggers in some spreadsheet
        // implementations. CR also forces outer quoting (CSV metachar).
        assert_eq!(csv_escape("\tHELLO"), "'\tHELLO");
        assert_eq!(csv_escape("\rDANGER"), "\"'\rDANGER\"");
    }

    #[test]
    fn csv_escape_formula_with_comma_quotes_outer() {
        // Leading `=` triggers the apostrophe guard, AND the embedded
        // comma forces outer double-quoting.
        assert_eq!(csv_escape("=A1,B2"), "\"'=A1,B2\"");
    }

    #[test]
    fn csv_escape_keeps_negative_numbers_safe_but_escaped() {
        // `-3.5` would be interpreted as a formula. Cell still
        // round-trips to the same number after the apostrophe is
        // stripped by spreadsheet apps.
        let r = csv_escape("-3.5");
        assert!(r.starts_with('\''));
    }

    #[test]
    fn csv_escape_does_not_alter_safe_leading_chars() {
        assert_eq!(csv_escape("hello"), "hello");
        assert_eq!(csv_escape("3 apples"), "3 apples");
        assert_eq!(csv_escape("Mr. Jones"), "Mr. Jones");
    }
