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

    // ── /stats budget registry: no-silent-drift guard ───────────────────

    /// Every provider registered in `budget_providers()` MUST be surfaced in the
    /// rendered `/stats` budget section. This is the project's standard
    /// no-silent-drift guard: a new `QuotaBudget`-backed provider added to the
    /// registry but accidentally dropped from the render (or a render that stops
    /// honouring the dotted-nesting convention) fails here rather than silently
    /// vanishing from operator-facing quota telemetry.
    #[test]
    fn stats_surfaces_every_budget_provider() {
        let rendered = super::stats_budget_map();
        for (name, _snapshot) in super::budget_providers() {
            // Resolve the (possibly one-level-nested) name against the rendered
            // map and assert the full five-field budget block is present.
            let block = match name.split_once('.') {
                Some((parent, child)) => rendered
                    .get(parent)
                    .and_then(serde_json::Value::as_object)
                    .and_then(|o| o.get(child)),
                None => rendered.get(name),
            }
            .unwrap_or_else(|| panic!("/stats must surface budget provider `{name}`"));
            for field in [
                "scan_used",
                "scan_cap",
                "session_used",
                "session_cap",
                "quota_exhausted",
            ] {
                assert!(
                    block.get(field).is_some(),
                    "provider `{name}` block missing field `{field}`"
                );
            }
        }
        // WiGLE's out-of-band account status is folded into its block; assert the
        // asymmetry stays contained (and surfaced) rather than rotting away.
        let account = rendered
            .get("wigle")
            .and_then(serde_json::Value::as_object)
            .and_then(|o| o.get("account"))
            .expect("wigle block must carry its account status");
        for field in ["verified", "user", "last_polled_ts"] {
            assert!(
                account.get(field).is_some(),
                "wigle.account missing field `{field}`"
            );
        }
    }

    /// The dotted-name renderer nests exactly one level: a flat name stays at the
    /// top, `a.b` lands at `map["a"]["b"]`, and two dotted entries sharing a
    /// parent merge into one object (not clobber).
    #[test]
    fn insert_budget_nests_one_level() {
        let mut map = serde_json::Map::new();
        super::insert_budget(&mut map, "flat", serde_json::json!({"k": 1}));
        super::insert_budget(&mut map, "parent.first", serde_json::json!({"k": 2}));
        super::insert_budget(&mut map, "parent.second", serde_json::json!({"k": 3}));
        assert_eq!(map.get("flat").and_then(|v| v.get("k")), Some(&1.into()));
        let parent = map
            .get("parent")
            .and_then(serde_json::Value::as_object)
            .expect("parent must be an object");
        assert_eq!(parent.get("first").and_then(|v| v.get("k")), Some(&2.into()));
        assert_eq!(parent.get("second").and_then(|v| v.get("k")), Some(&3.into()));
    }

    // ── Cross-scan loopback gate (entity_get / search_entities) ──────────

    /// `loopback_only` allows loopback and absent peers, refuses a non-loopback
    /// peer — the cross-scan exfiltration gate the two cross-scan reads share.
    #[test]
    fn loopback_only_gates_non_loopback_peer() {
        use std::net::SocketAddr;
        // Absent connect-info → allowed (unit-test / untrusted-bootstrap path).
        assert!(super::loopback_only(None, "x").is_none());
        // Loopback peer → allowed (the default loopback bind, a no-op gate).
        let lo: SocketAddr = "127.0.0.1:5555".parse().unwrap();
        assert!(super::loopback_only(Some(&lo), "x").is_none());
        let lo6: SocketAddr = "[::1]:5555".parse().unwrap();
        assert!(super::loopback_only(Some(&lo6), "x").is_none());
        // Non-loopback peer → 403 (the exfiltration case on a network bind).
        let lan: SocketAddr = "192.168.1.50:5555".parse().unwrap();
        let resp = super::loopback_only(Some(&lan), "x").expect("non-loopback must be refused");
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
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
