use crate::app::export::csv_escape;

    #[test]
    fn reject_non_loopback_allows_loopback_and_refuses_everything_else() {
        use super::reject_non_loopback;
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let peer = SocketAddr::new(ip, 8080);
            assert!(
                reject_non_loopback(&peer, "x is loopback-only").is_none(),
                "{ip} must be allowed"
            );
        }

        for ip in [
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        ] {
            let peer = SocketAddr::new(ip, 8080);
            let rejection = reject_non_loopback(&peer, "x is loopback-only")
                .expect("non-loopback peer must be rejected");
            assert_eq!(rejection.status(), axum::http::StatusCode::FORBIDDEN);
        }
    }

    #[test]
    fn validated_target_accepts_good_and_prefixes_bad() {
        use super::validated_target;
        use crate::core::scan::TargetKind;
        let ok = validated_target(TargetKind::Domain, "cloudflare.com".to_string());
        assert!(ok.is_ok());
        assert_eq!(ok.expect("should succeed").value, "cloudflare.com");
        let err = validated_target(TargetKind::Domain, "no-dot".to_string()).expect_err("should be an error");
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
        // "d" is running AND this process holds its handle: genuinely in flight.
        let in_flight: std::collections::HashSet<String> = ["d".to_string()].into();
        let agg = aggregate_scan_stats(&scans, &in_flight);
        assert_eq!(agg.total_entities, 18);
        assert_eq!(agg.total_deduped, 7);
        assert_eq!(agg.by_status.get("complete"), Some(&2));
        assert_eq!(agg.by_status.get("failed"), Some(&1));
        assert_eq!(agg.by_status.get("running"), Some(&1));
        assert_eq!(agg.by_status.get("interrupted"), None);
        assert_eq!(agg.by_status.get("pending"), None);

        // Empty input yields all-zero totals and an empty histogram.
        let empty = aggregate_scan_stats(&[], &in_flight);
        assert_eq!(empty, super::ScanStatsAgg::default());
    }

    /// REQ-SCANSTATUS-001: the same `running` row with NO handle in this
    /// process is a scan nobody is running. Pre-fix it was histogrammed as
    /// `running`, so `/stats` reported a hard-killed scan as in progress
    /// forever — observed on `ff4d63c` after `kill -9` + restart.
    /// REQ-SCANSTATUS-030: a scan row carries its derived
    /// `finalise_incomplete`, so the web views that read rows (the scan list,
    /// the scan-info Status row, the radar sweep list) can call a `Complete`
    /// scan with a finalise shortfall partial, as its exports do. Pre-fix
    /// only `interrupted` was derived, and every row view showed it green.
    #[test]
    fn a_scan_row_says_whether_its_finalise_was_cut_short() {
        use super::scan_json;
        use crate::core::scan::{Scan, ScanStatus, Target, TargetKind};

        let mk = |status: ScanStatus, error: Option<&str>| {
            let mut s = Scan::new("s", Target::new(TargetKind::Domain, "cloudflare.com"));
            s.status = status;
            s.error = error.map(str::to_string);
            s
        };
        let in_flight = std::collections::HashSet::new();
        let flag = |scan: &Scan| scan_json(scan, &in_flight)["finalise_incomplete"].clone();
        let cut = "1/20 entities failed to persist: disk full";
        assert_eq!(flag(&mk(ScanStatus::Complete, Some(cut))), serde_json::json!(true));
        assert_eq!(flag(&mk(ScanStatus::Aborted, Some(cut))), serde_json::json!(true));
        // Controls: a clean finish, and a failure (never "partial").
        assert_eq!(flag(&mk(ScanStatus::Complete, None)), serde_json::json!(false));
        assert_eq!(flag(&mk(ScanStatus::Failed, Some(cut))), serde_json::json!(false));
    }

    /// REQ-SCANSTATUS-034: a finished scan whose finalise fell short is
    /// histogrammed as the `partial` its row pill reads — the dashboard's
    /// Scan Status panel counted it under its stored `complete`, a green
    /// tally beside the Recent Scans row that called it `partial`.
    #[test]
    fn a_partial_scan_is_histogrammed_apart_from_complete() {
        use super::aggregate_scan_stats;
        use crate::core::scan::{Scan, ScanStatus, Target, TargetKind};

        let mk = |id: &str, status: ScanStatus, error: Option<&str>| {
            let mut s = Scan::new(id, Target::new(TargetKind::Domain, "cloudflare.com"));
            s.status = status;
            s.error = error.map(str::to_string);
            s
        };
        let cut = "3/3 relations failed to persist: disk full";
        let scans = [
            mk("short", ScanStatus::Complete, Some(cut)),
            mk("whole", ScanStatus::Complete, None),
            mk("stopped-short", ScanStatus::Aborted, Some(cut)),
            mk("stopped", ScanStatus::Aborted, None),
            // Control: a failure's error is its failure, never "partial".
            mk("failed", ScanStatus::Failed, Some(cut)),
        ];
        let agg = aggregate_scan_stats(&scans, &std::collections::HashSet::new());
        assert_eq!(agg.by_status.get("partial"), Some(&1), "{agg:?}");
        assert_eq!(agg.by_status.get("complete"), Some(&1), "{agg:?}");
        assert_eq!(agg.by_status.get("aborted_partial"), Some(&1), "{agg:?}");
        assert_eq!(agg.by_status.get("aborted"), Some(&1), "{agg:?}");
        assert_eq!(agg.by_status.get("failed"), Some(&1), "{agg:?}");
        assert_eq!(agg.by_status.values().sum::<u64>(), 5, "{agg:?}");
    }

    #[test]
    fn a_running_row_with_no_handle_is_histogrammed_as_interrupted() {
        use super::{aggregate_scan_stats, is_interrupted};
        use crate::core::scan::{Scan, ScanStatus, Target, TargetKind};

        let mk = |id: &str, status: ScanStatus| {
            let mut s = Scan::new(id, Target::new(TargetKind::Domain, "cloudflare.com"));
            s.status = status;
            s
        };
        let scans = [
            mk("orphan", ScanStatus::Running),
            mk("live", ScanStatus::Running),
            mk("done", ScanStatus::Complete),
            mk("queued", ScanStatus::Pending),
        ];
        let in_flight: std::collections::HashSet<String> = ["live".to_string()].into();

        assert!(is_interrupted(&scans[0], &in_flight), "running + no handle");
        // CONTROLS — each is what an over-eager derivation would get wrong:
        assert!(
            !is_interrupted(&scans[1], &in_flight),
            "running + handle is genuinely in flight, never interrupted"
        );
        assert!(
            !is_interrupted(&scans[2], &in_flight),
            "a terminal row is never interrupted"
        );
        assert!(
            !is_interrupted(&scans[3], &in_flight),
            "pending has a legitimate no-handle window between upsert and spawn"
        );

        let agg = aggregate_scan_stats(&scans, &in_flight);
        assert_eq!(agg.by_status.get("interrupted"), Some(&1));
        assert_eq!(agg.by_status.get("running"), Some(&1));
        assert_eq!(agg.by_status.get("complete"), Some(&1));
        assert_eq!(agg.by_status.get("pending"), Some(&1));
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
        let modules = v["modules"].as_array().expect("should succeed");
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
        assert!(v["modules"].as_array().expect("should succeed").is_empty());
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
                module: "ip_registry",
                kind: TargetKind::Asn,
                value: "AS15169",
                outcome: ProbeOutcome::Unreachable {
                    reason: "connect".into(),
                },
            },
            // A throttled canary: alive but asking for less — neither dead
            // nor drift, reported as its own outcome.
            ProbeReport {
                module: "ripestat",
                kind: TargetKind::IpAddress,
                value: "8.8.8.8",
                outcome: ProbeOutcome::RateLimited {
                    reason: "ripestat: HTTP 429 Too Many Requests: <empty>".into(),
                },
            },
            // A canary refused by an anti-bot challenge: alive, but not to
            // this client — neither dead nor drift, its own outcome.
            ProbeReport {
                module: "crtsh",
                kind: TargetKind::Domain,
                value: "example.com",
                outcome: ProbeOutcome::Blocked {
                    reason: "crtsh: HTTP 403 Forbidden: Attention Required! | Cloudflare".into(),
                },
            },
            // An Australia-only module declining the fleet's New York sample
            // in-band: not asked, so neither dead nor drift, its own outcome.
            ProbeReport {
                module: "au_geo",
                kind: TargetKind::Coordinates,
                value: "40.7128,-74.0060",
                outcome: ProbeOutcome::Skipped {
                    class: crate::core::event::SkipClass::NotApplicable,
                    reason: "40.7128,-74.006 is outside Australia; the ABS ASGS layers cover Australia only".into(),
                },
            },
        ];
        let v = capability_probe_json(&reports);
        assert_eq!(v["probed"], 7);
        assert_eq!(v["alive"], 1);
        assert_eq!(v["empty"], 2);
        assert_eq!(v["unreachable"], 1);
        assert_eq!(v["rate_limited"], 1);
        assert_eq!(v["blocked"], 1);
        assert_eq!(v["skipped"], 1);
        // Only the ip_geo canary's empty is confirmed drift.
        assert_eq!(v["drift"].as_array().expect("should succeed").len(), 1);
        assert_eq!(v["drift"][0], "ip_geo");
        let mods = v["modules"].as_array().expect("should succeed");
        let ip_geo = mods.iter().find(|m| m["module"] == "ip_geo").expect("should succeed");
        assert_eq!(ip_geo["canary"], true);
        assert_eq!(ip_geo["drift"], true);
        let breach = mods.iter().find(|m| m["module"] == "some_breach").expect("should succeed");
        assert_eq!(breach["canary"], false);
        assert_eq!(breach["drift"], false);
        let cs = mods.iter().find(|m| m["module"] == "certspotter").expect("should succeed");
        assert_eq!(cs["outcome"], "alive");
        assert_eq!(cs["found"], 9);
        // ip_registry is a canary that gave no answer: a dead canary, not drift.
        assert_eq!(v["dead_canaries"].as_array().expect("should succeed").len(), 1);
        assert_eq!(v["dead_canaries"][0], "ip_registry");
        let dead = mods.iter().find(|m| m["module"] == "ip_registry").expect("should succeed");
        assert_eq!(dead["dead_canary"], true);
        assert_eq!(dead["drift"], false);
        assert_eq!(ip_geo["dead_canary"], false, "drift is not death");
        let throttled = mods.iter().find(|m| m["module"] == "ripestat").expect("should succeed");
        assert_eq!(throttled["outcome"], "rate-limited");
        assert_eq!(throttled["dead_canary"], false, "a throttled canary answered");
        assert_eq!(throttled["drift"], false);
        let declined = mods.iter().find(|m| m["module"] == "au_geo").expect("should succeed");
        assert_eq!(declined["outcome"], "skipped");
        assert_eq!(declined["dead_canary"], false);
        assert_eq!(declined["drift"], false);
        assert!(
            declined["reason"]
                .as_str()
                .expect("reason")
                .starts_with("not_applicable: ")
        );
        let refused = mods.iter().find(|m| m["module"] == "crtsh").expect("should succeed");
        assert_eq!(refused["outcome"], "blocked");
        assert_eq!(refused["canary"], true);
        assert_eq!(refused["dead_canary"], false, "a refused canary answered");
        assert_eq!(refused["drift"], false);
        assert!(
            refused["reason"]
                .as_str()
                .expect("reason")
                .contains("Attention Required")
        );
        assert_eq!(v["dead_canaries"].as_array().expect("should succeed").len(), 1);
    }

    /// The Engines page's live-probe panel (`src/web/js/views/engines.js`) is
    /// the one operator surface for `POST /capabilities/probe`. Every counter
    /// the endpoint emits and every outcome label a module row can carry must
    /// be something the panel reads. Before this guard `rate_limited`,
    /// `blocked`, `skipped` and `dead_canaries` reached the JSON
    /// (REQ-DRIFT-001/002/003, REQ-SCOPE-001) while the panel painted all four
    /// the red of a provider that is down, counted none of them and flagged no
    /// dead canary: implemented, not reachable. Tying the panel to the contract
    /// at the boundary means a new state can never vanish from the UI silently.
    #[test]
    fn the_engines_panel_reads_every_probe_counter_and_outcome_label_the_api_emits() {
        use super::capability_probe_json;
        use crate::core::event::SkipClass;
        use crate::core::scan::TargetKind;
        use crate::selftest::capability_probe::{ProbeOutcome, ProbeReport};
        let report = |module: &'static str, outcome: ProbeOutcome| ProbeReport {
            module,
            kind: TargetKind::Domain,
            value: "example.com",
            outcome,
        };
        // One row per outcome variant, so every label the API can emit is on
        // the table.
        let reports = vec![
            report("alive_src", ProbeOutcome::Alive { found: 3 }),
            report("empty_src", ProbeOutcome::Empty),
            report(
                "down_src",
                ProbeOutcome::Unreachable {
                    reason: "transport error".into(),
                },
            ),
            report("slow_src", ProbeOutcome::TimedOut),
            report(
                "throttled_src",
                ProbeOutcome::RateLimited {
                    reason: "HTTP 429".into(),
                },
            ),
            report(
                "walled_src",
                ProbeOutcome::Blocked {
                    reason: "HTTP 403 Attention Required".into(),
                },
            ),
            report(
                "declined_src",
                ProbeOutcome::Skipped {
                    class: SkipClass::NotApplicable,
                    reason: "out of scope".into(),
                },
            ),
            report(
                "broken_src",
                ProbeOutcome::Panicked {
                    message: "index out of bounds".into(),
                },
            ),
        ];
        let v = capability_probe_json(&reports);
        let js = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/web/js/views/engines.js"
        ))
        .expect("engines.js is checked in");
        // Only the panel's renderer counts: the page's search-engine liveness
        // table has its own `'blocked'` state, and a match there would let the
        // probe panel drop the label unnoticed.
        let panel = js
            .split("export async function runCapabilityProbe(")
            .nth(1)
            .and_then(|rest| rest.split("\nexport ").next())
            .expect("runCapabilityProbe is an exported function in engines.js");

        let counters = v.as_object().expect("the probe JSON is an object");
        assert!(counters.len() >= 12, "{:?}", counters.keys().collect::<Vec<_>>());
        for key in counters.keys() {
            assert!(
                panel.contains(&format!("data.{key}")),
                "runCapabilityProbe never reads the probe field `{key}` the API emits"
            );
        }
        let labels: std::collections::BTreeSet<&str> = v["modules"]
            .as_array()
            .expect("modules")
            .iter()
            .map(|m| m["outcome"].as_str().expect("outcome label"))
            .collect();
        assert_eq!(labels.len(), 8, "one row per outcome variant: {labels:?}");
        for label in labels {
            assert!(
                panel.contains(&format!("'{label}'")),
                "runCapabilityProbe never renders the probe outcome `{label}`"
            );
        }
        for flag in ["m.drift", "m.canary", "m.dead_canary"] {
            assert!(
                panel.contains(flag),
                "runCapabilityProbe never reads the row flag `{flag}`"
            );
        }
    }

    #[test]
    fn capability_probe_json_reports_a_panicked_module_as_confirmed_drift() {
        use super::capability_probe_json;
        use crate::core::scan::TargetKind;
        use crate::selftest::capability_probe::{ProbeOutcome, ProbeReport};
        // A panicked module is confirmed drift unconditionally — not a canary,
        // yet must still surface as drift (see `ProbeOutcome::Panicked`'s doc).
        let reports = vec![ProbeReport {
            module: "some_breach",
            kind: TargetKind::Email,
            value: "test@example.com",
            outcome: ProbeOutcome::Panicked {
                message: "index out of bounds: the len is 0 but the index is 0".into(),
            },
        }];
        let v = capability_probe_json(&reports);
        assert_eq!(v["probed"], 1);
        assert_eq!(v["panicked"], 1);
        assert_eq!(v["alive"], 0);
        assert_eq!(v["empty"], 0);
        assert_eq!(v["drift"].as_array().expect("should succeed").len(), 1);
        assert_eq!(v["drift"][0], "some_breach");
        let m = &v["modules"][0];
        assert_eq!(m["outcome"], "panicked");
        assert_eq!(m["reason"], "index out of bounds: the len is 0 but the index is 0");
        assert_eq!(m["drift"], true);
        assert_eq!(m["canary"], false);
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

    /// The wire contract of `GET /api/v1/modules/graph`, asserted on the
    /// response type rather than a live server.
    ///
    /// This payload used to be assembled by hand-copying fields out of
    /// `ModuleGraphSummary` into a `json!` literal, which made the wire format a
    /// second, unchecked definition of a type that already derives `Serialize`.
    /// The consequence was silent: `terminal_kinds` was added to the summary and
    /// reached no client at all, because the handler simply never mentioned it.
    ///
    /// Both halves matter here. The flatten must keep `kinds` and `edges` at the
    /// TOP level, because `web/js/views/engines.js` reads `g.kinds` — nesting
    /// them under a sub-object would break the capability map without any
    /// compiler error. And a field present on the summary must actually appear,
    /// which is the regression that motivated the change.
    #[test]
    fn modules_graph_payload_flattens_the_summary_and_keeps_top_level_keys() {
        use crate::core::dependency::{ModuleGraph, ModuleGraphSummary};

        let modules = crate::modules::registry();
        let summary: ModuleGraphSummary = ModuleGraph::build(&modules).to_summary(&modules);
        let value = serde_json::to_value(super::ModuleGraphResponse {
            produced_kinds: summary.produced_entity_kinds(),
            module_count: modules.len(),
            graph: summary,
        })
        .expect("the response type must serialize");

        let obj = value.as_object().expect("payload is a JSON object");

        // Back-compat: the SPA's capability map reads these at the top level.
        for key in ["kinds", "edges", "produced_kinds", "module_count"] {
            assert!(obj.contains_key(key), "`{key}` must stay top-level");
        }
        // The regression: a summary field that the old hand-written payload
        // dropped on the floor.
        assert!(
            obj.contains_key("terminal_kinds"),
            "every ModuleGraphSummary field must reach the wire, not just the \
             ones someone remembered to list"
        );

        // And the joinable edge is present per module, so a client can actually
        // build the graph these edges exist for.
        let edges = obj["edges"].as_array().expect("edges is an array");
        assert!(!edges.is_empty(), "the real registry must produce edges");
        for e in edges {
            assert!(
                e.get("pivots_to").is_some(),
                "each edge must carry the dispatch-vocabulary join field: {e}"
            );
        }
    }

    /// The whole point of `pivots_to`: joining producers to consumers across the
    /// REAL registry must connect the graph. Asserted against the live module
    /// set, because the defect only showed up at that scale — `person` is
    /// emitted by dozens of modules and consumed under the name `full_name`, so
    /// a naive join on `produces` leaves them all looking like dead ends.
    #[test]
    fn the_real_registry_graph_has_no_false_dead_ends() {
        use crate::core::dependency::ModuleGraph;
        use std::collections::HashSet;

        let modules = crate::modules::registry();
        let summary = ModuleGraph::build(&modules).to_summary(&modules);

        let consumed: HashSet<&str> = summary
            .edges
            .iter()
            .flat_map(|e| e.consumes.iter().copied())
            .collect();
        let pivoted: HashSet<&str> = summary
            .edges
            .iter()
            .flat_map(|e| e.pivots_to.iter().copied())
            .collect();

        // Every kind a module can pivot to is consumed by something. A kind here
        // that nothing consumes would mean real modules deriving facts no module
        // can act on.
        let orphans: Vec<&&str> = pivoted.difference(&consumed).collect();
        assert!(
            orphans.is_empty(),
            "pivotable kinds that no module consumes: {orphans:?}"
        );

        // The specific case that was broken, pinned by name so a regression is
        // legible rather than a count changing.
        assert!(
            pivoted.contains("full_name"),
            "person-producing modules must pivot into full_name"
        );
    }

    /// The scan-log stream answers only for a scan in flight here or stored:
    /// an unknown id is a 404, which `EventSource` does not retry, not a pipe
    /// that sits silent for the idle timeout and is then reconnected to
    /// indefinitely. Each of the two is enough on its own. A scan is
    /// registered before its id reaches a client, so "in flight, no row yet"
    /// must stream too.
    #[tokio::test]
    async fn the_scan_stream_answers_only_for_a_scan_in_flight_or_stored() {
        use crate::core::cancel::CancelHandle;
        use crate::core::scan::{Scan, Target, TargetKind};
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt as _;

        let state = crate::api::test_state();
        let status = |id: &str| {
            let router = axum::Router::new()
                .route(
                    "/api/v1/scans/{id}/events",
                    axum::routing::get(super::scan_events_sse),
                )
                .with_state(std::sync::Arc::clone(&state));
            let uri = format!("/api/v1/scans/{id}/events");
            async move {
                router
                    .oneshot(Request::builder().uri(uri).body(Body::empty()).expect("request"))
                    .await
                    .expect("response")
                    .status()
            }
        };

        assert_eq!(status("never-existed").await, 404);

        let _in_flight = crate::api::CancelRegistryGuard::install(
            std::sync::Arc::clone(&state.cancellations),
            "in-flight-only".into(),
            CancelHandle::new(),
        );
        assert_eq!(status("in-flight-only").await, 200, "registered, no row yet");

        let scan = Scan::new("stored-only", Target::new(TargetKind::Domain, "example.com"));
        state.store.upsert_scan(&scan).expect("store the scan");
        assert_eq!(status("stored-only").await, 200, "stored, nothing in flight");
    }
