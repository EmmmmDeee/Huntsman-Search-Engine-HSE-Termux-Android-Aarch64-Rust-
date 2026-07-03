use super::*;

    // ── Event::new ──────────────────────────────────────────────────────

    #[test]
    fn event_new_sets_scan_id_and_ts() {
        let before = unix_now();
        let evt = Event::new(
            "scan-42",
            EventKind::ScanComplete {
                scan_id: "scan-42".into(),
                entity_count: 0,
            },
        );
        let after = unix_now();

        assert_eq!(evt.scan_id, "scan-42");
        assert!(evt.ts >= before && evt.ts <= after);
    }

    // ── EventKind round-trips ───────────────────────────────────────────

    #[test]
    fn scan_start_json_round_trip() {
        let kind = EventKind::ScanStart {
            target_kind: "email".into(),
            target_value: "a@b.com".into(),
        };
        let json = serde_json::to_string(&kind).unwrap();
        assert!(json.contains("\"type\":\"scan_start\""));

        let back: EventKind = serde_json::from_str(&json).unwrap();
        match back {
            EventKind::ScanStart {
                target_kind,
                target_value,
            } => {
                assert_eq!(target_kind, "email");
                assert_eq!(target_value, "a@b.com");
            }
            other => panic!("expected ScanStart, got: {other:?}"),
        }
    }

    #[test]
    fn entity_excluded_json_round_trip() {
        let kind = EventKind::EntityExcluded {
            kind: "ip_address".into(),
            value: "104.20.37.187".into(),
            reason: "incidental_infra".into(),
        };
        let json = serde_json::to_string(&kind).unwrap();
        assert!(json.contains("\"type\":\"entity_excluded\""));
        assert_eq!(kind.event_type_str(), "entity_excluded");
        let back: EventKind = serde_json::from_str(&json).unwrap();
        match back {
            EventKind::EntityExcluded {
                kind,
                value,
                reason,
            } => {
                assert_eq!(kind, "ip_address");
                assert_eq!(value, "104.20.37.187");
                assert_eq!(reason, "incidental_infra");
            }
            other => panic!("expected EntityExcluded, got: {other:?}"),
        }
    }

    #[test]
    fn module_done_json_round_trip() {
        let kind = EventKind::ModuleDone {
            module: "whois".into(),
            found: 7,
        };
        let json = serde_json::to_string(&kind).unwrap();
        let back: EventKind = serde_json::from_str(&json).unwrap();
        match back {
            EventKind::ModuleDone { module, found } => {
                assert_eq!(module, "whois");
                assert_eq!(found, 7);
            }
            other => panic!("expected ModuleDone, got: {other:?}"),
        }
    }

    #[test]
    fn module_error_json_round_trip() {
        let kind = EventKind::ModuleError {
            module: "dns_resolve".into(),
            error: "timeout".into(),
        };
        let json = serde_json::to_string(&kind).unwrap();
        let back: EventKind = serde_json::from_str(&json).unwrap();
        match back {
            EventKind::ModuleError { module, error } => {
                assert_eq!(module, "dns_resolve");
                assert_eq!(error, "timeout");
            }
            other => panic!("expected ModuleError, got: {other:?}"),
        }
    }

    #[test]
    fn scan_complete_json_round_trip() {
        let kind = EventKind::ScanComplete {
            scan_id: "scan-99".into(),
            entity_count: 42,
        };
        let json = serde_json::to_string(&kind).unwrap();
        let back: EventKind = serde_json::from_str(&json).unwrap();
        match back {
            EventKind::ScanComplete {
                scan_id,
                entity_count,
            } => {
                assert_eq!(scan_id, "scan-99");
                assert_eq!(entity_count, 42);
            }
            other => panic!("expected ScanComplete, got: {other:?}"),
        }
    }

    // ── Full Event round-trip ───────────────────────────────────────────

    #[test]
    fn full_event_json_round_trip() {
        let evt = Event::new(
            "scan-7",
            EventKind::ModuleDone {
                module: "shodan".into(),
                found: 3,
            },
        );
        let json = serde_json::to_string(&evt).unwrap();
        let back: Event = serde_json::from_str(&json).unwrap();

        assert_eq!(back.scan_id, evt.scan_id);
        assert_eq!(back.ts, evt.ts);
        match back.kind {
            EventKind::ModuleDone { module, found } => {
                assert_eq!(module, "shodan");
                assert_eq!(found, 3);
            }
            other => panic!("expected ModuleDone, got: {other:?}"),
        }
    }

    // ── module_yield_outcomes / zero_yield_module_names ────────────────

    fn done(module: &str, found: usize) -> Event {
        Event::new(
            "s",
            EventKind::ModuleDone {
                module: module.into(),
                found,
            },
        )
    }

    #[test]
    fn module_yield_outcomes_records_each_distinct_module_once() {
        let events = vec![done("shodan", 0), done("hunter_io", 3)];
        let outcomes = module_yield_outcomes(&events);
        assert_eq!(outcomes.len(), 2);
        assert!(!outcomes["shodan"]);
        assert!(outcomes["hunter_io"]);
    }

    /// The whole point of the dedup: a module dispatched twice (e.g. an empty
    /// first expansion round, a productive second one) is judged on whether
    /// it EVER yielded anything, not on its first or last dispatch alone —
    /// order of the events must not matter either.
    #[test]
    fn a_module_is_judged_by_its_best_outcome_across_dispatches() {
        let zero_then_hit = vec![done("shodan", 0), done("shodan", 2)];
        assert!(module_yield_outcomes(&zero_then_hit)["shodan"]);

        let hit_then_zero = vec![done("shodan", 2), done("shodan", 0)];
        assert!(module_yield_outcomes(&hit_then_zero)["shodan"]);

        let always_zero = vec![done("shodan", 0), done("shodan", 0)];
        assert!(!module_yield_outcomes(&always_zero)["shodan"]);
    }

    #[test]
    fn non_module_done_events_are_ignored() {
        let events = vec![
            Event::new(
                "s",
                EventKind::ModuleStart {
                    module: "shodan".into(),
                },
            ),
            Event::new(
                "s",
                EventKind::ModuleError {
                    module: "hunter_io".into(),
                    error: "timeout".into(),
                },
            ),
        ];
        assert!(module_yield_outcomes(&events).is_empty());
    }

    #[test]
    fn zero_yield_module_names_excludes_modules_that_yielded_anything() {
        let events = vec![
            done("shodan", 0),
            done("hunter_io", 0),
            done("search_engines", 5),
        ];
        assert_eq!(
            zero_yield_module_names(&events),
            vec!["hunter_io".to_string(), "shodan".to_string()]
        );
    }

    #[test]
    fn zero_yield_module_names_is_empty_when_nothing_was_zero_yield() {
        let events = vec![done("shodan", 1)];
        assert!(zero_yield_module_names(&events).is_empty());
    }
