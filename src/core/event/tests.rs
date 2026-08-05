use super::*;
use crate::core::scan::ScanStatus;

    // ── Event::new ──────────────────────────────────────────────────────

    #[test]
    fn event_new_sets_scan_id_and_ts() {
        let before = unix_now();
        let evt = Event::new(
            "scan-42",
            EventKind::ScanComplete {
                scan_id: "scan-42".into(),
                entity_count: 0,
                status: ScanStatus::Complete,
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
        let json = serde_json::to_string(&kind).expect("should succeed");
        assert!(json.contains("\"type\":\"scan_start\""));

        let back: EventKind = serde_json::from_str(&json).expect("should succeed");
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
        let json = serde_json::to_string(&kind).expect("should succeed");
        assert!(json.contains("\"type\":\"entity_excluded\""));
        assert_eq!(kind.event_type_str(), "entity_excluded");
        let back: EventKind = serde_json::from_str(&json).expect("should succeed");
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
        let json = serde_json::to_string(&kind).expect("should succeed");
        let back: EventKind = serde_json::from_str(&json).expect("should succeed");
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
        let json = serde_json::to_string(&kind).expect("should succeed");
        let back: EventKind = serde_json::from_str(&json).expect("should succeed");
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
            status: ScanStatus::Aborted,
        };
        let json = serde_json::to_string(&kind).expect("should succeed");
        let back: EventKind = serde_json::from_str(&json).expect("should succeed");
        match back {
            EventKind::ScanComplete {
                scan_id,
                entity_count,
                status,
            } => {
                assert_eq!(scan_id, "scan-99");
                assert_eq!(entity_count, 42);
                assert_eq!(status, ScanStatus::Aborted);
            }
            other => panic!("expected ScanComplete, got: {other:?}"),
        }
    }

    /// A `scan_complete` row persisted before the `status` field existed
    /// deserializes as `Complete` (the back-compat default), so old event logs
    /// keep rendering exactly as they did. Without `#[serde(default)]` this
    /// `from_str` would error and the whole row would be silently dropped by
    /// the `filter_map` on the read path.
    #[test]
    fn scan_complete_without_status_defaults_to_complete() {
        let legacy = r#"{"type":"scan_complete","scan_id":"s","entity_count":7}"#;
        let back: EventKind = serde_json::from_str(legacy).expect("legacy row must still parse");
        match back {
            EventKind::ScanComplete {
                status,
                entity_count,
                ..
            } => {
                assert_eq!(status, ScanStatus::Complete);
                assert_eq!(entity_count, 7);
            }
            other => panic!("expected ScanComplete, got: {other:?}"),
        }
    }

    /// The terminal event renders its true state: an aborted or failed scan
    /// must NOT read as a green success. This is the whole point of carrying
    /// `status` on the event — the downloaded `events.log` is the client-safe
    /// artifact, and it was asserting completion for scans that were stopped
    /// early or failed.
    #[test]
    fn scan_complete_log_summary_reflects_terminal_status() {
        let done = EventKind::ScanComplete {
            scan_id: "s".into(),
            entity_count: 5,
            status: ScanStatus::Complete,
        };
        let aborted = EventKind::ScanComplete {
            scan_id: "s".into(),
            entity_count: 5,
            status: ScanStatus::Aborted,
        };
        let failed = EventKind::ScanComplete {
            scan_id: "s".into(),
            entity_count: 0,
            status: ScanStatus::Failed,
        };
        assert_eq!(done.log_summary().1, "✔ scan complete · 5 entities");
        assert_eq!(
            aborted.log_summary().1,
            "■ scan aborted — stopped early · 5 entities"
        );
        assert_eq!(failed.log_summary().1, "✗ scan failed");
        // The failure line must not carry the success glyph a client would read
        // as "all good".
        assert!(!failed.log_summary().1.contains('✔'));
        assert!(!aborted.log_summary().1.contains('✔'));
    }

    // ── Wire-contract drift guard (event_type_str ⇄ serde `type`) ───────

    #[test]
    fn event_type_str_matches_serde_tag_for_every_variant() {
        use crate::core::correlator::{Correlation, Severity};
        use crate::core::entity::{Entity, EntityKind};

        // DRIFT GUARD. `event_type_str()` is a hand-written 15-arm match that MUST
        // equal the serde `type` tag for EVERY variant: the SPA switches on
        // `evt.type === 'module_start'`, and the SQLite event log / SSE stream both
        // carry the serde form — so a single divergent arm (e.g. `live_ticks` vs
        // `live_tick`) silently breaks that event in the live UI with no error.
        // Previously only ONE variant (entity_excluded) pinned this equality.
        //
        // `every` holds one representative per variant. The arm-less `match` (no
        // `_`) inside the loop is over the EventKind *type*, so adding a variant
        // fails to compile here until it is handled — the author then adds it to
        // `every` too (kept adjacent for exactly that reason). The loop proves, for
        // the whole set, that the hand tag equals the serde tag and that the tag
        // survives a JSON round-trip.
        let every = [
            EventKind::ScanStart {
                target_kind: "email".into(),
                target_value: "a@b.com".into(),
            },
            EventKind::ModuleStart { module: "m".into() },
            EventKind::ModuleDone {
                module: "m".into(),
                found: 1,
            },
            EventKind::ModuleError {
                module: "m".into(),
                error: "e".into(),
            },
            EventKind::ModuleSkipped {
                module: "m".into(),
                reason: "r".into(),
            },
            EventKind::EntityFound {
                entity: Entity::new(EntityKind::Email, "a@b.com", 0.5, "s"),
            },
            EventKind::ExpansionTick {
                depth: 1,
                queued: 2,
                visited: 3,
            },
            EventKind::ExpansionStop { reason: "r".into() },
            EventKind::EntityExcluded {
                kind: "ip_address".into(),
                value: "1.2.3.4".into(),
                reason: "r".into(),
            },
            EventKind::BreachSweep {
                anchors: 3,
                probes: 12,
                dropped: 1,
            },
            EventKind::ConsensusAudit {
                verdict: "pass".into(),
                examined: 4,
                corroborated: 2,
                flags: 1,
            },
            EventKind::CorrelationFound {
                correlation: Correlation::new(
                    "AU-001",
                    "rule",
                    Severity::High,
                    "d".into(),
                    vec!["u".into()],
                    "s",
                    0,
                ),
            },
            EventKind::CorrelationsDone { count: 1 },
            EventKind::LiveStart {
                live_id: "l".into(),
                target_kind: "email".into(),
                target_value: "a@b.com".into(),
                interval_secs: 60,
            },
            EventKind::LiveTick {
                live_id: "l".into(),
                iteration: 1,
                scan_id: "s".into(),
            },
            EventKind::LiveStop {
                live_id: "l".into(),
                reason: "r".into(),
            },
            EventKind::ScanComplete {
                scan_id: "s".into(),
                entity_count: 0,
                status: ScanStatus::Complete,
            },
        ];

        for kind in &every {
            // Compile-time tripwire: NO `_` arm, so a new EventKind variant fails to
            // compile until it is handled (and added to `every` above).
            match kind {
                EventKind::ScanStart { .. }
                | EventKind::ModuleStart { .. }
                | EventKind::ModuleDone { .. }
                | EventKind::ModuleError { .. }
                | EventKind::ModuleSkipped { .. }
                | EventKind::EntityFound { .. }
                | EventKind::ExpansionTick { .. }
                | EventKind::ExpansionStop { .. }
                | EventKind::EntityExcluded { .. }
                | EventKind::BreachSweep { .. }
                | EventKind::ConsensusAudit { .. }
                | EventKind::CorrelationFound { .. }
                | EventKind::CorrelationsDone { .. }
                | EventKind::LiveStart { .. }
                | EventKind::LiveTick { .. }
                | EventKind::LiveStop { .. }
                | EventKind::ScanComplete { .. } => {}
            }

            let value = serde_json::to_value(kind).expect("should succeed");
            let serde_tag = value
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or_else(|| panic!("event serialised without a `type` tag: {value}"));
            assert_eq!(
                serde_tag,
                kind.event_type_str(),
                "event_type_str() diverged from the serde `type` tag",
            );

            // The tag survives a full JSON round-trip (the SSE/event-log path).
            let json = serde_json::to_string(kind).expect("should succeed");
            let back: EventKind = serde_json::from_str(&json).expect("should succeed");
            assert_eq!(
                back.event_type_str(),
                kind.event_type_str(),
                "tag changed across a JSON round-trip",
            );
        }

        assert_eq!(every.len(), 17, "one representative per EventKind variant");
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
        let json = serde_json::to_string(&evt).expect("should succeed");
        let back: Event = serde_json::from_str(&json).expect("should succeed");

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

    // ── Correlation log lines must be distinguishable ───────────────────

    #[test]
    fn correlation_log_summary_distinguishes_repeats_of_one_rule() {
        // Regression, from a real 47-event scan log: rules that fire per-entity
        // (AU-003 "High cross-source corroboration" emits one Correlation per
        // corroborated entity) produced nine consecutive, byte-identical
        // `⚡ High cross-source corroboration` lines, because `log_summary`
        // rendered only `rule_name` and dropped the `description` that names
        // the entity. Two findings of the same rule must not render alike.
        use crate::core::correlator::{Correlation, Severity};

        let mk = |desc: &str| {
            EventKind::CorrelationFound {
                correlation: Correlation::new(
                    "AU-003",
                    "High cross-source corroboration",
                    Severity::Medium,
                    desc.into(),
                    vec!["u".into()],
                    "scan-1",
                    0,
                ),
            }
            .log_summary()
            .1
        };

        let a = mk("Email entity 'a@example.com' corroborated by 3 independent source(s)");
        let b = mk("Domain entity 'example.com' corroborated by 4 independent source(s)");

        assert_ne!(a, b, "per-entity findings must not render identically");
        assert!(a.contains("High cross-source corroboration"), "{a}");
        assert!(a.contains("a@example.com"), "log line must name the entity: {a}");
        assert!(b.contains("example.com"), "{b}");
    }

    #[test]
    fn correlation_log_summary_omits_separator_when_description_is_empty() {
        use crate::core::correlator::{Correlation, Severity};

        let line = EventKind::CorrelationFound {
            correlation: Correlation::new(
                "AU-001",
                "Some rule",
                Severity::High,
                String::new(),
                vec!["u".into()],
                "scan-1",
                0,
            ),
        }
        .log_summary()
        .1;
        assert_eq!(line, "⚡ Some rule");
    }

    // ── ModuleEventTally ────────────────────────────────────────────────

    #[test]
    fn module_event_tally_counts_each_module_kind_and_ignores_the_rest() {
        let ev = |kind| Event::new("s", kind);
        let events = vec![
            ev(EventKind::ModuleStart { module: "a".into() }),
            ev(EventKind::ModuleStart { module: "b".into() }),
            ev(EventKind::ModuleDone { module: "a".into(), found: 3 }),
            ev(EventKind::ModuleError { module: "b".into(), error: "boom".into() }),
            ev(EventKind::ModuleSkipped { module: "c".into(), reason: "no key".into() }),
            // Non-module events must not be counted into any bucket.
            ev(EventKind::ScanComplete { scan_id: "s".into(), entity_count: 9, status: ScanStatus::Complete }),
            ev(EventKind::ExpansionStop { reason: "depth".into() }),
        ];
        let t = ModuleEventTally::from_events(&events);
        assert_eq!(t.started, 2);
        assert_eq!(t.done, 1);
        assert_eq!(t.errored, 1);
        assert_eq!(t.skipped, 1);
        assert!(!t.is_empty());
        assert_eq!(
            t.summary_line(),
            "2 module_start, 1 module_done, 1 module_error, 1 module_skipped"
        );
    }

    #[test]
    fn module_event_tally_is_empty_when_no_module_activity_was_recorded() {
        assert!(ModuleEventTally::from_events(&[]).is_empty());
        let only_scan = vec![Event::new(
            "s",
            EventKind::ScanStart {
                target_kind: "email".into(),
                target_value: "a@b.com".into(),
            },
        )];
        assert!(ModuleEventTally::from_events(&only_scan).is_empty());
    }
