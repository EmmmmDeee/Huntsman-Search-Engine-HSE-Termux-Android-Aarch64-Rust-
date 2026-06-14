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
