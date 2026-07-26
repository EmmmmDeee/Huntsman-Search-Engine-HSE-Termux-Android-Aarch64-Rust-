use super::*;
    use crate::core::scan::TargetKind;

    #[test]
    fn live_id_format_is_deterministic_prefix() {
        let t = Target::new(TargetKind::Domain, "example.com");
        let a = new_live_id(&t);
        let b = new_live_id(&t);
        // Different nanosecond timestamps → different ids
        assert!(a.starts_with("live-"));
        assert!(b.starts_with("live-"));
        assert_ne!(a, b);
        assert_eq!(a.len(), "live-".len() + 16);
    }

    #[test]
    fn live_options_default() {
        let o = LiveOptions::default();
        assert_eq!(o.interval_secs, crate::LIVE_DEFAULT_INTERVAL_SECS);
        assert!(o.iterations.is_none());
    }

    #[test]
    fn live_options_round_trip_json() {
        let o = LiveOptions {
            interval_secs: 60,
            iterations: Some(3),
            radar: true,
        };
        let s = serde_json::to_string(&o).expect("should succeed");
        let back: LiveOptions = serde_json::from_str(&s).expect("should succeed");
        assert_eq!(back.interval_secs, 60);
        assert_eq!(back.iterations, Some(3));
        assert!(back.radar, "radar flag must round-trip");
        // Omitted `radar` defaults to false (classic live re-scan).
        let d: LiveOptions = serde_json::from_str(r#"{"interval_secs":10}"#).expect("should succeed");
        assert!(!d.radar);
    }

    #[test]
    fn live_request_default_options_inert() {
        let json = r#"{"kind":"domain","value":"x.com"}"#;
        let req: LiveRequest = serde_json::from_str(json).expect("should succeed");
        assert_eq!(req.kind, Some(TargetKind::Domain));
        assert_eq!(req.resolved_kind(), TargetKind::Domain);
        assert_eq!(req.live.interval_secs, crate::LIVE_DEFAULT_INTERVAL_SECS);
        assert!(req.live.iterations.is_none());
    }

    #[test]
    fn live_request_omitted_options_match_empty_object_and_scan_defaults() {
        // Two spellings of "operator expressed no scan-option preference" must
        // be identical — a bare #[serde(default)] gave the omitted form depth 0
        // (ScanOptions::default()) while "options": {} got the field-level
        // product defaults (depth 2), so the same intent ran zero-expansion or
        // two-hop iterations depending on serialisation style.
        let omitted: LiveRequest = serde_json::from_str(r#"{"value":"x.com"}"#).expect("should succeed");
        let empty: LiveRequest = serde_json::from_str(r#"{"value":"x.com","options":{}}"#).expect("should succeed");
        assert_eq!(omitted.options.depth, empty.options.depth);
        assert_eq!(omitted.options.max_concurrent, empty.options.max_concurrent);
        // And live matches scan: the shared product default (depth 2).
        assert_eq!(omitted.options.depth, crate::core::scan::DEFAULT_SCAN_DEPTH);
    }

    #[test]
    fn live_request_omitted_kind_auto_detects() {
        // Unified live scan: no kind → detected from the value.
        let req: LiveRequest = serde_json::from_str(r#"{"value":"x@y.com"}"#).expect("should succeed");
        assert_eq!(req.kind, None);
        assert_eq!(req.resolved_kind(), TargetKind::Email);
        // PR #102 review: resolved_kind sanitises paste artifacts before
        // detecting, so a quoted URL classes as Url (not Username).
        let dirty: LiveRequest =
            serde_json::from_str(r#"{"value":"\"https://cloudflare.com\","}"#).expect("should succeed");
        assert_eq!(dirty.resolved_kind(), TargetKind::Url);
    }

    #[test]
    fn live_status_serde_round_trip() {
        for (variant, expected) in [
            (LiveStatus::Running, "\"running\""),
            (LiveStatus::Completed, "\"completed\""),
            (LiveStatus::Stopped, "\"stopped\""),
        ] {
            let json = serde_json::to_string(&variant).expect("should succeed");
            assert_eq!(json, expected);
            let back: LiveStatus = serde_json::from_str(&json).expect("should succeed");
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn live_session_serde_round_trip() {
        let session = LiveSession {
            id: "live-abc123".into(),
            target: Target::new(TargetKind::Email, "x@y.com"),
            scan_options: ScanOptions::default(),
            live_options: LiveOptions::default(),
            status: LiveStatus::Running,
            started_at: 1700000000,
            last_iteration_at: None,
            iteration: 0,
            scan_ids: std::collections::HashSet::new(),
            scan_id_order: VecDeque::new(),
        };
        let json = serde_json::to_string(&session).expect("should succeed");
        // The internal insertion-order field must not change the wire format.
        assert!(
            !json.contains("scan_id_order"),
            "scan_id_order must not be serialized: {json}"
        );
        let back: LiveSession = serde_json::from_str(&json).expect("should succeed");
        assert_eq!(back.id, "live-abc123");
        assert_eq!(back.status, LiveStatus::Running);
    }

    #[test]
    fn record_scan_bounds_scan_ids_with_fifo_eviction() {
        let mut s = LiveSession {
            id: "live-fifo".into(),
            target: Target::new(TargetKind::Email, "x@y.com"),
            scan_options: ScanOptions::default(),
            live_options: LiveOptions::default(),
            status: LiveStatus::Running,
            started_at: 1700000000,
            last_iteration_at: None,
            iteration: 0,
            scan_ids: std::collections::HashSet::new(),
            scan_id_order: VecDeque::new(),
        };
        // Oldest id, then exactly enough distinct ids to push it past the cap.
        s.record_scan("first".to_string());
        for i in 0..SCAN_ID_CAP {
            s.record_scan(format!("scan-{i}"));
        }
        assert!(
            s.scan_ids.len() <= SCAN_ID_CAP,
            "ledger must stay within the cap"
        );
        assert!(
            !s.scan_ids.contains("first"),
            "the oldest id must be evicted first"
        );
        assert!(
            s.scan_ids.contains(&format!("scan-{}", SCAN_ID_CAP - 1)),
            "recent ids must be retained"
        );
        // A duplicate is a no-op (no double-tracking, no spurious eviction).
        let before = s.scan_ids.len();
        s.record_scan(format!("scan-{}", SCAN_ID_CAP - 1));
        assert_eq!(s.scan_ids.len(), before);
    }

    #[test]
    fn scan_ids_serialize_in_sorted_order_for_reproducible_api_output() {
        // `scan_ids` is a `HashSet`, whose native iteration order is
        // per-process-random (SipHash seed). It serializes directly into the
        // `GET /api/v1/live` responses, so without a stable order the SAME
        // live-session state would emit a differently-ordered `scan_ids` array
        // across separate server runs. 40 distinct ids make a coincidental
        // sorted hash order astronomically unlikely (1/N!).
        let mut s = mk_session("live-order", LiveStatus::Running, 1_700_000_000);
        for i in (0..40).rev() {
            s.record_scan(format!("scan-{i:02}"));
        }
        let json = serde_json::to_value(&s).expect("should succeed");
        let got: Vec<&str> = json["scan_ids"]
            .as_array()
            .expect("scan_ids serializes as a JSON array")
            .iter()
            .map(|v| v.as_str().expect("each scan id is a string"))
            .collect();
        let mut want = got.clone();
        want.sort_unstable();
        assert_eq!(
            got, want,
            "scan_ids must serialize in sorted order for byte-reproducible API output"
        );
    }

    fn mk_session(id: &str, status: LiveStatus, started_at: u64) -> LiveSession {
        LiveSession {
            id: id.to_string(),
            target: Target::new(TargetKind::Email, "x@y.com"),
            scan_options: ScanOptions::default(),
            live_options: LiveOptions::default(),
            status,
            started_at,
            last_iteration_at: None,
            iteration: 0,
            scan_ids: std::collections::HashSet::new(),
            scan_id_order: VecDeque::new(),
        }
    }

    #[test]
    fn prune_terminal_sessions_bounds_history_oldest_first() {
        // Regression: `sessions` had no bound at all — every live invocation
        // that ever finished left a permanent record for the life of a `serve`
        // process. Build well past the cap and confirm the oldest terminal
        // sessions are evicted while recent ones survive.
        let map: HashMap<String, LiveSession> = (0..MAX_TERMINAL_SESSIONS + 50)
            .map(|i| {
                let status = if i % 2 == 0 {
                    LiveStatus::Completed
                } else {
                    LiveStatus::Stopped
                };
                (format!("live-{i}"), mk_session(&format!("live-{i}"), status, i as u64))
            })
            .collect();
        let sessions = RwLock::new(map);

        prune_terminal_sessions(&sessions);

        let remaining = sessions.read();
        assert_eq!(
            remaining.len(),
            MAX_TERMINAL_SESSIONS,
            "terminal session count must be capped, not merely reduced"
        );
        for i in 0..50 {
            assert!(
                !remaining.contains_key(&format!("live-{i}")),
                "the oldest sessions must be evicted first"
            );
        }
        for i in 50..MAX_TERMINAL_SESSIONS + 50 {
            assert!(
                remaining.contains_key(&format!("live-{i}")),
                "recent sessions must be retained"
            );
        }
    }

    #[test]
    fn prune_terminal_sessions_never_evicts_running_sessions() {
        // Running sessions are active scans, not history — they must survive
        // regardless of how many terminal sessions also exist, and regardless
        // of how old they are relative to the terminal ones.
        let mut map: HashMap<String, LiveSession> = (0..MAX_TERMINAL_SESSIONS + 20)
            .map(|i| {
                (
                    format!("done-{i}"),
                    mk_session(&format!("done-{i}"), LiveStatus::Completed, i as u64),
                )
            })
            .collect();
        map.insert(
            "still-running".to_string(),
            mk_session("still-running", LiveStatus::Running, 0),
        );
        let sessions = RwLock::new(map);

        prune_terminal_sessions(&sessions);

        let remaining = sessions.read();
        assert!(
            remaining.contains_key("still-running"),
            "a Running session must never be evicted by terminal-history pruning"
        );
        assert_eq!(
            remaining.len(),
            MAX_TERMINAL_SESSIONS + 1,
            "cap applies to terminal sessions only, plus the one Running session"
        );
    }

    #[test]
    fn prune_terminal_sessions_is_a_no_op_under_the_cap() {
        let map: HashMap<String, LiveSession> = (0..5)
            .map(|i| {
                (
                    format!("live-{i}"),
                    mk_session(&format!("live-{i}"), LiveStatus::Stopped, i as u64),
                )
            })
            .collect();
        let sessions = RwLock::new(map);

        prune_terminal_sessions(&sessions);

        assert_eq!(sessions.read().len(), 5, "under the cap, nothing is evicted");
    }
