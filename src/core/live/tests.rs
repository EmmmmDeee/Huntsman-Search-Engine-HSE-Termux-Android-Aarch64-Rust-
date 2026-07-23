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
        let s = serde_json::to_string(&o).unwrap();
        let back: LiveOptions = serde_json::from_str(&s).unwrap();
        assert_eq!(back.interval_secs, 60);
        assert_eq!(back.iterations, Some(3));
        assert!(back.radar, "radar flag must round-trip");
        // Omitted `radar` defaults to false (classic live re-scan).
        let d: LiveOptions = serde_json::from_str(r#"{"interval_secs":10}"#).unwrap();
        assert!(!d.radar);
    }

    #[test]
    fn live_request_default_options_inert() {
        let json = r#"{"kind":"domain","value":"x.com"}"#;
        let req: LiveRequest = serde_json::from_str(json).unwrap();
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
        let omitted: LiveRequest = serde_json::from_str(r#"{"value":"x.com"}"#).unwrap();
        let empty: LiveRequest = serde_json::from_str(r#"{"value":"x.com","options":{}}"#).unwrap();
        assert_eq!(omitted.options.depth, empty.options.depth);
        assert_eq!(omitted.options.max_concurrent, empty.options.max_concurrent);
        // And live matches scan: the shared product default (depth 2).
        assert_eq!(omitted.options.depth, crate::core::scan::DEFAULT_SCAN_DEPTH);
    }

    #[test]
    fn live_request_omitted_kind_auto_detects() {
        // Unified live scan: no kind → detected from the value.
        let req: LiveRequest = serde_json::from_str(r#"{"value":"x@y.com"}"#).unwrap();
        assert_eq!(req.kind, None);
        assert_eq!(req.resolved_kind(), TargetKind::Email);
        // PR #102 review: resolved_kind sanitises paste artifacts before
        // detecting, so a quoted URL classes as Url (not Username).
        let dirty: LiveRequest =
            serde_json::from_str(r#"{"value":"\"https://cloudflare.com\","}"#).unwrap();
        assert_eq!(dirty.resolved_kind(), TargetKind::Url);
    }

    #[test]
    fn live_status_serde_round_trip() {
        for (variant, expected) in [
            (LiveStatus::Running, "\"running\""),
            (LiveStatus::Completed, "\"completed\""),
            (LiveStatus::Stopped, "\"stopped\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected);
            let back: LiveStatus = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&session).unwrap();
        // The internal insertion-order field must not change the wire format.
        assert!(
            !json.contains("scan_id_order"),
            "scan_id_order must not be serialized: {json}"
        );
        let back: LiveSession = serde_json::from_str(&json).unwrap();
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

    // Running-session count helper for the eviction tests below.
    fn running(map: &HashMap<String, LiveSession>) -> usize {
        map.values().filter(|s| s.status == LiveStatus::Running).count()
    }

    #[test]
    fn evict_oldest_running_if_full_frees_exactly_one_slot_synchronously() {
        // Regression for the check-then-act cap race: the previous code released
        // the lock to call the cooperative `stop()` (which leaves the evicted
        // session Running until its loop notices) and then inserted without
        // re-checking, so a burst of starts blew past MAX_SESSIONS. The eviction
        // must mark the oldest running session `Stopped` in place, under the
        // caller's lock, so the freed slot is visible to the very next insert.
        let mut map: HashMap<String, LiveSession> = (0..3)
            .map(|i| {
                (
                    format!("live-{i}"),
                    mk_session(&format!("live-{i}"), LiveStatus::Running, i as u64),
                )
            })
            .collect();
        let cancels = RwLock::new(HashMap::new());

        // Simulate `start`'s atomic block: evict-then-insert at the cap of 3.
        evict_oldest_running_if_full(&mut map, &cancels, 3);
        map.insert(
            "live-new".to_string(),
            mk_session("live-new", LiveStatus::Running, 99),
        );

        assert_eq!(
            running(&map),
            3,
            "running count must stay at the cap after evict-then-insert"
        );
        // The OLDEST (live-0, started_at 0) is the one evicted.
        assert_eq!(map["live-0"].status, LiveStatus::Stopped);
        assert_eq!(map["live-new"].status, LiveStatus::Running);
    }

    #[test]
    fn evict_oldest_running_if_full_is_a_no_op_below_the_cap() {
        let mut map: HashMap<String, LiveSession> = (0..2)
            .map(|i| {
                (
                    format!("live-{i}"),
                    mk_session(&format!("live-{i}"), LiveStatus::Running, i as u64),
                )
            })
            .collect();
        let cancels = RwLock::new(HashMap::new());

        evict_oldest_running_if_full(&mut map, &cancels, 10);

        assert_eq!(running(&map), 2, "below the cap, nothing is evicted");
    }

    #[test]
    fn evict_oldest_running_if_full_repeated_starts_never_exceed_the_cap() {
        // The multi-start burst the race produced: run evict-then-insert many
        // times and confirm the running count is pinned at the cap throughout,
        // never climbing — the invariant the cap exists to guarantee.
        const MAX: usize = 4;
        let mut map: HashMap<String, LiveSession> = HashMap::new();
        let cancels = RwLock::new(HashMap::new());
        for i in 0..20 {
            evict_oldest_running_if_full(&mut map, &cancels, MAX);
            map.insert(
                format!("live-{i}"),
                mk_session(&format!("live-{i}"), LiveStatus::Running, i as u64),
            );
            assert!(
                running(&map) <= MAX,
                "running count {} exceeded cap {MAX} at start #{i}",
                running(&map)
            );
        }
        assert_eq!(running(&map), MAX, "converges to exactly the cap");
    }
