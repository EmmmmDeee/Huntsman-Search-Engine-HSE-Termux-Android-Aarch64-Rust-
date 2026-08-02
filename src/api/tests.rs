use super::*;

    #[test]
    fn cancel_registry_guard_installs_and_removes_on_drop() {
        let registry: CancelRegistry = Arc::new(Mutex::new(HashMap::new()));
        let handle = CancelHandle::new();

        {
            let _guard =
                CancelRegistryGuard::install(Arc::clone(&registry), "scan-1".into(), handle);
            assert!(registry.lock().contains_key("scan-1"));
        }
        // Guard dropped → entry removed
        assert!(!registry.lock().contains_key("scan-1"));
    }

    #[test]
    fn cancel_registry_guard_cancel_propagates() {
        let registry: CancelRegistry = Arc::new(Mutex::new(HashMap::new()));
        let handle = CancelHandle::new();
        let handle_clone = handle.clone();

        let _guard = CancelRegistryGuard::install(Arc::clone(&registry), "scan-2".into(), handle);

        let stored = registry.lock().get("scan-2").cloned().expect("should succeed");
        stored.cancel();
        assert!(handle_clone.is_cancelled());
    }

    #[test]
    fn cancel_registry_guard_multiple_scans_independent() {
        let registry: CancelRegistry = Arc::new(Mutex::new(HashMap::new()));

        let h1 = CancelHandle::new();
        let h2 = CancelHandle::new();

        let guard1 = CancelRegistryGuard::install(Arc::clone(&registry), "s1".into(), h1.clone());
        let _guard2 = CancelRegistryGuard::install(Arc::clone(&registry), "s2".into(), h2.clone());

        assert_eq!(registry.lock().len(), 2);

        drop(guard1);
        assert_eq!(registry.lock().len(), 1);
        assert!(!registry.lock().contains_key("s1"));
        assert!(registry.lock().contains_key("s2"));
    }

    fn empty_live_scanner() -> crate::core::live::LiveScanner {
        // No session is ever started, so `live.list()` is always empty —
        // these tests exercise the `cancellations` (scan) side of
        // `drain_in_flight_work`; `LiveScanner::list`/`stop` have their own
        // dedicated coverage in `core::live::tests`.
        let store = crate::storage::Store::open(":memory:").expect("should succeed");
        let store: std::sync::Arc<dyn crate::core::port::StoragePort> = std::sync::Arc::new(store);
        let (bus, _rx) = tokio::sync::broadcast::channel(16);
        let engine = std::sync::Arc::new(crate::core::engine::ScanEngine::new(
            Vec::new(),
            store,
            bus.clone(),
        ));
        crate::core::live::LiveScanner::new(engine, bus, reqwest::Client::new(), Default::default())
    }

    #[tokio::test]
    async fn drain_returns_immediately_when_nothing_is_in_flight() {
        let cancellations: CancelRegistry =
            std::sync::Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
        let live = empty_live_scanner();
        let start = tokio::time::Instant::now();
        // A generously long grace period that the fast path must never wait
        // out — proves the empty-registry check short-circuits.
        drain_in_flight_work(&cancellations, &live, std::time::Duration::from_secs(30)).await;
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "drain must return immediately when nothing is in flight"
        );
    }

    #[tokio::test]
    async fn drain_signals_cancel_and_returns_once_the_scan_finishes() {
        // Simulate a real `CancelRegistryGuard`: a scan task holds the
        // registry entry and removes it when it actually finishes (here,
        // shortly after observing cancellation — the cooperative pattern
        // every dispatch loop already follows).
        let cancellations: CancelRegistry =
            std::sync::Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
        let handle = CancelHandle::new();
        cancellations
            .lock()
            .insert("scan-1".to_string(), handle.clone());
        let live = empty_live_scanner();

        let reg = std::sync::Arc::clone(&cancellations);
        let h = handle.clone();
        tokio::spawn(async move {
            // Wait for the real cancellation signal, then "finish" — exactly
            // what a cooperatively-cancelled dispatch loop does.
            while !h.is_cancelled() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            reg.lock().remove("scan-1");
        });

        let start = tokio::time::Instant::now();
        drain_in_flight_work(&cancellations, &live, std::time::Duration::from_secs(10)).await;
        let elapsed = start.elapsed();

        assert!(
            handle.is_cancelled(),
            "drain must call .cancel() on every in-flight scan's handle"
        );
        assert!(cancellations.lock().is_empty(), "the entry must be gone");
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "drain must return as soon as the scan actually finishes, not wait \
             out the full grace period: took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn drain_gives_up_after_the_grace_period_with_stuck_work() {
        // A handle that is cancelled but never removed (a scan stuck past the
        // engine's next cancellation poll point) must not hang `hse serve`
        // shutdown forever — drain must return once `grace` elapses.
        let cancellations: CancelRegistry =
            std::sync::Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
        cancellations
            .lock()
            .insert("stuck-scan".to_string(), CancelHandle::new());
        let live = empty_live_scanner();

        let grace = std::time::Duration::from_millis(100);
        let start = tokio::time::Instant::now();
        drain_in_flight_work(&cancellations, &live, grace).await;
        let elapsed = start.elapsed();

        assert!(
            elapsed >= grace,
            "drain must wait out at least the grace period: {elapsed:?}"
        );
        assert!(
            elapsed < grace * 5,
            "drain must not wait substantially longer than the grace period \
             once it has elapsed: {elapsed:?}"
        );
        // The stuck entry is still there — drain gave up, it didn't fake success.
        assert!(!cancellations.lock().is_empty());
    }
