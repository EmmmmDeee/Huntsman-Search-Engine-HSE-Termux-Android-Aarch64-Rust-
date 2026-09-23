use super::*;

    #[test]
    fn new_handle_is_not_cancelled() {
        assert!(!CancelHandle::new().is_cancelled());
    }

    #[test]
    fn cancel_is_observable_through_clones() {
        let a = CancelHandle::new();
        let b = a.clone();
        b.cancel();
        assert!(a.is_cancelled());
        assert!(b.is_cancelled());
    }

    #[test]
    fn cancel_is_idempotent() {
        let h = CancelHandle::new();
        h.cancel();
        h.cancel();
        assert!(h.is_cancelled());
    }

    #[test]
    fn default_is_uncancelled() {
        let h: CancelHandle = Default::default();
        assert!(!h.is_cancelled());
    }

    #[test]
    fn cancel_is_observed_on_another_thread() {
        // The whole POINT of the Arc<AtomicBool> is cross-thread/task visibility:
        // a controller (the cancel endpoint / Ctrl-C / wall-time watchdog) cancels
        // on one thread while the engine and modules poll their own clones on
        // others. The single-threaded clone tests above never exercise that. Prove
        // a `cancel()` on this thread becomes visible to a poll on a spawned thread
        // — the actual release/acquire contract the primitive exists to provide.
        let controller = CancelHandle::new();
        let worker = controller.clone();
        let handle = std::thread::spawn(move || {
            // Bounded spin: return whether cancellation became visible, so a broken
            // (never-propagating) impl fails the assertion fast instead of hanging.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !worker.is_cancelled() {
                if std::time::Instant::now() >= deadline {
                    return false;
                }
                std::thread::yield_now();
            }
            true
        });
        controller.cancel();
        assert!(
            handle.join().expect("should succeed"),
            "cancel() must become visible to is_cancelled() on another thread",
        );
        assert!(controller.is_cancelled());
    }

    #[test]
    fn clone_taken_after_cancel_observes_it() {
        // A handle cloned AFTER cancellation — e.g. a module dispatched late in the
        // scan receiving its ModuleContext clone — must still see the already-set
        // flag. Clones share one atomic, not a point-in-time snapshot.
        let h = CancelHandle::new();
        h.cancel();
        let late = h.clone();
        assert!(late.is_cancelled(), "a clone taken after cancel must observe it");
    }

    #[test]
    fn a_guards_scan_id_is_registered_for_as_long_as_it_can_be_read() {
        // The live loop reads its iteration's id back out of the guard rather
        // than minting it beside one, so the id it announces is one the
        // registry already holds (REQ-SSE-001). That only works if the guard
        // hands back exactly the key it registered.
        let registry = new_cancel_registry();
        let guard = CancelRegistryGuard::install(
            Arc::clone(&registry),
            "live-iteration".into(),
            CancelHandle::new(),
        );
        assert_eq!(guard.scan_id(), "live-iteration");
        assert!(registry.lock().contains_key(guard.scan_id()));
        drop(guard);
        assert!(registry.lock().is_empty());
    }
