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

        let stored = registry.lock().get("scan-2").cloned().unwrap();
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
