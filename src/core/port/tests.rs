use super::*;
    use std::sync::Arc;

    use crate::core::entity::EntityKind;
    use crate::core::scan::{Target, TargetKind};

    fn tmp_store() -> Arc<dyn StoragePort> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static CTR: AtomicUsize = AtomicUsize::new(0);
        let n = CTR.fetch_add(1, Ordering::SeqCst);
        let path = format!(
            "{}/.hse-port-test-{}-{}.db",
            std::env::temp_dir().to_string_lossy(),
            std::process::id(),
            n
        );
        let _ = std::fs::remove_file(&path);
        Arc::new(crate::storage::Store::open(&path).expect("should succeed"))
    }

    #[test]
    fn trait_object_scan_round_trip() {
        let store = tmp_store();
        let target = Target::new(TargetKind::Email, "x@y.com");
        let scan = Scan::new("port-scan-1", target);
        store.upsert_scan(&scan).expect("should succeed");
        let got = store.get_scan("port-scan-1").expect("should succeed").expect("should succeed");
        assert_eq!(got.id, "port-scan-1");
    }

    #[test]
    fn trait_object_entity_round_trip() {
        let store = tmp_store();
        let target = Target::new(TargetKind::Email, "x@y.com");
        let scan = Scan::new("port-ent", target);
        store.upsert_scan(&scan).expect("should succeed");

        let e = crate::core::entity::Entity::new(EntityKind::Email, "a@b.com", 0.8, "port-ent");
        store.upsert_entity(&e).expect("should succeed");

        let entities = store.entities_for_scan("port-ent").expect("should succeed");
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].value, "a@b.com");

        let got = store.get_entity(&e.uid).expect("should succeed").expect("should succeed");
        assert_eq!(got.uid, e.uid);
    }

    #[test]
    fn trait_object_list_and_delete() {
        let store = tmp_store();
        let t = Target::new(TargetKind::Domain, "example.com");
        store.upsert_scan(&Scan::new("ld-1", t.clone())).expect("should succeed");
        store.upsert_scan(&Scan::new("ld-2", t)).expect("should succeed");

        assert_eq!(store.list_scans(10).expect("should succeed").len(), 2);
        assert!(store.delete_scan("ld-1").expect("should succeed"));
        assert_eq!(store.list_scans(10).expect("should succeed").len(), 1);
    }

    #[test]
    fn trait_object_events_round_trip() {
        let store = tmp_store();
        let t = Target::new(TargetKind::Email, "x@y.com");
        store.upsert_scan(&Scan::new("evt-port", t)).expect("should succeed");

        let event = Event::new(
            "evt-port",
            crate::core::event::EventKind::ModuleStart {
                module: "test".into(),
            },
        );
        store.insert_event(&event).expect("should succeed");

        let events = store.events_for_scan("evt-port").expect("should succeed");
        assert_eq!(events.len(), 1);

        // prune_events via the trait object — the path the engine uses at
        // each scan boundary. A fresh event under the caps survives...
        let pruned = store
            .prune_events(
                crate::core::port::EVENTS_RETENTION_SECS,
                crate::core::port::EVENTS_MAX_ROWS,
            )
            .expect("should succeed");
        assert_eq!(pruned, 0);
        assert_eq!(store.events_for_scan("evt-port").expect("should succeed").len(), 1);
        // ...but a zero row-cap prunes it as excess.
        let pruned = store
            .prune_events(crate::core::port::EVENTS_RETENTION_SECS, 0)
            .expect("should succeed");
        assert!(pruned >= 1);
        assert!(store.events_for_scan("evt-port").expect("should succeed").is_empty());
    }

    #[test]
    fn default_optional_methods_are_documented_no_ops() {
        // Seven methods carry no-op defaults "for test doubles". `InMemoryStore`
        // overrides NONE of them, so it is the exact contract a non-SQLite backend
        // (or mock) inherits, and the engine hits these defaults through it at
        // every scan boundary (checkpoint/prune) and cache lookup. Exercise each
        // through the trait object (the real dyn-dispatch path) and pin its
        // documented return, so a future edit to a default body can't silently
        // change what a non-overriding backend gets. Complements the round-trip
        // tests above, which drive the concrete SQLite `Store` overrides.
        let store: Arc<dyn StoragePort> = Arc::new(crate::core::test_support::InMemoryStore::new());

        // Inter-scan entity cache: archive succeeds (best-effort), lookup misses.
        assert!(store.archive_module_result("k", 3600, &[]).is_ok());
        // `Entity` has no `PartialEq`, so assert the miss via `is_none`.
        assert!(store.lookup_module_result_fresh("k").expect("should succeed").is_none());

        // Pathway-template learning: record succeeds, count never credits a route.
        assert!(store.record_pathway_template("a>b").is_ok());
        assert_eq!(store.pathway_template_count("a>b").expect("should succeed"), 0);

        // Maintenance: checkpoint is a no-op Ok; both prunes report zero removed.
        assert!(store.checkpoint_truncate().is_ok());
        assert_eq!(
            store
                .prune_events(EVENTS_RETENTION_SECS, EVENTS_MAX_ROWS)
                .expect("should succeed"),
            0
        );
        assert_eq!(store.prune_raw_archive(RAW_ARCHIVE_MAX_ROWS).expect("should succeed"), 0);
    }

    #[test]
    fn trait_object_search_and_facets() {
        let store = tmp_store();
        let t = Target::new(TargetKind::Email, "x@y.com");
        store.upsert_scan(&Scan::new("sf-scan", t)).expect("should succeed");

        let e1 = crate::core::entity::Entity::new(EntityKind::Email, "alice@x.com", 0.9, "sf-scan");
        let e2 = crate::core::entity::Entity::new(EntityKind::Domain, "x.com", 0.8, "sf-scan");
        store.upsert_entity(&e1).expect("should succeed");
        store.upsert_entity(&e2).expect("should succeed");

        let results = store.search_entities("alice", 10).expect("should succeed");
        assert_eq!(results.len(), 1);

        let facets = store.entity_facets("sf-scan").expect("should succeed");
        assert!(!facets.is_empty());
    }
