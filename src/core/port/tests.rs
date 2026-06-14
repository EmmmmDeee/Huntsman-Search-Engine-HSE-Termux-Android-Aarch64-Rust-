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
        Arc::new(crate::storage::Store::open(&path).unwrap())
    }

    #[test]
    fn trait_object_scan_round_trip() {
        let store = tmp_store();
        let target = Target::new(TargetKind::Email, "x@y.com");
        let scan = Scan::new("port-scan-1", target);
        store.upsert_scan(&scan).unwrap();
        let got = store.get_scan("port-scan-1").unwrap().unwrap();
        assert_eq!(got.id, "port-scan-1");
    }

    #[test]
    fn trait_object_entity_round_trip() {
        let store = tmp_store();
        let target = Target::new(TargetKind::Email, "x@y.com");
        let scan = Scan::new("port-ent", target);
        store.upsert_scan(&scan).unwrap();

        let e = crate::core::entity::Entity::new(EntityKind::Email, "a@b.com", 0.8, "port-ent");
        store.upsert_entity(&e).unwrap();

        let entities = store.entities_for_scan("port-ent").unwrap();
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].value, "a@b.com");

        let got = store.get_entity(&e.uid).unwrap().unwrap();
        assert_eq!(got.uid, e.uid);
    }

    #[test]
    fn trait_object_list_and_delete() {
        let store = tmp_store();
        let t = Target::new(TargetKind::Domain, "example.com");
        store.upsert_scan(&Scan::new("ld-1", t.clone())).unwrap();
        store.upsert_scan(&Scan::new("ld-2", t)).unwrap();

        assert_eq!(store.list_scans(10).unwrap().len(), 2);
        assert!(store.delete_scan("ld-1").unwrap());
        assert_eq!(store.list_scans(10).unwrap().len(), 1);
    }

    #[test]
    fn trait_object_events_round_trip() {
        let store = tmp_store();
        let t = Target::new(TargetKind::Email, "x@y.com");
        store.upsert_scan(&Scan::new("evt-port", t)).unwrap();

        let event = Event::new(
            "evt-port",
            crate::core::event::EventKind::ModuleStart {
                module: "test".into(),
            },
        );
        store.insert_event(&event).unwrap();

        let events = store.events_for_scan("evt-port").unwrap();
        assert_eq!(events.len(), 1);

        // prune_events via the trait object — the path the engine uses at
        // each scan boundary. A fresh event under the caps survives...
        let pruned = store
            .prune_events(
                crate::core::port::EVENTS_RETENTION_SECS,
                crate::core::port::EVENTS_MAX_ROWS,
            )
            .unwrap();
        assert_eq!(pruned, 0);
        assert_eq!(store.events_for_scan("evt-port").unwrap().len(), 1);
        // ...but a zero row-cap prunes it as excess.
        let pruned = store
            .prune_events(crate::core::port::EVENTS_RETENTION_SECS, 0)
            .unwrap();
        assert!(pruned >= 1);
        assert!(store.events_for_scan("evt-port").unwrap().is_empty());
    }

    #[test]
    fn trait_object_search_and_facets() {
        let store = tmp_store();
        let t = Target::new(TargetKind::Email, "x@y.com");
        store.upsert_scan(&Scan::new("sf-scan", t)).unwrap();

        let e1 = crate::core::entity::Entity::new(EntityKind::Email, "alice@x.com", 0.9, "sf-scan");
        let e2 = crate::core::entity::Entity::new(EntityKind::Domain, "x.com", 0.8, "sf-scan");
        store.upsert_entity(&e1).unwrap();
        store.upsert_entity(&e2).unwrap();

        let results = store.search_entities("alice", 10).unwrap();
        assert_eq!(results.len(), 1);

        let facets = store.entity_facets("sf-scan").unwrap();
        assert!(!facets.is_empty());
    }
