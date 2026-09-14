use super::*;
    use std::sync::Arc;

    use crate::core::entity::EntityKind;
    use crate::core::scan::{Target, TargetKind};

    fn tmp_store() -> Arc<dyn StoragePort> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static CTR: AtomicUsize = AtomicUsize::new(0);
        static SWEPT: std::sync::Once = std::sync::Once::new();
        SWEPT.call_once(sweep_stale_test_dbs);
        let n = CTR.fetch_add(1, Ordering::SeqCst);
        let path = format!(
            "{}/.hse-port-test-{}-{}.db",
            std::env::temp_dir().to_string_lossy(),
            std::process::id(),
            n
        );
        Arc::new(crate::storage::Store::open(&path).expect("should succeed"))
    }

    /// Removes every `.hse-port-test-<pid>-<n>.db` file (and its `-wal`/
    /// `-shm` sidecars, on the off chance a crashed test left one behind —
    /// SQLite's normal clean close already checkpoints them away, which is
    /// why none were found in practice) left by a past, now-dead process.
    /// The single `remove_file` this replaced inside `tmp_store` itself
    /// could never match: it targeted a path built from THIS process's own
    /// pid and a counter that starts fresh at 0 every process, so it names a
    /// file that has never existed before the call that constructs it — a
    /// permanent no-op, the same shape found in this session's sibling
    /// `storage::tests::tmp_db`. Confirmed live: 665 leftover files (123MB)
    /// spanning the same 133 distinct process ids as that sibling leak had
    /// accumulated under `/tmp` before this fix. A file is swept only once
    /// its exact pid is confirmed dead via `/proc/<pid>` — never by name
    /// pattern alone, since several test binaries can legitimately run
    /// concurrently under different, simultaneously-live pids.
    fn sweep_stale_test_dbs() {
        let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(rest) = name.strip_prefix(".hse-port-test-") else {
                continue;
            };
            let core = rest
                .strip_suffix(".db-wal")
                .or_else(|| rest.strip_suffix(".db-shm"))
                .or_else(|| rest.strip_suffix(".db"))
                .unwrap_or(rest);
            let Some((pid_str, _n)) = core.split_once('-') else {
                continue;
            };
            let Ok(pid) = pid_str.parse::<u32>() else {
                continue;
            };
            if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    #[test]
    fn sweep_stale_test_dbs_removes_a_dead_pid_but_never_a_live_one() {
        let base = std::env::temp_dir();
        // A pid far past any real process's range: guaranteed dead, so its
        // file must be swept.
        let dead = base.join(".hse-port-test-999999999-0.db");
        std::fs::write(&dead, b"stale").expect("should succeed");
        // This test's OWN process is unquestionably alive, so a file
        // stamped with its real pid must survive the sweep untouched.
        let live = base.join(format!(".hse-port-test-{}-999999.db", std::process::id()));
        std::fs::write(&live, b"live").expect("should succeed");
        // An unrelated file that merely shares the temp dir must never be
        // touched by name-pattern matching alone.
        let unrelated = base.join(".hse-port-test-not-a-pid.db");
        std::fs::write(&unrelated, b"unrelated").expect("should succeed");

        sweep_stale_test_dbs();

        assert!(!dead.exists(), "a file whose pid is confirmed dead must be swept");
        assert!(
            live.exists(),
            "a file stamped with this (live) process's own pid must never be swept"
        );
        assert!(
            unrelated.exists(),
            "a non-numeric suffix must never be treated as a pid and swept"
        );

        let _ = std::fs::remove_file(&live);
        let _ = std::fs::remove_file(&unrelated);
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
        // ...and so does a zero row-cap while the scan is still live: a
        // pending/running scan's own log is exempt from the excess cut (see
        // `Store::prune_events`), so a sibling scan's finalise-time prune can
        // never truncate a scan that has not finished.
        let pruned = store
            .prune_events(crate::core::port::EVENTS_RETENTION_SECS, 0)
            .expect("should succeed");
        assert_eq!(pruned, 0, "a live scan's events are never pruned as excess");
        assert_eq!(store.events_for_scan("evt-port").expect("should succeed").len(), 1);
        // Once the scan has finished, the same zero cap prunes it as excess.
        let mut finished = Scan::new("evt-port", Target::new(TargetKind::Email, "x@y.com"));
        finished.status = crate::core::scan::ScanStatus::Complete;
        store.upsert_scan(&finished).expect("should succeed");
        let pruned = store
            .prune_events(crate::core::port::EVENTS_RETENTION_SECS, 0)
            .expect("should succeed");
        assert!(pruned >= 1);
        assert!(store.events_for_scan("evt-port").expect("should succeed").is_empty());
    }

    #[test]
    fn default_optional_methods_are_documented_no_ops() {
        // Five methods still carry the trait's no-op default for `InMemoryStore`
        // (pathway-template learning, checkpoint, both prunes), and the engine
        // hits these defaults through it at every scan boundary. The remaining
        // two — the inter-scan entity cache — were deliberately given REAL
        // in-memory semantics instead (see `InMemoryStore::archive_module_result`/
        // `lookup_module_result_fresh`): a no-op cache made the dispatch-level
        // cache-hit-skips-`process()` path structurally untestable against this
        // port, which is exactly the gap
        // `core::engine::tests::cache_hit_skips_reprocessing_a_later_scan_of_the_same_target`
        // closes (REQ-CORE-009). Exercise each through the trait object (the
        // real dyn-dispatch path) and pin its documented return, so a future
        // edit to a default/override body can't silently change what a
        // non-SQLite backend gets. Complements the round-trip tests above,
        // which drive the concrete SQLite `Store` overrides.
        let store: Arc<dyn StoragePort> = Arc::new(crate::core::test_support::InMemoryStore::new());

        // Inter-scan entity cache: now a genuine round-trip, not a no-op — a
        // fresh archive is a real hit, and an unarchived key still misses.
        // `Entity` has no `PartialEq`, so assert the hit via its length.
        assert!(store.archive_module_result("k", 3600, &[]).is_ok());
        let hit = store.lookup_module_result_fresh("k").expect("should succeed");
        assert_eq!(
            hit.map(|v| v.len()),
            Some(0),
            "a fresh archive must be a genuine hit, not the old no-op miss"
        );
        assert!(
            store
                .lookup_module_result_fresh("unarchived-key")
                .expect("should succeed")
                .is_none(),
            "a key that was never archived must still miss"
        );

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
        assert_eq!(store.prune_module_result_cache(MODULE_RESULT_CACHE_MAX_ROWS).expect("should succeed"), 0);
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
