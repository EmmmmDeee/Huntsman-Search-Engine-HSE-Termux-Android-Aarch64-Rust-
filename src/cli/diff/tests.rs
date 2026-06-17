use super::*;
    use crate::core::entity::EntityKind;

    #[test]
    fn label_truncates_long_ids_keeps_short_args() {
        assert_eq!(label("0123456789abcdef0123"), "0123456789abcdef…");
        assert_eq!(label("snapshot.json"), "snapshot.json");
        assert_eq!(label(""), "");
    }

    #[test]
    fn resolve_errors_on_unknown_scan() {
        let store = Store::open(":memory:").unwrap();
        let err = crate::cli::resolve_scan_id(&store, "deadbeef").unwrap_err();
        assert!(
            err.to_string().contains("deadbeef"),
            "error should name the missing scan: {err}"
        );
    }

    #[test]
    fn resolve_latest_errors_when_store_empty() {
        let store = Store::open(":memory:").unwrap();
        assert!(crate::cli::resolve_scan_id(&store, "latest").is_err());
    }

    #[test]
    fn load_side_tags_store_scans_with_their_id_for_self_diff_guard() {
        // A store-scan side carries its resolved id; two sides resolving to the
        // same id is what `cmd_diff` detects as a self-diff. Seed a scan and
        // confirm both the id is set and it round-trips equal for the same arg.
        use crate::core::scan::{Scan, ScanStatus, Target, TargetKind};
        let store = Store::open(":memory:").unwrap();
        let mut scan = Scan::new("scan-x", Target::new(TargetKind::Domain, "example.com"));
        scan.status = ScanStatus::Complete;
        store.upsert_scan(&scan).unwrap();
        store
            .upsert_entity(&Entity::new(
                EntityKind::Domain,
                "example.com",
                0.9,
                "scan-x",
            ))
            .unwrap();

        let a = load_side(&store, "scan-x").unwrap();
        let b = load_side(&store, "scan-x").unwrap();
        assert_eq!(a.scan_id.as_deref(), Some("scan-x"));
        assert_eq!(a.scan_id, b.scan_id, "same arg → same id → self-diff");
        assert_eq!(a.entities.len(), 1);
    }

    #[test]
    fn load_side_reads_json_entity_snapshot_file() {
        let store = Store::open(":memory:").unwrap();
        let ents = vec![Entity::new(EntityKind::Email, "a@b.com", 0.8, "s")];
        let json = serde_json::to_string(&ents).unwrap();
        let path = std::env::temp_dir().join(format!(
            "hse-diff-snap-{}-{}.json",
            std::process::id(),
            "load"
        ));
        std::fs::write(&path, json).unwrap();
        let loaded = load_side(&store, path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.entities.len(), 1);
        assert_eq!(loaded.entities[0].value, "a@b.com");
        // A snapshot-file side carries no scan id (so it's never flagged as a
        // same-scan self-diff).
        assert!(loaded.scan_id.is_none());
        let _ = std::fs::remove_file(&path);
    }
