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
        let store = Store::open(":memory:").expect("should succeed");
<<<<<<< HEAD
        let err = crate::app::runtime::resolve_scan_id(&store, "deadbeef").expect("should be an error");
=======
        let err = crate::app::runtime::resolve_scan_id(&store, "deadbeef").expect_err("should be an error");
>>>>>>> origin/main
        assert!(
            err.to_string().contains("deadbeef"),
            "error should name the missing scan: {err}"
        );
    }

    #[test]
    fn resolve_latest_errors_when_store_empty() {
        let store = Store::open(":memory:").expect("should succeed");
        assert!(crate::app::runtime::resolve_scan_id(&store, "latest").is_err());
    }

    #[test]
    fn load_side_tags_store_scans_with_their_id_for_self_diff_guard() {
        // A store-scan side carries its resolved id; two sides resolving to the
        // same id is what `cmd_diff` detects as a self-diff. Seed a scan and
        // confirm both the id is set and it round-trips equal for the same arg.
        use crate::core::scan::{Scan, ScanStatus, Target, TargetKind};
        let store = Store::open(":memory:").expect("should succeed");
        let mut scan = Scan::new("scan-x", Target::new(TargetKind::Domain, "example.com"));
        scan.status = ScanStatus::Complete;
        store.upsert_scan(&scan).expect("should succeed");
        store
            .upsert_entity(&Entity::new(
                EntityKind::Domain,
                "example.com",
                0.9,
                "scan-x",
            ))
            .expect("should succeed");

        let a = load_side(&store, "scan-x").expect("should succeed");
        let b = load_side(&store, "scan-x").expect("should succeed");
        assert_eq!(a.scan_id.as_deref(), Some("scan-x"));
        assert_eq!(a.scan_id, b.scan_id, "same arg → same id → self-diff");
        assert_eq!(a.entities.len(), 1);
    }

    #[test]
    fn load_side_strips_quarantined_candidate_entities_from_a_scan() {
        // A candidate-tagged entity (a breach co-occurrence "stranger" — non-
        // subject PII) must never surface from the scan-id branch, matching the
        // export path's `confirmed_entities` filter. Otherwise it leaks as
        // foreign PII in the diff output, and — for the documented
        // export-then-diff workflow — every candidate on a re-scan would show
        // up as spuriously "added" even when nothing about the target changed.
        use crate::core::scan::{Scan, ScanStatus, Target, TargetKind};
        let store = Store::open(":memory:").expect("should succeed");
        let mut scan = Scan::new("scan-y", Target::new(TargetKind::Domain, "example.org"));
        scan.status = ScanStatus::Complete;
        store.upsert_scan(&scan).expect("should succeed");
        store
            .upsert_entity(&Entity::new(
                EntityKind::Domain,
                "example.org",
                0.9,
                "scan-y",
            ))
            .expect("should succeed");
        let mut stranger = Entity::new(EntityKind::Email, "stranger@other.com", 0.4, "scan-y");
        stranger.tag(crate::core::tags::CANDIDATE);
        store.upsert_entity(&stranger).expect("should succeed");

        let side = load_side(&store, "scan-y").expect("should succeed");
        assert_eq!(
            side.entities.len(),
            1,
            "the candidate-tagged stranger must be stripped, not just the confirmed domain: {:?}",
            side.entities.iter().map(|e| &e.value).collect::<Vec<_>>()
        );
        assert!(
            !side
                .entities
                .iter()
                .any(|e| e.has_tag(crate::core::tags::CANDIDATE)),
            "no remaining entity may carry the candidate tag"
        );
    }

    #[test]
    fn load_side_reads_json_entity_snapshot_file() {
        let store = Store::open(":memory:").expect("should succeed");
        let ents = vec![Entity::new(EntityKind::Email, "a@b.com", 0.8, "s")];
        let json = serde_json::to_string(&ents).expect("should succeed");
        let path = std::env::temp_dir().join(format!(
            "hse-diff-snap-{}-{}.json",
            std::process::id(),
            "load"
        ));
        std::fs::write(&path, json).expect("should succeed");
        let loaded = load_side(&store, path.to_str().expect("should succeed")).expect("should succeed");
        assert_eq!(loaded.entities.len(), 1);
        assert_eq!(loaded.entities[0].value, "a@b.com");
        // A snapshot-file side carries no scan id (so it's never flagged as a
        // same-scan self-diff).
        assert!(loaded.scan_id.is_none());
        let _ = std::fs::remove_file(&path);
    }
