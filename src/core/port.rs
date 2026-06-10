//! Storage port — trait-based boundary between the engine and its
//! persistence layer.
//!
//! # Architecture
//!
//! `StoragePort` defines the minimal contract the scan engine and
//! correlator need from storage. The concrete `Store` (SQLite WAL)
//! implements this trait. By depending on the trait rather than the
//! concrete type, the engine becomes:
//!
//! - **Testable** without SQLite: tests can inject a mock/stub.
//! - **Replaceable**: a future PostgreSQL or in-memory backend only
//!   needs to implement `StoragePort`.
//! - **Boundary-explicit**: the engine's storage needs are enumerated
//!   in one place.
//!
//! # Boundary enforcement
//!
//! `core/` and `api/` never import `storage::Store` directly —
//! architecture tests in `tests/architecture.rs` scan the source tree
//! and fail CI if a direct import is introduced. The only legitimate
//! `Store::open()` call sites are the CLI composition roots
//! (`cli/mod.rs`, `cli/provision.rs`) which construct the concrete
//! instance and immediately upcast to `Arc<dyn StoragePort>`.

use crate::core::{
    correlator::Correlation, entity::Entity, error::Result, event::Event, relation::Relation,
    scan::Scan,
};

/// Retention policy for the `events` table, shared by the startup prune
/// (`cli`) and the per-scan-boundary prune (engine) so the two can't drift.
pub const EVENTS_RETENTION_SECS: u64 = 7 * 86_400; // 7 days
pub const EVENTS_MAX_ROWS: usize = 100_000;

pub trait StoragePort: Send + Sync {
    // ── Scans ──────────────────────────────────────────────────────────────
    fn upsert_scan(&self, scan: &Scan) -> Result<()>;
    fn get_scan(&self, id: &str) -> Result<Option<Scan>>;
    fn list_scans(&self, limit: usize) -> Result<Vec<Scan>>;
    fn delete_scan(&self, scan_id: &str) -> Result<bool>;

    // ── Entities ───────────────────────────────────────────────────────────
    fn upsert_entity(&self, entity: &Entity) -> Result<()>;
    /// Persist many entities in a single transaction. Takes a slice (not
    /// an owned `Vec`) so the caller retains ownership and can fall back
    /// to per-entity `upsert_entity` if the batch rolls back.
    fn upsert_entities_batch(&self, entities: &[Entity]) -> Result<usize>;
    fn entities_for_scan(&self, scan_id: &str) -> Result<Vec<Entity>>;
    fn entities_filtered(
        &self,
        scan_id: &str,
        kind: Option<&str>,
        min_confidence: Option<f64>,
        value_contains: Option<&str>,
    ) -> Result<Vec<Entity>>;
    fn entity_facets(&self, scan_id: &str) -> Result<Vec<(String, u64)>>;
    fn get_entity(&self, uid: &str) -> Result<Option<Entity>>;
    fn search_entities(&self, query: &str, limit: usize) -> Result<Vec<Entity>>;
    fn scan_ids_for_entity(&self, entity_uid: &str) -> Result<Vec<String>>;
    fn observation_count(&self, entity_uid: &str) -> Result<usize>;

    // ── Correlations ───────────────────────────────────────────────────────
    fn upsert_correlation(&self, c: &Correlation) -> Result<()>;
    fn correlations_for_scan(&self, scan_id: &str) -> Result<Vec<Correlation>>;

    // ── Relations (typed entity-to-entity edges) ────────────────────────────
    fn upsert_relation(&self, r: &Relation) -> Result<()>;
    fn relations_for_scan(&self, scan_id: &str) -> Result<Vec<Relation>>;

    // ── Events ─────────────────────────────────────────────────────────────
    fn insert_event(&self, event: &Event) -> Result<()>;
    fn events_for_scan(&self, scan_id: &str) -> Result<Vec<Event>>;

    // ── Maintenance ─────────────────────────────────────────────────────────
    /// Bound the backing store's write-ahead footprint at a safe boundary
    /// (e.g. a completed scan). Default is a no-op for backends without a
    /// WAL; the SQLite store truncates its `-wal` file. Best-effort.
    fn checkpoint_truncate(&self) -> Result<()> {
        Ok(())
    }

    /// Bound the `events` table: delete rows older than `max_age_secs` and
    /// any beyond the newest `max_rows`. Returns the number pruned. Default
    /// no-op so non-`Store` ports (e.g. test doubles) need not implement it;
    /// the real impl lives on `Store`. Called at each scan boundary so a
    /// long-lived `serve`/`live`/`radar` process can't grow the table
    /// unbounded (it was previously pruned only at startup).
    fn prune_events(&self, _max_age_secs: u64, _max_rows: usize) -> Result<usize> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
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
}
