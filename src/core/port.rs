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
//! Migration strategy (Strangler Fig):
//! 1. Introduce `StoragePort` (this commit) — `Store` implements it.
//! 2. Migrate `ScanEngine` to accept `Arc<dyn StoragePort>`.
//! 3. Migrate `Correlator` likewise.
//! 4. Remove all direct `Store` imports from `core/`.

use crate::core::{
    correlator::Correlation, entity::Entity, error::Result, event::Event, scan::Scan,
};

pub trait StoragePort: Send + Sync {
    // ── Scans ──────────────────────────────────────────────────────────────
    fn upsert_scan(&self, scan: &Scan) -> Result<()>;
    fn get_scan(&self, id: &str) -> Result<Option<Scan>>;
    fn list_scans(&self, limit: usize) -> Result<Vec<Scan>>;
    fn delete_scan(&self, scan_id: &str) -> Result<bool>;

    // ── Entities ───────────────────────────────────────────────────────────
    fn upsert_entity(&self, entity: &Entity) -> Result<()>;
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

    // ── Events ─────────────────────────────────────────────────────────────
    fn insert_event(&self, event: &Event) -> Result<()>;
    fn events_for_scan(&self, scan_id: &str) -> Result<Vec<Event>>;
}
