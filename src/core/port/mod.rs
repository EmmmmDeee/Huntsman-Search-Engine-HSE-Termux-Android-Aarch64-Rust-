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

// ── Module health types (T2.7 / SOL-HEALTH-SIGNAL) ────────────────────────

/// Outcome of one module dispatch run passed to
/// [`StoragePort::record_module_run`].
#[derive(Debug)]
pub enum ModuleRunOutcome {
    Success { result_count: usize },
    Error { message: String },
    Timeout,
}

/// One row from [`StoragePort::module_health_summary`]: the lifetime health
/// counters for a single module, ordered by descending `consecutive_failures`.
#[derive(Debug)]
pub struct ModuleHealthRow {
    pub module_name: String,
    /// Unix timestamp of the last successful run, or `None` if the module has
    /// never succeeded since health tracking started.
    pub last_success_at: Option<u64>,
    pub last_failure_at: Option<u64>,
    /// Current unbroken failure streak (reset to 0 on any success).
    pub consecutive_failures: u64,
    pub total_runs: u64,
    pub total_successes: u64,
    /// Error message / `"timeout"` from the most recent non-success run.
    pub last_error: Option<String>,
    pub updated_at: u64,
}

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

    // ── Inter-scan entity cache (C9 / SOL-CACHE-INTERSCAN) ────────────────
    /// Persist a module result under `key` with a TTL. Called after a
    /// successful `process()` when `module.cache_ttl_secs() > 0`. Best-effort:
    /// a failure must not abort the scan; callers ignore the error.
    ///
    /// Default no-op for test doubles; the SQLite `Store` persists to
    /// `raw_archive`.
    fn archive_module_result(
        &self,
        _key: &str,
        _ttl_secs: u64,
        _entities: &[Entity],
    ) -> Result<()> {
        Ok(())
    }

    /// Return a previously-archived module result if it is still within its
    /// TTL, or `None` if absent or expired. Called before `process()` when
    /// `module.cache_ttl_secs() > 0`; a `Some` return short-circuits the
    /// provider call entirely.
    ///
    /// Default no-op returns `None` for test doubles.
    fn lookup_module_result_fresh(&self, _key: &str) -> Result<Option<Vec<Entity>>> {
        Ok(None)
    }

    // ── Module health (T2.7 / SOL-HEALTH-SIGNAL) ──────────────────────────

    /// Record the outcome of one module dispatch run in the per-module health
    /// ledger. Called by the engine after every `process()` invocation (except
    /// `MissingKey` skips, which are not failures). Best-effort — a write
    /// failure must never abort the scan; callers use `let _ = …`.
    ///
    /// Default no-op so test doubles and non-SQLite backends need not
    /// implement it.
    fn record_module_run(&self, _module_name: &str, _outcome: &ModuleRunOutcome) -> Result<()> {
        Ok(())
    }

    /// Return a health summary for every module that has been run, ordered by
    /// descending `consecutive_failures` then ascending `module_name`. Modules
    /// with a `consecutive_failures` streak ≥ 3 are flagged as degraded by
    /// `hse doctor` and the SPA dashboard.
    ///
    /// Default empty vec so test doubles and non-SQLite backends compile
    /// without implementing it.
    fn module_health_summary(&self) -> Result<Vec<ModuleHealthRow>> {
        Ok(vec![])
    }

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
    include!("tests.rs");
}
