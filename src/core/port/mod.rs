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

/// Row cap for the `raw_archive` inter-scan cache, pruned at the same lifecycle
/// points as [`EVENTS_MAX_ROWS`]. Expired rows (past their per-entry TTL) are
/// always deleted; this additionally caps the newest retained rows so scanning
/// many distinct `(module, target)` pairs can't grow the table (and the DB/WAL)
/// without bound on a low-disk device. The cache is best-effort, so evicting a
/// still-fresh row only costs a re-query, never correctness.
pub const RAW_ARCHIVE_MAX_ROWS: usize = 20_000;

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

    // ── Cross-scan pathway-template learning (C1 universal linking) ───────────
    /// Record that a direction-canonical pathway `template` was confirmed by a
    /// scan, incrementing its cross-scan seen-count. Best-effort; callers ignore
    /// the error. Default no-op for test doubles; the SQLite `Store` persists to
    /// `pathway_templates`.
    fn record_pathway_template(&self, _template: &str) -> Result<()> {
        Ok(())
    }

    /// The number of *earlier* scans that confirmed `template` (0 if never).
    /// Consulted before the current scan records its own templates, so a
    /// non-zero count credits a route proven in a strictly earlier scan. Default
    /// `0` for test doubles.
    fn pathway_template_count(&self, _template: &str) -> Result<u32> {
        Ok(0)
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

    /// Bound the `raw_archive` inter-scan cache: delete rows past their per-entry
    /// TTL, then cap the table to the newest `max_rows`. Returns the number
    /// pruned. Default no-op for non-`Store` ports; the real impl lives on
    /// `Store`. Called at the same lifecycle points as [`Self::prune_events`] so a
    /// long-lived `serve`/`live`/`radar` process scanning many distinct targets
    /// can't grow the cache (and the DB/WAL) without bound.
    fn prune_raw_archive(&self, _max_rows: usize) -> Result<usize> {
        Ok(0)
    }
}

/// Compile-time proof that `StoragePort` stays usable as `Arc<dyn StoragePort>`.
///
/// The entire boundary design (and ~11 call sites: `AppState.store` shared across
/// `tokio` tasks, the engine, the correlator, the CLI composition roots) depends
/// on `StoragePort` being **dyn-compatible** (object-safe) AND
/// `dyn StoragePort: Send + Sync + 'static`. A method that broke dyn-compatibility
/// — a generic type parameter, a `-> Self` return, an `impl Trait` argument, a
/// `const` fn — or a supertrait change that dropped `Send`/`Sync` would otherwise
/// fail far away at a `Arc<dyn StoragePort>` use site with an opaque error. This
/// assertion localises that guarantee to the trait definition: adding such a
/// method fails to compile right here, next to the doc that explains why.
const _: fn() = || {
    fn assert_dyn_send_sync_static<T: ?Sized + Send + Sync + 'static>() {}
    assert_dyn_send_sync_static::<dyn StoragePort>();
};

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
