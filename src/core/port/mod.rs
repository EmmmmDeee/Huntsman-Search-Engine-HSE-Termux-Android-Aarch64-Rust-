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
//! and fail CI if a direct import is introduced. Shared runtime construction
//! belongs to `app::runtime`, which opens the concrete store and immediately
//! upcasts it to `Arc<dyn StoragePort>` for the CLI and HTTP adapters.

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
    /// Chronological (newest-first) list of past radar sweeps — scans whose
    /// target is one of the radar endpoints' sentinel anchors. See
    /// `crate::storage::Store::radar_history` for the full rationale.
    fn radar_history(&self, limit: usize) -> Result<Vec<Scan>>;
    fn delete_scan(&self, scan_id: &str) -> Result<bool>;

    // ── Entities ───────────────────────────────────────────────────────────
    fn upsert_entity(&self, entity: &Entity) -> Result<()>;
    /// Persist many entities in a single transaction. Takes a slice (not
    /// an owned `Vec`) so the caller retains ownership and can fall back
    /// to per-entity `upsert_entity` if the batch rolls back.
    fn upsert_entities_batch(&self, entities: &[Entity]) -> Result<usize>;
    fn entities_for_scan(&self, scan_id: &str) -> Result<Vec<Entity>>;
    /// Remove the given entity uids from this scan's view (delete their
    /// `entity_observations` rows for `scan_id`) and clean up any entity left
    /// with no remaining observations. Used at finalise to purge the stale rows
    /// of address-locality variants folded away by `consolidate_address_localities`
    /// — those variants were checkpointed pre-finalise, and the finalise
    /// correlator reads the persisted scan, so they would otherwise double-count.
    /// Returns the number of observations removed.
    fn delete_scan_entities(&self, scan_id: &str, uids: &[String]) -> Result<usize>;
    /// Filtered scan entities, confidence-DESC. `limit` bounds the SQL result
    /// (top-N by confidence) — `Some(n)` for a memory-bounded read (recall),
    /// `None` for the deliberately-unbounded UI/facets set.
    fn entities_filtered(
        &self,
        scan_id: &str,
        kind: Option<&str>,
        min_confidence: Option<f64>,
        value_contains: Option<&str>,
        limit: Option<usize>,
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
    /// Persist many relations in a single transaction. The default loops
    /// [`upsert_relation`](Self::upsert_relation) so in-memory / test impls
    /// need no change; the SQLite store overrides it to avoid an autocommit
    /// (BEGIN/COMMIT + fsync) per edge at finalise. Takes a slice so the
    /// caller can fall back to per-relation persistence if the batch rolls back.
    fn upsert_relations_batch(&self, rels: &[Relation]) -> Result<usize> {
        for r in rels {
            self.upsert_relation(r)?;
        }
        Ok(rels.len())
    }
    fn relations_for_scan(&self, scan_id: &str) -> Result<Vec<Relation>>;

    // ── Events ─────────────────────────────────────────────────────────────
    fn insert_event(&self, event: &Event) -> Result<()>;
    /// Insert many events in a single transaction. The default loops
    /// [`insert_event`](Self::insert_event); the SQLite store overrides it so
    /// the db-writer's coalesced ≤64-event drain commits once (one fsync on a
    /// phone's flash filesystem) instead of once per event. Slice-taking so the
    /// caller can fall back to per-event insertion on a batch rollback.
    fn insert_events_batch(&self, events: &[Event]) -> Result<usize> {
        for e in events {
            self.insert_event(e)?;
        }
        Ok(events.len())
    }
    fn events_for_scan(&self, scan_id: &str) -> Result<Vec<Event>>;

    /// Recent `ModuleDone`/`ModuleError` outcome events across ALL scans,
    /// newest-first, bounded to `limit` — the substrate for
    /// `util::scraper_health`'s per-source health signal (`hse doctor`'s
    /// "Scraper health" section and the SPA's Engines-page panel). Default
    /// empty for test doubles; the real impl lives on `Store`.
    fn recent_module_outcome_events(&self, _limit: usize) -> Result<Vec<Event>> {
        Ok(Vec::new())
    }

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

    // ── Stealer-log credential rows (Stealer Logs Viewer) ───────────────────
    /// Persist paired stealer-log credential rows for one scan/import.
    /// Best-effort, called only from the stealer-log importer. Default no-op
    /// for test doubles; the SQLite `Store` persists to `stealer_rows`.
    fn insert_stealer_rows_batch(
        &self,
        _scan_id: &str,
        _rows: &[crate::core::stealer_row::StealerRow],
    ) -> Result<usize> {
        Ok(0)
    }

    /// Every persisted stealer-log credential row for a scan, insertion
    /// order. Default empty for test doubles; the SQLite `Store` reads
    /// `stealer_rows`.
    fn stealer_rows_for_scan(
        &self,
        _scan_id: &str,
    ) -> Result<Vec<crate::core::stealer_row::StealerRow>> {
        Ok(Vec::new())
    }

    // ── Maintenance ─────────────────────────────────────────────────────────
    /// Bound the backing store's write-ahead footprint at a safe boundary
    /// (e.g. a completed scan). Default is a no-op for backends without a
    /// WAL; the SQLite store truncates its `-wal` file. Best-effort.
    fn checkpoint_truncate(&self) -> Result<()> {
        Ok(())
    }

    /// Run the backing store's integrity check, returning the check rows —
    /// exactly `["ok"]` for a healthy database, or one or more problem
    /// descriptions for a corrupt one. Default `["ok"]` for backends without a
    /// verifier (test doubles); the SQLite store runs `PRAGMA integrity_check`.
    /// Surfaced by the system debug bundle so on-disk corruption — invisible to
    /// every other health signal — reaches the DETECTED ISSUES verdict.
    fn integrity_check(&self) -> Result<Vec<String>> {
        Ok(vec!["ok".to_string()])
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
