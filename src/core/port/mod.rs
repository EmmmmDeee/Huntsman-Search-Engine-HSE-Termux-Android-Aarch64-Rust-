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

/// One module result as the inter-scan entity cache (C9) holds it: the
/// entities, and the module's own completeness verdict
/// (`ModuleResult::truncation`).
///
/// The verdict travels with the entities because a replay IS the module's
/// answer for this scan: the engine emits the same `ModuleDone` for it, and
/// `core::coverage` reads completeness from that event alone. The cache held
/// entities only, so a partial answer replayed within its TTL was reported
/// complete on every re-scan (REQ-CACHE-001). Sightings and the link record are
/// deliberately NOT here: a replay observed nothing.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CachedModuleResult {
    /// The entities the module returned, stamped with the ARCHIVING scan's
    /// id; the engine re-stamps them to the replaying scan.
    pub entities: Vec<Entity>,
    /// `None` when the archived answer was complete.
    #[serde(default)]
    pub truncation: Option<String>,
}

/// Retention policy for the `events` table, shared by the startup prune
/// (`cli`) and the per-scan-boundary prune (engine) so the two can't drift.
pub const EVENTS_RETENTION_SECS: u64 = 7 * 86_400; // 7 days
/// Row cap for the `events` table, applied after the age prune at the same
/// lifecycle points as [`EVENTS_RETENTION_SECS`], so a burst of scans inside
/// the retention window still cannot grow the table without bound.
pub const EVENTS_MAX_ROWS: usize = 100_000;

/// Row cap for the `module_result_cache` inter-scan cache (SQLite table
/// `raw_archive`, distinct from the permanent filesystem archive at
/// [`crate::util::raw_archive`]), pruned at the same lifecycle points as
/// [`EVENTS_MAX_ROWS`]. Expired rows (past their per-entry TTL) are
/// always deleted; this additionally caps the newest retained rows so scanning
/// many distinct `(module, target)` pairs can't grow the table (and the DB/WAL)
/// without bound on a low-disk device. The cache is best-effort, so evicting a
/// still-fresh row only costs a re-query, never correctness.
pub const MODULE_RESULT_CACHE_MAX_ROWS: usize = 20_000;

/// The persistence boundary every layer above `core` goes through. The engine,
/// the HTTP API and the CLI hold an `Arc<dyn StoragePort>`, never a concrete
/// store; the SQLite `crate::storage::Store` is the production implementation
/// and `crate::core::test_support::InMemoryStore` the test double. Methods with
/// a default body are optional capabilities a double may leave as a no-op.
pub trait StoragePort: Send + Sync {
    // ── Scans ──────────────────────────────────────────────────────────────
    /// Insert `scan`, or update every mutable column when its id exists.
    fn upsert_scan(&self, scan: &Scan) -> Result<()>;
    /// The scan with this id, or `None` when no such row exists. A corrupt
    /// stored row is an `Err`, never a silent `None`.
    fn get_scan(&self, id: &str) -> Result<Option<Scan>>;
    /// The most recent `limit` scans, newest first, with a deterministic
    /// tie-break for scans sharing a start second.
    fn list_scans(&self, limit: usize) -> Result<Vec<Scan>>;
    /// Chronological (newest-first) list of past radar sweeps — scans whose
    /// target is one of the radar endpoints' sentinel anchors. See
    /// `crate::storage::Store::radar_history` for the full rationale.
    fn radar_history(&self, limit: usize) -> Result<Vec<Scan>>;
    /// Delete a scan and everything scoped to it (its correlations,
    /// relations, events and observations) in one transaction. `Ok(false)`
    /// when no such scan existed, in which case nothing is touched.
    fn delete_scan(&self, scan_id: &str) -> Result<bool>;

    // ── Entities ───────────────────────────────────────────────────────────
    /// Persist one entity, merging it into the stored row with the same uid
    /// (entities are content-addressed and shared across scans), and record
    /// that its scan observed it.
    fn upsert_entity(&self, entity: &Entity) -> Result<()>;
    /// Persist many entities in a single transaction. Takes a slice (not
    /// an owned `Vec`) so the caller retains ownership and can fall back
    /// to per-entity `upsert_entity` if the batch rolls back.
    fn upsert_entities_batch(&self, entities: &[Entity]) -> Result<usize>;
    /// Every entity `scan_id` observed, confidence-descending then uid.
    /// Membership is the scan's observation set, not `Entity::scan_id` (which
    /// is only the scan that first saw it).
    fn entities_for_scan(&self, scan_id: &str) -> Result<Vec<Entity>>;
    /// [`Self::entities_for_scan`] narrowed by any of: an exact `kind`, a
    /// `min_confidence` floor, and a `value_contains` substring.
    fn entities_filtered(
        &self,
        scan_id: &str,
        kind: Option<&str>,
        min_confidence: Option<f64>,
        value_contains: Option<&str>,
    ) -> Result<Vec<Entity>>;
    /// `(kind, count)` over the entities `scan_id` observed, most frequent
    /// kind first, ties by kind name.
    fn entity_facets(&self, scan_id: &str) -> Result<Vec<(String, u64)>>;
    /// The stored entity with this uid, from any scan, or `None`.
    fn get_entity(&self, uid: &str) -> Result<Option<Entity>>;
    /// Search every stored entity for `query`, best matches first, at most
    /// `limit`. The SQLite store ranks by full-text relevance and falls back
    /// to a substring match; see `crate::storage::Store::search_entities`.
    fn search_entities(&self, query: &str, limit: usize) -> Result<Vec<Entity>>;
    /// Every scan that observed this entity, most recent observation first —
    /// the substrate of cross-scan recall.
    fn scan_ids_for_entity(&self, entity_uid: &str) -> Result<Vec<String>>;
    /// How many scans observed this entity.
    fn observation_count(&self, entity_uid: &str) -> Result<usize>;

    /// Detach `entity_uids` from `scan_id`'s observation set — the store-side
    /// half of a finalise-time fold (see
    /// [`crate::core::engine`]'s address-locality consolidation). The `entities`
    /// ROW is never deleted: another scan may legitimately observe the same uid,
    /// and the content-addressed store is shared. Returns the number of
    /// observation rows removed. Default `Ok(0)` so existing implementors compile
    /// unchanged; a store that cannot detach simply keeps the duplicate.
    fn detach_scan_observations(&self, _scan_id: &str, _entity_uids: &[String]) -> Result<usize> {
        Ok(0)
    }

    // ── Correlations ───────────────────────────────────────────────────────
    /// Persist a correlator finding. The SQLite store deduplicates by member
    /// set within one scan and rule: a finding whose members are a strict
    /// superset of an earlier one supersedes it, and a subset is skipped, so a
    /// cluster growing across expansion rounds is stored once.
    fn upsert_correlation(&self, c: &Correlation) -> Result<()>;
    /// The scan's correlator findings, highest ranked first.
    fn correlations_for_scan(&self, scan_id: &str) -> Result<Vec<Correlation>>;

    // ── Relations (typed entity-to-entity edges) ────────────────────────────
    /// Persist one typed edge. Idempotent on the relation's id, so a re-scan
    /// that re-derives the same edge never duplicates it.
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
    /// The scan's typed edges, ordered by kind then id.
    fn relations_for_scan(&self, scan_id: &str) -> Result<Vec<Relation>>;

    // ── Events ─────────────────────────────────────────────────────────────
    /// Append one event to the durable log.
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
    /// The scan's events in the order they were written.
    fn events_for_scan(&self, scan_id: &str) -> Result<Vec<Event>>;

    /// Clear all events for a scan at the start of that scan so event logs don't
    /// accumulate stale events from abandoned previous runs with the same target
    /// in long-lived processes (`hse serve`). Default no-op for test doubles;
    /// the SQLite `Store` deletes from the `events` table. Non-fatal: a failure
    /// is logged as a warning but doesn't abort the scan.
    fn delete_events_for_scan(&self, _scan_id: &str) -> Result<()> {
        Ok(())
    }

    /// Recent `ModuleDone`/`ModuleError` outcome events across ALL scans,
    /// newest-first, bounded to `limit` — the substrate for
    /// `util::scraper_health`'s per-source health signal (`hse doctor`'s
    /// "Scraper health" section and the SPA's Engines-page panel). Default
    /// empty for test doubles; the real impl lives on `Store`.
    fn recent_module_outcome_events(&self, _limit: usize) -> Result<Vec<Event>> {
        Ok(Vec::new())
    }

    // ── Inter-scan entity cache (C9 / SOL-CACHE-INTERSCAN) ────────────────
    /// Persist a module result — its entities and its completeness verdict
    /// (see [`CachedModuleResult`]) — under `key` with a TTL. Called after a
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
        _truncation: Option<&str>,
    ) -> Result<()> {
        Ok(())
    }

    /// Return a previously-archived module result if it is still within its
    /// TTL, or `None` if absent or expired. Called before `process()` when
    /// `module.cache_ttl_secs() > 0`; a `Some` return short-circuits the
    /// provider call entirely.
    ///
    /// Default no-op returns `None` for test doubles.
    fn lookup_module_result_fresh(&self, _key: &str) -> Result<Option<CachedModuleResult>> {
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

    // ── RF sightings (wardriving captures + radar sweeps) ───────────────────
    /// Persist per-sighting RF observations for one scan/import. Best-effort,
    /// called from the capture importers and the radar. Default no-op for test
    /// doubles; the SQLite `Store` persists to `rf_sightings`.
    fn insert_rf_sightings_batch(
        &self,
        _scan_id: &str,
        _rows: &[crate::core::rf::RfSighting],
    ) -> Result<usize> {
        Ok(0)
    }

    /// The scan of the most recent sighting, or `None` when nothing has been
    /// recorded — "the survey you just ran", so neither `hse signal` nor the
    /// web reader makes the operator paste an id they never saw. Most recently
    /// *recorded*, not the newest clock: a capture can carry an older wall
    /// clock than a sweep imported after it. Default `None` for test doubles;
    /// the SQLite `Store` reads `rf_sightings`.
    fn rf_latest_scan_id(&self) -> Result<Option<String>> {
        Ok(None)
    }

    /// Scan-level sighting totals. Default empty for test doubles; the SQLite
    /// `Store` computes them in SQL.
    fn rf_summary(&self, _scan_id: &str) -> Result<crate::core::rf::RfSummary> {
        Ok(crate::core::rf::RfSummary::default())
    }

    /// Every device in a scan, strongest first. Default empty for test doubles;
    /// the SQLite `Store` reads its `rf_devices` roll-up.
    fn rf_devices_for_scan(&self, _scan_id: &str) -> Result<Vec<crate::core::rf::RfDeviceRow>> {
        Ok(Vec::new())
    }

    /// Devices with a fixed hardware address — the only ones whose recurrence
    /// across sightings means anything (AU-122). This filter is THE one
    /// definition of "trackable", provided here so `hse signal --trackable` and
    /// `GET /api/v1/radar/signals?trackable=1` cannot disagree; the `rf_trackable`
    /// SQL view that once encoded the same predicate was queried by nothing and
    /// is retired on open.
    fn rf_trackable_devices(&self, scan_id: &str) -> Result<Vec<crate::core::rf::RfDeviceRow>> {
        Ok(self
            .rf_devices_for_scan(scan_id)?
            .into_iter()
            .filter(|d| d.locally_administered == Some(false))
            .collect())
    }

    /// Every sighting of one device in a scan, oldest first — the movement
    /// track. Default empty for test doubles; the SQLite `Store` reads
    /// `rf_sightings`.
    fn rf_sightings_for_device(
        &self,
        _scan_id: &str,
        _network_id: &str,
    ) -> Result<Vec<crate::core::rf::RfSighting>> {
        Ok(Vec::new())
    }

    /// Every sighting of one device across EVERY scan — a whole radar session
    /// (one scan per iteration) or a wardriving day — oldest first, capped to
    /// the newest `limit`. The movement record the per-scan track cannot give,
    /// and the trail the map draws. Default empty for test doubles; the SQLite
    /// `Store` reads `rf_sightings` through its `network_id` index.
    fn rf_device_track(
        &self,
        _network_id: &str,
        _limit: usize,
    ) -> Result<Vec<crate::core::rf::RfTrackPoint>> {
        Ok(Vec::new())
    }

    // ── The device's own Wi-Fi link (REQ-RESILIENCE-002) ────────────────────
    /// Persist one sweep's link state — "not connected" included, because for
    /// the disruption review the absence is the observation. Default no-op for
    /// test doubles; the SQLite `Store` writes `wifi_links`.
    fn insert_wifi_link(&self, _scan_id: &str, _link: &crate::core::link::LinkState) -> Result<()> {
        Ok(())
    }

    /// One sweep's link state, or `None` for a sweep that recorded none (one
    /// from before the record existed, or a sweep without `device_sensors`).
    /// Default `None` for test doubles.
    fn wifi_link_for_scan(&self, _scan_id: &str) -> Result<Option<crate::core::link::LinkState>> {
        Ok(None)
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

    /// Bound the `module_result_cache` inter-scan cache (SQLite table
    /// `raw_archive`): delete rows past their per-entry TTL, then cap the
    /// table to the newest `max_rows`. Returns the number pruned. Default
    /// no-op for non-`Store` ports; the real impl lives on `Store`. Called at
    /// the same lifecycle points as [`Self::prune_events`] so a long-lived
    /// `serve`/`live`/`radar` process scanning many distinct targets can't
    /// grow the cache (and the DB/WAL) without bound.
    fn prune_module_result_cache(&self, _max_rows: usize) -> Result<usize> {
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
