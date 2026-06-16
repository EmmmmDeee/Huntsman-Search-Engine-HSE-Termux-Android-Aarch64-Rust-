//! Persistence, correlation, and result-assembly helpers.
//!
//! The terminal half of a scan, split out of `mod.rs` so that file reads as the
//! scan-loop orchestration: turning the in-memory working set into durable
//! intel. Covers the finalise transaction (batch-then-per-entity entity
//! persist, scan-record update, key-pool save, WAL checkpoint + events prune),
//! the typed entity-relation edge persist, the authoritative finalise-time
//! correlation pass, the live per-round incremental correlation, and the
//! mid-scan entity checkpoint. All are `&self` methods threaded through `run`
//! and `run_expansion`, kept on `ScanEngine` so behaviour is identical to the
//! pre-split inline definitions.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tracing::{info, warn};

use super::expansion::correlation_key;
use super::passes::consolidate_address_localities;
use super::{ModuleStats, ScanEngine};
use crate::core::{
    entity::Entity,
    error::Result,
    event::EventKind,
    module::ModuleContext,
    relation::Relation,
    scan::{Scan, ScanStatus},
};

impl ScanEngine {
    /// Persist entities, run the correlator, and mark the scan terminal.
    pub(super) fn finalise_scan(
        &self,
        scan: &mut Scan,
        entity_map: HashMap<String, Entity>,
        ctx: &ModuleContext,
        stats: ModuleStats,
        lineage_relations: Vec<Relation>,
        mut emitted_corr: HashSet<String>,
    ) -> Result<Scan> {
        // Persist the scan's entities in a single transaction. On the common
        // path (every entity is new or a clean GREATEST-merge) this collapses
        // N per-entity commits into one WAL fsync — a material win on
        // low-power aarch64 where each commit is the dominant cost. The batch
        // is all-or-nothing, so on any error we fall back to per-entity
        // upserts: this salvages whatever is persistable and recovers the
        // granular `first_err`, preserving the prior continue-on-error
        // resilience semantics (partial persist → Complete-with-error;
        // nothing persisted → Failed).
        // Mint ApiKey entities for every FOREIGN key identified in this scan's
        // endpoint responses (deduped by value across all modules; our own auth
        // keys already excluded by the sink). This guarantees leaked third-party
        // keys land in the graph + dossier no matter which module surfaced the
        // data — not only the breach pools that scan their own record fields.
        // They are merged THROUGH `entity_map` by UID (not appended to the batch)
        // so a key a specialised module already emitted with richer
        // tags/evidence is GREATEST-merged, never duplicated or blindly
        // overwritten.
        let mut entity_map = entity_map;
        for e in crate::modules::drain_found_key_entities(&scan.id) {
            match entity_map.get_mut(&e.uid) {
                Some(existing) => existing.merge(e),
                None => {
                    entity_map.insert(e.uid.clone(), e);
                }
            }
        }
        let mut entities: Vec<Entity> = entity_map.into_values().collect();
        // Codebase-wide address-locality consolidation. The UID merge above
        // dedups by exact normalised value, so "X, NSW" and "X, NSW 2582" (one
        // place at two granularities) survive as two Address entities — which
        // double-counts the location in the geo correlations. This runs once,
        // AFTER every module (APIs included) and every expansion round has
        // contributed, folding such variants into the most-specific one. It is
        // the engine-level backstop to the per-module dedup in `search_engines`.
        consolidate_address_localities(&mut entities);
        // Determinism: normalise each entity's evidence/tags ordering before
        // persist, so concurrent dispatch's completion-order merging can't leak
        // into the stored/exported result (see `Entity::canonicalize_order`).
        for e in &mut entities {
            e.canonicalize_order();
        }
        let total = entities.len();
        let (persisted, first_err): (usize, Option<String>) = match self
            .store
            .upsert_entities_batch(&entities)
        {
            Ok(n) => (n, None),
            Err(batch_err) => {
                warn!(scan_id = %scan.id, error = %batch_err, "batch entity persist rolled back; falling back to per-entity upserts");
                let mut persisted = 0usize;
                let mut first_err: Option<String> = None;
                for entity in &entities {
                    match self.store.upsert_entity(entity) {
                        Ok(()) => persisted += 1,
                        Err(e) => {
                            warn!(scan_id = %scan.id, entity_uid = %entity.uid, error = %e, "entity persist failed");
                            if first_err.is_none() {
                                first_err = Some(e.to_string());
                            }
                        }
                    }
                }
                (persisted, first_err)
            }
        };
        let entity_count = persisted;
        let failed = total - persisted;

        scan.modules_run = stats.run;
        scan.modules_errored = stats.errored;
        scan.modules_timed_out = stats.timed_out;
        scan.modules_deduped = stats.deduped;
        scan.modules_skipped = stats.skipped;

        if persisted == 0 && first_err.is_some() {
            scan.status = ScanStatus::Failed;
            scan.entity_count = 0;
            scan.error = first_err;
            scan.finished_at = Some(crate::core::entity::unix_now());
            // Persist the failed-scan record. Best-effort like the WAL
            // checkpoint below — we still return the failed scan to the
            // caller — but log on error rather than discarding it silently,
            // matching the success path's `upsert_scan(scan)?` and the
            // "no silent failures" invariant.
            if let Err(e) = self.store.upsert_scan(scan) {
                warn!(scan_id = %scan.id, error = %e, "failed to persist failed-scan record");
            }
            self.emit(
                &scan.id,
                EventKind::ScanComplete {
                    scan_id: scan.id.clone(),
                    entity_count: 0,
                },
            );
            return Ok(scan.clone());
        }

        scan.status = if ctx.cancel.is_cancelled() {
            ScanStatus::Aborted
        } else {
            ScanStatus::Complete
        };
        scan.entity_count = entity_count;
        if failed > 0 {
            scan.error = Some(format!(
                "{failed}/{total} entities failed to persist: {}",
                first_err.as_deref().unwrap_or("unknown")
            ));
        }
        scan.finished_at = Some(crate::core::entity::unix_now());
        self.store.upsert_scan(scan)?;

        // Derive + persist the typed entity-relation edges (attribution
        // graph): the lineage edges captured during expansion plus the
        // structural edges derived from the persisted entity set.
        self.persist_relations(&scan.id, &entities, &lineage_relations);

        self.run_correlator(&scan.id, &mut emitted_corr);

        // Persist the key pool to disk after every scan. Keys discovered
        // during this scan (from breach data, page bodies, entity values)
        // are permanently stored with full provenance metadata.
        let pool = crate::util::key_pool::global_pool();
        if let Err(e) = crate::util::key_pool::save_pool(&pool) {
            warn!("failed to save key pool after scan: {e}");
        }

        // Scan-boundary WAL checkpoint: fold the WAL into the main DB and
        // truncate the -wal file back to zero. Bounds the on-disk/mmap WAL
        // footprint between scans under a long-lived `serve`/`live` process
        // (the 'everything bounded' invariant). Best-effort — a busy
        // checkpoint just defers to the next scan boundary.
        if let Err(e) = self.store.checkpoint_truncate() {
            warn!(scan_id = %scan.id, error = %e, "WAL checkpoint deferred (busy)");
        }

        // Bound the events table during long-lived serve/live/radar processes
        // (otherwise pruned only at startup). Best-effort + same retention
        // policy as the startup prune — a busy prune just defers to the next
        // scan boundary.
        if let Err(e) = self.store.prune_events(
            crate::core::port::EVENTS_RETENTION_SECS,
            crate::core::port::EVENTS_MAX_ROWS,
        ) {
            warn!(scan_id = %scan.id, error = %e, "events prune deferred");
        }

        self.emit(
            &scan.id,
            EventKind::ScanComplete {
                scan_id: scan.id.clone(),
                entity_count,
            },
        );

        Ok(scan.clone())
    }

    /// Persist the scan's typed entity-relation edges: the `lineage` edges
    /// captured during expansion (`DerivedFrom`) plus the deterministic
    /// structural edges derived from the persisted entity set. Best-effort: a
    /// relation that fails to persist is logged, never fatal to the scan.
    /// Endpoints are entity UIDs already persisted above; upserts are
    /// idempotent on the deterministic edge id.
    pub(super) fn persist_relations(
        &self,
        scan_id: &str,
        entities: &[Entity],
        lineage: &[Relation],
    ) {
        // The lineage-free structural set (structural/colocation/resolution/
        // registration/name-lineage) is derived identically here and on the
        // import paths via `derive_all`, so a live scan and an imported dossier
        // can't drift on which edges a finished scan carries.
        let derived = crate::core::relation::derive_all(entities, scan_id);
        if lineage.is_empty() && derived.is_empty() {
            return;
        }
        let mut persisted = 0usize;
        for r in lineage.iter().chain(derived.iter()) {
            match self.store.upsert_relation(r) {
                Ok(()) => persisted += 1,
                Err(e) => warn!(scan_id, relation = %r.id, error = %e, "relation persist failed"),
            }
        }
        info!(
            scan_id,
            lineage = lineage.len(),
            derived = derived.len(),
            persisted,
            "entity relations persisted"
        );
    }

    /// Authoritative finalise-time correlation pass. Runs the full rule set
    /// (entity + graph-aware relation rules) over the persisted scan, persists
    /// every firing, and emits `CorrelationFound` only for correlations not
    /// already streamed live during ingestion (deduped via `emitted`). The
    /// `CorrelationsDone` count is the authoritative total for the scan.
    pub(super) fn run_correlator(&self, scan_id: &str, emitted: &mut HashSet<String>) {
        match crate::core::correlator::Correlator::new(Arc::clone(&self.store)).run(scan_id) {
            Ok(firings) => {
                for c in &firings {
                    if emitted.insert(correlation_key(c)) {
                        self.emit(
                            scan_id,
                            EventKind::CorrelationFound {
                                correlation: c.clone(),
                            },
                        );
                    }
                }
                self.emit(
                    scan_id,
                    EventKind::CorrelationsDone {
                        count: firings.len(),
                    },
                );
            }
            Err(e) => warn!(scan_id, error = %e, "correlator failed"),
        }
    }

    /// Live cross-correlation during ingestion. Evaluates the entity rules
    /// against an in-memory snapshot of the working set (no store round-trip)
    /// and streams any newly-fired correlation immediately, persisting it as it
    /// appears. Idempotent across rounds: a correlation's stable identity
    /// (`rule_id` + sorted entity uids) is recorded in `emitted` so it fires
    /// exactly once even though the rules are re-run every round.
    pub(super) fn correlate_incremental(
        &self,
        scan_id: &str,
        entities: &[Entity],
        emitted: &mut HashSet<String>,
    ) {
        // Rank live-streamed correlations with the same severity × max-child-
        // C_eff score the finalize pass uses, so a scan that is killed at its
        // wall/entity budget (and never reaches finalize) still persists ranked
        // correlations — not rank=0.0 rows. Build the C_eff map once per call.
        let ceff: HashMap<String, f64> = entities
            .iter()
            .map(|e| (e.uid.clone(), e.c_effective()))
            .collect();
        // Contain a correlator panic exactly as module dispatch does
        // (`run_module_guarded`): the 34 AU-rules run index/parse-heavy logic over
        // entity data, so a single malformed value in one rule must degrade to "no
        // new correlations this round" rather than unwind through finalize and lose
        // the scan. Entities are already checkpointed and persisted, so nothing
        // discovered is lost — only this round's correlation pass is skipped.
        let produced = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::core::correlator::correlate_entities(entities, scan_id)
        }))
        .unwrap_or_else(|_| {
            warn!(
                scan_id,
                "correlation pass panicked — entities preserved, correlations skipped this round"
            );
            Vec::new()
        });
        let mut fresh: Vec<crate::core::correlator::Correlation> = produced
            .into_iter()
            .filter(|c| emitted.insert(correlation_key(c)))
            .collect();
        crate::core::correlator::rank_and_sort(&mut fresh, &ceff);
        for c in fresh {
            if let Err(e) = self.store.upsert_correlation(&c) {
                warn!(scan_id, error = %e, "live correlation persist failed");
            }
            self.emit(scan_id, EventKind::CorrelationFound { correlation: c });
        }
    }

    /// Checkpoint the working entity set to durable storage mid-scan so a crash
    /// or kill preserves discovered intel instead of losing everything until
    /// `finalise_scan`. Runs at every productive round boundary. The upsert is
    /// idempotent GREATEST-merge — replaying the same entities only ever raises
    /// confidence/corroboration, so a resumed or re-run scan never regresses.
    /// Best-effort: a checkpoint failure is logged and retried at finalise.
    pub(super) fn checkpoint_entities(&self, scan_id: &str, entities: &[Entity]) {
        if entities.is_empty() {
            return;
        }
        if let Err(e) = self.store.upsert_entities_batch(entities) {
            warn!(scan_id, error = %e, "entity checkpoint failed (will retry at finalise)");
        }
    }
}
