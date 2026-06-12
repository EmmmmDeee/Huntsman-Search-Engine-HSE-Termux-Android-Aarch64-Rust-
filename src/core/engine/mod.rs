//! Scan engine — module dispatcher + autonomous expansion + parallel dispatch
//! + per-scan dispatch deduplication.
//!
//! Each scan has two phases:
//!   1. Seed dispatch — every accepting module runs against the seed target.
//!   2. Expansion (when `ScanOptions::depth > 0`) — entities produced so far
//!      with `c_effective() ≥ min_expand_confidence` are converted to new
//!      targets and re-dispatched, up to `depth` rounds. Already-visited
//!      (kind, normalised-value) pairs are skipped, so cycles terminate
//!      naturally. Budgets (`max_entities`, `max_wall_time_secs`) short-circuit
//!      if exceeded.
//!
//! API deduplication: a per-scan `DispatchLog` tracks every
//! (module_name, target_kind, normalised_value) triple dispatched during the
//! scan. Non-free modules (KeyGated, Paid) are skipped if the same triple
//! was already dispatched — this ensures each API key/service is utilised at
//! most once per target in the pivot pipeline. Free modules are exempt since
//! re-running them can corroborate entities with independent evidence.
//!
//! Dispatch mode is selected by `ScanOptions::max_concurrent`:
//!   * `0` (default) → sequential. Best for low-power Termux devices.
//!   * `N > 0` → up to N modules in flight concurrently via
//!     `tokio::sync::Semaphore`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{info, warn};

mod circuit;
mod dispatch;
mod enrich;
mod expansion;
mod ledger;
mod timeout;
pub use ledger::DispatchLog;
// The dispatch loops now live in `dispatch`; these items are referenced only by
// the tests that stayed in this file, so the bridge is test-only.
#[cfg(test)]
use dispatch::{
    dispatch_key, log_module_dispatch, module_skip_reason, run_module_guarded,
    target_distinct_sources,
};
use enrich::{address_to_coords_pass, enrich_geospatial, scan_entity_for_keys, seed_anchor_entity};
use expansion::{
    apply_roi_cutoff, budget_check, cmp_expansion_candidates, correlation_key, visit_key,
};
use timeout::resolve_timeout;
// Used only by the dispatch-related tests retained in this file.
#[cfg(test)]
use crate::core::{error::Error, module::ModuleCost};

use crate::core::{
    dependency::ModuleGraph,
    entity::Entity,
    error::Result,
    event::{Event, EventBus, EventKind},
    module::{Module, ModuleContext},
    port::StoragePort,
    relation::{Relation, RelationKind},
    scan::{Scan, ScanOptions, ScanStatus, Target, TargetKind},
};

pub struct ScanEngine {
    modules: Vec<Arc<dyn Module>>,
    store: Arc<dyn StoragePort>,
    bus: EventBus,
    emitter: EventEmitter,
    /// Pre-computed dispatch index + richness scoring. Built once at
    /// engine construction so the per-target dispatch loop can skip
    /// the O(M) `accepts()` scan and so the expansion ranker can pull
    /// the richness factor in constant time.
    graph: Arc<ModuleGraph>,
}

/// Reason an expansion round stopped before depth was exhausted.
enum StopReason {
    NoMoreCandidates,
    DepthExhausted,
    MaxEntities(usize),
    MaxWallTime(u64),
    Cancelled,
}

/// Accumulator for per-scan module execution statistics.
/// Created in `run()`, threaded through the dispatch chain, and applied
/// to the `Scan` record in `finalise_scan`.
#[derive(Debug, Default)]
pub(crate) struct ModuleStats {
    pub run: usize,
    pub errored: usize,
    pub timed_out: usize,
    pub deduped: usize,
    /// Modules skipped rather than run: gate-skips (excluded, disabled in
    /// config, not in the allowlist, filtered by free-only/passive-only, or a
    /// sensor that already ran) plus modules that dispatched then cleanly opted
    /// out because a required API key is absent. Counted separately from
    /// `errored` so an unconfigured optional provider is never a failure.
    pub skipped: usize,
}

impl StopReason {
    fn label(&self) -> String {
        match self {
            Self::NoMoreCandidates => "no more high-confidence candidates".into(),
            Self::DepthExhausted => "maximum expansion depth reached".into(),
            Self::MaxEntities(n) => format!("max_entities={n} reached"),
            Self::MaxWallTime(s) => format!("max_wall_time_secs={s} exceeded"),
            Self::Cancelled => "cancelled by operator".into(),
        }
    }
}

/// Cheaply-cloneable event emitter. Persist-first, then broadcast.
/// Spawned tasks clone this instead of cloning store + bus separately.
#[derive(Clone)]
struct EventEmitter {
    store: Arc<dyn StoragePort>,
    bus: EventBus,
}

impl EventEmitter {
    fn new(store: Arc<dyn StoragePort>, bus: EventBus) -> Self {
        Self { store, bus }
    }

    fn emit(&self, scan_id: &str, kind: EventKind) {
        let event = Event::new(scan_id, kind);
        if let Err(e) = self.store.insert_event(&event) {
            warn!(scan_id = %event.scan_id, error = %e, "failed to persist event to store");
        }
        // Best-effort live fan-out to SSE subscribers. `broadcast::send` errors
        // ONLY when there are zero active receivers — the normal case for a CLI
        // scan with no `/events` client attached. The event is already durably
        // persisted above (and the CLI/report reads from the store, not the
        // bus), so a missing subscriber is a no-op, NOT a condition worth
        // logging: at the default TRACE verbosity a per-event log here floods
        // the terminal with one line per entity — hundreds on a breach-heavy
        // scan — burying the real output. Drop silently.
        let _ = self.bus.send(event);
    }
}

impl ScanEngine {
    pub fn new(
        mut modules: Vec<Arc<dyn Module>>,
        store: Arc<dyn StoragePort>,
        bus: EventBus,
    ) -> Self {
        modules.sort_by_key(|m| std::cmp::Reverse(m.priority()));
        let emitter = EventEmitter::new(Arc::clone(&store), bus.clone());
        let graph = Arc::new(ModuleGraph::build(&modules));
        Self {
            modules,
            store,
            bus,
            emitter,
            graph,
        }
    }

    /// Read-only access to the pre-computed module dependency graph.
    /// Used by the HTTP API to surface `/api/v1/modules/graph` and by
    /// integration tests that need to introspect dispatch counts.
    pub fn graph(&self) -> &ModuleGraph {
        &self.graph
    }

    fn emit(&self, scan_id: &str, kind: EventKind) {
        self.emitter.emit(scan_id, kind);
    }

    /// Emit a `ModuleSkipped` event — the gate-rejection path shared by
    /// `run_expansion` and both dispatchers (cancel/quota/cost-dedup/skip-rule).
    fn emit_skipped(&self, scan_id: &str, module: &str, reason: &str) {
        self.emit(
            scan_id,
            EventKind::ModuleSkipped {
                module: module.into(),
                reason: reason.into(),
            },
        );
    }

    /// Emit an `EntityExcluded` event — an expansion-pruning OR admission-drop
    /// decision made visible so the pipeline is never a black box (the reason
    /// names exactly why the entity was not pivoted on, or was rejected before
    /// ever entering the graph: `bogus_ip`, `placeholder_artifact`,
    /// `fragment_value`, …).
    fn emit_excluded(&self, scan_id: &str, entity: &Entity, reason: &str) {
        self.emit(
            scan_id,
            EventKind::EntityExcluded {
                kind: entity.kind.to_string(),
                value: entity.value.clone(),
                reason: reason.into(),
            },
        );
    }

    pub fn modules(&self) -> &[Arc<dyn Module>] {
        &self.modules
    }

    pub fn bus(&self) -> &EventBus {
        &self.bus
    }

    /// Run a scan to completion, including any expansion rounds.
    /// Run one scan with a fresh dispatch ledger (the normal one-shot path).
    pub async fn run(&self, scan: Scan, target: Target, ctx: ModuleContext) -> Result<Scan> {
        let mut dispatched: DispatchLog = DispatchLog::new();
        self.run_with_ledger(scan, target, ctx, &mut dispatched)
            .await
    }

    /// Run one scan against a caller-owned dispatch ledger.
    ///
    /// Identical to [`run`](Self::run) except the keyed/paid-module
    /// deduplication set is supplied by the caller, so a continuous mode
    /// (radar) can persist ONE ledger across iterations: a keyed module that
    /// already queried a given seed in an earlier sweep is skipped on every
    /// later sweep, so the APIs are never re-hit on already-covered seeds.
    /// Free modules still re-run each sweep (they corroborate with fresh
    /// evidence and cost nothing), so the radar keeps surfacing new leads.
    pub async fn run_with_ledger(
        &self,
        mut scan: Scan,
        target: Target,
        mut ctx: ModuleContext,
        dispatched: &mut DispatchLog,
    ) -> Result<Scan> {
        scan.status = ScanStatus::Running;
        self.store.upsert_scan(&scan)?;

        // Reset per-scan budget counters so long-lived processes
        // (`hse serve` / `hse live`) get a fresh budget per scan.
        crate::modules::oathnet_pro::reset_budget();
        crate::modules::see_know::reset_budget();
        crate::modules::wigle::reset_budget();
        // Clear the foreign-API-key sink so this scan reports only the keys IT
        // retrieves from endpoint responses (and refresh the own-key exclusion).
        // Via the module-layer shim — core must not import util directly.
        crate::modules::reset_found_keys();
        // Apply the regional-search toggle for this scan. Regional augmentation
        // is on when EITHER the per-scan flag (`--regional`) is set OR the
        // persistent default `feature.regional` is on (universal toggleability;
        // default off ⇒ geolocation-neutral queries). The per-scan flag only
        // adds regional — set the standing baseline via `hse config
        // feature.regional <on|off>`. Mirrors the see_know per-scan global.
        crate::modules::search_engines::set_regional(
            scan.options.regional_search
                || crate::util::settings::get_bool("feature.regional", false),
        );

        // Apply per-scan SeekNow budget override if the operator asked
        // for one. Capped at 500 so a single scan cannot blow the
        // per-session ceiling. `reset_budget` above cleared any prior
        // override; this re-installs it for the current scan only.
        if let Some(cap) = scan.options.seeknow_scan_cap {
            let clamped = cap.min(500);
            crate::util::see_know::set_scan_cap_override(clamped);
        }

        self.emit(
            &scan.id,
            EventKind::ScanStart {
                target_kind: target.kind.canonical_str().to_string(),
                target_value: target.value.clone(),
            },
        );

        let opts = scan.options.clone();
        let started = Instant::now();

        // Wall-time watchdog. `budget_check` only enforces the wall budget
        // BETWEEN expansion candidates, so the seed round (all accepting
        // modules fan out at once) and any long in-flight concurrent batch
        // could blow far past `max_wall_time_secs` — observed: a
        // `--max-wall-time 5` scan ran until an external SIGKILL because no
        // deadline was checked during the seed round. This watchdog fires the
        // engine-wide cancel flag at the deadline; every dispatch loop already
        // polls `ctx.cancel`, and finalise treats cancellation as a clean
        // `Aborted` with all collected entities persisted — so the scan stops
        // promptly AND still prints/streams what it found (the "always display
        // results" + "fallback bound that actually bounds" requirements).
        let wall_watchdog = opts.max_wall_time_secs.map(|secs| {
            let cancel = ctx.cancel.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(secs)).await;
                cancel.cancel();
            })
        });

        let mut entity_map: HashMap<String, Entity> =
            HashMap::with_capacity(opts.max_entities.unwrap_or(256).min(4096));
        let mut visited: HashSet<(TargetKind, String)> = HashSet::new();
        let mut stats = ModuleStats::default();
        // Lineage `DerivedFrom` edges (child → the parent it was expanded
        // from), accumulated across expansion rounds and persisted in
        // finalise_scan.
        let mut lineage: Vec<Relation> = Vec::new();
        // Live cross-correlation dedup set: the stable identity (rule_id +
        // sorted entity uids) of every correlation already streamed during
        // ingestion. Shared across the seed round, every expansion round, and
        // the authoritative finalise pass so each correlation is emitted at
        // most once even though the rules are re-evaluated continuously.
        let mut emitted_corr: HashSet<String> = HashSet::new();

        visited.insert(visit_key(&target));
        // Anchor the queried subject as a root entity BEFORE dispatch, so the
        // result graph always has a node for what the operator searched for —
        // the hub every relation/correlation hangs off. Pre-inserting (rather
        // than appending) means a module that re-emits the seed merges its
        // evidence onto this anchor by uid instead of duplicating it. `FullName`
        // is delegated to name_intel's Person anchor (see seed_anchor_entity).
        // Guard on cancellation: a scan cancelled before it starts does no work
        // and persists nothing — not even the anchor — so the "pre-cancel is a
        // clean no-op" invariant holds. A live scan inserts the anchor, then
        // dispatch may still abort mid-flight, leaving the subject node present
        // (we always show what was queried), consistent with finalise persisting
        // collected entities on a clean Aborted.
        if !ctx.cancel.is_cancelled()
            && let Some(anchor) = seed_anchor_entity(&target, &scan.id)
        {
            entity_map.insert(anchor.uid.clone(), anchor);
        }
        // Seed-dispatch errors are warn-and-continue, exactly like
        // expansion-round dispatch below: propagating here returned before
        // finalise_scan (losing every collected entity and leaving the scan
        // row stuck `Running`) AND leaked the wall-time watchdog, which then
        // fired `cancel()` on the caller's context long after this scan was
        // gone — poisoning the shared token under a long-lived serve/radar.
        // Per-module failures are already surfaced as ModuleError events.
        if let Err(e) = self
            .dispatch_target(
                &scan.id,
                &target,
                &mut ctx,
                &opts,
                &mut entity_map,
                false,
                &mut stats,
                dispatched,
            )
            .await
        {
            warn!(scan_id = %scan.id, error = %e, "seed dispatch failed (continuing to finalise)");
        }

        // Convert Address entities to Coordinates (offline city lookup) so they
        // feed AU-052/053 geo correlation rules.  Run before the snapshot so
        // derived Coordinates are checkpointed and correlated in the same pass.
        for mut derived in address_to_coords_pass(&entity_map, &scan.id) {
            enrich_geospatial(&mut derived);
            if let Some(existing) = entity_map.get_mut(&derived.uid) {
                existing.merge(derived);
            } else {
                entity_map.insert(derived.uid.clone(), derived);
            }
        }

        // Checkpoint + correlate the seed round from a single snapshot: the
        // entities are made durable before expansion begins (crash-safety) and
        // single-round (depth=0) scans stream correlations live rather than
        // waiting for finalise.
        let seed_snapshot: Vec<Entity> = entity_map.values().cloned().collect();
        self.checkpoint_entities(&scan.id, &seed_snapshot);
        self.correlate_incremental(&scan.id, &seed_snapshot, &mut emitted_corr);

        if opts.depth > 0 {
            let _ = self
                .run_expansion(
                    &scan.id,
                    &target,
                    &mut ctx,
                    &opts,
                    started,
                    &mut entity_map,
                    &mut visited,
                    &mut stats,
                    dispatched,
                    &mut lineage,
                    &mut emitted_corr,
                )
                .await;
        }

        // Scan body done — stop the wall-time watchdog so it can't fire after
        // we've already finished (and is reaped promptly rather than sleeping
        // out its full deadline in the background on a long-lived `serve`).
        if let Some(handle) = wall_watchdog {
            handle.abort();
        }

        self.finalise_scan(&mut scan, entity_map, &ctx, stats, lineage, emitted_corr)
    }

    /// Persist entities, run the correlator, and mark the scan terminal.
    fn finalise_scan(
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
    fn persist_relations(&self, scan_id: &str, entities: &[Entity], lineage: &[Relation]) {
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
    fn run_correlator(&self, scan_id: &str, emitted: &mut HashSet<String>) {
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
    fn correlate_incremental(
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
    fn checkpoint_entities(&self, scan_id: &str, entities: &[Entity]) {
        if entities.is_empty() {
            return;
        }
        if let Err(e) = self.store.upsert_entities_batch(entities) {
            warn!(scan_id, error = %e, "entity checkpoint failed (will retry at finalise)");
        }
    }

    /// Drive the expansion loop. Returns the stop reason for diagnostics.
    #[allow(clippy::too_many_arguments)]
    async fn run_expansion(
        &self,
        scan_id: &str,
        seed: &Target,
        ctx: &mut ModuleContext,
        opts: &ScanOptions,
        started: Instant,
        entity_map: &mut HashMap<String, Entity>,
        visited: &mut HashSet<(TargetKind, String)>,
        stats: &mut ModuleStats,
        dispatched: &mut DispatchLog,
        relations: &mut Vec<Relation>,
        emitted_corr: &mut HashSet<String>,
    ) -> StopReason {
        // Reused across candidates to capture lineage: the set of entity UIDs
        // present *before* a candidate's dispatch, so new UIDs afterward are
        // children that candidate surfaced. Reusing the buffer avoids a
        // per-candidate allocation; the key clones are bounded by max_entities.
        let mut before: HashSet<String> = HashSet::new();
        for depth in 1..=opts.depth {
            // Refresh keys from the pool at the start of each round. Keys
            // discovered during the previous round (oathnet_pro breach data,
            // api_key_probe validation, web_crawler scraping) become available
            // to this round's modules automatically.
            hot_inject_keys(&mut ctx.keys);

            // Refresh SeekNow's per-round budget so it is utilised in EVERY
            // iteration (not just until a wide first round drains it). The
            // per-session ceiling still bounds total volume across all rounds.
            crate::modules::see_know::refresh_round_budget();

            if ctx.cancel.is_cancelled() {
                let stop = StopReason::Cancelled;
                self.emit(
                    scan_id,
                    EventKind::ExpansionStop {
                        reason: stop.label(),
                    },
                );
                return stop;
            }
            // Snapshot the entity set at round start — entities discovered
            // during this round will be expansion candidates in the next round,
            // not this one.
            let entities_at_round_start = entity_map.len();
            let has_paid = ctx.keys.contains_key("HUNTSMAN_OATHNET_KEY");
            // Each candidate carries the UID of the parent entity it was
            // derived from, so a `DerivedFrom` lineage edge can be recorded
            // for whatever new entities its dispatch surfaces.
            // Subject identity fingerprints for wrong-identity gating: the seed
            // itself plus every VERIFIED identity entity confirmed so far. A
            // discovered Username/Person that shares no name/handle overlap with
            // ANY of these — and is uncorroborated — is almost certainly a
            // different person, and pivoting on it pulls a stranger's whole
            // footprint into the scan (a real run chased `arizonambb` —
            // Arizona basketball — off an `jordanavery` seed). Rebuilt each
            // round so confirmed aliases widen the identity as the scan learns.
            let subject_identities: Vec<String> = std::iter::once(seed.value.clone())
                .chain(entity_map.values().filter_map(|e| {
                    use crate::core::entity::{Classification, EntityKind};
                    let is_identity = matches!(
                        e.kind,
                        EntityKind::Username | EntityKind::Person | EntityKind::Email
                    );
                    (is_identity && e.c_effective() >= Classification::VERIFIED_MIN)
                        .then(|| e.value.clone())
                }))
                .collect();

            let mut next: Vec<(Target, f64, String)> = Vec::new();
            for entity in entity_map.values() {
                if entity.c_effective() < opts.min_expand_confidence {
                    self.emit_excluded(scan_id, entity, "below_min_expand_confidence");
                    continue;
                }
                // Search-snippet recycling is the lowest-reliability discovery
                // path: a value scraped from the *text* of whatever page a search
                // engine returned for a recycled query — a Subway-directory
                // "Austin, Texas", an unrelated contact email on a scraped page.
                // At the relaxed deep/`--full` expansion floor these clear
                // `min_expand_confidence` on a single source, so without this gate
                // the recursion budget gets burned pivoting on strangers. The
                // wrong-identity gate below can't catch them: it only covers
                // Username/Person and is lifted entirely by
                // `--expand-all-identities`. Record the lead, but don't pivot
                // until a second, independent source corroborates it —
                // corroboration lifts `source_count` past 1 and the entity
                // expands normally on a later round.
                if entity.is_uncorroborated_recycled() {
                    self.emit_excluded(scan_id, entity, "uncorroborated_recycled");
                    continue;
                }
                // ROI bundle: convergence-pruning. Once an entity has 2+
                // corroborating sources at high confidence, further dispatch
                // only re-confirms what we already know. Skip it.
                if opts.max_roi && crate::core::roi::is_saturated(entity) {
                    self.emit_excluded(scan_id, entity, "roi_saturated");
                    continue;
                }
                // A kind with no external search target (Credential, Password,
                // DeviceId, TrackingId, Other) cannot be pivoted on. Previously
                // this was a silent `continue` — a black box. Record it so the
                // logs show exactly why the entity was not expanded.
                let Some(tk) = TargetKind::from_entity_kind(&entity.kind) else {
                    self.emit_excluded(scan_id, entity, "non_pivotable_kind");
                    continue;
                };
                // Wrong-identity gate: an uncorroborated, non-verified
                // Username/Person whose handle shares no overlap with the
                // subject's confirmed identity is a different person. Recording it
                // as a candidate is fine, but pivoting on it would search the web
                // for a stranger and import their footprint. Verified or
                // multi-source identities, and anything overlapping the subject,
                // still expand — so genuine aliases are never lost.
                if !opts.expand_all_identities
                    && crate::core::scan::is_wrong_identity_pivot(
                        &entity.kind,
                        entity.c_effective(),
                        entity.source_count(),
                        &entity.value,
                        &subject_identities,
                    )
                {
                    self.emit_excluded(scan_id, entity, "identity_mismatch");
                    continue;
                }
                // Never pivot on a non-routable / reserved / documentation IP
                // (e.g. 192.0.2.1 scraped from a tutorial page, or a private
                // 192.168.x surfaced by local sensors). No external OSINT source
                // can resolve these, so expanding them only burns whole rounds
                // on guaranteed-empty lookups and pollutes the graph with noise.
                if tk == TargetKind::IpAddress
                    && crate::core::validation::is_non_routable_ip(&entity.value)
                {
                    self.emit_excluded(scan_id, entity, "non_routable_ip");
                    continue;
                }
                // Don't deep-expand *incidentally-discovered* haystack
                // infrastructure — it maps a platform/CDN/provider's own estate,
                // not the subject, and burns the round budget that should go to
                // target-specific enrichment:
                //   • a non-central DOMAIN — a mega/social platform
                //     (twitter.com, …) or shared mail/DNS/registrar infra
                //     (sendgrid.net, secureserver.net, ns*.dnsmadeeasy.com), whose
                //     NS/MX/SOA fan out into dozens of generic provider domains;
                //   • a CDN-edge IP — a Cloudflare/Fastly anycast address whose
                //     reverse-IP lookup returns thousands of co-tenant strangers
                //     (a real scan pulled 480+ co-hosted domains through two).
                // Still expand when the candidate IS the seed (you're
                // investigating that property itself).
                {
                    let strip = |s: &str| s.trim().trim_start_matches("www.").to_ascii_lowercase();
                    let candidate_is_seed =
                        seed.kind == tk && strip(&seed.value) == strip(&entity.value);
                    let is_incidental_infra = match tk {
                        // Freemail / social / shared CDN-DNS-registrar infra is
                        // never the subject's own estate — expanding it maps the
                        // provider, not the target. All consolidated in the
                        // core-side `is_noncentral_domain` (mega + infra lists,
                        // incl. freemail and ISP webmail) so the engine stays free
                        // of any `util` import (core → modules → util only).
                        TargetKind::Domain => {
                            crate::core::scan::is_noncentral_domain(&entity.value)
                        }
                        TargetKind::IpAddress => {
                            crate::core::validation::is_cdn_edge_ip(&entity.value)
                        }
                        _ => false,
                    };
                    if is_incidental_infra && !candidate_is_seed {
                        self.emit_excluded(scan_id, entity, "incidental_infra");
                        continue;
                    }
                }
                let new_target = Target::new(tk, entity.value.clone());
                let key = visit_key(&new_target);
                if visited.insert(key) {
                    let richness = self.graph.richness_for(tk);
                    // Strategy weight × a non-saturating corroboration prior.
                    // c_effective() clamps at 1.0, erasing the cross-correlation
                    // signal for confident pivots; re-apply it on the ranking so
                    // a lead confirmed by N independent sources is dispatched
                    // ahead of an equally-confident single-source lead (its
                    // dispatch is likelier to yield genuine children).
                    let mut weight =
                        crate::core::scan::expansion_weight_for_strategy(
                            opts.expansion_strategy,
                            tk,
                            entity.c_effective(),
                            &entity.value,
                            has_paid,
                            richness,
                        ) * crate::core::scan::corroboration_prior(entity.source_count());
                    // Convex (optionality / barbell) budget allocation, opt-in:
                    // multiply by a convexity premium for heavy-tailed upside over
                    // per-kind dispatch cost, so the bounded budget favours cheap,
                    // high-optionality identity leads over saturated infrastructure.
                    // Neutral (×≈1) for the confident cheap core, so it only
                    // re-sorts the uncertain tail and the expensive infra.
                    if opts.convex_budget {
                        weight *= crate::core::convex::optionality_multiplier(
                            tk,
                            entity.source_count(),
                            entity.c_effective(),
                            richness,
                        );
                    }
                    // Geo-corroboration bonus: entities confirmed by anchoring
                    // geo sources (self-reported address, photo GPS, registry
                    // address, person-enrichment location) rank slightly ahead
                    // of equal-weight entities with no person-anchored geo
                    // signal. Each anchoring geo source contributes +2%, capped
                    // at +10%, keeping the bonus sub-dominant to the confidence
                    // and corroboration factors.
                    let anchoring_geo_count = entity
                        .corroborating_sources()
                        .into_iter()
                        .filter(|s| crate::core::correlator::is_anchoring_geo_source(s))
                        .count();
                    if anchoring_geo_count > 0 {
                        weight *= 1.0 + (anchoring_geo_count as f64 * 0.02).min(0.10);
                    }
                    next.push((new_target, weight, entity.uid.clone()));
                } else {
                    // This exact target was already dispatched (or queued) this
                    // scan. Skipping it prevents an infinite pivot cycle, but the
                    // decision must be visible rather than a silent drop.
                    self.emit_excluded(scan_id, entity, "already_dispatched_this_scan");
                }
            }

            // Sort expansion candidates by weighted score (descending), with a
            // DETERMINISTIC total tie-break. The weight combines geo_npv with
            // entity confidence and dampens generic mega-domains. `next` is built
            // by iterating a HashMap (random per-process seed), so without a
            // tie-break two equal-weight candidates sorted Equal would keep that
            // non-deterministic input order — and the ROI `truncate(keep)` below
            // would then drop a DIFFERENT candidate run-to-run, making the very
            // results non-reproducible (Determinism Requirement). Breaking ties by
            // (kind, value) gives identical inputs an identical dispatch order.
            next.sort_by(cmp_expansion_candidates);

            // ROI bundle: top-K gate + relative knee. Keep the leading
            // candidates by weight (budget-bounded via top-K, scaled with
            // concurrency) AND drop the long tail that sorts far below this
            // round's best lead (quality-bounded via the knee). Stops both
            // a flood of low-weight domains from a single SERP and the
            // dampened mega-domain noise that survives top-K on a thin round.
            if opts.max_roi {
                apply_roi_cutoff(&mut next, visited, opts.max_concurrent);
            }
            let dispatched_this_round = next.len();
            let next: Vec<(Target, String)> = next.into_iter().map(|(t, _, p)| (t, p)).collect();

            if next.is_empty() {
                let stop = StopReason::NoMoreCandidates;
                self.emit(
                    scan_id,
                    EventKind::ExpansionStop {
                        reason: stop.label(),
                    },
                );
                return stop;
            }

            self.emit(
                scan_id,
                EventKind::ExpansionTick {
                    depth,
                    queued: next.len(),
                    visited: visited.len(),
                },
            );

            for (nt, parent_uid) in &next {
                if ctx.cancel.is_cancelled() {
                    let stop = StopReason::Cancelled;
                    self.emit(
                        scan_id,
                        EventKind::ExpansionStop {
                            reason: stop.label(),
                        },
                    );
                    return stop;
                }
                if let Some(stop) = budget_check(opts, started, entity_map.len()) {
                    self.emit(
                        scan_id,
                        EventKind::ExpansionStop {
                            reason: stop.label(),
                        },
                    );
                    return stop;
                }
                // Snapshot UIDs before dispatch so we can attribute the
                // entities this candidate surfaces back to its parent.
                before.clear();
                before.extend(entity_map.keys().cloned());
                if let Err(e) = self
                    .dispatch_target(scan_id, nt, ctx, opts, entity_map, true, stats, dispatched)
                    .await
                {
                    // Per-target dispatch errors are already surfaced as
                    // ModuleError events; we keep going through the round.
                    warn!(scan_id, error = %e, "dispatch_target failed (continuing)");
                }
                // Record a DerivedFrom edge for every entity newly created by
                // this candidate's dispatch (merges into existing entities are
                // not "new" and are skipped, avoiding cross-round edge spam).
                // Direction is child -> parent: the new entity (`uid`) was
                // *derived from* the parent it was expanded out of (`parent_uid`),
                // matching the `DerivedFrom` edge name.
                for (uid, child) in entity_map.iter() {
                    if !before.contains(uid) {
                        relations.push(Relation::new(
                            uid.as_str(),
                            parent_uid.as_str(),
                            RelationKind::DerivedFrom,
                            child.confidence,
                            scan_id,
                        ));
                    }
                }
            }

            // ROI bundle: adaptive-depth termination. After the round,
            // measure new-entities-per-dispatched-target; if below floor,
            // stop early. Marginal yield collapses near convergence.
            let new_this_round = entity_map.len().saturating_sub(entities_at_round_start);

            // Round-boundary durability + live correlation from one snapshot:
            // checkpoint the freshly-grown graph to storage so a crash here
            // preserves everything through this round, then re-evaluate the
            // entity rules and stream any newly-fired correlations. Gated on
            // dispatch activity — a round that dispatched nothing cannot have
            // changed the graph, so we skip both passes (backpressure).
            if dispatched_this_round > 0 {
                // Address→Coords pass: any new Address entities this round may
                // name a known city; derive Coordinates before the snapshot so
                // AU-052/053 can correlate them immediately.
                for derived in address_to_coords_pass(entity_map, scan_id) {
                    let mut d = derived;
                    enrich_geospatial(&mut d);
                    if let Some(existing) = entity_map.get_mut(&d.uid) {
                        existing.merge(d);
                    } else {
                        entity_map.insert(d.uid.clone(), d);
                    }
                }
                let snapshot: Vec<Entity> = entity_map.values().cloned().collect();
                self.checkpoint_entities(scan_id, &snapshot);
                self.correlate_incremental(scan_id, &snapshot, emitted_corr);
            }

            let floor = opts
                .min_marginal_yield
                .unwrap_or(crate::core::roi::DEFAULT_MIN_MARGINAL_YIELD);
            if crate::core::roi::should_terminate_adaptive(
                opts.max_roi,
                new_this_round,
                dispatched_this_round,
                floor,
            ) {
                let stop = StopReason::NoMoreCandidates;
                self.emit(
                    scan_id,
                    EventKind::ExpansionStop {
                        reason: format!(
                            "adaptive-depth: marginal yield {:.2} < floor {:.2}",
                            crate::core::roi::marginal_yield(new_this_round, dispatched_this_round),
                            floor
                        ),
                    },
                );
                return stop;
            }
        }
        StopReason::DepthExhausted
    }
}

/// Collapse `Address` entities that denote the **same locality** — differing
/// only by a trailing postcode, case or punctuation — into a single entity,
/// keeping the most specific spelling and folding the rest's evidence and
/// corroboration into it.
///
/// Why at finalise, not in a module: the engine's per-entity UID merge keys on
/// the exact normalised value, so `"Murrumbateman, NSW"` and `"Murrumbateman,
/// NSW 2582"` hash to different UIDs and survive as two Address entities for one
/// place — inflating the location count in the geo correlations (a live scan
/// showed AU-018 reporting a subject co-located with "2" addresses for one
/// suburb). Running here, after every module (API sources included) and every
/// expansion round has folded into `entities`, makes this the codebase-wide,
/// recursion-spanning backstop to the per-module dedup in `search_engines`.
///
/// The survivor is the longest value in the locality group (the postcode-bearing
/// form), with a lexicographic tie-break for determinism; only addresses sharing
/// a [`crate::util::address_au::locality_key`] are merged, so a street address is
/// never folded into a bare suburb.
fn consolidate_address_localities(entities: &mut Vec<Entity>) {
    use crate::core::entity::EntityKind;
    use std::collections::HashMap;

    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, e) in entities.iter().enumerate() {
        if e.kind == EntityKind::Address {
            let key = crate::util::address_au::locality_key(&e.value);
            if !key.is_empty() {
                groups.entry(key).or_default().push(i);
            }
        }
    }

    let mut remove = vec![false; entities.len()];
    let mut folds: Vec<(usize, Entity)> = Vec::new();
    for idxs in groups.values() {
        if idxs.len() < 2 {
            continue;
        }
        // Most specific = longest value; tie → lexicographically smallest, so
        // the survivor is independent of discovery order (Determinism).
        let survivor = *idxs
            .iter()
            .max_by(|&&a, &&b| {
                entities[a]
                    .value
                    .len()
                    .cmp(&entities[b].value.len())
                    .then_with(|| entities[b].value.cmp(&entities[a].value))
            })
            .expect("group is non-empty");
        for &victim in idxs {
            if victim != survivor {
                folds.push((survivor, entities[victim].clone()));
                remove[victim] = true;
            }
        }
    }
    if folds.is_empty() {
        return;
    }
    for (survivor, victim) in folds {
        entities[survivor].absorb(victim);
    }
    let mut idx = 0;
    entities.retain(|_| {
        let keep = !remove[idx];
        idx += 1;
        keep
    });
}

/// Pull any newly-available pooled API key into `keys` for every service that
/// doesn't already have one. This is the key-cascade that makes recursion pay
/// off: a key a module just discovered (oathnet breach data, api_key_probe
/// validation, web_crawler scraping) becomes usable by the next module in the
/// round and by the next expansion round. Idempotent — only fills gaps, never
/// overwrites an operator-supplied key. Shared by `run_expansion` (per-round
/// refresh) and both dispatchers (per-module hot-inject).
fn hot_inject_keys(keys: &mut HashMap<String, String>) {
    let pool = crate::util::key_pool::global_pool();
    for svc in crate::util::key_pool::service_defs() {
        if keys.contains_key(svc.env_var) {
            continue;
        }
        if let Some(key) = pool.next_key(svc.name) {
            let roi = crate::util::key_roi::classify(svc.name);
            info!(
                service = svc.name,
                env_var = svc.env_var,
                roi = roi.label(),
                "hot-inject: pooled key available ({} tier)",
                roi.label()
            );
            keys.insert(svc.env_var.to_string(), key);
        }
    }
}

// ---------------------------------------------------------------------------
// Per-target module dispatch — sequential and concurrent paths.
//
// `ScanEngine::dispatch_target` chooses between:
//   * `dispatch_target_sequential` — `opts.max_concurrent == 0`,
//     Best on low-power Termux devices.
//   * `dispatch_target_concurrent` — `opts.max_concurrent > 0`, up to N
//     modules in flight via `tokio::sync::Semaphore + JoinSet`.
//
// Both paths share `module_skip_reason` for the
// allowlist/exclude/free_only/passive_only filter so the event payloads
// stay identical regardless of dispatch mode.
// ---------------------------------------------------------------------------

/// Modules that legitimately consume private IPs / local domains —
/// sensor modules that run against the local network. Universal
/// preflight (private-IP / local-domain rejection) skips these.
///
/// Re-exposed at `pub(crate)` because `hse radar` drives the same
/// set on every sweep — single source of truth, so adding a new
/// sensor module here both bypasses preflight AND joins the radar
/// loop in one edit.
pub(crate) const LOCAL_PASSIVE_MODULES: &[&str] =
    &["device_sensors", "wifi_intel", "cell_intel", "local_net"];

#[cfg(test)]
mod tests;
