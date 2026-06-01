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

use tokio::time::{sleep, timeout};
use tracing::{info, warn};

use crate::core::{
    dependency::ModuleGraph,
    entity::{Entity, normalise},
    error::Result,
    event::{Event, EventBus, EventKind},
    module::{Module, ModuleContext, ModuleCost},
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
}

/// Per-scan log of (module_name, target_kind, normalised_value) triples
/// already dispatched. Prevents the same keyed API from being invoked on
/// the same normalised target across expansion rounds — the primary
/// mechanism that ensures each API key/service is utilised at most once
/// per (target, module) pair in a pivot pipeline.
///
/// Free modules are exempt: their cost is zero and re-running them on the
/// same target across rounds can corroborate entities with fresh evidence.
type DispatchLog = HashSet<(&'static str, TargetKind, String)>;

fn dispatch_key(module_name: &'static str, target: &Target) -> (&'static str, TargetKind, String) {
    let entity_kind = target.kind.to_entity_kind();
    let normalised = normalise(&entity_kind, &target.value);
    (module_name, target.kind, normalised)
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
        if self.bus.send(event).is_err() {
            tracing::trace!(scan_id, "broadcast dropped (no subscribers)");
        }
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

    pub fn modules(&self) -> &[Arc<dyn Module>] {
        &self.modules
    }

    pub fn bus(&self) -> &EventBus {
        &self.bus
    }

    /// Run a scan to completion, including any expansion rounds.
    pub async fn run(
        &self,
        mut scan: Scan,
        target: Target,
        mut ctx: ModuleContext,
    ) -> Result<Scan> {
        scan.status = ScanStatus::Running;
        self.store.upsert_scan(&scan)?;

        // Reset per-scan budget counters so long-lived processes
        // (`hse serve` / `hse live`) get a fresh budget per scan.
        crate::modules::oathnet_pro::reset_budget();
        crate::modules::see_know::reset_budget();
        crate::modules::wigle::reset_budget();

        // Apply per-scan SeekNow budget override if the operator asked
        // for one. Capped at 200 so a single scan cannot blow the
        // per-session ceiling. `reset_budget` above cleared any prior
        // override; this re-installs it for the current scan only.
        if let Some(cap) = scan.options.seeknow_scan_cap {
            let clamped = cap.min(200);
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
        let mut dispatched: DispatchLog = HashSet::new();
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
        self.dispatch_target(
            &scan.id,
            &target,
            &mut ctx,
            &opts,
            &mut entity_map,
            false,
            &mut stats,
            &mut dispatched,
        )
        .await?;

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
                    &mut ctx,
                    &opts,
                    started,
                    &mut entity_map,
                    &mut visited,
                    &mut stats,
                    &mut dispatched,
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
        let entities: Vec<Entity> = entity_map.into_values().collect();
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

        if persisted == 0 && first_err.is_some() {
            scan.status = ScanStatus::Failed;
            scan.entity_count = 0;
            scan.error = first_err;
            scan.finished_at = Some(crate::core::entity::unix_now());
            let _ = self.store.upsert_scan(scan);
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
        let structural = crate::core::relation::derive_structural(entities, scan_id);
        let colocation = crate::core::relation::derive_colocation(entities, scan_id);
        let resolution = crate::core::relation::derive_resolution(entities, scan_id);
        let registration = crate::core::relation::derive_registration(entities, scan_id);
        if lineage.is_empty()
            && structural.is_empty()
            && colocation.is_empty()
            && resolution.is_empty()
            && registration.is_empty()
        {
            return;
        }
        let mut persisted = 0usize;
        for r in lineage
            .iter()
            .chain(structural.iter())
            .chain(colocation.iter())
            .chain(resolution.iter())
            .chain(registration.iter())
        {
            match self.store.upsert_relation(r) {
                Ok(()) => persisted += 1,
                Err(e) => warn!(scan_id, relation = %r.id, error = %e, "relation persist failed"),
            }
        }
        info!(
            scan_id,
            lineage = lineage.len(),
            structural = structural.len(),
            colocation = colocation.len(),
            resolution = resolution.len(),
            registration = registration.len(),
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
        let mut fresh: Vec<crate::core::correlator::Correlation> =
            crate::core::correlator::correlate_entities(entities, scan_id)
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
            let mut next: Vec<(Target, f64, String)> = Vec::new();
            for entity in entity_map.values() {
                if entity.c_effective() < opts.min_expand_confidence {
                    continue;
                }
                // ROI bundle: convergence-pruning. Once an entity has 2+
                // corroborating sources at high confidence, further dispatch
                // only re-confirms what we already know. Skip it.
                if opts.max_roi && crate::core::roi::is_saturated(entity) {
                    continue;
                }
                let Some(tk) = TargetKind::from_entity_kind(&entity.kind) else {
                    continue;
                };
                // Never pivot on a non-routable / reserved / documentation IP
                // (e.g. 192.0.2.1 scraped from a tutorial page, or a private
                // 192.168.x surfaced by local sensors). No external OSINT source
                // can resolve these, so expanding them only burns whole rounds
                // on guaranteed-empty lookups and pollutes the graph with noise.
                if tk == TargetKind::IpAddress
                    && crate::core::validation::is_non_routable_ip(&entity.value)
                {
                    continue;
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
                    let weight = crate::core::scan::expansion_weight_for_strategy(
                        opts.expansion_strategy,
                        tk,
                        entity.c_effective(),
                        &entity.value,
                        has_paid,
                        richness,
                    ) * crate::core::scan::corroboration_prior(entity.source_count());
                    next.push((new_target, weight, entity.uid.clone()));
                }
            }

            // Sort expansion candidates by weighted score (descending).
            // The weight combines geo_npv with entity confidence and
            // dampens generic mega-domains that waste expansion budget.
            next.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

            // ROI bundle: top-K gate + relative knee. Keep the leading
            // candidates by weight (budget-bounded via top-K, scaled with
            // concurrency) AND drop the long tail that sorts far below this
            // round's best lead (quality-bounded via the knee). Stops both
            // a flood of low-weight domains from a single SERP and the
            // dampened mega-domain noise that survives top-K on a thin round.
            if opts.max_roi {
                let weights: Vec<f64> = next.iter().map(|(_, w, _)| *w).collect();
                let keep = crate::core::roi::effective_cutoff(&weights, opts.max_concurrent);
                if next.len() > keep {
                    next.truncate(keep);
                }
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

/// Stable identity for a correlation, used to dedup live-streamed firings
/// against the authoritative finalise pass. Order-independent in the entity
/// set so the same rule firing over the same entities keys identically
/// regardless of discovery order.
fn correlation_key(c: &crate::core::correlator::Correlation) -> String {
    let mut uids = c.entity_uids.clone();
    uids.sort();
    format!("{}\u{1f}{}", c.rule_id, uids.join("\u{1e}"))
}

/// Visit-key for the expansion visited-set. Normalises the value the same
/// way `Entity::new` does, so the seed target matches entities that point
/// back at it.
fn visit_key(target: &Target) -> (TargetKind, String) {
    let entity_kind = target.kind.to_entity_kind();
    let normalised = normalise(&entity_kind, &target.value);
    (target.kind, normalised)
}

/// Upper bound (ms) on any single module's timeout when running on Termux and
/// the operator hasn't pinned `--module-timeout`. On a low-power, metered,
/// often-flaky mobile connection a 90–120 s module (search_engines, api_key_probe)
/// can stall the whole scan; capping the worst offenders keeps a phone scan
/// responsive. Desktop and any explicit user timeout are unaffected.
/// Hard ceiling on any single module's `process()` on Termux (no user
/// override). Lowered from 60 s after live device transcripts showed
/// `search_engines` burning the full minute for zero results on a phone:
/// 45 s still clears every legitimately-long module's happy path
/// (social_probe ~36 s, oathnet/overpass <30 s) while reclaiming the dead
/// tail of hung mobile requests. Per-module `termux_timeout_ms()` can trim
/// further below this.
const TERMUX_MODULE_TIMEOUT_CAP_MS: u64 = 45_000;

fn resolve_timeout(opts: &ScanOptions, module: &dyn Module) -> u64 {
    let user_set = opts.module_timeout_ms;
    let is_termux = crate::is_termux();
    // On Termux, consult the module's Termux-specific budget (defaults to
    // max_timeout_ms, so most modules are unaffected) so phone-pathological
    // modules self-trim; off Termux, the full desktop budget. A user-pinned
    // --module-timeout replaces both and is honoured verbatim by the cap.
    let base = match user_set {
        Some(ms) => ms,
        None if is_termux => module.termux_timeout_ms(),
        None => module.max_timeout_ms(),
    };
    apply_termux_cap(base, user_set.is_some(), is_termux)
}

/// Pure timeout-capping policy (split out so it's unit-testable without env):
/// on Termux with no user override, clamp to [`TERMUX_MODULE_TIMEOUT_CAP_MS`];
/// otherwise pass the resolved value through unchanged.
fn apply_termux_cap(base_ms: u64, user_set: bool, is_termux: bool) -> u64 {
    if is_termux && !user_set {
        base_ms.min(TERMUX_MODULE_TIMEOUT_CAP_MS)
    } else {
        base_ms
    }
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

fn budget_check(opts: &ScanOptions, started: Instant, current_count: usize) -> Option<StopReason> {
    if let Some(max) = opts.max_entities
        && current_count >= max
    {
        return Some(StopReason::MaxEntities(max));
    }
    if let Some(max_secs) = opts.max_wall_time_secs
        && started.elapsed() >= Duration::from_secs(max_secs)
    {
        return Some(StopReason::MaxWallTime(max_secs));
    }
    None
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

/// The output of one `module.process()` call after the engine wraps it
/// in `tokio::time::timeout` — either `Elapsed` (outer timeout fired),
/// `Err` (module returned an error), or `Ok(ModuleResult)` (success).
type TimeoutResult =
    std::result::Result<Result<crate::core::module::ModuleResult>, tokio::time::error::Elapsed>;

/// What a spawned per-module task returns to the consumer loop.
struct DispatchOutcome {
    name: &'static str,
    result: TimeoutResult,
}

impl ScanEngine {
    /// Translate one module's `process()` result into engine events
    /// (`ModuleError` / `EntityFound` / `ModuleDone`) and merge any
    /// emitted entities into the per-scan `entity_map`. Shared by
    /// `dispatch_target_sequential` and `dispatch_target_concurrent`
    /// so the event payload shape is identical between the two paths.
    fn finalise_module_result(
        &self,
        scan_id: &str,
        name: &'static str,
        min_confidence: Option<f64>,
        entity_map: &mut HashMap<String, Entity>,
        result: TimeoutResult,
        stats: &mut ModuleStats,
    ) {
        stats.run += 1;
        match result {
            Err(_) => {
                stats.timed_out += 1;
                warn!(module = name, "timeout");
                self.emit(
                    scan_id,
                    EventKind::ModuleError {
                        module: name.into(),
                        error: "timeout".into(),
                    },
                );
            }
            Ok(Err(e)) => {
                stats.errored += 1;
                warn!(module = name, error = %e, "module error");
                self.emit(
                    scan_id,
                    EventKind::ModuleError {
                        module: name.into(),
                        error: e.to_string(),
                    },
                );
            }
            Ok(Ok(mut mr)) => {
                let mut found = 0usize;
                for entity in mr.entities.drain(..) {
                    if let Some(min) = min_confidence
                        && entity.confidence < min
                    {
                        continue;
                    }
                    // Drop guaranteed-bogus IPs (documentation / reserved /
                    // benchmark ranges, e.g. 192.0.2.1 scraped off a tutorial
                    // page) at admission so they never enter the graph, fire
                    // correlations, or appear as findings. RFC1918 private and
                    // loopback are intentionally kept — local sensors surface
                    // those legitimately on-device.
                    if entity.kind == crate::core::entity::EntityKind::IpAddress
                        && crate::core::validation::is_bogus_ip(&entity.value)
                    {
                        continue;
                    }
                    self.emit(
                        scan_id,
                        EventKind::EntityFound {
                            entity: entity.clone(),
                        },
                    );
                    scan_entity_for_keys(&entity);
                    let mut entity = entity;
                    enrich_geospatial(&mut entity);
                    if let Some(existing) = entity_map.get_mut(&entity.uid) {
                        existing.merge(entity);
                    } else {
                        entity_map.insert(entity.uid.clone(), entity);
                    }
                    found += 1;
                }
                self.emit(
                    scan_id,
                    EventKind::ModuleDone {
                        module: name.into(),
                        found,
                    },
                );
                info!(module = name, found, "done");
            }
        }
    }

    /// Dispatch every accepting module against `target`. Picks the
    /// sequential or concurrent codepath based on `opts.max_concurrent`.
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_target(
        &self,
        scan_id: &str,
        target: &Target,
        ctx: &mut ModuleContext,
        opts: &ScanOptions,
        entity_map: &mut HashMap<String, Entity>,
        is_expansion: bool,
        stats: &mut ModuleStats,
        dispatched: &mut DispatchLog,
    ) -> Result<()> {
        if opts.max_concurrent == 0 {
            self.dispatch_target_sequential(
                scan_id,
                target,
                ctx,
                opts,
                entity_map,
                is_expansion,
                stats,
                dispatched,
            )
            .await
        } else {
            self.dispatch_target_concurrent(
                scan_id,
                target,
                ctx,
                opts,
                entity_map,
                is_expansion,
                stats,
                dispatched,
            )
            .await
        }
    }

    /// Sequential dispatcher (max_concurrent == 0).
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_target_sequential(
        &self,
        scan_id: &str,
        target: &Target,
        ctx: &mut ModuleContext,
        opts: &ScanOptions,
        entity_map: &mut HashMap<String, Entity>,
        is_expansion: bool,
        stats: &mut ModuleStats,
        dispatched: &mut DispatchLog,
    ) -> Result<()> {
        // O(1) dispatch-index lookup replaces the O(M) accepts() scan.
        // Modules are already priority-sorted within each bucket so we
        // walk them in the same order the legacy `for module in &self.modules`
        // loop did. Iterating index-by-index (instead of pre-allocating
        // a `Vec<Arc<dyn Module>>` and Arc-cloning per target) avoids
        // a heap allocation + N atomic increments per dispatch — meaningful
        // on the hot path that runs once per expansion candidate.
        // Distinct-source count of the target entity (for the high-value-API
        // cross-correlation gate); computed once per target, not per module.
        let target_sources = target_distinct_sources(entity_map, target);
        for &idx in self.graph.modules_for(target.kind) {
            let Some(module) = self.modules.get(idx) else {
                continue;
            };
            if ctx.cancel.is_cancelled() {
                return Ok(());
            }
            if opts.max_entities.is_some_and(|cap| entity_map.len() >= cap) {
                return Ok(());
            }
            let name = module.name();

            // Belt-and-braces: a module whose `consumes()` declaration
            // diverges from its runtime `accepts()` would otherwise
            // slip through. Cheap re-check on the hit path.
            if !module.accepts(target) {
                continue;
            }
            if let Some(reason) =
                module_skip_reason(&**module, target, opts, is_expansion, target_sources)
            {
                self.emit_skipped(scan_id, name, reason);
                continue;
            }
            if !matches!(module.cost(), ModuleCost::Free)
                && !dispatched.insert(dispatch_key(name, target))
            {
                stats.deduped += 1;
                self.emit_skipped(scan_id, name, "already dispatched for this target");
                continue;
            }

            self.emit(
                scan_id,
                EventKind::ModuleStart {
                    module: name.into(),
                },
            );

            let result = timeout(
                Duration::from_millis(resolve_timeout(opts, &**module)),
                module.process(target, ctx),
            )
            .await;

            self.finalise_module_result(
                scan_id,
                name,
                opts.min_confidence,
                entity_map,
                result,
                stats,
            );

            hot_inject_keys(&mut ctx.keys);

            // Re-check the cancel flag before the throttle sleep so an
            // operator cancel between modules doesn't pay the full
            // `throttle_ms` latency before the next gate at the top of
            // the loop is reached. The throttle exists to be polite to
            // upstreams; once the operator has asked us to stop there's
            // nothing left to be polite about.
            if ctx.cancel.is_cancelled() {
                return Ok(());
            }
            if opts.throttle_ms > 0 {
                sleep(Duration::from_millis(opts.throttle_ms)).await;
            }
        }
        Ok(())
    }

    /// Concurrent dispatcher (max_concurrent > 0). Launches up to `opts.max_concurrent`
    /// modules at a time via a Semaphore; collects results as tasks complete.
    ///
    /// Paid modules run synchronously first (key-discovery-first pattern):
    /// oathnet_pro, dehashed, intelx discover API keys that hot-inject into
    /// ctx before the remaining modules are spawned concurrently. Without this,
    /// all modules launch with a cloned ctx that lacks discovered keys.
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_target_concurrent(
        &self,
        scan_id: &str,
        target: &Target,
        ctx: &mut ModuleContext,
        opts: &ScanOptions,
        entity_map: &mut HashMap<String, Entity>,
        is_expansion: bool,
        stats: &mut ModuleStats,
        dispatched: &mut DispatchLog,
    ) -> Result<()> {
        use tokio::sync::Semaphore;
        use tokio::task::JoinSet;

        // O(1) dispatch-index lookup — only modules accepting `target.kind`
        // are even considered. Phase 1 then filters to Paid. We iterate
        // indices directly rather than allocating a `Vec<Arc<dyn Module>>`
        // and Arc-cloning per target; on the hot path this saves a heap
        // allocation + N atomic increments per dispatch.

        // Phase 1: Run Paid modules synchronously so discovered keys are
        // available via hot-inject before the concurrent phase begins.
        let target_sources = target_distinct_sources(entity_map, target);
        for &idx in self.graph.modules_for(target.kind) {
            let Some(module) = self.modules.get(idx) else {
                continue;
            };
            if !matches!(module.cost(), ModuleCost::Paid) {
                continue;
            }
            if ctx.cancel.is_cancelled() {
                break;
            }
            let name = module.name();
            if !module.accepts(target) {
                continue;
            }
            if let Some(reason) =
                module_skip_reason(&**module, target, opts, is_expansion, target_sources)
            {
                self.emit_skipped(scan_id, name, reason);
                continue;
            }
            if !dispatched.insert(dispatch_key(name, target)) {
                stats.deduped += 1;
                self.emit_skipped(scan_id, name, "already dispatched for this target");
                continue;
            }
            self.emit(
                scan_id,
                EventKind::ModuleStart {
                    module: name.into(),
                },
            );
            let result = timeout(
                Duration::from_millis(resolve_timeout(opts, &**module)),
                module.process(target, ctx),
            )
            .await;
            self.finalise_module_result(
                scan_id,
                name,
                opts.min_confidence,
                entity_map,
                result,
                stats,
            );
            // Hot-inject discovered keys so Phase 2 modules can use them.
            // Multiplier-tier keys (Shodan, Censys, Hunter, Proxycurl etc.)
            // cascade — their outputs feed web_crawler/search_engines, which
            // discover MORE keys.
            hot_inject_keys(&mut ctx.keys);
        }

        // Phase 2: Spawn remaining (Free + KeyGated) modules concurrently.
        // ctx now contains any keys discovered in Phase 1. Same
        // index-iteration pattern as Phase 1 — Arc::clone moves to the
        // single spawn site below, instead of being paid for every
        // candidate during candidate-list construction.
        let sem = Arc::new(Semaphore::new(opts.max_concurrent));
        let mut set: JoinSet<DispatchOutcome> = JoinSet::new();
        let scan_id_arc: Arc<str> = scan_id.into();
        // Share one context across all spawned modules in this round instead of
        // deep-cloning the keys map + scan_id per dispatch. Modules take
        // `&ModuleContext` (read-only) and ctx is stable within a round, so an
        // Arc bump per spawn replaces N HashMap/String clones — a real win on a
        // low-RAM phone with ~80 modules/round.
        let ctx_shared: Arc<ModuleContext> = Arc::new(ctx.clone());

        let target_sources = target_distinct_sources(entity_map, target);
        for &idx in self.graph.modules_for(target.kind) {
            let Some(module) = self.modules.get(idx) else {
                continue;
            };
            if matches!(module.cost(), ModuleCost::Paid) {
                continue;
            }
            if ctx.cancel.is_cancelled() {
                break;
            }
            if opts.max_entities.is_some_and(|cap| entity_map.len() >= cap) {
                break;
            }
            let name = module.name();

            if !module.accepts(target) {
                continue;
            }
            if let Some(reason) =
                module_skip_reason(&**module, target, opts, is_expansion, target_sources)
            {
                self.emit_skipped(scan_id, name, reason);
                continue;
            }
            if !matches!(module.cost(), ModuleCost::Free)
                && !dispatched.insert(dispatch_key(name, target))
            {
                stats.deduped += 1;
                self.emit_skipped(scan_id, name, "already dispatched for this target");
                continue;
            }

            let Ok(permit) = Arc::clone(&sem).acquire_owned().await else {
                break;
            };

            let module_arc: Arc<dyn Module> = Arc::clone(module);
            let target = target.clone();
            let ctx = Arc::clone(&ctx_shared);
            let emitter = self.emitter.clone();
            let sid = Arc::clone(&scan_id_arc);
            let throttle_ms = opts.throttle_ms;
            let module_timeout_ms = resolve_timeout(opts, &*module_arc);

            set.spawn(async move {
                let _permit = permit;

                emitter.emit(
                    &sid,
                    EventKind::ModuleStart {
                        module: name.into(),
                    },
                );

                let result = timeout(
                    Duration::from_millis(module_timeout_ms),
                    module_arc.process(&target, &ctx),
                )
                .await;

                if throttle_ms > 0 {
                    sleep(Duration::from_millis(throttle_ms)).await;
                }

                DispatchOutcome { name, result }
            });
        }

        while let Some(joined) = set.join_next().await {
            let outcome = match joined {
                Ok(o) => o,
                Err(e) if e.is_cancelled() => {
                    tracing::debug!("concurrent module task cancelled");
                    continue;
                }
                Err(e) => {
                    warn!(error = %e, "concurrent module task panicked");
                    self.emit(
                        scan_id,
                        EventKind::ModuleError {
                            module: "unknown (panicked)".into(),
                            error: e.to_string(),
                        },
                    );
                    continue;
                }
            };
            self.finalise_module_result(
                scan_id,
                outcome.name,
                opts.min_confidence,
                entity_map,
                outcome.result,
                stats,
            );
        }
        Ok(())
    }
}

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

/// Returns `Some(reason)` if `module` should be skipped under `opts`.
/// `accepts(target)` is intentionally NOT checked here — that case skips
/// silently with no `ModuleSkipped` event, the others all emit one.
/// Count the DISTINCT evidence sources backing the entity that `target`
/// refers to, by re-deriving the entity UID the same way `Entity::new` does.
/// Used to gate high-value paid modules behind "sufficient cross-correlation"
/// on expansion rounds. Returns 0 when the target isn't (yet) in the map — the
/// seed target itself isn't an entity, but seed dispatch (`!is_expansion`)
/// never consults this gate, so 0 is safe there.
fn target_distinct_sources(entity_map: &HashMap<String, Entity>, target: &Target) -> usize {
    let entity_kind = target.kind.to_entity_kind();
    let normalised = normalise(&entity_kind, &target.value);
    let uid = crate::core::entity::derive_uid(&entity_kind, &normalised);
    entity_map
        .get(&uid)
        .map_or(0, |e| e.evidence_sources().len())
}

fn module_skip_reason(
    module: &dyn Module,
    target: &Target,
    opts: &ScanOptions,
    is_expansion: bool,
    target_distinct_sources: usize,
) -> Option<&'static str> {
    let name = module.name();
    if !is_expansion
        && let Some(allow) = &opts.modules
        && !allow.iter().any(|n| n == name)
    {
        return Some("not in allowlist");
    }
    if opts.exclude_modules.iter().any(|n| n == name) {
        return Some("excluded");
    }
    if opts.free_only && !matches!(module.cost(), ModuleCost::Free) {
        return Some("requires key/payment");
    }
    if opts.passive_only && !module.is_passive() {
        return Some("not passive");
    }
    if is_expansion && module.is_passive() && LOCAL_PASSIVE_MODULES.contains(&name) {
        return Some("sensor (already ran on seed round)");
    }
    // High-value-only modules: the heaviest paid API (oathnet_pro, priority
    // 127, Paid, 30s) burns one query per target and a low-specificity seed
    // fans out into a large unrelated corpus — a live `name="Onur Ada"` scan
    // pulled 172 unrelated US-banking breach records that buried the real
    // findings. Per the operator's rule, such a module may fire when the
    // target is EITHER the initial seed query OR a discovered entity that has
    // reached *sufficient cross-correlation* — i.e. corroborated by at least
    // `CROSS_CORRELATION_MIN_SOURCES` DISTINCT evidence sources, not just a
    // bumped corroboration counter. On the live scan this admits the genuinely
    // on-target pivots (the breach email at 4 sources, the person at 3, the
    // employer domain at 2) while excluding the 97 single-source banking
    // emails that would otherwise trigger fresh fan-out. SeekNow (`see_know`)
    // is intentionally NOT gated here: its own per-scan budget in
    // `util::see_know` bounds the quota while letting it pivot freely.
    const HIGH_VALUE_ONLY_MODULES: &[&str] = &["oathnet_pro"];
    const CROSS_CORRELATION_MIN_SOURCES: usize = 2;
    if is_expansion
        && HIGH_VALUE_ONLY_MODULES.contains(&name)
        && target_distinct_sources < CROSS_CORRELATION_MIN_SOURCES
    {
        return Some("high-value API — awaiting cross-correlation (>=2 sources)");
    }
    // ── Universal preflight: reject private IPs / local domains for
    // modules that talk to external APIs. Sensor modules opt out via
    // LOCAL_PASSIVE_MODULES — they legitimately scan the local
    // network. Every other module is treated as "may reach an external
    // service" so we save its quota / suppress its "HTTP 400 invalid
    // IP" responses before the dispatch even fires.
    //
    // Modules with non-IP/Domain accepts (Email, Phone, Username, etc.)
    // fall through the `_` arm and run normally — there's no concept
    // of a "private email".
    if !LOCAL_PASSIVE_MODULES.contains(&name) {
        use crate::util::preflight;
        match target.kind {
            // Use the v6-tolerant gate — public IPv6 must pass through
            // (shodan, censys, RDAP, abuseipdb, etc. all support v6).
            // `should_skip_external_ipv4` rejects ANY `:`-containing
            // string and is reserved for the small set of IPv4-only
            // modules (ipapi, ip-api.com, ipinfo.io, ipquery.io)
            // that route through it inside their own `process`.
            TargetKind::IpAddress if preflight::should_skip_external_ip(&target.value) => {
                return Some("private/reserved IP — external API would reject");
            }
            TargetKind::Domain if preflight::is_local_domain(&target.value) => {
                return Some("local/reserved domain — external API would reject");
            }
            // SSRF gate: a URL whose host is a private IP or local
            // domain must not reach a URL-accepting external module
            // (dns_intel, doh_resolver, exif_geo, geo_domain_classifier,
            // web_crawler). Without this, an autonomously-discovered
            // `http://192.168.1.1/admin` would coerce HSE into
            // hitting the operator's internal network.
            TargetKind::Url if url_host_is_private(&target.value) => {
                return Some("URL with private host — external API would reject (SSRF gate)");
            }
            _ => {}
        }
    }
    None
}

/// True if `url` parses cleanly AND its host is a reserved IP or
/// a local-only domain. Mid-parse failures return false (let the
/// module's own validation reject malformed URLs as usual).
fn url_host_is_private(url: &str) -> bool {
    use crate::util::preflight::{is_local_domain, is_private_ip};
    let Ok(parsed) = url::Url::parse(url.trim()) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    // url 2.5 returns IPv6 host_str WITH brackets (`[::1]`); strip
    // them before passing to is_private_ip so the IpAddr parse fires.
    let bare = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    if is_private_ip(bare) {
        return true;
    }
    is_local_domain(bare)
}

/// Augment Coordinates entities with geohash + timezone, and Address
/// entities with parsed admin-hierarchy components. Runs once per
/// emission so downstream correlators see the enriched evidence.
fn enrich_geospatial(entity: &mut crate::core::entity::Entity) {
    use crate::core::entity::{EntityKind, Evidence};
    use crate::util::geohash;
    match entity.kind {
        EntityKind::Coordinates => {
            if let Some((lat, lon)) = geohash::parse_coords(&entity.value) {
                let h = geohash::geohash(lat, lon, 7);
                let tz = geohash::timezone_for(lat, lon);
                let iso = geohash::reverse_country_iso(lat, lon);
                let mut ev = Evidence::new("geo_normalize", "Geospatial enrichment");
                if !h.is_empty() {
                    ev = ev.with_attr("geohash", &h);
                    // Multiple precision-tagged hashes for proximity matching
                    // at different scales (region/city/suburb/street).
                    ev = ev
                        .with_attr("geohash_4", &h[..h.len().min(4)])
                        .with_attr("geohash_5", &h[..h.len().min(5)])
                        .with_attr("geohash_6", &h[..h.len().min(6)]);
                    if let Ok(h9) = std::panic::catch_unwind(|| geohash::geohash(lat, lon, 9)) {
                        ev = ev.with_attr("geohash_9", &h9);
                    }
                }
                ev = ev.with_attr("timezone", tz);
                ev = ev.with_attr("lat", format!("{lat:.6}"));
                ev = ev.with_attr("lon", format!("{lon:.6}"));
                let hemisphere = if lat >= 0.0 { "northern" } else { "southern" };
                ev = ev.with_attr("hemisphere", hemisphere);
                if let Some(iso) = iso {
                    ev = ev.with_attr("country_iso", iso);
                    if let Some(name) = geohash::country_name_for_iso(iso) {
                        ev = ev.with_attr("country_name", name);
                    }
                    entity.tag(format!("country:{iso}"));
                }
                entity.add_evidence(ev);
                entity.tag(format!("geohash:{}", &h[..h.len().min(5)]));
                entity.tag(format!("tz:{tz}"));
            }
        }
        EntityKind::Address => {
            let parsed = geohash::parse_address(&entity.value);
            let mut ev = Evidence::new("geo_normalize", "Address parse + normalization");
            let mut any = false;
            if let Some(s) = &parsed.street {
                ev = ev.with_attr("addr_street", s);
                any = true;
            }
            if let Some(c) = &parsed.city {
                ev = ev.with_attr("addr_city", c);
                any = true;
            }
            if let Some(s) = &parsed.state {
                ev = ev.with_attr("addr_state", s);
                any = true;
            }
            if let Some(p) = &parsed.postal_code {
                ev = ev.with_attr("addr_postal", p);
                any = true;
            }
            if let Some(c) = &parsed.country {
                ev = ev.with_attr("addr_country", c);
                any = true;
            }
            if let Some(iso) = &parsed.iso_country {
                ev = ev.with_attr("addr_iso", iso);
                entity.tag(format!("country:{iso}"));
                any = true;
            }
            if any {
                entity.add_evidence(ev);
            }
        }
        _ => {}
    }
}

fn scan_entity_for_keys(entity: &crate::core::entity::Entity) {
    use crate::modules::oathnet_pro::key_harvest::identify_api_key;
    use crate::util::key_pool::{KeyEntry, KeyStatus, global_pool};

    let pool = global_pool();
    let now = crate::core::entity::unix_now();
    let entity_ref = format!("{}:{}", entity.kind, &entity.uid[..8]);

    let harvest = |text: &str, source: &str, notes: Option<String>| {
        if let Some((service, key_val)) = identify_api_key(text) {
            let mut entry = KeyEntry::new(key_val);
            entry.status = KeyStatus::Untested;
            entry.discovered_at = Some(now);
            entry.discovered_by = Some(source.to_string());
            entry.discovered_in_scan = Some(entity.scan_id.clone());
            entry.source_entity = Some(entity_ref.clone());
            entry.notes = notes;
            pool.add(service, entry);
        }
    };

    harvest(&entity.value, "entity_value", None);

    for ev in &entity.evidence {
        for val in ev.attributes.values() {
            if (16..=200).contains(&val.len()) {
                harvest(
                    val,
                    &ev.source,
                    Some(format!("Evidence attr from {}", ev.source)),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn termux_cap_bounds_long_modules_only_on_termux_without_override() {
        // Desktop (not Termux): full timeout preserved, even 120 s.
        assert_eq!(apply_termux_cap(120_000, false, false), 120_000);
        // Termux, no user override: the worst offenders are clamped to 45 s...
        assert_eq!(
            apply_termux_cap(120_000, false, true),
            TERMUX_MODULE_TIMEOUT_CAP_MS
        );
        assert_eq!(
            apply_termux_cap(90_000, false, true),
            TERMUX_MODULE_TIMEOUT_CAP_MS
        );
        // ...the old 60 s ceiling is now itself clamped down to the 45 s cap...
        assert_eq!(
            apply_termux_cap(60_000, false, true),
            TERMUX_MODULE_TIMEOUT_CAP_MS
        );
        assert_eq!(TERMUX_MODULE_TIMEOUT_CAP_MS, 45_000);
        // ...while the common short timeouts pass through unchanged.
        assert_eq!(apply_termux_cap(8_000, false, true), 8_000);
        assert_eq!(apply_termux_cap(20_000, false, true), 20_000);
        // An explicit --module-timeout is honoured verbatim, even on Termux,
        // even above the cap (the operator asked for it).
        assert_eq!(apply_termux_cap(120_000, true, true), 120_000);
    }

    #[test]
    fn resolve_timeout_uses_termux_budget_then_cap() {
        // A module whose Termux budget is below the cap is honoured as-is on a
        // phone, while its larger desktop budget is what's used off-Termux.
        // (apply_termux_cap carries the is_termux branch; here we assert the
        // base-selection + clamp composition for both a default and an
        // override module, independent of the runtime environment.)
        struct DefaultMod; // termux_timeout_ms defaults to max_timeout_ms
        #[async_trait::async_trait]
        impl Module for DefaultMod {
            fn name(&self) -> &'static str {
                "d"
            }
            fn priority(&self) -> u8 {
                1
            }
            fn accepts(&self, _t: &Target) -> bool {
                false
            }
            async fn process(
                &self,
                _t: &Target,
                _c: &ModuleContext,
            ) -> Result<crate::core::module::ModuleResult> {
                Ok(crate::core::module::ModuleResult::new())
            }
            fn max_timeout_ms(&self) -> u64 {
                120_000
            }
        }
        struct TrimmedMod; // overrides termux budget down
        #[async_trait::async_trait]
        impl Module for TrimmedMod {
            fn name(&self) -> &'static str {
                "t"
            }
            fn priority(&self) -> u8 {
                1
            }
            fn accepts(&self, _t: &Target) -> bool {
                false
            }
            async fn process(
                &self,
                _t: &Target,
                _c: &ModuleContext,
            ) -> Result<crate::core::module::ModuleResult> {
                Ok(crate::core::module::ModuleResult::new())
            }
            fn max_timeout_ms(&self) -> u64 {
                120_000
            }
            fn termux_timeout_ms(&self) -> u64 {
                30_000
            }
        }
        // Default module: desktop budget is the full 120 s; the Termux budget
        // defaults to the same value but is clamped by the cap to 45 s.
        assert_eq!(DefaultMod.termux_timeout_ms(), 120_000);
        assert_eq!(
            apply_termux_cap(DefaultMod.termux_timeout_ms(), false, true),
            45_000
        );
        // Trimmed module: its 30 s Termux budget is under the cap, so it is
        // used verbatim on a phone and is strictly tighter than the default.
        assert_eq!(TrimmedMod.termux_timeout_ms(), 30_000);
        assert_eq!(
            apply_termux_cap(TrimmedMod.termux_timeout_ms(), false, true),
            30_000
        );
        assert!(TrimmedMod.termux_timeout_ms() < DefaultMod.termux_timeout_ms());
    }

    #[test]
    fn visit_key_normalises_email() {
        let t = Target::new(TargetKind::Email, "ALICE@Example.COM");
        let (kind, val) = visit_key(&t);
        assert_eq!(kind, TargetKind::Email);
        assert_eq!(val, "alice@example.com");
    }

    #[test]
    fn visit_key_normalises_domain_trailing_dot() {
        let t = Target::new(TargetKind::Domain, "example.com.");
        let (_, val) = visit_key(&t);
        assert_eq!(val, "example.com");
    }

    #[test]
    fn budget_check_none_when_no_limits() {
        let opts = ScanOptions::default();
        let started = Instant::now();
        assert!(budget_check(&opts, started, 1000).is_none());
    }

    #[test]
    fn budget_check_max_entities_triggers() {
        let opts = ScanOptions {
            max_entities: Some(5),
            ..Default::default()
        };
        let started = Instant::now();
        assert!(budget_check(&opts, started, 4).is_none());
        assert!(budget_check(&opts, started, 5).is_some());
    }

    #[test]
    fn budget_check_wall_time_triggers() {
        let opts = ScanOptions {
            max_wall_time_secs: Some(0),
            ..Default::default()
        };
        let started = Instant::now() - Duration::from_secs(1);
        assert!(budget_check(&opts, started, 0).is_some());
    }

    #[test]
    fn stop_reason_labels_are_descriptive() {
        assert!(StopReason::NoMoreCandidates.label().contains("candidate"));
        assert!(StopReason::DepthExhausted.label().contains("depth"));
        assert!(StopReason::MaxEntities(10).label().contains("10"));
        assert!(StopReason::MaxWallTime(60).label().contains("60"));
        assert!(StopReason::Cancelled.label().contains("cancel"));
    }

    // -- dispatch tests (from former dispatch.rs) --

    struct StubModule {
        name: &'static str,
        cost: ModuleCost,
        passive: bool,
    }

    #[async_trait::async_trait]
    impl Module for StubModule {
        fn name(&self) -> &'static str {
            self.name
        }
        fn priority(&self) -> u8 {
            50
        }
        fn accepts(&self, _: &Target) -> bool {
            true
        }
        fn cost(&self) -> ModuleCost {
            self.cost
        }
        fn is_passive(&self) -> bool {
            self.passive
        }
        async fn process(
            &self,
            _: &Target,
            _: &ModuleContext,
        ) -> crate::core::error::Result<crate::core::module::ModuleResult> {
            Ok(crate::core::module::ModuleResult::new())
        }
    }

    /// Neutral public IP target used by skip-reason tests so the
    /// universal preflight gate doesn't fire on the test fixture.
    fn pub_target() -> Target {
        Target::new(TargetKind::IpAddress, "1.1.1.1")
    }

    fn free_active() -> StubModule {
        StubModule {
            name: "test_free",
            cost: ModuleCost::Free,
            passive: false,
        }
    }

    fn keygated() -> StubModule {
        StubModule {
            name: "test_keygated",
            cost: ModuleCost::KeyGated,
            passive: false,
        }
    }

    fn paid_passive() -> StubModule {
        StubModule {
            name: "test_paid",
            cost: ModuleCost::Paid,
            passive: true,
        }
    }

    #[test]
    fn skip_reason_none_for_default_opts() {
        let m = free_active();
        let opts = ScanOptions::default();
        assert!(module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none());
    }

    #[test]
    fn skip_reason_not_in_allowlist() {
        let m = free_active();
        let opts = ScanOptions {
            modules: Some(vec!["other_module".into()]),
            ..Default::default()
        };
        assert_eq!(
            module_skip_reason(&m, &pub_target(), &opts, false, 0),
            Some("not in allowlist")
        );
    }

    #[test]
    fn skip_reason_in_allowlist_passes() {
        let m = free_active();
        let opts = ScanOptions {
            modules: Some(vec!["test_free".into()]),
            ..Default::default()
        };
        assert!(module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none());
    }

    #[test]
    fn skip_reason_excluded() {
        let m = free_active();
        let opts = ScanOptions {
            exclude_modules: vec!["test_free".into()],
            ..Default::default()
        };
        assert_eq!(
            module_skip_reason(&m, &pub_target(), &opts, false, 0),
            Some("excluded")
        );
    }

    #[test]
    fn skip_reason_free_only_skips_keygated() {
        let m = keygated();
        let opts = ScanOptions {
            free_only: true,
            ..Default::default()
        };
        assert_eq!(
            module_skip_reason(&m, &pub_target(), &opts, false, 0),
            Some("requires key/payment")
        );
    }

    #[test]
    fn skip_reason_free_only_passes_free() {
        let m = free_active();
        let opts = ScanOptions {
            free_only: true,
            ..Default::default()
        };
        assert!(module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none());
    }

    #[test]
    fn skip_reason_passive_only_skips_active() {
        let m = free_active();
        let opts = ScanOptions {
            passive_only: true,
            ..Default::default()
        };
        assert_eq!(
            module_skip_reason(&m, &pub_target(), &opts, false, 0),
            Some("not passive")
        );
    }

    #[test]
    fn skip_reason_passive_only_passes_passive() {
        let m = paid_passive();
        let opts = ScanOptions {
            passive_only: true,
            ..Default::default()
        };
        assert!(module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none());
    }

    // ── high-value-API cross-correlation gate (oathnet_pro) ────────────────

    /// Stub standing in for the high-value paid module by name.
    fn high_value() -> StubModule {
        StubModule {
            name: "oathnet_pro",
            cost: ModuleCost::Paid,
            passive: false,
        }
    }

    #[test]
    fn high_value_module_runs_on_seed_regardless_of_sources() {
        // Seed round (is_expansion=false): always allowed, even with 0 sources
        // (the seed target isn't an entity yet).
        let m = high_value();
        let opts = ScanOptions::default();
        assert!(
            module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none(),
            "high-value module must run on the initial seed query"
        );
    }

    #[test]
    fn high_value_module_skipped_on_expansion_below_cross_correlation() {
        // Expansion, target corroborated by only 1 distinct source → skip.
        let m = high_value();
        let opts = ScanOptions::default();
        assert_eq!(
            module_skip_reason(&m, &pub_target(), &opts, true, 1),
            Some("high-value API — awaiting cross-correlation (>=2 sources)"),
            "single-source discovered entity must NOT trigger the high-value API"
        );
        // 0 sources (not yet in map) on expansion is likewise gated.
        assert!(module_skip_reason(&m, &pub_target(), &opts, true, 0).is_some());
    }

    #[test]
    fn high_value_module_runs_on_expansion_when_cross_correlated() {
        // Expansion, target corroborated by >=2 distinct sources → allowed.
        let m = high_value();
        let opts = ScanOptions::default();
        assert!(
            module_skip_reason(&m, &pub_target(), &opts, true, 2).is_none(),
            "cross-correlated (>=2 sources) entity must reach the high-value API on expansion"
        );
        assert!(module_skip_reason(&m, &pub_target(), &opts, true, 5).is_none());
    }

    #[test]
    fn non_high_value_module_unaffected_by_source_gate() {
        // A normal module is never subject to the high-value cross-correlation
        // gate, even at 0 sources on expansion.
        let m = free_active();
        let opts = ScanOptions::default();
        assert!(module_skip_reason(&m, &pub_target(), &opts, true, 0).is_none());
    }

    #[test]
    fn skip_reason_allowlist_takes_priority_over_exclude() {
        let m = free_active();
        let opts = ScanOptions {
            modules: Some(vec!["test_free".into()]),
            exclude_modules: vec!["test_free".into()],
            ..Default::default()
        };
        assert_eq!(
            module_skip_reason(&m, &pub_target(), &opts, false, 0),
            Some("excluded")
        );
    }

    // -- universal preflight gate (private IP / local domain) --

    #[test]
    fn skip_reason_rejects_private_ip_for_external_module() {
        let m = free_active();
        let private = Target::new(TargetKind::IpAddress, "192.168.1.1");
        let opts = ScanOptions::default();
        assert_eq!(
            module_skip_reason(&m, &private, &opts, false, 0),
            Some("private/reserved IP — external API would reject")
        );
    }

    #[test]
    fn skip_reason_rejects_local_domain_for_external_module() {
        let m = free_active();
        let local = Target::new(TargetKind::Domain, "router.local");
        let opts = ScanOptions::default();
        assert_eq!(
            module_skip_reason(&m, &local, &opts, false, 0),
            Some("local/reserved domain — external API would reject")
        );
    }

    #[test]
    fn skip_reason_lets_local_passive_module_see_private_ip() {
        // local_net, device_sensors, wifi_intel, cell_intel are
        // listed in LOCAL_PASSIVE_MODULES and bypass the preflight.
        let m = StubModule {
            name: "local_net",
            cost: ModuleCost::Free,
            passive: true,
        };
        let private = Target::new(TargetKind::IpAddress, "192.168.1.1");
        let opts = ScanOptions::default();
        assert!(module_skip_reason(&m, &private, &opts, false, 0).is_none());
    }

    #[test]
    fn skip_reason_passes_public_ip_through() {
        let m = free_active();
        let opts = ScanOptions::default();
        assert!(module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none());
    }

    #[test]
    fn skip_reason_passes_public_ipv6_through() {
        // Regression: the universal preflight previously rejected
        // every `:`-containing string via should_skip_external_ipv4,
        // silently breaking IPv6 lookups for v6-capable modules
        // (shodan, censys, abuseipdb, RDAP, etc.). The v6-tolerant
        // gate must let public IPv6 pass through to module dispatch.
        let m = free_active();
        let opts = ScanOptions::default();
        for v6 in [
            "2606:4700:4700::1111", // Cloudflare
            "2001:4860:4860::8888", // Google
            "2620:fe::fe",          // Quad9
        ] {
            let t = Target::new(TargetKind::IpAddress, v6);
            assert!(
                module_skip_reason(&m, &t, &opts, false, 0).is_none(),
                "public IPv6 {v6} should NOT be rejected by the universal gate",
            );
        }
    }

    #[test]
    fn skip_reason_rejects_url_with_private_host_ssrf_gate() {
        // SSRF gate: a Url target whose host parses as a private IP
        // or a local domain must not reach external-API modules.
        // Without this, autonomous expansion that yields
        // `http://192.168.1.1/admin` would coerce HSE into hitting
        // the operator's internal LAN.
        let m = free_active();
        let opts = ScanOptions::default();
        for hostile in [
            "http://192.168.1.1/admin",
            "http://10.0.0.1:8080/",
            "http://127.0.0.1/health",
            "http://[::1]/",
            // IPv4-mapped IPv6 literal: the OS connects this to the underlying
            // IPv4 metadata host, so the bracket-stripped host must canonicalise
            // to v4 and be refused (regression guard for the to_canonical fix).
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://router.local/",
            "https://intra.internal/api",
        ] {
            let t = Target::new(TargetKind::Url, hostile);
            let reason = module_skip_reason(&m, &t, &opts, false, 0);
            assert!(
                reason.is_some_and(|r| r.contains("SSRF") || r.contains("private")),
                "Url {hostile} should be SSRF-rejected, got {reason:?}",
            );
        }
    }

    #[test]
    fn skip_reason_lets_public_url_through() {
        let m = free_active();
        let opts = ScanOptions::default();
        for benign in [
            "https://example.com/",
            "https://api.github.com/users/octocat",
            "http://[2606:4700:4700::1111]/",
        ] {
            let t = Target::new(TargetKind::Url, benign);
            assert!(
                module_skip_reason(&m, &t, &opts, false, 0).is_none(),
                "Url {benign} should pass through",
            );
        }
    }

    #[test]
    fn skip_reason_still_rejects_private_ipv6() {
        // Loopback / unique-local / link-local IPv6 are private and
        // should still be skipped by the universal gate.
        let m = free_active();
        let opts = ScanOptions::default();
        for private_v6 in ["::1", "fc00::1", "fe80::1"] {
            let t = Target::new(TargetKind::IpAddress, private_v6);
            assert!(
                module_skip_reason(&m, &t, &opts, false, 0).is_some(),
                "private IPv6 {private_v6} should be rejected",
            );
        }
    }

    // -- dispatch dedup tests --

    #[test]
    fn dispatch_key_normalises_consistently() {
        let t1 = Target::new(TargetKind::Email, "ALICE@Example.COM");
        let t2 = Target::new(TargetKind::Email, "alice@example.com");
        assert_eq!(dispatch_key("hibp", &t1), dispatch_key("hibp", &t2));
    }

    #[test]
    fn dispatch_key_differs_across_modules() {
        let t = Target::new(TargetKind::Email, "alice@example.com");
        assert_ne!(dispatch_key("hibp", &t), dispatch_key("shodan", &t));
    }

    #[test]
    fn dispatch_key_differs_across_target_kinds() {
        let email = Target::new(TargetKind::Email, "alice@example.com");
        let domain = Target::new(TargetKind::Domain, "alice@example.com");
        assert_ne!(dispatch_key("hibp", &email), dispatch_key("hibp", &domain));
    }

    #[test]
    fn dispatch_log_prevents_duplicate_keyed_module() {
        let mut log: DispatchLog = HashSet::new();
        let t = Target::new(TargetKind::Email, "alice@example.com");
        let key = dispatch_key("hibp", &t);
        assert!(log.insert(key.clone()), "first insert should succeed");
        assert!(!log.insert(key), "second insert should be rejected");
    }

    #[test]
    fn dispatch_log_allows_same_module_on_different_targets() {
        let mut log: DispatchLog = HashSet::new();
        let t1 = Target::new(TargetKind::Email, "alice@example.com");
        let t2 = Target::new(TargetKind::Domain, "example.com");
        assert!(log.insert(dispatch_key("hibp", &t1)));
        assert!(log.insert(dispatch_key("hibp", &t2)));
    }

    #[test]
    fn dispatch_log_allows_different_modules_on_same_target() {
        let mut log: DispatchLog = HashSet::new();
        let t = Target::new(TargetKind::IpAddress, "1.2.3.4");
        assert!(log.insert(dispatch_key("shodan", &t)));
        assert!(log.insert(dispatch_key("greynoise", &t)));
    }
}
