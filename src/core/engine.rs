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
        let mut entity_map: HashMap<String, Entity> =
            HashMap::with_capacity(opts.max_entities.unwrap_or(256).min(4096));
        let mut visited: HashSet<(TargetKind, String)> = HashSet::new();
        let mut dispatched: DispatchLog = HashSet::new();
        let mut stats = ModuleStats::default();
        // Lineage edges (parent entity → child surfaced by expanding it),
        // accumulated across expansion rounds and persisted in finalise_scan.
        let mut lineage: Vec<Relation> = Vec::new();

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
                )
                .await;
        }

        self.finalise_scan(&mut scan, entity_map, &ctx, stats, lineage)
    }

    /// Persist entities, run the correlator, and mark the scan terminal.
    fn finalise_scan(
        &self,
        scan: &mut Scan,
        entity_map: HashMap<String, Entity>,
        ctx: &ModuleContext,
        stats: ModuleStats,
        lineage_relations: Vec<Relation>,
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

        self.run_correlator(&scan.id);

        // Persist the key pool to disk after every scan. Keys discovered
        // during this scan (from breach data, page bodies, entity values)
        // are permanently stored with full provenance metadata.
        let pool = crate::util::key_pool::global_pool();
        if let Err(e) = crate::util::key_pool::save_pool(&pool) {
            warn!("failed to save key pool after scan: {e}");
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
        if lineage.is_empty() && structural.is_empty() && colocation.is_empty() {
            return;
        }
        let mut persisted = 0usize;
        for r in lineage
            .iter()
            .chain(structural.iter())
            .chain(colocation.iter())
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
            persisted,
            "entity relations persisted"
        );
    }

    fn run_correlator(&self, scan_id: &str) {
        match crate::core::correlator::Correlator::new(Arc::clone(&self.store)).run(scan_id) {
            Ok(firings) => {
                for c in &firings {
                    self.emit(
                        scan_id,
                        EventKind::CorrelationFound {
                            correlation: c.clone(),
                        },
                    );
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
    ) -> StopReason {
        // Reused across candidates to capture lineage: the set of entity UIDs
        // present *before* a candidate's dispatch, so new UIDs afterward are
        // children that candidate surfaced. Reusing the buffer avoids a
        // per-candidate allocation; the key clones are bounded by max_entities.
        let mut before: HashSet<String> = HashSet::new();
        for depth in 1..=opts.depth {
            // Refresh keys from the pool at the start of each round.
            // Keys discovered during the previous round (oathnet_pro breach
            // data, api_key_probe validation, web_crawler credential scraping)
            // become available to modules in this round automatically.
            {
                let pool = crate::util::key_pool::global_pool();
                for svc in crate::util::key_pool::service_defs() {
                    if ctx.keys.contains_key(svc.env_var) {
                        continue;
                    }
                    if let Some(key) = pool.next_key(svc.name) {
                        ctx.keys.insert(svc.env_var.to_string(), key);
                    }
                }
            }

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
                let new_target = Target::new(tk, entity.value.clone());
                let key = visit_key(&new_target);
                if visited.insert(key) {
                    let richness = self.graph.richness_for(tk);
                    let weight = crate::core::scan::expansion_weight_for_strategy(
                        opts.expansion_strategy,
                        tk,
                        entity.c_effective(),
                        &entity.value,
                        has_paid,
                        richness,
                    );
                    next.push((new_target, weight, entity.uid.clone()));
                }
            }

            // Sort expansion candidates by weighted score (descending).
            // The weight combines geo_npv with entity confidence and
            // dampens generic mega-domains that waste expansion budget.
            next.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

            // ROI bundle: top-K gate. Keep only the top candidates by
            // weight, scaled with concurrency. Stops long-tail noise
            // (e.g. 80 low-weight domains from a single SERP) from
            // consuming the round.
            if opts.max_roi {
                let k = crate::core::roi::top_k_for_round(opts.max_concurrent);
                if next.len() > k {
                    next.truncate(k);
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
                for (uid, child) in entity_map.iter() {
                    if !before.contains(uid) {
                        relations.push(Relation::new(
                            parent_uid.as_str(),
                            uid.as_str(),
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

/// Visit-key for the expansion visited-set. Normalises the value the same
/// way `Entity::new` does, so the seed target matches entities that point
/// back at it.
fn visit_key(target: &Target) -> (TargetKind, String) {
    let entity_kind = target.kind.to_entity_kind();
    let normalised = normalise(&entity_kind, &target.value);
    (target.kind, normalised)
}

fn resolve_timeout(opts: &ScanOptions, module: &dyn Module) -> u64 {
    opts.module_timeout_ms
        .unwrap_or_else(|| module.max_timeout_ms())
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
            if let Some(reason) = module_skip_reason(&**module, target, opts, is_expansion) {
                self.emit(
                    scan_id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason: reason.into(),
                    },
                );
                continue;
            }
            if !matches!(module.cost(), ModuleCost::Free)
                && !dispatched.insert(dispatch_key(name, target))
            {
                stats.deduped += 1;
                self.emit(
                    scan_id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason: "already dispatched for this target".into(),
                    },
                );
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

            {
                let pool = crate::util::key_pool::global_pool();
                for svc in crate::util::key_pool::service_defs() {
                    if ctx.keys.contains_key(svc.env_var) {
                        continue;
                    }
                    if let Some(key) = pool.next_key(svc.name) {
                        let roi = crate::util::key_roi::classify(svc.name);
                        info!(
                            service = svc.name,
                            env_var = svc.env_var,
                            roi = roi.label(),
                            "hot-inject: key available — {} tier",
                            roi.label()
                        );
                        ctx.keys.insert(svc.env_var.to_string(), key);
                    }
                }
            }

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
            if let Some(reason) = module_skip_reason(&**module, target, opts, is_expansion) {
                self.emit(
                    scan_id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason: reason.into(),
                    },
                );
                continue;
            }
            if !dispatched.insert(dispatch_key(name, target)) {
                stats.deduped += 1;
                self.emit(
                    scan_id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason: "already dispatched for this target".into(),
                    },
                );
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
            // discover MORE keys. Tier is logged for operator visibility.
            {
                let pool = crate::util::key_pool::global_pool();
                for svc in crate::util::key_pool::service_defs() {
                    if ctx.keys.contains_key(svc.env_var) {
                        continue;
                    }
                    if let Some(key) = pool.next_key(svc.name) {
                        let roi = crate::util::key_roi::classify(svc.name);
                        info!(
                            service = svc.name,
                            roi = roi.label(),
                            "hot-inject: key available for concurrent phase ({})",
                            roi.label()
                        );
                        ctx.keys.insert(svc.env_var.to_string(), key);
                    }
                }
            }
        }

        // Phase 2: Spawn remaining (Free + KeyGated) modules concurrently.
        // ctx now contains any keys discovered in Phase 1. Same
        // index-iteration pattern as Phase 1 — Arc::clone moves to the
        // single spawn site below, instead of being paid for every
        // candidate during candidate-list construction.
        let sem = Arc::new(Semaphore::new(opts.max_concurrent));
        let mut set: JoinSet<DispatchOutcome> = JoinSet::new();
        let scan_id_arc: Arc<str> = scan_id.into();

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
            if let Some(reason) = module_skip_reason(&**module, target, opts, is_expansion) {
                self.emit(
                    scan_id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason: reason.into(),
                    },
                );
                continue;
            }
            if !matches!(module.cost(), ModuleCost::Free)
                && !dispatched.insert(dispatch_key(name, target))
            {
                stats.deduped += 1;
                self.emit(
                    scan_id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason: "already dispatched for this target".into(),
                    },
                );
                continue;
            }

            let Ok(permit) = Arc::clone(&sem).acquire_owned().await else {
                break;
            };

            let module_arc: Arc<dyn Module> = Arc::clone(module);
            let target = target.clone();
            let ctx = ctx.clone();
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
fn module_skip_reason(
    module: &dyn Module,
    target: &Target,
    opts: &ScanOptions,
    is_expansion: bool,
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
    // oathnet_pro stays seed-only — it has the heaviest per-query weight
    // and its own internal pivot logic. SeekNow (`see_know`) was previously
    // gated here too, but the per-scan budget cap inside
    // `util::see_know` (default 24, env-tunable) already protects the
    // quota while letting expansion rounds pivot on newly-discovered
    // identities. The /credits endpoint plus the `is_quota_exhausted`
    // flag in the util layer collapse any post-quota calls to no-ops.
    const SEED_ONLY_MODULES: &[&str] = &["oathnet_pro"];
    if is_expansion && SEED_ONLY_MODULES.contains(&name) {
        return Some("API-expensive (seed round only)");
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
        assert!(module_skip_reason(&m, &pub_target(), &opts, false).is_none());
    }

    #[test]
    fn skip_reason_not_in_allowlist() {
        let m = free_active();
        let opts = ScanOptions {
            modules: Some(vec!["other_module".into()]),
            ..Default::default()
        };
        assert_eq!(
            module_skip_reason(&m, &pub_target(), &opts, false),
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
        assert!(module_skip_reason(&m, &pub_target(), &opts, false).is_none());
    }

    #[test]
    fn skip_reason_excluded() {
        let m = free_active();
        let opts = ScanOptions {
            exclude_modules: vec!["test_free".into()],
            ..Default::default()
        };
        assert_eq!(
            module_skip_reason(&m, &pub_target(), &opts, false),
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
            module_skip_reason(&m, &pub_target(), &opts, false),
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
        assert!(module_skip_reason(&m, &pub_target(), &opts, false).is_none());
    }

    #[test]
    fn skip_reason_passive_only_skips_active() {
        let m = free_active();
        let opts = ScanOptions {
            passive_only: true,
            ..Default::default()
        };
        assert_eq!(
            module_skip_reason(&m, &pub_target(), &opts, false),
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
        assert!(module_skip_reason(&m, &pub_target(), &opts, false).is_none());
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
            module_skip_reason(&m, &pub_target(), &opts, false),
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
            module_skip_reason(&m, &private, &opts, false),
            Some("private/reserved IP — external API would reject")
        );
    }

    #[test]
    fn skip_reason_rejects_local_domain_for_external_module() {
        let m = free_active();
        let local = Target::new(TargetKind::Domain, "router.local");
        let opts = ScanOptions::default();
        assert_eq!(
            module_skip_reason(&m, &local, &opts, false),
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
        assert!(module_skip_reason(&m, &private, &opts, false).is_none());
    }

    #[test]
    fn skip_reason_passes_public_ip_through() {
        let m = free_active();
        let opts = ScanOptions::default();
        assert!(module_skip_reason(&m, &pub_target(), &opts, false).is_none());
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
                module_skip_reason(&m, &t, &opts, false).is_none(),
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
            "http://router.local/",
            "https://intra.internal/api",
        ] {
            let t = Target::new(TargetKind::Url, hostile);
            let reason = module_skip_reason(&m, &t, &opts, false);
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
                module_skip_reason(&m, &t, &opts, false).is_none(),
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
                module_skip_reason(&m, &t, &opts, false).is_some(),
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
