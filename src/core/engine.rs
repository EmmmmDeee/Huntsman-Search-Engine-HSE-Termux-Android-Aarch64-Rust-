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
    entity::{Entity, normalise},
    error::Result,
    event::{Event, EventBus, EventKind},
    module::{Module, ModuleContext, ModuleCost},
    port::StoragePort,
    scan::{Scan, ScanOptions, ScanStatus, Target, TargetKind},
};

pub struct ScanEngine {
    modules: Vec<Arc<dyn Module>>,
    store: Arc<dyn StoragePort>,
    bus: EventBus,
    emitter: EventEmitter,
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
        Self {
            modules,
            store,
            bus,
            emitter,
        }
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
                )
                .await;
        }

        self.finalise_scan(&mut scan, entity_map, &ctx, stats)
    }

    /// Persist entities, run the correlator, and mark the scan terminal.
    fn finalise_scan(
        &self,
        scan: &mut Scan,
        entity_map: HashMap<String, Entity>,
        ctx: &ModuleContext,
        stats: ModuleStats,
    ) -> Result<Scan> {
        let total = entity_map.len();
        let mut persisted = 0usize;
        let mut first_err: Option<String> = None;
        for entity in entity_map.into_values() {
            match self.store.upsert_entity(&entity) {
                Ok(()) => persisted += 1,
                Err(e) => {
                    warn!(scan_id = %scan.id, entity_uid = %entity.uid, error = %e, "entity persist failed");
                    if first_err.is_none() {
                        first_err = Some(e.to_string());
                    }
                }
            }
        }
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
    ) -> StopReason {
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
            let has_paid = ctx.keys.contains_key("HUNTSMAN_OATHNET_KEY");
            let mut next: Vec<(Target, f64)> = Vec::new();
            for entity in entity_map.values() {
                if entity.c_effective() < opts.min_expand_confidence {
                    continue;
                }
                let Some(tk) = TargetKind::from_entity_kind(&entity.kind) else {
                    continue;
                };
                let new_target = Target::new(tk, entity.value.clone());
                let key = visit_key(&new_target);
                if visited.insert(key) {
                    let weight = crate::core::scan::expansion_weight(
                        tk,
                        entity.c_effective(),
                        &entity.value,
                        has_paid,
                    );
                    next.push((new_target, weight));
                }
            }

            // Sort expansion candidates by weighted score (descending).
            // The weight combines geo_npv with entity confidence and
            // dampens generic mega-domains that waste expansion budget.
            next.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            let next: Vec<Target> = next.into_iter().map(|(t, _)| t).collect();

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

            for nt in &next {
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
                if let Err(e) = self
                    .dispatch_target(scan_id, nt, ctx, opts, entity_map, true, stats, dispatched)
                    .await
                {
                    // Per-target dispatch errors are already surfaced as
                    // ModuleError events; we keep going through the round.
                    warn!(scan_id, error = %e, "dispatch_target failed (continuing)");
                }
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
        for module in &self.modules {
            if ctx.cancel.is_cancelled() {
                return Ok(());
            }
            if opts.max_entities.is_some_and(|cap| entity_map.len() >= cap) {
                return Ok(());
            }
            let name = module.name();

            if !module.accepts(target) {
                continue;
            }
            if let Some(reason) = module_skip_reason(&**module, opts, is_expansion) {
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

        // Phase 1: Run Paid modules synchronously so discovered keys are
        // available via hot-inject before the concurrent phase begins.
        for module in &self.modules {
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
            if let Some(reason) = module_skip_reason(&**module, opts, is_expansion) {
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
        // ctx now contains any keys discovered in Phase 1.
        let sem = Arc::new(Semaphore::new(opts.max_concurrent));
        let mut set: JoinSet<DispatchOutcome> = JoinSet::new();
        let scan_id_arc: Arc<str> = scan_id.into();

        for module in &self.modules {
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
            if let Some(reason) = module_skip_reason(&**module, opts, is_expansion) {
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

/// Returns `Some(reason)` if `module` should be skipped under `opts`.
/// `accepts(target)` is intentionally NOT checked here — that case skips
/// silently with no `ModuleSkipped` event, the others all emit one.
fn module_skip_reason(
    module: &dyn Module,
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
    // Skip "any-target" passive modules on expansion — device sensors
    // produce the same local data regardless of the expansion target.
    // Passive modules that accept specific target kinds (email_parse,
    // phone_intl, abn_lookup) still run since their output varies.
    const SENSOR_MODULES: &[&str] = &["device_sensors", "wifi_intel", "cell_intel", "local_net"];
    if is_expansion && module.is_passive() && SENSOR_MODULES.contains(&name) {
        return Some("sensor (already ran on seed round)");
    }
    const SEED_ONLY_MODULES: &[&str] = &["oathnet_pro", "see_know"];
    if is_expansion && SEED_ONLY_MODULES.contains(&name) {
        return Some("API-expensive (seed round only)");
    }
    None
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
        assert!(module_skip_reason(&m, &opts, false).is_none());
    }

    #[test]
    fn skip_reason_not_in_allowlist() {
        let m = free_active();
        let opts = ScanOptions {
            modules: Some(vec!["other_module".into()]),
            ..Default::default()
        };
        assert_eq!(
            module_skip_reason(&m, &opts, false),
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
        assert!(module_skip_reason(&m, &opts, false).is_none());
    }

    #[test]
    fn skip_reason_excluded() {
        let m = free_active();
        let opts = ScanOptions {
            exclude_modules: vec!["test_free".into()],
            ..Default::default()
        };
        assert_eq!(module_skip_reason(&m, &opts, false), Some("excluded"));
    }

    #[test]
    fn skip_reason_free_only_skips_keygated() {
        let m = keygated();
        let opts = ScanOptions {
            free_only: true,
            ..Default::default()
        };
        assert_eq!(
            module_skip_reason(&m, &opts, false),
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
        assert!(module_skip_reason(&m, &opts, false).is_none());
    }

    #[test]
    fn skip_reason_passive_only_skips_active() {
        let m = free_active();
        let opts = ScanOptions {
            passive_only: true,
            ..Default::default()
        };
        assert_eq!(module_skip_reason(&m, &opts, false), Some("not passive"));
    }

    #[test]
    fn skip_reason_passive_only_passes_passive() {
        let m = paid_passive();
        let opts = ScanOptions {
            passive_only: true,
            ..Default::default()
        };
        assert!(module_skip_reason(&m, &opts, false).is_none());
    }

    #[test]
    fn skip_reason_allowlist_takes_priority_over_exclude() {
        let m = free_active();
        let opts = ScanOptions {
            modules: Some(vec!["test_free".into()]),
            exclude_modules: vec!["test_free".into()],
            ..Default::default()
        };
        assert_eq!(module_skip_reason(&m, &opts, false), Some("excluded"));
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
