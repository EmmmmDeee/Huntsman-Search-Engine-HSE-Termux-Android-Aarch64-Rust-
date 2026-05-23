//! Scan engine — module dispatcher + autonomous expansion (v0.2+) + parallel
//! dispatch (v0.8+).
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
//! Dispatch mode is selected by `ScanOptions::max_concurrent`:
//!   * `0` (default) → sequential, byte-identical to v0.1–v0.7 behaviour.
//!     Best for low-power Termux devices where serialising modules avoids
//!     I/O contention.
//!   * `N > 0` → up to N modules in flight concurrently via
//!     `tokio::sync::Semaphore`. Wall-time roughly divides by
//!     `min(N, n_accepting_modules)`. Event ordering across concurrent
//!     modules is interleaved; SSE consumers handle this transparently.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::time::{sleep, timeout};
use tracing::{info, warn};

use crate::{
    MODULE_TIMEOUT_MS,
    core::{
        entity::{Entity, normalise},
        error::Result,
        event::{Event, EventBus, EventKind},
        module::{Module, ModuleContext, ModuleCost},
        scan::{Scan, ScanOptions, ScanStatus, Target, TargetKind},
    },
    storage::store::Store,
};

pub struct ScanEngine {
    modules: Vec<Arc<dyn Module>>,
    store: Arc<Store>,
    bus: EventBus,
}

/// Reason an expansion round stopped before depth was exhausted.
enum StopReason {
    NoMoreCandidates,
    MaxEntities(usize),
    MaxWallTime(u64),
}

impl StopReason {
    fn label(&self) -> String {
        match self {
            Self::NoMoreCandidates => "no more high-confidence candidates".into(),
            Self::MaxEntities(n) => format!("max_entities={n} reached"),
            Self::MaxWallTime(s) => format!("max_wall_time_secs={s} exceeded"),
        }
    }
}

impl ScanEngine {
    pub fn new(mut modules: Vec<Arc<dyn Module>>, store: Arc<Store>, bus: EventBus) -> Self {
        modules.sort_by_key(|m| std::cmp::Reverse(m.priority()));
        Self {
            modules,
            store,
            bus,
        }
    }

    pub fn modules(&self) -> &[Arc<dyn Module>] {
        &self.modules
    }

    pub fn bus(&self) -> &EventBus {
        &self.bus
    }

    /// Run a scan to completion, including any expansion rounds.
    pub async fn run(&self, mut scan: Scan, target: Target, ctx: ModuleContext) -> Result<Scan> {
        scan.status = ScanStatus::Running;
        self.store.upsert_scan(&scan)?;

        let _ = self.bus.send(Event::new(
            &scan.id,
            EventKind::ScanStart {
                target_kind: target.kind.canonical_str().to_string(),
                target_value: target.value.clone(),
            },
        ));

        let opts = scan.options.clone();
        let started = Instant::now();
        let mut entity_map: HashMap<String, Entity> = HashMap::new();
        let mut visited: HashSet<(TargetKind, String)> = HashSet::new();

        // Round 0 — seed.
        visited.insert(visit_key(&target));
        self.dispatch_target(&scan.id, &target, &ctx, &opts, &mut entity_map)
            .await?;

        // Rounds 1..=depth — autonomous expansion.
        if opts.depth > 0 {
            let _ = self
                .run_expansion(
                    &scan.id,
                    &ctx,
                    &opts,
                    started,
                    &mut entity_map,
                    &mut visited,
                )
                .await;
        }

        // Persist & complete. If either step fails, mark the scan Failed
        // (rather than leaving it Running forever) and still emit a
        // terminal ScanComplete-with-zero so SSE consumers don't hang.
        let entity_count = entity_map.len();
        let persist_err: Option<String> = entity_map
            .into_values()
            .find_map(|entity| self.store.upsert_entity(&entity).err())
            .map(|e| e.to_string());

        if let Some(err) = persist_err {
            warn!(scan_id = %scan.id, error = %err, "entity persist failed; marking scan failed");
            scan.status = ScanStatus::Failed;
            scan.entity_count = 0;
            scan.error = Some(err);
            scan.finished_at = Some(crate::core::entity::unix_now());
            // Best-effort upsert; if even this fails there's nothing more to do.
            let _ = self.store.upsert_scan(&scan);
            let _ = self.bus.send(Event::new(
                &scan.id,
                EventKind::ScanComplete {
                    scan_id: scan.id.clone(),
                    entity_count: 0,
                },
            ));
            return Ok(scan);
        }

        scan.status = ScanStatus::Complete;
        scan.entity_count = entity_count;
        scan.finished_at = Some(crate::core::entity::unix_now());
        self.store.upsert_scan(&scan)?;

        // Post-scan correlator (v0.4+). Runs synchronously after entities
        // are persisted — it reads from the store, not the in-memory map,
        // so the upsert above must complete first. Errors don't fail the
        // scan; correlations are an enrichment, not a correctness invariant.
        match crate::core::correlator::Correlator::new(Arc::clone(&self.store)).run(&scan.id) {
            Ok(firings) => {
                for c in &firings {
                    let _ = self.bus.send(Event::new(
                        &scan.id,
                        EventKind::CorrelationFound {
                            correlation: c.clone(),
                        },
                    ));
                }
                let _ = self.bus.send(Event::new(
                    &scan.id,
                    EventKind::CorrelationsDone {
                        count: firings.len(),
                    },
                ));
            }
            Err(e) => warn!(scan_id = %scan.id, error = %e, "correlator failed"),
        }

        let _ = self.bus.send(Event::new(
            &scan.id,
            EventKind::ScanComplete {
                scan_id: scan.id.clone(),
                entity_count,
            },
        ));

        Ok(scan)
    }

    /// Drive the expansion loop. Returns the stop reason for diagnostics.
    async fn run_expansion(
        &self,
        scan_id: &str,
        ctx: &ModuleContext,
        opts: &ScanOptions,
        started: Instant,
        entity_map: &mut HashMap<String, Entity>,
        visited: &mut HashSet<(TargetKind, String)>,
    ) -> StopReason {
        for depth in 1..=opts.depth {
            // Snapshot the entity set at round start — entities discovered
            // during this round will be expansion candidates in the next round,
            // not this one.
            let snapshot: Vec<Entity> = entity_map.values().cloned().collect();

            let mut next: Vec<Target> = Vec::new();
            for entity in &snapshot {
                if entity.c_effective() < opts.min_expand_confidence {
                    continue;
                }
                let Some(tk) = TargetKind::from_entity_kind(&entity.kind) else {
                    continue;
                };
                let new_target = Target::new(tk, entity.value.clone());
                let key = visit_key(&new_target);
                if visited.insert(key) {
                    next.push(new_target);
                }
            }

            if next.is_empty() {
                let stop = StopReason::NoMoreCandidates;
                let _ = self.bus.send(Event::new(
                    scan_id,
                    EventKind::ExpansionStop {
                        reason: stop.label(),
                    },
                ));
                return stop;
            }

            let _ = self.bus.send(Event::new(
                scan_id,
                EventKind::ExpansionTick {
                    depth,
                    queued: next.len(),
                    visited: visited.len(),
                },
            ));

            for nt in &next {
                if let Some(stop) = budget_check(opts, started, entity_map.len()) {
                    let _ = self.bus.send(Event::new(
                        scan_id,
                        EventKind::ExpansionStop {
                            reason: stop.label(),
                        },
                    ));
                    return stop;
                }
                if let Err(e) = self
                    .dispatch_target(scan_id, nt, ctx, opts, entity_map)
                    .await
                {
                    // Per-target dispatch errors are already surfaced as
                    // ModuleError events; we keep going through the round.
                    warn!(scan_id, error = %e, "dispatch_target failed (continuing)");
                }
            }
        }
        StopReason::NoMoreCandidates
    }

    /// Run every accepting, allowed module against one target. Merges
    /// results into `entity_map` using GREATEST semantics. Emits events.
    ///
    /// When `opts.max_concurrent > 0`, modules run concurrently with that
    /// many in flight at once; otherwise the v0.1 sequential path is used.
    /// Sequential preserves event ordering (ModuleStart→Done per module
    /// before the next starts); concurrent interleaves events but cuts
    /// wall-time roughly by `min(max_concurrent, n_modules)`.
    async fn dispatch_target(
        &self,
        scan_id: &str,
        target: &Target,
        ctx: &ModuleContext,
        opts: &ScanOptions,
        entity_map: &mut HashMap<String, Entity>,
    ) -> Result<()> {
        if opts.max_concurrent == 0 {
            self.dispatch_target_sequential(scan_id, target, ctx, opts, entity_map)
                .await
        } else {
            self.dispatch_target_concurrent(scan_id, target, ctx, opts, entity_map)
                .await
        }
    }

    /// v0.1 sequential dispatcher. Kept unchanged so the default scan
    /// behaviour (max_concurrent == 0) is byte-identical to pre-v0.8.
    async fn dispatch_target_sequential(
        &self,
        scan_id: &str,
        target: &Target,
        ctx: &ModuleContext,
        opts: &ScanOptions,
        entity_map: &mut HashMap<String, Entity>,
    ) -> Result<()> {
        let module_timeout_ms = opts.module_timeout_ms.unwrap_or(MODULE_TIMEOUT_MS);

        for module in &self.modules {
            let name = module.name();

            if !module.accepts(target) {
                continue;
            }
            if let Some(allow) = &opts.modules
                && !allow.iter().any(|n| n == name)
            {
                let _ = self.bus.send(Event::new(
                    scan_id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason: "not in allowlist".into(),
                    },
                ));
                continue;
            }
            if opts.exclude_modules.iter().any(|n| n == name) {
                let _ = self.bus.send(Event::new(
                    scan_id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason: "excluded".into(),
                    },
                ));
                continue;
            }
            if opts.free_only && !matches!(module.cost(), ModuleCost::Free) {
                let _ = self.bus.send(Event::new(
                    scan_id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason: "requires key/payment".into(),
                    },
                ));
                continue;
            }
            if opts.passive_only && !module.is_passive() {
                let _ = self.bus.send(Event::new(
                    scan_id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason: "not passive".into(),
                    },
                ));
                continue;
            }

            let _ = self.bus.send(Event::new(
                scan_id,
                EventKind::ModuleStart {
                    module: name.into(),
                },
            ));

            let result = timeout(
                Duration::from_millis(module_timeout_ms),
                module.process(target, ctx),
            )
            .await;

            match result {
                Err(_) => {
                    warn!(module = name, "timeout");
                    let _ = self.bus.send(Event::new(
                        scan_id,
                        EventKind::ModuleError {
                            module: name.into(),
                            error: "timeout".into(),
                        },
                    ));
                }
                Ok(Err(e)) => {
                    warn!(module = name, error = %e, "module error");
                    let _ = self.bus.send(Event::new(
                        scan_id,
                        EventKind::ModuleError {
                            module: name.into(),
                            error: e.to_string(),
                        },
                    ));
                }
                Ok(Ok(mut mr)) => {
                    let mut found = 0usize;
                    for entity in mr.entities.drain(..) {
                        if let Some(min) = opts.min_confidence
                            && entity.confidence < min
                        {
                            continue;
                        }

                        let _ = self.bus.send(Event::new(
                            scan_id,
                            EventKind::EntityFound {
                                entity: entity.clone(),
                            },
                        ));

                        let uid = entity.uid.clone();
                        if let Some(existing) = entity_map.get_mut(&uid) {
                            existing.merge(entity);
                        } else {
                            entity_map.insert(uid, entity);
                        }
                        found += 1;
                    }
                    let _ = self.bus.send(Event::new(
                        scan_id,
                        EventKind::ModuleDone {
                            module: name.into(),
                            found,
                        },
                    ));
                    info!(module = name, found, "done");
                }
            }

            if opts.throttle_ms > 0 {
                sleep(Duration::from_millis(opts.throttle_ms)).await;
            }
        }
        Ok(())
    }

    /// v0.8 concurrent dispatcher. Launches up to `opts.max_concurrent`
    /// modules at a time via a `tokio::sync::Semaphore`; collects results
    /// as tasks complete. Module-side filtering (allowlist, exclude,
    /// free_only, passive_only, accepts) is performed serially before
    /// spawning so the skip-events still emit in priority order; only the
    /// `process()` call itself parallelises.
    ///
    /// Event ordering caveat: `ModuleStart` events from concurrent tasks
    /// can interleave with each other and with `EntityFound` events from
    /// faster modules. SSE consumers handle this fine (each event is
    /// self-describing); CLI tracing logs will look interleaved.
    async fn dispatch_target_concurrent(
        &self,
        scan_id: &str,
        target: &Target,
        ctx: &ModuleContext,
        opts: &ScanOptions,
        entity_map: &mut HashMap<String, Entity>,
    ) -> Result<()> {
        use tokio::sync::Semaphore;
        use tokio::task::JoinSet;

        let module_timeout_ms = opts.module_timeout_ms.unwrap_or(MODULE_TIMEOUT_MS);
        let sem = Arc::new(Semaphore::new(opts.max_concurrent));
        let mut set: JoinSet<DispatchOutcome> = JoinSet::new();

        for module in &self.modules {
            let name = module.name();

            if !module.accepts(target) {
                continue;
            }
            if let Some(allow) = &opts.modules
                && !allow.iter().any(|n| n == name)
            {
                let _ = self.bus.send(Event::new(
                    scan_id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason: "not in allowlist".into(),
                    },
                ));
                continue;
            }
            if opts.exclude_modules.iter().any(|n| n == name) {
                let _ = self.bus.send(Event::new(
                    scan_id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason: "excluded".into(),
                    },
                ));
                continue;
            }
            if opts.free_only && !matches!(module.cost(), ModuleCost::Free) {
                let _ = self.bus.send(Event::new(
                    scan_id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason: "requires key/payment".into(),
                    },
                ));
                continue;
            }
            if opts.passive_only && !module.is_passive() {
                let _ = self.bus.send(Event::new(
                    scan_id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason: "not passive".into(),
                    },
                ));
                continue;
            }

            // Acquire BEFORE spawning so dispatch *launches* respect the
            // concurrency cap (not just completions). The permit is held
            // for the duration of the spawned task.
            let permit = match Arc::clone(&sem).acquire_owned().await {
                Ok(p) => p,
                Err(_) => break, // semaphore closed — shouldn't happen
            };

            let module_arc: Arc<dyn Module> = Arc::clone(module);
            let target = target.clone();
            let ctx = ctx.clone();
            let bus = self.bus.clone();
            let scan_id_owned = scan_id.to_string();
            let throttle_ms = opts.throttle_ms;

            set.spawn(async move {
                let _permit = permit;
                let name = module_arc.name();

                let _ = bus.send(Event::new(
                    &scan_id_owned,
                    EventKind::ModuleStart {
                        module: name.into(),
                    },
                ));

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

        // Consume results as tasks finish. entity_map is single-owner
        // in this loop, so no Mutex needed.
        while let Some(joined) = set.join_next().await {
            let outcome = match joined {
                Ok(o) => o,
                Err(e) => {
                    warn!(error = %e, "concurrent module task panicked");
                    continue;
                }
            };
            let name = outcome.name;
            match outcome.result {
                Err(_) => {
                    warn!(module = name, "timeout");
                    let _ = self.bus.send(Event::new(
                        scan_id,
                        EventKind::ModuleError {
                            module: name.into(),
                            error: "timeout".into(),
                        },
                    ));
                }
                Ok(Err(e)) => {
                    warn!(module = name, error = %e, "module error");
                    let _ = self.bus.send(Event::new(
                        scan_id,
                        EventKind::ModuleError {
                            module: name.into(),
                            error: e.to_string(),
                        },
                    ));
                }
                Ok(Ok(mut mr)) => {
                    let mut found = 0usize;
                    for entity in mr.entities.drain(..) {
                        if let Some(min) = opts.min_confidence
                            && entity.confidence < min
                        {
                            continue;
                        }
                        let _ = self.bus.send(Event::new(
                            scan_id,
                            EventKind::EntityFound {
                                entity: entity.clone(),
                            },
                        ));
                        let uid = entity.uid.clone();
                        if let Some(existing) = entity_map.get_mut(&uid) {
                            existing.merge(entity);
                        } else {
                            entity_map.insert(uid, entity);
                        }
                        found += 1;
                    }
                    let _ = self.bus.send(Event::new(
                        scan_id,
                        EventKind::ModuleDone {
                            module: name.into(),
                            found,
                        },
                    ));
                    info!(module = name, found, "done (concurrent)");
                }
            }
        }
        Ok(())
    }
}

/// What a spawned per-module task returns to the consumer loop.
struct DispatchOutcome {
    name: &'static str,
    result:
        std::result::Result<Result<crate::core::module::ModuleResult>, tokio::time::error::Elapsed>,
}

/// Visit-key for the expansion visited-set. Normalises the value the same
/// way `Entity::new` does, so the seed target matches entities that point
/// back at it.
fn visit_key(target: &Target) -> (TargetKind, String) {
    let entity_kind = target.kind.to_entity_kind();
    let normalised = normalise(&entity_kind, &target.value);
    (target.kind, normalised)
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
