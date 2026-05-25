mod dispatch;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::warn;

use crate::core::{
    entity::{Entity, normalise},
    error::Result,
    event::{Event, EventBus, EventKind},
    module::{Module, ModuleContext},
    scan::{Scan, ScanOptions, ScanStatus, Target, TargetKind},
};
use crate::storage::store::Store;

pub struct ScanEngine {
    modules: Vec<Arc<dyn Module>>,
    store: Arc<Store>,
    bus: EventBus,
}

enum StopReason {
    NoMoreCandidates,
    MaxEntities(usize),
    MaxWallTime(u64),
    Cancelled,
}

impl StopReason {
    fn label(&self) -> String {
        match self {
            Self::NoMoreCandidates => "no more high-confidence candidates".into(),
            Self::MaxEntities(n) => format!("max_entities={n} reached"),
            Self::MaxWallTime(s) => format!("max_wall_time_secs={s} exceeded"),
            Self::Cancelled => "cancelled by operator".into(),
        }
    }
}

/// Free function so spawned tasks (which capture cloned `store` + `bus`
/// rather than `&self`) can use the same emit path as `ScanEngine::emit`.
pub(crate) fn emit_event(store: &Store, bus: &EventBus, scan_id: &str, kind: EventKind) {
    let event = Event::new(scan_id, kind);
    // Persist first so SSE subscribers can't see events that history-fetch misses.
    if let Err(e) = store.insert_event(&event) {
        warn!(scan_id = %event.scan_id, error = %e, "failed to persist event to store");
    }
    if bus.send(event).is_err() {
        tracing::trace!(scan_id, "broadcast dropped (no subscribers)");
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

    fn emit(&self, scan_id: &str, kind: EventKind) {
        emit_event(&self.store, &self.bus, scan_id, kind);
    }

    pub fn modules(&self) -> &[Arc<dyn Module>] {
        &self.modules
    }

    pub fn bus(&self) -> &EventBus {
        &self.bus
    }

    pub async fn run(&self, mut scan: Scan, target: Target, ctx: ModuleContext) -> Result<Scan> {
        if let Err(msg) = target.validate() {
            scan.status = ScanStatus::Failed;
            scan.error = Some(format!("invalid target: {msg}"));
            scan.finished_at = Some(crate::core::entity::unix_now());
            let _ = self.store.upsert_scan(&scan);
            return Ok(scan);
        }
        if let Err(msg) = scan.options.validate() {
            scan.status = ScanStatus::Failed;
            scan.error = Some(format!("invalid options: {msg}"));
            scan.finished_at = Some(crate::core::entity::unix_now());
            let _ = self.store.upsert_scan(&scan);
            return Ok(scan);
        }

        scan.status = ScanStatus::Running;
        self.store.upsert_scan(&scan)?;

        self.emit(
            &scan.id,
            EventKind::ScanStart {
                target_kind: target.kind.canonical_str().to_string(),
                target_value: target.value.clone(),
            },
        );

        let opts = scan.options.clone();
        let started = Instant::now();
        let mut entity_map: HashMap<String, Entity> = HashMap::with_capacity(64);
        let mut visited: HashSet<(TargetKind, String)> = HashSet::new();

        visited.insert(visit_key(&target));
        self.dispatch_target(&scan.id, &target, &ctx, &opts, &mut entity_map)
            .await?;

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

        self.finalise_scan(&mut scan, entity_map, &ctx)
    }

    fn finalise_scan(
        &self,
        scan: &mut Scan,
        entity_map: HashMap<String, Entity>,
        ctx: &ModuleContext,
    ) -> Result<Scan> {
        let entity_count = entity_map.len();

        let persist_err: Option<String> = entity_map
            .into_values()
            .find_map(|entity| self.store.upsert_entity(&entity).err())
            .map(|e| e.to_string());

        if let Some(err) = persist_err {
            warn!(scan_id = %scan.id, error = %err, "entity persist failed");
            scan.status = ScanStatus::Failed;
            scan.entity_count = 0;
            scan.error = Some(err);
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
        scan.finished_at = Some(crate::core::entity::unix_now());
        self.store.upsert_scan(scan)?;

        self.run_correlator(&scan.id);

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
            if ctx.cancel.is_cancelled() {
                let stop = StopReason::Cancelled;
                let _ = self.bus.send(Event::new(
                    scan_id,
                    EventKind::ExpansionStop {
                        reason: stop.label(),
                    },
                ));
                return stop;
            }
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
                    let _ = self.bus.send(Event::new(
                        scan_id,
                        EventKind::ExpansionStop {
                            reason: stop.label(),
                        },
                    ));
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
                    .dispatch_target(scan_id, nt, ctx, opts, entity_map)
                    .await
                {
                    warn!(scan_id, error = %e, "dispatch_target failed (continuing)");
                }
            }
        }
        StopReason::NoMoreCandidates
    }
}

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
