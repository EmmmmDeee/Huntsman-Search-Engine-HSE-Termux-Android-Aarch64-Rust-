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
    MaxEntities(usize),
    MaxWallTime(u64),
    /// Operator-initiated cancellation via the `CancelHandle` plumbed
    /// through `ModuleContext`. Distinct from the budget stops so the
    /// `ExpansionStop` event reads "cancelled" rather than "budget
    /// exceeded" — the SPA / log consumers can colour it differently.
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

/// Cheaply-cloneable event emitter. Persist-first, then broadcast.
/// Spawned tasks clone this instead of cloning store + bus separately.
#[derive(Clone)]
pub(super) struct EventEmitter {
    store: Arc<dyn StoragePort>,
    bus: EventBus,
}

impl EventEmitter {
    fn new(store: Arc<dyn StoragePort>, bus: EventBus) -> Self {
        Self { store, bus }
    }

    pub(super) fn emit(&self, scan_id: &str, kind: EventKind) {
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
    pub async fn run(&self, mut scan: Scan, target: Target, ctx: ModuleContext) -> Result<Scan> {
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

    /// Persist entities, run the correlator, and mark the scan terminal.
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
            // Cancellation gate at round entry — between rounds is the
            // cheapest place to exit because nothing new has spawned.
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
                    // Per-target dispatch errors are already surfaced as
                    // ModuleError events; we keep going through the round.
                    warn!(scan_id, error = %e, "dispatch_target failed (continuing)");
                }
            }
        }
        StopReason::NoMoreCandidates
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
        assert!(StopReason::MaxEntities(10).label().contains("10"));
        assert!(StopReason::MaxWallTime(60).label().contains("60"));
        assert!(StopReason::Cancelled.label().contains("cancel"));
    }
}
