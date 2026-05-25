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
    scan::{Scan, ScanOptions, ScanStatus, Target, TargetKind},
};
use crate::storage::store::Store;

pub struct ScanEngine {
    modules: Vec<Arc<dyn Module>>,
    by_kind: HashMap<TargetKind, Vec<Arc<dyn Module>>>,
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

        let mut by_kind: HashMap<TargetKind, Vec<Arc<dyn Module>>> = HashMap::new();
        let all_kinds = [
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::Phone,
            TargetKind::FullName,
            TargetKind::IpAddress,
            TargetKind::Domain,
            TargetKind::Asn,
            TargetKind::Coordinates,
            TargetKind::Address,
            TargetKind::MacAddress,
        ];
        for kind in all_kinds {
            let probe = Target::new(kind, "probe");
            let accepting: Vec<Arc<dyn Module>> = modules
                .iter()
                .filter(|m| m.accepts(&probe))
                .cloned()
                .collect();
            by_kind.insert(kind, accepting);
        }

        Self {
            modules,
            by_kind,
            store,
            bus,
        }
    }

    pub fn modules(&self) -> &[Arc<dyn Module>] {
        &self.modules
    }

    pub fn modules_for(&self, kind: TargetKind) -> &[Arc<dyn Module>] {
        self.by_kind.get(&kind).map(Vec::as_slice).unwrap_or(&[])
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
        // Budget check after the seed: if a chatty module already blew
        // past `max_entities` (or wall-time), skip expansion entirely
        // and emit an ExpansionStop event so SSE consumers see the
        // reason. Gated on `depth > 0` so a depth-0 scan that happens
        // to be over-budget doesn't emit a spurious ExpansionStop —
        // there was no expansion plan to begin with, and the event is
        // documented as a round-boundary signal.
        if opts.depth > 0 {
            if let Some(stop) = budget_check(&opts, started, entity_map.len()) {
                let _ = self.bus.send(Event::new(
                    &scan.id,
                    EventKind::ExpansionStop {
                        reason: stop.label(),
                    },
                ));
            } else {
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
