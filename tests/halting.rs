//! Halting + budget proofs for the expansion engine.
//!
//! The brief requires two distinct guarantees, proved deterministically with
//! mock modules (no network, no timers) whose complete reachable entity set is
//! computable by hand:
//!
//!   1. HALTING — with *no budget at all*, a scan over a finite, acyclic mock
//!      module graph must terminate on its own with the frontier empty, and the
//!      number of expansions (module dispatches) must stay within the structural
//!      bound `entities × tiers`. "Finished within the time limit" is NOT a
//!      halting proof — these tests pass no time/entity/depth budget that could
//!      mask non-termination (depth is set high enough to exceed the graph's
//!      natural diameter, so depth is not what stops it).
//!
//!   2. OVER-BUDGET STOP — a graph that would otherwise produce many entities
//!      must stop at an explicit `max_entities` budget.
//!
//! These use the public API + a real tempfile `Store` (the in-memory test
//! `StoragePort` lives behind `#[cfg(test)]` in the library and isn't visible to
//! this integration crate).

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use huntsman_search_engine::{
    core::{
        engine::ScanEngine,
        entity::{Entity, EntityKind},
        error::Result,
        module::{Module, ModuleContext, ModuleResult},
        scan::{Scan, ScanOptions, ScanStatus, Target, TargetKind},
    },
    storage::Store,
};

/// A deterministic mock module: when dispatched on a target whose value is a
/// key in `edges`, it emits exactly the listed entities. Offline, synchronous,
/// no timers — so the reachable closure is fully determined by `edges`.
struct DagModule {
    edges: HashMap<String, Vec<(EntityKind, String, f64)>>,
}

impl DagModule {
    fn new() -> Self {
        Self {
            edges: HashMap::new(),
        }
    }
    fn edge(mut self, from: &str, kind: EntityKind, to: &str, confidence: f64) -> Self {
        self.edges
            .entry(from.to_string())
            .or_default()
            .push((kind, to.to_string(), confidence));
        self
    }
}

#[async_trait]
impl Module for DagModule {
    fn name(&self) -> &'static str {
        "dag_mock"
    }
    fn priority(&self) -> u8 {
        100
    }
    fn accepts(&self, _t: &Target) -> bool {
        true
    }
    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        if let Some(emits) = self.edges.get(&target.value) {
            for (kind, value, confidence) in emits {
                r.push(Entity::new(
                    kind.clone(),
                    value.clone(),
                    *confidence,
                    &ctx.scan_id,
                ));
            }
        }
        Ok(r)
    }
}

fn setup(
    modules: Vec<Arc<dyn Module>>,
    suffix: &str,
    kind: TargetKind,
    value: &str,
) -> (ScanEngine, Arc<Store>, String, Target, ModuleContext) {
    common::engine_setup("halting", modules, suffix, kind, value)
}

/// Build a finite, ACYCLIC mock graph whose closure is computable by hand:
///
/// ```text
///   name "Onur Ada"  ──▶ email  onur@contoso.com   (0.95)
///   email            ──▶ domain contoso.com        (0.85)
///   email            ──▶ username onur             (0.80)
///   domain           ──▶ ip     93.184.216.34      (0.90)
///   username         ──▶ (nothing)
///   ip               ──▶ (nothing)
/// ```
///
/// Reachable entity set = { email, domain, username, ip } = 4 NEW entities
/// (the seed `name` is the target, not a produced entity). No cycle exists,
/// so the frontier must empty on its own.
fn dag() -> DagModule {
    DagModule::new()
        .edge("Onur Ada", EntityKind::Email, "onur@contoso.com", 0.95)
        .edge("onur@contoso.com", EntityKind::Domain, "contoso.com", 0.85)
        .edge("onur@contoso.com", EntityKind::Username, "onur", 0.80)
        .edge("contoso.com", EntityKind::IpAddress, "93.184.216.34", 0.90)
}

#[tokio::test]
async fn scan_halts_frontier_empty_within_structural_bound() {
    let (engine, store, sid, target, ctx) = setup(
        vec![Arc::new(dag())],
        "halt",
        TargetKind::FullName,
        "Onur Ada",
    );

    // NO budget: no max_entities, no max_wall_time. Depth is set well above the
    // graph diameter (3) so that depth-exhaustion is NOT what halts the scan —
    // the frontier emptying is. min_expand_confidence is low so every produced
    // entity is eligible to expand (nothing is filtered out by confidence).
    let opts = ScanOptions {
        depth: 25,
        min_expand_confidence: 0.0,
        max_entities: None,
        max_wall_time_secs: None,
        max_concurrent: 0, // deterministic sequential dispatch
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);

    // If the scan did not halt, this await would hang — the test harness
    // timeout would fail it. Reaching the assert *is* the termination proof.
    let result = engine.run(scan, target, ctx).await.unwrap();

    // 1. It halted cleanly (not aborted/failed).
    assert_eq!(result.status, ScanStatus::Complete, "scan must complete");

    // 2. Hand-computed closure: exactly the 4 reachable entities.
    let entities = store.entities_for_scan(&sid).unwrap();
    let values: std::collections::BTreeSet<&str> =
        entities.iter().map(|e| e.value.as_str()).collect();
    assert_eq!(
        values,
        ["93.184.216.34", "contoso.com", "onur", "onur@contoso.com"]
            .into_iter()
            .collect(),
        "reachable closure must be exactly the hand-computed set"
    );
    assert_eq!(entities.len(), 4, "exactly 4 entities reachable");

    // 3. Expansion count is within the structural bound `entities × tiers`.
    //    Each entity is expanded at most once per tier; there are
    //    Classification::COUNT (=3) tiers. We count module-dispatch events
    //    (ModuleStart) as expansions. The seed dispatch + per-entity
    //    expansions must not exceed (entities + 1) × tiers.
    let events = store.events_for_scan(&sid).unwrap();
    let module_starts = events
        .iter()
        .filter(|e| {
            matches!(
                e.kind,
                huntsman_search_engine::core::event::EventKind::ModuleStart { .. }
            )
        })
        .count();
    let entity_count = entities.len();
    // Use the engine's own tier-ladder constant so this bound stays in sync if
    // the tier count ever changes (rather than silently drifting from a 3).
    let tiers = huntsman_search_engine::core::Classification::COUNT as usize;
    let bound = (entity_count + 1) * tiers;
    assert!(
        module_starts <= bound,
        "expansions ({module_starts}) must be within entities×tiers bound ({bound})"
    );
}

#[tokio::test]
async fn scan_stops_at_entity_budget() {
    // A fan-out graph that would produce 5 entities, capped at 2. The budget is
    // a graceful early stop — distinct from the halting guarantee above.
    // Non-reserved domains: `.example` is gated by the preflight check, which
    // would suppress dispatch and make the budget assertion vacuous.
    let big = DagModule::new()
        .edge("seed-target.com", EntityKind::Domain, "a-node.com", 0.9)
        .edge("seed-target.com", EntityKind::Domain, "b-node.com", 0.9)
        .edge("a-node.com", EntityKind::Domain, "c-node.com", 0.9)
        .edge("b-node.com", EntityKind::Domain, "d-node.com", 0.9)
        .edge("c-node.com", EntityKind::Domain, "e-node.com", 0.9);

    let (engine, store, sid, target, ctx) = setup(
        vec![Arc::new(big)],
        "budget",
        TargetKind::Domain,
        "seed-target.com",
    );

    let opts = ScanOptions {
        depth: 25,
        min_expand_confidence: 0.0,
        max_entities: Some(2),
        max_concurrent: 0,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let result = engine.run(scan, target, ctx).await.unwrap();

    // The scan terminated and the entity budget capped growth. The cap is
    // checked at expansion-candidate boundaries, so the final count is at or
    // near the cap — and crucially far below the unbudgeted closure of 5.
    assert!(
        result.entity_count <= 3,
        "entity budget (2) must cap growth near the limit, got {}",
        result.entity_count
    );
    let unbudgeted_closure = 5;
    assert!(
        store.entities_for_scan(&sid).unwrap().len() < unbudgeted_closure,
        "budget must stop the scan before the full closure is reached"
    );
}

/// A module that emits one entity, then sleeps far longer than any test wall
/// budget — stands in for a slow/unresponsive upstream so we can prove the
/// wall-time watchdog interrupts promptly instead of waiting the module out.
struct SlowModule;

#[async_trait]
impl Module for SlowModule {
    fn name(&self) -> &'static str {
        "slow_mock"
    }
    fn priority(&self) -> u8 {
        100
    }
    fn accepts(&self, _t: &Target) -> bool {
        true
    }
    fn max_timeout_ms(&self) -> u64 {
        60_000 // would block the scan for a minute absent the watchdog
    }
    async fn process(&self, _t: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        r.push(Entity::new(
            EntityKind::Email,
            "seed@found-host.com",
            0.9,
            &ctx.scan_id,
        ));
        // Poll the cancel flag so the watchdog can interrupt this mid-flight,
        // mirroring how real long-running modules cooperate with cancellation.
        for _ in 0..600 {
            if ctx.cancel.is_cancelled() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Ok(r)
    }
}

#[tokio::test]
async fn wall_time_budget_stops_promptly_and_preserves_findings() {
    // Regression: --max-wall-time was only checked BETWEEN expansion
    // candidates, so the seed round / in-flight modules could blow past it
    // (observed: a 5s budget ran until an external SIGKILL). The watchdog must
    // now interrupt within ~the budget and still finalize the entities found.
    // NB: a non-reserved domain — `.example` is treated as local/reserved by
    // the preflight gate and would suppress dispatch entirely (making this
    // test vacuous).
    let (engine, store, sid, target, ctx) = setup(
        vec![Arc::new(SlowModule)],
        "walltime",
        TargetKind::Domain,
        "seed-target.com",
    );
    let opts = ScanOptions {
        depth: 0,
        max_wall_time_secs: Some(1),
        max_concurrent: 4,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);

    let t0 = std::time::Instant::now();
    let result = engine.run(scan, target, ctx).await.unwrap();
    let elapsed = t0.elapsed();

    // Must return well before the module's 60s timeout — proving the wall
    // budget interrupted the in-flight seed round, not that the module
    // happened to finish.
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "wall-time budget must interrupt promptly; took {elapsed:?}"
    );
    // And it still persisted what it collected (always display results).
    assert_eq!(
        result.status,
        ScanStatus::Aborted,
        "deadline → clean Aborted"
    );
    assert!(
        !store.entities_for_scan(&sid).unwrap().is_empty(),
        "findings collected before the deadline must be persisted, not lost"
    );
}
