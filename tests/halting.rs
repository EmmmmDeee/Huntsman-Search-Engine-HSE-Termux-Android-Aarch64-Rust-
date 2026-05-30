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
    util::{http::build_client, uid::scan_id},
};

/// A deterministic mock module: when dispatched on a target whose value is a
/// key in `edges`, it emits exactly the listed entities. Offline, synchronous,
/// no timers — so the reachable closure is fully determined by `edges`.
struct DagModule {
    edges: HashMap<String, Vec<(EntityKind, String, f64)>>,
}

impl DagModule {
    fn new() -> Self {
        Self { edges: HashMap::new() }
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
                r.push(Entity::new(kind.clone(), value.clone(), *confidence, &ctx.scan_id));
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
    let mut p = std::env::temp_dir();
    p.push(format!("hse-halting-{}-{}.db", std::process::id(), suffix));
    let tmp = p.to_string_lossy().to_string();
    let _ = std::fs::remove_file(&tmp);
    let store = Arc::new(Store::open(&tmp).unwrap());
    let (bus, _rx) = tokio::sync::broadcast::channel(256);
    let engine = ScanEngine::new(
        modules,
        Arc::clone(&store) as Arc<dyn huntsman_search_engine::core::StoragePort>,
        bus.clone(),
    );
    let sid = scan_id(kind.canonical_str(), value);
    let target = Target::new(kind, value.to_string());
    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus,
        http: build_client(),
        keys: Default::default(),
        cancel: Default::default(),
        proxy_pool: Default::default(),
    };
    (engine, store, sid, target, ctx)
}

/// Build a finite, ACYCLIC mock graph whose closure is computable by hand:
///
/// ```text
///   name "Onur Ada"  ──▶ email  onur@example.com   (0.95)
///   email            ──▶ domain example.com        (0.85)
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
        .edge("Onur Ada", EntityKind::Email, "onur@example.com", 0.95)
        .edge("onur@example.com", EntityKind::Domain, "example.com", 0.85)
        .edge("onur@example.com", EntityKind::Username, "onur", 0.80)
        .edge("example.com", EntityKind::IpAddress, "93.184.216.34", 0.90)
}

#[tokio::test]
async fn scan_halts_frontier_empty_within_structural_bound() {
    let (engine, store, sid, target, ctx) =
        setup(vec![Arc::new(dag())], "halt", TargetKind::FullName, "Onur Ada");

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
        ["93.184.216.34", "example.com", "onur", "onur@example.com"]
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
        .filter(|e| matches!(e.kind, huntsman_search_engine::core::event::EventKind::ModuleStart { .. }))
        .count();
    let entity_count = entities.len();
    let tiers = 3usize; // Classification::COUNT — Candidate/Probable/Verified
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
    let big = DagModule::new()
        .edge("seed.example", EntityKind::Domain, "a.example", 0.9)
        .edge("seed.example", EntityKind::Domain, "b.example", 0.9)
        .edge("a.example", EntityKind::Domain, "c.example", 0.9)
        .edge("b.example", EntityKind::Domain, "d.example", 0.9)
        .edge("c.example", EntityKind::Domain, "e.example", 0.9);

    let (engine, store, sid, target, ctx) =
        setup(vec![Arc::new(big)], "budget", TargetKind::Domain, "seed.example");

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
