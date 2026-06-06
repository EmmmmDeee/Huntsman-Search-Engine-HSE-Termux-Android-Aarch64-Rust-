//! Module dependency graph and dispatch index.
//!
//! At engine startup the registry is introspected once to produce a
//! [`ModuleGraph`] that the dispatcher reuses on every scan:
//!
//! * **Dispatch index** — `TargetKind → Vec<module_idx>`. Replaces the
//!   O(M) `accepts()` scan-per-target with an O(1) hash lookup. With
//!   80 modules and a depth-5 expansion the saving is significant on
//!   low-power Termux devices.
//!
//! * **Module count per kind** — how many modules consume each
//!   [`TargetKind`]. Drives the *richness* factor in
//!   [`crate::core::scan::expansion_weight_with_richness`]: an entity
//!   that unlocks 30 modules outranks one that unlocks 3, regardless
//!   of confidence parity.
//!
//! * **Pivot edges** — `produces(EntityKind) ⨯ consumes(TargetKind)` —
//!   useful for the UI to render *"what does this entity unlock?"* and
//!   for future strategies that explicitly chase the longest pivot
//!   chain.
//!
//! The graph is **pure data**: building it makes no I/O and has no
//! side effects, so the engine constructor can call it eagerly without
//! risking blocking on async work.
//!
//! Spiderfoot's `watched_events` / `produced_events` graph is the
//! closest analogue; this implementation goes further by exposing the
//! result as a richness scalar that the expansion ranker consumes.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde::Serialize;

use crate::core::entity::EntityKind;
use crate::core::module::{Module, ModuleCost};
use crate::core::scan::{Target, TargetKind};

/// Every `TargetKind` variant — used by both the dispatch-index builder
/// and the `consumes()` default-probe implementation in [`Module`].
pub const ALL_TARGET_KINDS: &[TargetKind] = &[
    TargetKind::Email,
    TargetKind::Username,
    TargetKind::Phone,
    TargetKind::FullName,
    TargetKind::IpAddress,
    TargetKind::Domain,
    TargetKind::Url,
    TargetKind::Asn,
    TargetKind::Coordinates,
    TargetKind::Address,
    TargetKind::Organisation,
    TargetKind::AbnAcn,
    TargetKind::MacAddress,
    TargetKind::ApiKey,
    TargetKind::CryptoAddress,
];

/// Probe seed value used when introspecting a module's `accepts()` via
/// the default `consumes()` implementation. Modules that gate by value
/// shape (rather than `t.kind`) MUST override `consumes()` explicitly.
///
/// `pub(crate)` so the trait-default in `module::Module::consumes()`
/// can reach it without a method-pointer indirection.
pub(crate) const PROBE_VALUE: &str = "huntsman-graph-probe-1.2.3.4@example.com";

/// Run `m.accepts()` against every `TargetKind` to discover which kinds
/// the module dispatches on. Used as the default body for
/// [`Module::consumes()`] so modules that don't override the method
/// still report sensible data.
pub fn consumes_via_probe(m: &dyn Module) -> Vec<TargetKind> {
    ALL_TARGET_KINDS
        .iter()
        .copied()
        .filter(|k| {
            // Use a stable probe value. Every TargetKind accepts arbitrary
            // strings for the purpose of accepts() — the module's kind-gate
            // is what we want to read.
            m.accepts(&Target::new(*k, PROBE_VALUE))
        })
        .collect()
}

/// Pre-computed graph of module ↔ TargetKind/EntityKind relationships.
///
/// Built once at engine construction; immutable afterward. Cheap to
/// share across threads via `Arc`.
#[derive(Debug, Default, Clone)]
pub struct ModuleGraph {
    /// For each `TargetKind`, the indices into the engine's `modules`
    /// vec that accept that kind. Pre-sorted by module priority
    /// (descending), so callers can iterate without re-sorting.
    dispatch_index: HashMap<TargetKind, Vec<usize>>,

    /// Cached `count(modules.consume(kind))` for every `TargetKind`.
    /// Used by `richness_for()` to compute the normalised richness
    /// factor in `expansion_weight_with_richness()`.
    consumer_count: HashMap<TargetKind, usize>,

    /// The maximum consumer count across all kinds. Used as the
    /// normaliser in `richness_for()`. Always ≥ 1 to avoid div-by-zero.
    max_consumer_count: usize,

    /// For each `EntityKind` a module produces, the set of indices
    /// into the engine's `modules` vec that produce it. Used for the
    /// JSON view exported via `/api/v1/modules/graph`.
    producer_index: HashMap<EntityKind, Vec<usize>>,
}

impl ModuleGraph {
    /// Build the graph from the engine's module list. Modules are
    /// expected to already be priority-sorted (descending); this
    /// method preserves that order in each `dispatch_index` bucket.
    pub fn build(modules: &[Arc<dyn Module>]) -> Self {
        let mut dispatch_index: HashMap<TargetKind, Vec<usize>> = HashMap::new();
        let mut consumer_count: HashMap<TargetKind, usize> = HashMap::new();
        let mut producer_index: HashMap<EntityKind, Vec<usize>> = HashMap::new();

        for (idx, m) in modules.iter().enumerate() {
            for kind in m.consumes() {
                dispatch_index.entry(kind).or_default().push(idx);
                *consumer_count.entry(kind).or_default() += 1;
            }
            for ek in m.produces() {
                producer_index.entry(ek.clone()).or_default().push(idx);
            }
        }

        // Every TargetKind must have an entry even if no module accepts
        // it — keeps `module_count_for()` total without an `Option`.
        for k in ALL_TARGET_KINDS {
            consumer_count.entry(*k).or_insert(0);
            dispatch_index.entry(*k).or_default();
        }

        let max_consumer_count = consumer_count.values().copied().max().unwrap_or(1).max(1);

        Self {
            dispatch_index,
            consumer_count,
            max_consumer_count,
            producer_index,
        }
    }

    /// Indices into the engine's `modules` vec of every module that
    /// accepts `kind`, in priority-descending order.
    pub fn modules_for(&self, kind: TargetKind) -> &[usize] {
        self.dispatch_index
            .get(&kind)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Number of modules that consume `kind`. Zero is legal (e.g. a
    /// new `TargetKind` variant that no module yet supports).
    pub fn module_count_for(&self, kind: TargetKind) -> usize {
        self.consumer_count.get(&kind).copied().unwrap_or(0)
    }

    /// Normalised richness in `[0.0, 1.0]`: `module_count / max_count`.
    /// Used as a multiplicative factor in
    /// `expansion_weight_with_richness()`.
    ///
    /// A kind no module consumes returns `0.0`. The most-served kind
    /// returns `1.0`.
    pub fn richness_for(&self, kind: TargetKind) -> f64 {
        let n = self.module_count_for(kind) as f64;
        let denom = self.max_consumer_count as f64;
        if denom <= 0.0 {
            0.0
        } else {
            (n / denom).clamp(0.0, 1.0)
        }
    }

    /// Entity kinds for which at least one module declares production.
    pub fn produced_kinds(&self) -> Vec<EntityKind> {
        let mut v: Vec<_> = self.producer_index.keys().cloned().collect();
        v.sort_by_key(|k| k.to_string());
        v
    }

    /// Serializable summary suitable for the UI / API. The engine
    /// supplies the module list so we can attach names + descriptions.
    pub fn to_summary(&self, modules: &[Arc<dyn Module>]) -> ModuleGraphSummary {
        let mut consumers_by_kind: Vec<KindNode> = ALL_TARGET_KINDS
            .iter()
            .map(|k| {
                let mut names: Vec<&'static str> = self
                    .modules_for(*k)
                    .iter()
                    .filter_map(|&idx| modules.get(idx).map(|m| m.name()))
                    .collect();
                names.sort_unstable();
                KindNode {
                    kind: k.canonical_str(),
                    module_count: self.module_count_for(*k),
                    richness: self.richness_for(*k),
                    modules: names,
                }
            })
            .collect();
        consumers_by_kind.sort_by_key(|n| std::cmp::Reverse(n.module_count));

        // Pivot edges: for each module, the (consumes → produces) pairs
        // it bridges. Lets the UI render a flow diagram.
        let edges: Vec<PivotEdge> = modules
            .iter()
            .map(|m| PivotEdge {
                module: m.name(),
                category: m.category().as_str(),
                cost: cost_str(m.cost()),
                passive: m.is_passive(),
                consumes: m
                    .consumes()
                    .into_iter()
                    .map(|t| t.canonical_str())
                    .collect(),
                produces: m
                    .produces()
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect(),
            })
            .collect();

        ModuleGraphSummary {
            kinds: consumers_by_kind,
            edges,
        }
    }
}

fn cost_str(c: ModuleCost) -> &'static str {
    match c {
        ModuleCost::Free => "free",
        ModuleCost::KeyGated => "key_gated",
        ModuleCost::Paid => "paid",
    }
}

/// JSON-friendly view of the per-target consumer summary.
#[derive(Debug, Clone, Serialize)]
pub struct KindNode {
    pub kind: &'static str,
    pub module_count: usize,
    pub richness: f64,
    pub modules: Vec<&'static str>,
}

/// JSON-friendly description of one module's data-flow signature.
#[derive(Debug, Clone, Serialize)]
pub struct PivotEdge {
    pub module: &'static str,
    pub category: &'static str,
    pub cost: &'static str,
    pub passive: bool,
    pub consumes: Vec<&'static str>,
    pub produces: Vec<String>,
}

/// Top-level serializable structure for `/api/v1/modules/graph`.
#[derive(Debug, Clone, Serialize)]
pub struct ModuleGraphSummary {
    pub kinds: Vec<KindNode>,
    pub edges: Vec<PivotEdge>,
}

impl ModuleGraphSummary {
    /// Convenience: collect the unique set of EntityKinds named by any
    /// `produces` field across all edges. Used by the UI to render the
    /// downstream node list.
    pub fn produced_entity_kinds(&self) -> Vec<String> {
        let mut set: HashSet<String> = HashSet::new();
        for e in &self.edges {
            for p in &e.produces {
                set.insert(p.clone());
            }
        }
        let mut v: Vec<_> = set.into_iter().collect();
        v.sort();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::module::{Module, ModuleContext, ModuleResult};
    use crate::core::scan::Target;
    use async_trait::async_trait;

    struct EmailToDomain;

    #[async_trait]
    impl Module for EmailToDomain {
        fn name(&self) -> &'static str {
            "email_to_domain"
        }
        fn priority(&self) -> u8 {
            50
        }
        fn accepts(&self, t: &Target) -> bool {
            matches!(t.kind, TargetKind::Email)
        }
        async fn process(
            &self,
            _t: &Target,
            _ctx: &ModuleContext,
        ) -> crate::core::error::Result<ModuleResult> {
            Ok(ModuleResult::new())
        }
        fn produces(&self) -> &'static [EntityKind] {
            const KINDS: &[EntityKind] = &[EntityKind::Domain];
            KINDS
        }
    }

    struct DomainToIp;
    #[async_trait]
    impl Module for DomainToIp {
        fn name(&self) -> &'static str {
            "domain_to_ip"
        }
        fn priority(&self) -> u8 {
            40
        }
        fn accepts(&self, t: &Target) -> bool {
            matches!(t.kind, TargetKind::Domain | TargetKind::Url)
        }
        async fn process(
            &self,
            _t: &Target,
            _ctx: &ModuleContext,
        ) -> crate::core::error::Result<ModuleResult> {
            Ok(ModuleResult::new())
        }
        fn produces(&self) -> &'static [EntityKind] {
            const KINDS: &[EntityKind] = &[EntityKind::IpAddress];
            KINDS
        }
    }

    fn make_registry() -> Vec<Arc<dyn Module>> {
        vec![
            Arc::new(EmailToDomain),
            Arc::new(DomainToIp),
            Arc::new(DomainToIp), // duplicate to check counts
        ]
    }

    #[test]
    fn build_dispatch_index_for_consumed_kinds() {
        let modules = make_registry();
        let g = ModuleGraph::build(&modules);

        assert_eq!(g.modules_for(TargetKind::Email).len(), 1);
        assert_eq!(g.modules_for(TargetKind::Domain).len(), 2);
        assert_eq!(g.modules_for(TargetKind::Url).len(), 2);
        assert!(g.modules_for(TargetKind::Coordinates).is_empty());
    }

    #[test]
    fn consumer_count_matches_dispatch_index() {
        let modules = make_registry();
        let g = ModuleGraph::build(&modules);

        for k in ALL_TARGET_KINDS {
            assert_eq!(
                g.module_count_for(*k),
                g.modules_for(*k).len(),
                "count mismatch for {k:?}"
            );
        }
    }

    #[test]
    fn richness_normalises_to_unit_interval() {
        let modules = make_registry();
        let g = ModuleGraph::build(&modules);

        let richest = g.richness_for(TargetKind::Domain);
        let poorest = g.richness_for(TargetKind::Coordinates);

        // Two modules consume Domain, max count is 2 → richness = 1.0
        assert!((richest - 1.0).abs() < f64::EPSILON);
        // Zero modules consume Coordinates → richness = 0.0
        assert_eq!(poorest, 0.0);

        // All other kinds are in [0, 1].
        for k in ALL_TARGET_KINDS {
            let r = g.richness_for(*k);
            assert!((0.0..=1.0).contains(&r));
        }
    }

    #[test]
    fn richness_never_panics_on_empty_registry() {
        let modules: Vec<Arc<dyn Module>> = Vec::new();
        let g = ModuleGraph::build(&modules);
        assert_eq!(g.richness_for(TargetKind::Email), 0.0);
        assert_eq!(g.module_count_for(TargetKind::Email), 0);
        assert!(g.modules_for(TargetKind::Email).is_empty());
    }

    #[test]
    fn produced_kinds_collects_unique_entries() {
        let modules = make_registry();
        let g = ModuleGraph::build(&modules);
        let pk = g.produced_kinds();
        // We register IpAddress (twice) and Domain (once); produced_kinds
        // dedupes to two entries.
        assert_eq!(pk.len(), 2);
        assert!(pk.contains(&EntityKind::Domain));
        assert!(pk.contains(&EntityKind::IpAddress));
    }

    #[test]
    fn summary_includes_every_kind_sorted_by_module_count() {
        let modules = make_registry();
        let g = ModuleGraph::build(&modules);
        let s = g.to_summary(&modules);
        assert_eq!(s.kinds.len(), ALL_TARGET_KINDS.len());

        // Strictly non-increasing.
        for w in s.kinds.windows(2) {
            assert!(w[0].module_count >= w[1].module_count);
        }
        // Richest first should be Domain or Url (each 2 modules).
        assert!(matches!(s.kinds[0].kind, "domain" | "url"));
    }

    #[test]
    fn summary_edges_carry_consume_and_produce_lists() {
        let modules = make_registry();
        let g = ModuleGraph::build(&modules);
        let s = g.to_summary(&modules);
        assert_eq!(s.edges.len(), modules.len());

        let etd = s
            .edges
            .iter()
            .find(|e| e.module == "email_to_domain")
            .expect("email_to_domain edge");
        assert_eq!(etd.consumes, vec!["email"]);
        assert_eq!(etd.produces, vec!["domain"]);
    }

    #[test]
    fn consumes_via_probe_finds_kind_gates_in_accepts() {
        let m = EmailToDomain;
        let kinds = consumes_via_probe(&m);
        assert_eq!(kinds, vec![TargetKind::Email]);

        let m2 = DomainToIp;
        let kinds = consumes_via_probe(&m2);
        assert!(kinds.contains(&TargetKind::Domain));
        assert!(kinds.contains(&TargetKind::Url));
    }
}
