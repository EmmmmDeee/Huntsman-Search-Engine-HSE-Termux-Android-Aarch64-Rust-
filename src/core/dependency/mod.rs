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
//!   [`crate::core::scan::expansion_weight_for_strategy`]: an entity
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
use crate::core::module::Module;
use crate::core::scan::{Target, TargetKind};

pub mod reachability;

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
    TargetKind::Cidr,
    TargetKind::Coordinates,
    TargetKind::Address,
    TargetKind::Organisation,
    TargetKind::AbnAcn,
    TargetKind::MacAddress,
    TargetKind::ApiKey,
    TargetKind::CryptoAddress,
    TargetKind::DeviceId,
    // A WiFi SSID seed routes to WiGLE's SSID-search (geolocates where the
    // network was observed). Omitting it here left `wigle`'s `Ssid` branch DEAD
    // at runtime: the dispatch index and the `consumes()` default-probe iterate
    // ONLY this array, so no `Ssid` seed ever reached any module. The
    // `all_target_kinds_lists_every_enum_variant` guard now prevents this drift.
    TargetKind::Ssid,
    TargetKind::TrackingId,
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

    /// The same buckets as [`Self::dispatch_index`], but ordered by convex
    /// **query value** ([`crate::core::convex::query_value`]) descending — cheap,
    /// keyless, identity-/key-unlocking queries first; expensive, terminal ones
    /// last. Walked instead of `dispatch_index` when a scan runs under
    /// [`crate::core::scan::ScanOptions::convex_budget`], so that a dispatch
    /// sequence cut short by the phone's budget has already spent it on the
    /// highest-return-per-query modules. Same *membership* as `dispatch_index`
    /// (every accepting module is present) — only the order differs — so it never
    /// changes which modules run, and with the flag off the plain priority order
    /// is used and behaviour is byte-identical. Precomputed here (pure function of
    /// static module metadata) so the hot dispatch path pays no per-target sort.
    convex_dispatch_index: HashMap<TargetKind, Vec<usize>>,

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
            // Deduplicate each module's declared kinds. `consumes()`/`produces()`
            // are module-supplied (the trait default probes uniquely, but a
            // hand-written override is free to list a kind twice). A duplicate
            // would push the same module index into a dispatch bucket twice — and
            // since free modules are exempt from the per-scan DispatchLog dedup,
            // that module would then run twice on every target in a round (double
            // work, double evidence) AND inflate its kind's consumer_count, which
            // skews richness. Index each (module, kind) at most once.
            let mut seen_consumes: HashSet<TargetKind> = HashSet::new();
            for kind in m.consumes() {
                if !seen_consumes.insert(kind) {
                    continue;
                }
                dispatch_index.entry(kind).or_default().push(idx);
                *consumer_count.entry(kind).or_default() += 1;
            }
            let mut seen_produces: HashSet<EntityKind> = HashSet::new();
            for ek in m.produces() {
                if seen_produces.insert(ek.clone()) {
                    producer_index.entry(ek.clone()).or_default().push(idx);
                }
            }
        }

        // Every TargetKind must have an entry even if no module accepts
        // it — keeps `module_count_for()` total without an `Option`.
        for k in ALL_TARGET_KINDS {
            consumer_count.entry(*k).or_insert(0);
            dispatch_index.entry(*k).or_default();
        }

        let max_consumer_count = consumer_count.values().copied().max().unwrap_or(1).max(1);

        // Convex query-value order: precompute each module's static query value
        // once (pure function of cost / passivity / produced kinds / category),
        // then re-order a copy of every dispatch bucket by it — highest-return
        // query first. Determinism is load-bearing (the engine's whole output is
        // reproducible), so the f64 key is compared with `total_cmp` and ties are
        // broken by the SAME (priority desc, name asc) order `dispatch_index`
        // already carries, so equal-value modules keep their established sequence.
        let query_value: Vec<f64> = modules
            .iter()
            .map(|m| {
                crate::core::convex::query_value(
                    m.cost(),
                    m.is_passive(),
                    crate::core::convex::module_cascade(m.produces(), m.category()),
                )
            })
            .collect();
        let convex_dispatch_index: HashMap<TargetKind, Vec<usize>> = dispatch_index
            .iter()
            .map(|(kind, bucket)| {
                let mut ordered = bucket.clone();
                ordered.sort_by(|&a, &b| {
                    query_value[b]
                        .total_cmp(&query_value[a])
                        .then_with(|| modules[b].priority().cmp(&modules[a].priority()))
                        .then_with(|| modules[a].name().cmp(modules[b].name()))
                });
                (*kind, ordered)
            })
            .collect();

        Self {
            dispatch_index,
            convex_dispatch_index,
            consumer_count,
            max_consumer_count,
            producer_index,
        }
    }

    /// Indices into the engine's `modules` vec of every module that
    /// accepts `kind`, in priority-descending order.
    pub fn modules_for(&self, kind: TargetKind) -> &[usize] {
        self.dispatch_index.get(&kind).map_or(&[], Vec::as_slice)
    }

    /// The same module indices as [`Self::modules_for`], but ordered by convex
    /// **query value** (cheap, high-optionality queries first) — the dispatch
    /// order a scan uses under
    /// [`crate::core::scan::ScanOptions::convex_budget`]. Identical membership to
    /// `modules_for`; only the order differs.
    pub fn convex_modules_for(&self, kind: TargetKind) -> &[usize] {
        self.convex_dispatch_index
            .get(&kind)
            .map_or(&[], Vec::as_slice)
    }

    /// The dispatch order for `kind` under scan options: the convex query-value
    /// order when `convex_budget` is on, else the plain priority order. One
    /// helper so every dispatch loop selects the SAME order from the SAME flag,
    /// and the choice can't drift between the sequential and concurrent paths.
    pub fn dispatch_order_for(&self, kind: TargetKind, convex_budget: bool) -> &[usize] {
        if convex_budget {
            self.convex_modules_for(kind)
        } else {
            self.modules_for(kind)
        }
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
        v.sort_by_key(std::string::ToString::to_string);
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
                cost: m.cost().as_str(),
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
                // The joinable edge: the SAME mapping dispatch uses, so the
                // rendered graph and the runtime agree by construction rather
                // than by two hand-maintained lists happening to match.
                pivots_to: {
                    let mut v: Vec<&'static str> = m
                        .produces()
                        .iter()
                        .filter_map(TargetKind::from_entity_kind)
                        .map(|t| t.canonical_str())
                        .collect();
                    v.sort_unstable();
                    v.dedup();
                    v
                },
            })
            .collect();

        // Derived from the edges rather than from a hand-written list, so a new
        // terminal EntityKind is reported the moment a module emits one.
        let mut terminal_kinds: Vec<String> = modules
            .iter()
            .flat_map(|m| m.produces().iter())
            .filter(|k| TargetKind::from_entity_kind(k).is_none())
            .map(std::string::ToString::to_string)
            .collect();
        terminal_kinds.sort_unstable();
        terminal_kinds.dedup();

        ModuleGraphSummary {
            kinds: consumers_by_kind,
            edges,
            terminal_kinds,
        }
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
///
/// # Two vocabularies, and which one joins
///
/// [`Self::consumes`] is drawn from [`TargetKind`] (what dispatch can hand a
/// module) and [`Self::produces`] from [`EntityKind`] (what a module emits).
/// These are different enums. They agree on almost every spelling, which is
/// exactly what made the difference easy to miss: joining a producer to a
/// consumer by string equality across the two appears to work, and silently
/// fails on the one term where they diverge — `EntityKind::Person` is spelled
/// `person`, but the target kind dispatch routes it to is `full_name`.
///
/// `person` is produced by 55 of 168 modules, so that single mismatch made the
/// most connected pivot in the system look like a dead end: every one of those
/// modules appeared to feed nothing. Kinds with no [`TargetKind`] at all
/// (`credential`, `password`) were indistinguishable from it, so a terminal-by-
/// design kind and a broken join looked the same from outside.
///
/// [`Self::pivots_to`] is therefore the field to join on: `produces` mapped
/// through [`TargetKind::from_entity_kind`], the same authority dispatch itself
/// uses. `produces` is retained unchanged — it is the truthful record of what a
/// module emits, and provenance is not the same question as reachability.
#[derive(Debug, Clone, Serialize)]
pub struct PivotEdge {
    pub module: &'static str,
    pub category: &'static str,
    pub cost: &'static str,
    pub passive: bool,
    /// Target kinds dispatch may hand this module — [`TargetKind`] vocabulary.
    pub consumes: Vec<&'static str>,
    /// Entity kinds this module emits — [`EntityKind`] vocabulary. Provenance,
    /// not reachability: join on [`Self::pivots_to`] instead.
    pub produces: Vec<String>,
    /// [`Self::produces`] mapped into the [`TargetKind`] vocabulary — the
    /// module's real outbound edges. A consumer renders the data-flow graph by
    /// joining this against another edge's `consumes`. Entity kinds that cannot
    /// be pivoted at all are absent here and listed in
    /// [`ModuleGraphSummary::terminal_kinds`].
    pub pivots_to: Vec<&'static str>,
}

/// Top-level serializable structure for `/api/v1/modules/graph`.
#[derive(Debug, Clone, Serialize)]
pub struct ModuleGraphSummary {
    pub kinds: Vec<KindNode>,
    pub edges: Vec<PivotEdge>,
    /// Entity kinds that no module can be dispatched on — they have no
    /// [`TargetKind`] counterpart, so an entity of this kind is always a leaf.
    ///
    /// Stated explicitly because "produced by many, consumed by none" is
    /// otherwise ambiguous between a deliberate terminal kind (a `password` is
    /// evidence, never a scan seed) and a genuine coverage gap. A consumer
    /// auditing the graph for dead ends needs to tell those apart; without this
    /// it cannot.
    pub terminal_kinds: Vec<String>,
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
    include!("tests.rs");
}
