//! End-to-end module reachability over the producer/consumer graph.
//!
//! A module only runs during a scan when a `Target` of a kind it `accepts()`
//! actually appears — as the seed, or produced by an earlier module's entity and
//! re-fed by the engine's expansion (`TargetKind::from_entity_kind`). The
//! [`ModuleGraph`] already indexes *who consumes* and *who produces* each kind;
//! this walks that graph to answer the completeness question the raw indices
//! cannot: **from a given set of seed kinds, which modules are ever reachable —
//! and is any registered module wired such that no scan can reach it at all?**
//!
//! This is the "100% of modules run" guarantee. [`fully_wired`] proves the strong
//! form — from EVERY realistic seed kind ([`human_seed_kinds`]) the closure
//! reaches every registered module (the graph is fully connected, so a scan
//! seeded with anything can dispatch the whole engine). [`unreachable_modules`]
//! with the full seed universe catches a globally-dead module, and
//! [`coverage_from`] reports the transitive coverage a single seed achieves.

use std::collections::HashSet;
use std::sync::Arc;

use super::ModuleGraph;
use crate::core::dependency::ALL_TARGET_KINDS;
use crate::core::module::Module;
use crate::core::scan::TargetKind;

/// The transitive closure of target kinds a scan reaches from `seeds`: each
/// reachable kind's accepting modules produce entities, whose pivotable kinds
/// ([`TargetKind::from_entity_kind`]) become new reachable target kinds, until a
/// fixpoint. The fixpoint set is order-independent, so `HashSet` iteration
/// non-determinism cannot change the result.
#[must_use]
pub fn reachable_target_kinds(
    graph: &ModuleGraph,
    modules: &[Arc<dyn Module>],
    seeds: &[TargetKind],
) -> HashSet<TargetKind> {
    let mut reachable: HashSet<TargetKind> = seeds.iter().copied().collect();
    loop {
        let mut added = false;
        // Snapshot the current frontier so we can mutate `reachable` while
        // iterating the kinds discovered so far.
        let current: Vec<TargetKind> = reachable.iter().copied().collect();
        for tk in current {
            for &idx in graph.modules_for(tk) {
                let Some(m) = modules.get(idx) else { continue };
                for ek in m.produces() {
                    if let Some(new_tk) = TargetKind::from_entity_kind(ek)
                        && reachable.insert(new_tk)
                    {
                        added = true;
                    }
                }
            }
        }
        if !added {
            break;
        }
    }
    reachable
}

/// Indices of the modules a scan seeded with `seeds` can ever dispatch: those
/// accepting at least one reachable target kind. Priority order is irrelevant
/// here, so the result is sorted ascending for determinism.
#[must_use]
pub fn reachable_modules(
    graph: &ModuleGraph,
    modules: &[Arc<dyn Module>],
    seeds: &[TargetKind],
) -> Vec<usize> {
    let reachable_kinds = reachable_target_kinds(graph, modules, seeds);
    let mut out: Vec<usize> = (0..modules.len())
        .filter(|&idx| {
            modules[idx]
                .consumes()
                .iter()
                .any(|k| reachable_kinds.contains(k))
        })
        .collect();
    out.sort_unstable();
    out
}

/// The registered modules NO scan seeded with `seeds` can reach — a wiring gap.
/// Returns their names, sorted. With the full seed universe
/// ([`ALL_TARGET_KINDS`]) an empty result is the "100% of modules are wired to
/// run" guarantee; a non-empty result names a module that can never dispatch.
#[must_use]
pub fn unreachable_modules<'a>(
    graph: &ModuleGraph,
    modules: &'a [Arc<dyn Module>],
    seeds: &[TargetKind],
) -> Vec<&'a str> {
    let reachable: HashSet<usize> = reachable_modules(graph, modules, seeds)
        .into_iter()
        .collect();
    let mut names: Vec<&str> = (0..modules.len())
        .filter(|idx| !reachable.contains(idx))
        .map(|idx| modules[idx].name())
        .collect();
    names.sort_unstable();
    names
}

/// `(reachable, total)` module counts for a scan seeded with a single `seed`
/// kind — the transitive footprint one seed achieves. Useful for the coverage
/// report ("an Email seed reaches N of M modules").
#[must_use]
pub fn coverage_from(
    graph: &ModuleGraph,
    modules: &[Arc<dyn Module>],
    seed: TargetKind,
) -> (usize, usize) {
    (
        reachable_modules(graph, modules, &[seed]).len(),
        modules.len(),
    )
}

/// Every kind that can legitimately START a scan — the seed universe. A user (or
/// the auto-scanner) can seed any kind the target auto-detector recognises, and
/// each kind seeds itself, so the union transitively reaches every producible
/// kind. Used to prove no module is globally dead.
#[must_use]
pub fn seed_universe() -> &'static [TargetKind] {
    ALL_TARGET_KINDS
}

/// The kinds a scan realistically STARTS from — what `hse scan` auto-detects or a
/// `--kind` flag names, and what the SPA's New Scan wizard offers. The strong
/// end-to-end guarantee ([`fully_wired`]) is measured from these, not from
/// self-seeding a produced-only kind (`TrackingId`, `DeviceId`, `Ssid`), so it
/// reflects what a genuine investigation can reach.
#[must_use]
pub fn human_seed_kinds() -> &'static [TargetKind] {
    const SEEDS: &[TargetKind] = &[
        TargetKind::Email,
        TargetKind::Username,
        TargetKind::Phone,
        TargetKind::FullName,
        TargetKind::Domain,
        TargetKind::IpAddress,
        TargetKind::Url,
        TargetKind::Address,
        TargetKind::Coordinates,
        TargetKind::Organisation,
        TargetKind::AbnAcn,
        TargetKind::MacAddress,
    ];
    SEEDS
}

/// The strong "wired end-to-end so 100% of modules run" verdict: from EVERY
/// realistic seed kind ([`human_seed_kinds`]), the transitive producer/consumer
/// closure must reach every registered module. Returns `Ok(module_count)` when
/// it does, or `Err((seed, unreachable_names))` naming the first seed from which
/// a module is unreachable — a wiring regression. Currently holds for all seeds
/// (the module graph is fully connected).
///
/// # Errors
/// Returns the offending seed kind and the modules unreachable from it.
pub fn fully_wired(
    graph: &ModuleGraph,
    modules: &[Arc<dyn Module>],
) -> Result<usize, (TargetKind, Vec<String>)> {
    for &seed in human_seed_kinds() {
        let dead = unreachable_modules(graph, modules, &[seed]);
        if !dead.is_empty() {
            return Err((seed, dead.into_iter().map(str::to_string).collect()));
        }
    }
    Ok(modules.len())
}

/// True iff a probe `Target` of `kind` is accepted by at least one module — a
/// kind with zero consumers is a dead seed. Convenience over the graph index.
#[must_use]
pub fn kind_has_consumer(graph: &ModuleGraph, kind: TargetKind) -> bool {
    !graph.modules_for(kind).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph_and_modules() -> (ModuleGraph, Vec<Arc<dyn Module>>) {
        let modules = crate::modules::registry();
        let graph = ModuleGraph::build(&modules);
        (graph, modules)
    }

    #[test]
    fn no_registered_module_is_globally_unreachable() {
        // Seeded with the full kind universe, EVERY registered module must be
        // reachable — otherwise it is dead wiring no scan can ever dispatch.
        let (graph, modules) = graph_and_modules();
        let dead = unreachable_modules(&graph, &modules, seed_universe());
        assert!(
            dead.is_empty(),
            "these registered modules can never be dispatched by any scan (dead wiring): {dead:?}"
        );
    }

    #[test]
    fn every_module_is_reachable_from_every_realistic_seed() {
        // The strong end-to-end guarantee: seed the engine with ANY realistic
        // kind (email, username, phone, name, domain, ip, …) and the transitive
        // producer/consumer closure reaches 100% of the registered modules — so a
        // scan is genuinely "wired end-to-end". A regression (a module accepting a
        // kind that the seed can no longer produce) names the offending seed.
        let (graph, modules) = graph_and_modules();
        match fully_wired(&graph, &modules) {
            Ok(n) => assert_eq!(n, modules.len()),
            Err((seed, dead)) => {
                panic!("from a {seed:?} seed these modules are unreachable: {dead:?}")
            }
        }
    }

    #[test]
    fn a_username_seed_transitively_reaches_many_modules() {
        // A real single seed reaches a large, non-trivial fraction of the
        // registry through recursion — not just its direct consumers.
        let (graph, modules) = graph_and_modules();
        let direct = graph.modules_for(TargetKind::Username).len();
        let (transitive, total) = coverage_from(&graph, &modules, TargetKind::Username);
        assert!(transitive >= direct, "transitive >= direct by construction");
        assert!(
            transitive > direct,
            "recursion must reach modules beyond the seed's direct consumers \
             (direct={direct}, transitive={transitive}, total={total})"
        );
    }
}
