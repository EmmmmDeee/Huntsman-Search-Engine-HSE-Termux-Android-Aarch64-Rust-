//! `core::gap` — discovery-gap analysis over the live seed graph.
//!
//! # What this answers
//! The engine's whole purpose is to connect a subject's findings into one graph. The
//! blunt operational question this module answers is the inverse: *which validated seeds
//! did a scan produce that are NOT connected to anything — and what, concretely, would
//! connect them?* An isolated seed is a discovery blind spot: a real, execution-derived
//! entity sitting in live state with no evidence-backed link to the rest of the graph.
//!
//! # Strictly evidence-grounded
//! Every input is a **validated** seed — an [`Entity`] that exists in live state because a
//! module produced it during a real scan — and every link is an evidence-backed
//! [`Relation`]. This module *reads* that state and classifies it; it infers nothing, it
//! stores nothing as truth, and it never fabricates a seed or a link. The corrective
//! actions it emits are observable next steps (re-inject this seed, run the modules that
//! accept its kind), not assertions. When there are no seeds at all it reports an explicit
//! [`null state`](GapReport::null_state) rather than inventing one.
//!
//! # Pure and deterministic
//! [`analyze`] is pure synthesis over `(entities, relations)`: read-only, no I/O, no clock,
//! independent of input order. It builds the shared [`Graph`]
//! primitive (parallel edges collapsed, self-loops and dangling endpoints dropped) and
//! calls a seed *isolated* exactly when its graph degree is zero — so a self-loop or a
//! relation to an absent entity never counts as a real link. The result is byte-identical
//! across runs of the same (unordered) inputs.

use serde::Serialize;

use crate::core::entity::Entity;
use crate::core::graph::Graph;
use crate::core::relation::Relation;
use crate::core::scan::TargetKind;

/// Confidence at or above which the engine's default expansion gate
/// (`min_expand_confidence`, 0.40–0.50 across profiles) would re-inject a seed. An
/// isolated *scannable* seed below this was never expanded *because* of its confidence;
/// at or above it, the gap is missing coverage, not a gate decision.
pub const EXPAND_FLOOR: f64 = 0.50;

/// Why a validated seed has no evidence-backed link in the live graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    /// A scannable seed at/above the [`EXPAND_FLOOR`] with no links: the modules for its
    /// kind either never ran or returned no relation. The actionable gap — missing trace
    /// / index coverage. Corrective: re-inject it and query the modules that accept it.
    Unexpanded,
    /// A scannable seed BELOW the [`EXPAND_FLOOR`]: the engine's gate would not have
    /// expanded it. Corrective: corroborate it (raise confidence) or force a re-scan.
    BelowExpandFloor,
    /// A non-scannable kind (credential, password, tracking id, …): isolation is
    /// EXPECTED — a terminal leaf, not a blind spot. No corrective scan exists.
    Terminal,
}

impl Isolation {
    /// Sort rank, most-actionable first (`Unexpanded` < `BelowExpandFloor` < `Terminal`).
    fn rank(self) -> u8 {
        match self {
            Isolation::Unexpanded => 0,
            Isolation::BelowExpandFloor => 1,
            Isolation::Terminal => 2,
        }
    }

    /// The deterministic corrective action, in operator language.
    fn action(self) -> &'static str {
        match self {
            Isolation::Unexpanded => {
                "no trace/index coverage — re-inject as a seed and run the modules that accept its kind"
            }
            Isolation::BelowExpandFloor => {
                "below the expansion floor — corroborate to raise confidence, or force a re-scan, to expand it"
            }
            Isolation::Terminal => {
                "terminal leaf — kind is not independently scannable; no corrective scan"
            }
        }
    }
}

/// One isolated seed, classified, with the next observable step that would connect it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OrphanSeed {
    /// The seed's UID — its identity in live state.
    pub uid: String,
    /// The seed's [`EntityKind`](crate::core::entity::EntityKind), snake_case.
    pub kind: String,
    /// The seed's value, so the corrective scan has something concrete to re-inject.
    pub value: String,
    /// Cross-source effective confidence
    /// ([`c_effective`](crate::core::entity::Entity::c_effective)).
    pub confidence: f64,
    /// Why it is isolated.
    pub isolation: Isolation,
    /// The [`TargetKind`] this seed re-injects as
    /// (canonical name), or `None` when the kind is not independently scannable.
    pub reinjection_target: Option<String>,
    /// The corrective action, in operator language.
    pub action: &'static str,
}

/// Histogram of isolated seeds by [`Isolation`] class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IsolationCounts {
    /// Scannable, coverage-gap orphans — the actionable ones.
    pub unexpanded: usize,
    /// Scannable but below the expansion floor.
    pub below_expand_floor: usize,
    /// Non-scannable terminal leaves (expected isolation).
    pub terminal: usize,
}

/// The discovery-gap report for a scan's live seed set.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GapReport {
    /// Failure model: `true` when there are NO validated seeds at all — the explicit null
    /// state (no synthetic data is invented; keep monitoring live execution).
    pub null_state: bool,
    /// Total validated seeds (distinct entities).
    pub total_seeds: usize,
    /// Seeds linked into the graph (graph degree ≥ 1).
    pub linked_seeds: usize,
    /// Seeds with no evidence-backed link (graph degree 0).
    pub isolated_seeds: usize,
    /// Fraction of seeds that are linked, in `[0, 1]`; `0.0` for an empty scan.
    pub linked_fraction: f64,
    /// Isolation breakdown over [`isolated_seeds`](GapReport::isolated_seeds).
    pub isolation: IsolationCounts,
    /// The isolated seeds, most-actionable first (`Unexpanded` → `BelowExpandFloor` →
    /// `Terminal`), then by descending confidence, then UID — deterministic.
    pub orphans: Vec<OrphanSeed>,
}

/// Analyse a scan's live seed set for discovery gaps: which validated seeds are isolated,
/// why, and what would connect them.
///
/// Pure, deterministic, read-only over `(entities, relations)`. A seed is *isolated* when
/// its degree in the shared [`Graph`] is zero (self-loops and
/// dangling relations never count as links). Isolated seeds are classified by
/// [`Isolation`] and emitted most-actionable first. An empty entity slice yields the
/// explicit [`null state`](GapReport::null_state).
///
/// ```
/// use huntsman_search_engine::core::gap;
///
/// let r = gap::analyze(&[], &[]);
/// assert!(r.null_state);
/// assert_eq!(r.total_seeds, 0);
/// assert!(r.orphans.is_empty());
/// ```
#[must_use]
pub fn analyze(entities: &[Entity], relations: &[Relation]) -> GapReport {
    let g = Graph::build(entities, relations);

    let mut linked_seeds = 0usize;
    let mut total_seeds = 0usize;
    let mut counts = IsolationCounts {
        unexpanded: 0,
        below_expand_floor: 0,
        terminal: 0,
    };
    let mut orphans: Vec<OrphanSeed> = Vec::new();
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();

    for e in entities {
        // Count each distinct seed once (the store keys by UID, but stay robust).
        if !seen.insert(e.uid.as_str()) {
            continue;
        }
        total_seeds += 1;

        let degree = g.index_of(&e.uid).map_or(0, |i| g.degree(i));
        if degree > 0 {
            linked_seeds += 1;
            continue;
        }

        // Isolated → classify and prescribe the corrective action.
        let reinjection_target = TargetKind::from_entity_kind(&e.kind);
        let isolation = if reinjection_target.is_none() {
            counts.terminal += 1;
            Isolation::Terminal
        } else if e.c_effective() < EXPAND_FLOOR {
            counts.below_expand_floor += 1;
            Isolation::BelowExpandFloor
        } else {
            counts.unexpanded += 1;
            Isolation::Unexpanded
        };

        orphans.push(OrphanSeed {
            uid: e.uid.clone(),
            kind: e.kind.to_string(),
            value: e.value.clone(),
            confidence: e.c_effective(),
            isolation,
            reinjection_target: reinjection_target.map(|t| t.canonical_str().to_string()),
            action: isolation.action(),
        });
    }

    // Most-actionable first, then strongest seed, then UID — a total order, deterministic.
    orphans.sort_by(|a, b| {
        a.isolation
            .rank()
            .cmp(&b.isolation.rank())
            .then_with(|| b.confidence.total_cmp(&a.confidence))
            .then_with(|| a.uid.cmp(&b.uid))
    });

    let isolated_seeds = orphans.len();
    let linked_fraction = if total_seeds == 0 {
        0.0
    } else {
        linked_seeds as f64 / total_seeds as f64
    };

    GapReport {
        null_state: total_seeds == 0,
        total_seeds,
        linked_seeds,
        isolated_seeds,
        linked_fraction,
        isolation: counts,
        orphans,
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
