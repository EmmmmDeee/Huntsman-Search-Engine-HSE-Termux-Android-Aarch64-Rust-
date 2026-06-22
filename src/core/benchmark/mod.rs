//! `core::benchmark` — a consolidated, auditable per-scan benchmark report.
//!
//! Rolls the engine's measurable OSINT dimensions into ONE reproducible artifact for
//! head-to-head comparison: the graph-intelligence metrics ([`crate::core::metrics`]),
//! the pivot count and structural fragility ([`crate::core::pivot`]), and the scan's own
//! performance counters (wall-clock duration, throughput, and the module run / error /
//! timeout tallies). The [`Scorecard`] is the headline — the dimensions a competitive
//! OSINT benchmark is scored on: multi-hop discovery depth, graph coverage, relationship
//! corroboration, density, structural fragility (cut vertices / bridges), and raw yield
//! — so two tools (or two HSE configurations) run on an identical seed can be compared
//! field by field.
//!
//! Pure synthesis over a persisted [`Scan`] plus its [`Entity`] and [`Relation`] sets:
//! deterministic and read-only, the evidence artifact the verification loop emits.

use serde::Serialize;

use crate::core::entity::Entity;
use crate::core::metrics::ScanMetrics;
use crate::core::relation::Relation;
use crate::core::scan::Scan;

/// The headline benchmark dimensions — the axes a competitive OSINT comparison scores.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Scorecard {
    /// Multi-hop discovery depth: the deepest finding's hop distance from the seed.
    pub multi_hop_depth: usize,
    /// Graph coverage: fraction of entities reachable from the seed.
    pub graph_coverage: f64,
    /// Relationship corroboration: fraction of entities confirmed by ≥2 sources — a
    /// false-positive-resistance proxy.
    pub corroborated_fraction: f64,
    /// Undirected graph density.
    pub graph_density: f64,
    /// Structural fragility: the number of **cut vertices** (articulation points) — the
    /// entities whose removal fragments the network. A robustness/criticality axis
    /// SpiderFoot reports nothing on; lower relative to size means a more resilient,
    /// better-corroborated footprint.
    pub cut_vertex_count: usize,
    /// Structural fragility: the number of **bridges** (cut edges) — the single links
    /// whose removal splits the graph. The irreplaceable connections; pairs with
    /// [`cut_vertex_count`](Scorecard::cut_vertex_count) as the graph's fragility map.
    pub bridge_count: usize,
    /// Raw entity yield.
    pub total_entities: usize,
    /// Typed-edge yield.
    pub total_relations: usize,
    /// Cross-scan bridges — historical-flywheel continuity into earlier scans.
    pub cross_scan_bridges: usize,
}

/// A consolidated, reproducible benchmark report for one scan.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BenchmarkReport {
    pub scan_id: String,
    pub seed: String,
    pub seed_kind: String,
    pub status: String,
    /// Wall-clock scan duration in seconds (`finished_at − started_at`); `None` if the
    /// scan never finished. Network-bound, so it is comparable only under like
    /// conditions — fair for an A/B on identical seeds and network.
    pub duration_secs: Option<u64>,
    /// Entities discovered per second of wall-clock (`0.0` when the duration is unknown
    /// or zero).
    pub entities_per_sec: f64,
    /// Modules that actually ran.
    pub modules_run: usize,
    /// Modules that errored — a reliability signal.
    pub modules_errored: usize,
    /// Modules that hit their timeout — a constrained-environment signal.
    pub modules_timed_out: usize,
    /// Number of pivot nodes (high-connectivity intermediaries) detected.
    pub pivot_count: usize,
    /// The single most central pivot's UID, if any.
    pub top_pivot_uid: Option<String>,
    /// The headline scorecard.
    pub scorecard: Scorecard,
    /// The full graph-intelligence metrics, embedded for complete traceability.
    pub metrics: ScanMetrics,
}

/// Build the [`BenchmarkReport`] for a scan from its record and its entities and
/// relations.
///
/// Pure, deterministic, read-only — it combines [`crate::core::metrics::compute`],
/// [`crate::core::pivot::detect`], and the scan's own performance counters into one
/// artifact. The [`metrics`](BenchmarkReport::metrics) are embedded whole so the report
/// is a complete, self-contained record (the traceability the verification loop wants).
#[must_use]
pub fn report(scan: &Scan, entities: &[Entity], relations: &[Relation]) -> BenchmarkReport {
    let metrics = crate::core::metrics::compute(entities, relations);
    let pivots = crate::core::pivot::detect(entities, relations);
    // Structural fragility: cut vertices come off the pivots' flags (a cut vertex always
    // has degree ≥ 1, so every one is among the pivots); bridges are the graph's cut
    // edges. Both are dimensions SpiderFoot reports nothing on.
    let cut_vertex_count = pivots.iter().filter(|p| p.is_cut_vertex).count();
    let bridge_count = crate::core::pivot::bridges(entities, relations).len();

    let duration_secs = scan.finished_at.map(|f| f.saturating_sub(scan.started_at));
    let entities_per_sec = match duration_secs {
        Some(d) if d > 0 => entities.len() as f64 / d as f64,
        _ => 0.0,
    };

    let scorecard = Scorecard {
        multi_hop_depth: metrics.seed_reach.max_depth,
        graph_coverage: metrics.seed_reach.reachable_fraction,
        corroborated_fraction: metrics.corroborated_fraction,
        graph_density: metrics.graph_density,
        cut_vertex_count,
        bridge_count,
        total_entities: metrics.total_entities,
        total_relations: metrics.total_relations,
        cross_scan_bridges: metrics.cross_scan_bridges,
    };

    BenchmarkReport {
        scan_id: scan.id.clone(),
        seed: scan.target.value.clone(),
        seed_kind: scan.target.kind.canonical_str().to_string(),
        status: scan.status.as_str().to_string(),
        duration_secs,
        entities_per_sec,
        modules_run: scan.modules_run,
        modules_errored: scan.modules_errored,
        modules_timed_out: scan.modules_timed_out,
        pivot_count: pivots.len(),
        top_pivot_uid: pivots.first().map(|p| p.uid.clone()),
        scorecard,
        metrics,
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
