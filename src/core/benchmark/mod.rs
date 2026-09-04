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
    /// Structural **cohesion**: the graph's degeneracy — the largest `k` for which a
    /// `k`-core exists (see [`crate::core::metrics::ScanMetrics::graph_degeneracy`]). The
    /// exact complement to the fragility counts above: where cut vertices and bridges
    /// measure where the footprint *breaks*, degeneracy measures whether it has a
    /// redundantly-corroborated *core that holds* — `≥2` means a cluster of entities each
    /// bound by multiple independent links, not a sprawl of single-thread leads. Another
    /// robustness axis SpiderFoot reports nothing on.
    pub degeneracy: usize,
    /// Structural cohesion: the size of the **main core** — how many entities sit in that
    /// densest `k`-core (see [`crate::core::metrics::ScanMetrics::main_core_size`]). The
    /// count of entities forming the cohesive heart of the footprint; read with
    /// [`degeneracy`](Scorecard::degeneracy) it says both *how* corroborated the core is
    /// and *how much* of the graph it spans.
    pub main_core_size: usize,
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
    /// Provider coverage for the run behind this scorecard — see
    /// [`crate::core::intelligence::CoverageVerdict`]. `None` when the scan has
    /// no retained dispatch events, which is itself a reason not to compare.
    pub coverage: Option<crate::core::intelligence::CoverageVerdict>,
    /// The caveat this report needs before its scorecard is set against another
    /// run's, or `None` when the run asked everything — see
    /// [`BenchmarkReport::comparability_caveat`]. Carried as a field so a JSON
    /// consumer gets it without recomputing the rule.
    pub comparability_caveat: Option<String>,
}

impl BenchmarkReport {
    /// Why this scorecard is not straightforwardly comparable to another run's,
    /// or `None` when it is.
    ///
    /// The scorecard exists for head-to-head comparison — two configurations on
    /// an identical seed, field by field. That reading is only sound if both
    /// runs actually asked the same questions. A run where a third of its
    /// providers had no credential, or whose circuits were open, yields fewer
    /// entities for a reason that has nothing to do with the configuration under
    /// test, and attributing the difference to the configuration is exactly the
    /// false conclusion a benchmark is supposed to prevent.
    ///
    /// Unknown coverage is its own caveat: a scan whose event log has been
    /// pruned cannot vouch for what it asked, so it is not silently treated as
    /// having asked everything.
    #[must_use]
    pub fn comparability_caveat(&self) -> Option<String> {
        let Some(coverage) = self.coverage else {
            return Some(
                "provider coverage for this run is unknown (no dispatch events retained), so a \
                 yield difference cannot be attributed to the configuration under test"
                    .to_string(),
            );
        };
        if coverage.unavailable_count > 0 {
            return Some(format!(
                "{} of {} provider(s) could not be used during this run; a lower yield here may \
                 reflect that rather than the configuration under test",
                coverage.unavailable_count, coverage.provider_count
            ));
        }
        if coverage.out_of_scope_count > 0 {
            return Some(format!(
                "{} of {} provider(s) were out of scope for this run; compare only against a run \
                 with the same scope",
                coverage.out_of_scope_count, coverage.provider_count
            ));
        }
        None
    }
}

/// Build the [`BenchmarkReport`] for a scan from its record and its entities and
/// relations.
///
/// Pure, deterministic, read-only — it combines [`crate::core::metrics::compute`],
/// [`crate::core::pivot::detect`], the scan's own performance counters, and the
/// provider coverage derived from `events` into one artifact. The
/// [`metrics`](BenchmarkReport::metrics) are embedded whole so the report is a
/// complete, self-contained record (the traceability the verification loop wants).
///
/// `events` is the scan's retained dispatch event log. It is what makes the
/// report say whether its own scorecard is safe to compare — see
/// [`BenchmarkReport::comparability_caveat`]. Pass an empty slice only when the
/// log genuinely holds nothing for the scan; doing so is reported as unknown
/// coverage, never as a complete sweep.
#[must_use]
pub fn report(
    scan: &Scan,
    entities: &[Entity],
    relations: &[Relation],
    events: &[crate::core::event::Event],
) -> BenchmarkReport {
    let metrics = crate::core::metrics::compute(entities, relations);
    let pivots = crate::core::pivot::detect(entities, relations);
    // Structural fragility: cut vertices (articulation points) and bridges (cut
    // edges), both counted over the WHOLE graph — dimensions SpiderFoot reports
    // nothing on. `pivots` above is truncated to the top PIVOT_CAP by score, so
    // counting cut vertices off it undercounts them on a large graph; use the
    // uncapped `pivot::cut_vertex_count` (the node complement to `pivot::bridges`).
    let cut_vertex_count = crate::core::pivot::cut_vertex_count(entities, relations);
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
        degeneracy: metrics.graph_degeneracy,
        main_core_size: metrics.main_core_size,
        total_entities: metrics.total_entities,
        total_relations: metrics.total_relations,
        cross_scan_bridges: metrics.cross_scan_bridges,
    };

    let rows = crate::core::intelligence::provider_coverage_from_events(events);
    let coverage = (!rows.is_empty()).then(|| crate::core::intelligence::coverage_verdict(&rows));

    let mut report = BenchmarkReport {
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
        coverage,
        // Filled immediately below: the caveat is derived from the report, so
        // the rule lives in one place and the serialised field can never
        // disagree with `comparability_caveat()`.
        comparability_caveat: None,
    };
    report.comparability_caveat = report.comparability_caveat();
    report
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
