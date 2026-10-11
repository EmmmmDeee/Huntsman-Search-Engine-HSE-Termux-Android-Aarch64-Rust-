//! Shared analysis fan-out over one immutable pipeline snapshot.

use serde::Serialize;

use crate::attack_reporting::{HierarchyCoverage, coverage_from_observations};
use crate::coref::{self, CorefCluster};
use crate::correlator::{Correlation, RuleContext, confirmed_only, rank_and_sort, registry};
use crate::coverage::{CoverageVerdict, coverage_verdict};
use crate::cross_scan::{
    CrossScanCategory, CrossScanOptions, CrossScanRecord, CrossScanStore, build_cross_scan_history,
    category_from_entities,
};
use crate::error::Error;
use crate::gap::{self, GapReport};
use crate::graph::Graph;
use crate::intelligence::{self, IntelligenceReport};
use crate::metrics::{self, ScanMetrics};
use crate::pipeline::{AnalysisSnapshot, PipelineLimits};
use crate::pivot::{self, PivotScore};
use crate::termination::{
    FrontierState, TerminationReason, TerminationSignals, decide_termination,
};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InvestigationReport {
    pub attack: HierarchyCoverage,
    pub intelligence: IntelligenceReport,
    pub metrics: ScanMetrics,
    pub gaps: GapReport,
    pub pivots: Vec<PivotScore>,
    pub coreference: Vec<CorefCluster>,
    pub correlations: Vec<Correlation>,
    pub cross_scan: Option<CrossScanCategory>,
    pub cross_scan_history: Vec<CrossScanRecord>,
    pub coverage: CoverageVerdict,
    pub termination: TerminationReason,
    pub truncated: bool,
}

fn termination_for(snapshot: &AnalysisSnapshot) -> TerminationReason {
    let frontier = FrontierState {
        admissible_work: usize::from(snapshot.truncated),
        ..FrontierState::default()
    };
    let signals = TerminationSignals {
        resource_limit_reached: snapshot.truncated,
        ..TerminationSignals::default()
    };
    decide_termination(frontier, signals).unwrap_or(TerminationReason::FixedPoint)
}

fn correlate_entities_at(
    entities: &[crate::entity::Entity],
    scan_id: &str,
    now_unix: u64,
) -> Vec<Correlation> {
    let confirmed = confirmed_only(entities);
    let context = RuleContext::new(&confirmed, &[]);
    let mut correlations = Vec::new();
    for rule in registry() {
        correlations.extend(rule.run(&context, scan_id, now_unix));
    }
    rank_and_sort(&mut correlations, &confirmed);
    correlations
}

fn base_report(snapshot: &AnalysisSnapshot) -> InvestigationReport {
    let graph = Graph::build(&snapshot.entities, &snapshot.relations);
    let scan_id = snapshot
        .entities
        .first()
        .map_or("analysis", |entity| entity.scan_id.as_str());
    let now_unix = snapshot
        .entities
        .iter()
        .map(|entity| entity.observed_at_unix)
        .max()
        .unwrap_or(0);
    InvestigationReport {
        attack: coverage_from_observations(&snapshot.entities, &snapshot.relations),
        intelligence: intelligence::build_intelligence_report(
            &snapshot.entities,
            &snapshot.relations,
        ),
        metrics: metrics::compute(&snapshot.entities, &snapshot.relations),
        gaps: gap::analyze(&snapshot.entities, &snapshot.relations),
        pivots: pivot::rank_pivots(&graph),
        coreference: coref::cluster_entities(&snapshot.entities),
        correlations: correlate_entities_at(&snapshot.entities, scan_id, now_unix),
        cross_scan: None,
        cross_scan_history: build_cross_scan_history(&snapshot.entities),
        coverage: coverage_verdict(&snapshot.coverage),
        termination: termination_for(snapshot),
        truncated: snapshot.truncated,
    }
}

#[must_use]
pub fn analyze_snapshot(snapshot: &AnalysisSnapshot) -> InvestigationReport {
    base_report(snapshot)
}

/// Analyze the same immutable snapshot with injected historical scan storage.
///
/// # Errors
/// Propagates cross-scan storage failures.
pub fn analyze_snapshot_with_cross_scan<S: CrossScanStore>(
    snapshot: &AnalysisSnapshot,
    scan_id: &str,
    store: &S,
    limits: &PipelineLimits,
) -> Result<InvestigationReport, Error> {
    let mut report = base_report(snapshot);
    report.cross_scan = Some(category_from_entities(
        store,
        scan_id,
        &snapshot.entities,
        CrossScanOptions {
            max_frontier: limits.max_cross_scan_frontier,
            max_visited: limits.max_cross_scan_visited,
        },
    )?);
    Ok(report)
}
