//! Shared analysis fan-out over one immutable pipeline snapshot.

use serde::Serialize;

use crate::attack_reporting::{HierarchyCoverage, coverage_from_observations};
use crate::coref::{self, CorefCluster};
use crate::correlator::{Correlation, evaluate_rules};
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

fn base_report(snapshot: &AnalysisSnapshot, expand_floor: f64) -> InvestigationReport {
    let graph = Graph::build(&snapshot.entities, &snapshot.relations);
    let scan_id = snapshot
        .entities
        .first()
        .map_or("analysis", |entity| entity.scan_id.as_str());
    InvestigationReport {
        attack: coverage_from_observations(&snapshot.entities, &snapshot.relations),
        intelligence: intelligence::build_intelligence_report(
            &snapshot.entities,
            &snapshot.relations,
        ),
        metrics: metrics::compute(&snapshot.entities, &snapshot.relations),
        gaps: gap::analyze_on(&graph, &snapshot.entities, expand_floor),
        pivots: pivot::rank_pivots(&graph),
        coreference: coref::cluster_entities(&snapshot.entities),
        // The rules read domain relations, which they derive from the entities. The snapshot's
        // relations are only their graph projection (`EntityRelation`), so none are passed.
        correlations: evaluate_rules(&snapshot.entities, &[], scan_id),
        cross_scan: None,
        cross_scan_history: build_cross_scan_history(&snapshot.entities),
        coverage: coverage_verdict(&snapshot.coverage),
        termination: termination_for(snapshot),
        truncated: snapshot.truncated,
    }
}

#[must_use]
pub fn analyze_snapshot(snapshot: &AnalysisSnapshot) -> InvestigationReport {
    base_report(snapshot, gap::EXPAND_FLOOR)
}

/// [`analyze_snapshot`] for a crawl that expanded by `expand_floor`, so the gap report names as
/// below the floor exactly the orphans the crawl would not follow.
#[must_use]
pub fn analyze_snapshot_with_expand_floor(
    snapshot: &AnalysisSnapshot,
    expand_floor: f64,
) -> InvestigationReport {
    base_report(snapshot, expand_floor)
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
    let mut report = base_report(snapshot, gap::EXPAND_FLOOR);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
    use crate::evidence_ancestry::EvidenceAncestryGraph;

    /// A confirmed domain whose DNS evidence names the address it resolves to.
    fn hosted_on(domain: &str, ip: &str) -> Entity {
        let mut entity = Entity::new(EntityKind::Domain, domain, 0.9, "analysis-test");
        entity.add_evidence(
            Evidence::new(EvidenceProvenance::new("dns"), format!("{domain} A record"))
                .with_attr("ip", ip),
        );
        entity
    }

    /// Two confirmed domains on one address (RFC 5737 documentation range) share hosting.
    /// AU-110 reads `ResolvesTo` relations, so the analysis reports it only when the rules are
    /// given the relations these entities imply. Given none, as before, it stayed silent.
    #[test]
    fn analysis_correlates_over_the_relations_its_entities_imply() {
        let snapshot = AnalysisSnapshot {
            entities: vec![
                hosted_on("alpha.example", "192.0.2.10"),
                hosted_on("beta.example", "192.0.2.10"),
                Entity::new(EntityKind::IpAddress, "192.0.2.10", 0.9, "analysis-test"),
            ],
            relations: Vec::new(),
            coverage: Vec::new(),
            ancestry: EvidenceAncestryGraph::default(),
            truncated: false,
        };
        let report = analyze_snapshot(&snapshot);
        let fired: Vec<&str> = report
            .correlations
            .iter()
            .map(|correlation| correlation.rule_id.as_str())
            .collect();
        assert!(fired.contains(&"AU-110"), "rules that fired: {fired:?}");
    }

    /// An entity demoted to candidate is excluded before the rules run, so deriving relations
    /// cannot make it assert a link: the same domains and address, demoted, fire nothing.
    #[test]
    fn entities_demoted_to_candidate_assert_no_correlation() {
        let mut entities = vec![
            hosted_on("alpha.example", "192.0.2.10"),
            hosted_on("beta.example", "192.0.2.10"),
            Entity::new(EntityKind::IpAddress, "192.0.2.10", 0.9, "analysis-test"),
        ];
        for entity in &mut entities {
            entity.demote_to_candidate();
        }
        let snapshot = AnalysisSnapshot {
            entities,
            relations: Vec::new(),
            coverage: Vec::new(),
            ancestry: EvidenceAncestryGraph::default(),
            truncated: false,
        };
        assert_eq!(
            analyze_snapshot(&snapshot).correlations,
            Vec::<Correlation>::new()
        );
    }
}
