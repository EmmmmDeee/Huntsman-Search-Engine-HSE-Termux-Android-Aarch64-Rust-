use std::collections::BTreeSet;

use huntsman_recon::evidence_ancestry::{
    EvidenceAncestryGraph, EvidenceAncestryNode, EvidenceNodeId,
};
use huntsman_recon::identity_benchmark::{BenchmarkCase, evaluate};
use huntsman_recon::identity_resolution::{
    AutoMergePolicy, IdentityResolutionDecision, ResolutionState,
};

fn graph() -> EvidenceAncestryGraph {
    let mut graph = EvidenceAncestryGraph::default();
    let mut insert = |id: &str, family: &str, parents: &[&str]| {
        graph
            .insert(EvidenceAncestryNode {
                id: EvidenceNodeId::from(id),
                source_family: family.to_owned(),
                parents: parents
                    .iter()
                    .copied()
                    .map(EvidenceNodeId::from)
                    .collect::<BTreeSet<_>>(),
                derived: !parents.is_empty(),
            })
            .expect("valid ancestry");
    };
    insert("registry", "company-registry", &[]);
    insert("profile", "first-party-profile", &[]);
    insert("court", "court-record", &[]);
    insert("breach-root", "breach-dataset", &[]);
    insert("mirror-a", "provider-a", &["breach-root"]);
    insert("mirror-b", "provider-b", &["breach-root"]);
    graph
}

fn decision(
    state: ResolutionState,
    probability: Option<f64>,
    support: &[&str],
    contradicting: &[&str],
) -> IdentityResolutionDecision {
    IdentityResolutionDecision {
        left_entity_uid: "left".into(),
        right_entity_uid: "right".into(),
        state,
        probability,
        supporting: support.iter().copied().map(EvidenceNodeId::from).collect(),
        contradicting: contradicting
            .iter()
            .copied()
            .map(EvidenceNodeId::from)
            .collect(),
        temporal_conflict: false,
        geographic_conflict: false,
        decided_at_unix: 1,
    }
}

#[test]
fn adversarial_benchmark_has_zero_false_merges_and_preserves_strong_matches() {
    let cases = vec![
        BenchmarkCase::new(
            "strong-independent-match",
            decision(
                ResolutionState::Match,
                Some(0.99),
                &["registry", "profile"],
                &[],
            ),
            true,
        ),
        BenchmarkCase::new(
            "missing-probability-must-not-bypass-threshold",
            decision(ResolutionState::Match, None, &["registry", "profile"], &[]),
            false,
        ),
        BenchmarkCase::new(
            "redistributed-breach-mirrors-are-one-root",
            decision(
                ResolutionState::Match,
                Some(0.99),
                &["mirror-a", "mirror-b"],
                &[],
            ),
            false,
        ),
        BenchmarkCase::new(
            "contradiction-is-non-compensatory",
            decision(
                ResolutionState::Match,
                Some(0.999),
                &["registry", "profile"],
                &["court"],
            ),
            false,
        ),
        BenchmarkCase::new(
            "probable-is-not-auto-merge",
            decision(
                ResolutionState::Probable,
                Some(0.99),
                &["registry", "profile"],
                &[],
            ),
            false,
        ),
        BenchmarkCase::new(
            "below-threshold-match-stays-unmerged",
            decision(
                ResolutionState::Match,
                Some(0.89),
                &["registry", "profile"],
                &[],
            ),
            false,
        ),
    ];

    let summary = evaluate(&cases, &graph(), AutoMergePolicy::default());
    assert_eq!(summary.cases, 6);
    assert_eq!(summary.true_positive, 1);
    assert_eq!(summary.true_negative, 5);
    assert_eq!(summary.false_positive, 0);
    assert_eq!(summary.false_negative, 0);
    assert_eq!(summary.precision, 1.0);
    assert_eq!(summary.recall, 1.0);
}
