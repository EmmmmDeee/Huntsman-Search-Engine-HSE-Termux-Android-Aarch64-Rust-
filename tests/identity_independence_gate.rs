use std::collections::BTreeSet;

use huntsman_recon::evidence_ancestry::{
    EvidenceAncestryGraph, EvidenceAncestryNode, EvidenceNodeId,
};
use huntsman_recon::identity_resolution::{
    AutoMergePolicy, IdentityResolutionDecision, ResolutionState,
};

fn root(id: &str, family: &str) -> EvidenceAncestryNode {
    EvidenceAncestryNode {
        id: EvidenceNodeId::from(id),
        source_family: family.to_owned(),
        parents: BTreeSet::new(),
        derived: false,
    }
}

#[test]
fn disjoint_unproven_roots_cannot_auto_merge_an_identity() {
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(root("registry", "company registry")).unwrap();
    graph.insert(root("profile", "profile page")).unwrap();

    let decision = IdentityResolutionDecision {
        left_entity_uid: "entity-a".into(),
        right_entity_uid: "entity-b".into(),
        state: ResolutionState::Match,
        probability: Some(0.99),
        supporting: vec!["registry".into(), "profile".into()],
        contradicting: Vec::new(),
        temporal_conflict: false,
        geographic_conflict: false,
        decided_at_unix: 1,
    };

    assert!(
        !decision.allows_automatic_merge(&graph, AutoMergePolicy::default()),
        "distinct root labels are not proof of independent causal origins"
    );
}
