//! Public-API regression checks for evidence-gated investigative review.
//!
//! This is a review-only analysis library, not a finding of criminal culpability.

use huntsman_recon::trafficking_intel::entity_tree::{
    EntityEdge, EntityKind, EntityNode, EntityTree, GraphError, RelationshipKind,
};
use huntsman_recon::trafficking_intel::{
    AssessmentStatus, Indicator, Observation, ReviewPolicy, assess,
};

fn observation(origin: &str) -> Observation {
    Observation {
        indicator: Indicator::DebtBondage,
        source_id: format!("source-{origin}"),
        origin_id: origin.to_owned(),
        evidence_ref: format!("public-record-{origin}"),
        observed_at: "2026-10-19".to_owned(),
        corroborated: true,
    }
}

#[test]
fn review_abstains_until_independent_origins_support_the_same_indicator() {
    let repeated = [observation("publisher-a"), observation("publisher-a")];
    assert_eq!(
        assess(&repeated).status,
        AssessmentStatus::InsufficientEvidence
    );

    let independent = [observation("publisher-a"), observation("publisher-b")];
    let assessment = ReviewPolicy::default().assess(&independent);
    assert_eq!(
        assessment.status,
        AssessmentStatus::IndicatorsForHumanReview
    );
    assert_eq!(
        assessment.supported_indicators,
        vec![Indicator::DebtBondage]
    );
    assert_eq!(assessment.independent_origins, 2);
}

#[test]
fn review_and_tree_serialise_without_losing_citations() {
    let graph = EntityTree {
        nodes: vec![
            EntityNode {
                id: "organisation".to_owned(),
                kind: EntityKind::Organisation,
                label: "Fictional Agency".to_owned(),
            },
            EntityNode {
                id: "document".to_owned(),
                kind: EntityKind::Evidence,
                label: "Public record".to_owned(),
            },
        ],
        edges: vec![EntityEdge {
            from: "organisation".to_owned(),
            to: "document".to_owned(),
            kind: RelationshipKind::MentionedIn,
            evidence_refs: vec!["public-record-1".to_owned()],
            alleged: false,
        }],
    };
    let encoded = serde_json::to_string(&graph).expect("serialize");
    let decoded: EntityTree = serde_json::from_str(&encoded).expect("deserialize");
    assert_eq!(decoded.edges[0].evidence_refs, vec!["public-record-1"]);
    assert_eq!(
        decoded.expand("organisation", 1, 10).expect("expand").len(),
        2
    );

    let mut invalid = decoded;
    invalid.edges[0].evidence_refs.clear();
    assert_eq!(invalid.validate(), Err(GraphError::MissingEvidence));
}

#[test]
fn existing_core_graph_exposes_only_documented_relationships() {
    use huntsman_recon::entity::{
        Entity, EntityKind as CoreEntityKind, Evidence, EvidenceProvenance,
    };
    use huntsman_recon::graph::{EntityRelation, Graph, RelationKind};
    use huntsman_recon::trafficking_intel::graph_bridge::expand_documented;

    let root = Entity::new(CoreEntityKind::Organisation, "Example Agency", 0.5, "scan");
    let record = Entity::new(CoreEntityKind::Document, "Published Record", 0.5, "scan");
    let unrelated = Entity::new(CoreEntityKind::Domain, "example.org", 0.5, "scan");
    let documented = EntityRelation::new(
        root.uid.clone(),
        record.uid.clone(),
        RelationKind::MentionedWith,
        0.6,
    )
    .with_evidence(Evidence::new(
        EvidenceProvenance::new("published-case-record"),
        "The public record mentions this organisation",
    ));
    let unsupported = EntityRelation::new(
        root.uid.clone(),
        unrelated.uid.clone(),
        RelationKind::AssociatedWith,
        0.9,
    );
    let relations = [documented, unsupported];
    let graph = Graph::build(&[root.clone(), record.clone(), unrelated], &relations);
    let view = expand_documented(&graph, &relations, &root.uid, 2, 10).expect("traverse");
    assert_eq!(view.len(), 2);
    assert_eq!(view[0].id, root.uid);
    assert_eq!(view[1].id, record.uid);
    assert_eq!(view[1].parent.as_deref(), Some(root.uid.as_str()));
    assert_eq!(
        expand_documented(&graph, &relations, "unknown", 2, 0),
        Err(GraphError::UnknownEndpoint("unknown".to_owned()))
    );
}
