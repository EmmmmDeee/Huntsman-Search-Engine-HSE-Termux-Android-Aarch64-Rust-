use std::collections::{BTreeMap, BTreeSet};

use huntsman_recon::claim_policy::{VerificationBlocker, VerificationPolicy};
use huntsman_recon::evidence_ancestry::{
    EvidenceAncestryGraph, EvidenceAncestryNode, EvidenceNodeId, IndependenceBasis,
    IndependenceEvidence,
};
use huntsman_recon::intelligence::{
    Claim, ClaimId, ClaimObject, ClaimState, EvidenceId, EvidenceNature, EvidenceRecord,
    IntelligenceLedger, SourceAuthority, SourceLineage,
};
use huntsman_recon::retrieval_artifact::ArtifactId;

fn evidence(id: &str, declared_origin: &str) -> EvidenceRecord {
    EvidenceRecord {
        id: EvidenceId::from(id),
        subject_uid: "uid-1".into(),
        summary: format!("evidence-{id}"),
        lineage: SourceLineage {
            source_id: format!("provider-{id}"),
            origin_id: Some(declared_origin.into()),
            chain: Vec::new(),
            authority: SourceAuthority::Primary,
        },
        observed_at_unix: Some(1),
        recorded_at_unix: 2,
        nature: EvidenceNature::Observed,
        content_digest: Some(format!("digest-{id}")),
        attributes: BTreeMap::new(),
        ancestry_root_families: BTreeSet::new(),
    }
}

fn node(id: &str, family: &str, parents: &[&str]) -> EvidenceAncestryNode {
    EvidenceAncestryNode {
        id: EvidenceNodeId::from(id),
        source_family: family.into(),
        parents: parents.iter().copied().map(EvidenceNodeId::from).collect(),
        derived: !parents.is_empty(),
    }
}

fn prove_independent(graph: &mut EvidenceAncestryGraph, left: &str, right: &str) {
    graph
        .insert_independence_evidence(IndependenceEvidence {
            left_root: left.into(),
            right_root: right.into(),
            basis: IndependenceBasis::ExplicitUpstreamProvenance,
            method_id: "fixture:claim-independence".into(),
            method_version: 1,
            supporting_artifact_ids: BTreeSet::from([ArtifactId::from("sha256:claim-proof")]),
            observed_at_unix: 1,
        })
        .unwrap();
}

fn policy(min_proven_roots: usize) -> VerificationPolicy {
    VerificationPolicy {
        id: "test:ancestry:v1".into(),
        version: 1,
        min_proven_roots,
        require_resolved_ancestry: true,
        required_natures: vec![EvidenceNature::Observed],
    }
}

fn ledger_with_support(ids: &[(&str, &str)]) -> (IntelligenceLedger, ClaimId, Vec<EvidenceId>) {
    let mut ledger = IntelligenceLedger::default();
    let claim_id = ClaimId::from("claim-1");
    ledger
        .insert_claim(Claim::new(
            claim_id.clone(),
            "uid-1",
            ClaimObject::Narrative("claim".into()),
        ))
        .unwrap();

    let mut evidence_ids = Vec::new();
    for (id, declared_origin) in ids {
        let evidence_id = ledger
            .insert_evidence(evidence(id, declared_origin))
            .unwrap();
        ledger.attach_support(&claim_id, &evidence_id).unwrap();
        evidence_ids.push(evidence_id);
    }
    (ledger, claim_id, evidence_ids)
}

fn ledger_with_generated_support(count: usize) -> (IntelligenceLedger, ClaimId, Vec<EvidenceId>) {
    let mut ledger = IntelligenceLedger::default();
    let claim_id = ClaimId::from("claim-generated");
    ledger
        .insert_claim(Claim::new(
            claim_id.clone(),
            "uid-1",
            ClaimObject::Narrative("generated claim".into()),
        ))
        .unwrap();

    let mut evidence_ids = Vec::new();
    for index in 0..count {
        let id = format!("evidence-{index:02}");
        let origin = format!("legacy-{index:02}");
        let evidence_id = ledger.insert_evidence(evidence(&id, &origin)).unwrap();
        ledger.attach_support(&claim_id, &evidence_id).unwrap();
        evidence_ids.push(evidence_id);
    }
    (ledger, claim_id, evidence_ids)
}

#[test]
fn disjoint_root_labels_do_not_satisfy_two_route_policy_without_independence_evidence() {
    let (ledger, claim_id, ids) = ledger_with_support(&[("a", "legacy-a"), ("b", "legacy-b")]);
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("root-a", "registry", &[])).unwrap();
    graph.insert(node("root-b", "court", &[])).unwrap();
    let bindings = BTreeMap::from([
        (ids[0].clone(), EvidenceNodeId::from("root-a")),
        (ids[1].clone(), EvidenceNodeId::from("root-b")),
    ]);

    let assessment = ledger
        .assess_claim_with_ancestry(&claim_id, &policy(2), &graph, &bindings)
        .unwrap();

    assert_eq!(assessment.proven_roots, 1);
    assert_eq!(assessment.distinct_resolved_roots, 2);
    assert!(!assessment.independence_incomplete);
    assert_eq!(assessment.epistemic, ClaimState::Supported);
    assert!(
        assessment
            .blockers
            .contains(&VerificationBlocker::InsufficientIndependentSupport)
    );
}

#[test]
fn explicit_independence_can_satisfy_two_route_policy() {
    let (ledger, claim_id, ids) = ledger_with_support(&[("a", "legacy-a"), ("b", "legacy-b")]);
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("root-a", "same-label", &[])).unwrap();
    graph.insert(node("root-b", "same-label", &[])).unwrap();
    prove_independent(&mut graph, "root-a", "root-b");
    let bindings = BTreeMap::from([
        (ids[0].clone(), EvidenceNodeId::from("root-a")),
        (ids[1].clone(), EvidenceNodeId::from("root-b")),
    ]);

    let assessment = ledger
        .assess_claim_with_ancestry(&claim_id, &policy(2), &graph, &bindings)
        .unwrap();

    assert_eq!(assessment.proven_roots, 2);
    assert_eq!(assessment.distinct_resolved_roots, 2);
    assert!(!assessment.independence_incomplete);
    assert_eq!(assessment.epistemic, ClaimState::Verified);
    assert!(assessment.blockers.is_empty());
}

#[test]
fn known_shared_origin_stays_one_route() {
    let (ledger, claim_id, ids) =
        ledger_with_support(&[("mirror-a", "legacy-a"), ("mirror-b", "legacy-b")]);

    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("raw", "shared-corpus", &[])).unwrap();
    graph
        .insert(node("mirror-a-node", "provider-a", &["raw"]))
        .unwrap();
    graph
        .insert(node("mirror-b-node", "provider-b", &["raw"]))
        .unwrap();

    let bindings = BTreeMap::from([
        (ids[0].clone(), EvidenceNodeId::from("mirror-a-node")),
        (ids[1].clone(), EvidenceNodeId::from("mirror-b-node")),
    ]);

    let assessment = ledger
        .assess_claim_with_ancestry(&claim_id, &policy(2), &graph, &bindings)
        .unwrap();

    assert_eq!(assessment.proven_roots, 1);
    assert_eq!(assessment.distinct_resolved_roots, 1);
    assert_eq!(assessment.epistemic, ClaimState::Supported);
    assert!(
        assessment
            .blockers
            .contains(&VerificationBlocker::InsufficientIndependentSupport)
    );
}

#[test]
fn independence_search_truncation_blocks_verification() {
    let (ledger, claim_id, ids) = ledger_with_generated_support(24);
    let mut graph = EvidenceAncestryGraph::default();
    let mut bindings = BTreeMap::new();

    for (index, evidence_id) in ids.iter().enumerate() {
        let root = format!("root-{index:02}");
        graph.insert(node(&root, &root, &[])).unwrap();
        bindings.insert(evidence_id.clone(), EvidenceNodeId(root));
    }

    let assessment = ledger
        .assess_claim_with_ancestry(&claim_id, &policy(2), &graph, &bindings)
        .unwrap();

    assert_eq!(assessment.proven_roots, 1);
    assert_eq!(assessment.distinct_resolved_roots, 24);
    assert!(assessment.independence_incomplete);
    assert_ne!(assessment.epistemic, ClaimState::Verified);
    assert!(
        assessment
            .blockers
            .contains(&VerificationBlocker::IncompleteIndependenceProof)
    );
    assert!(
        assessment
            .blockers
            .contains(&VerificationBlocker::InsufficientIndependentSupport)
    );
}

#[test]
fn missing_ancestry_binding_fails_closed() {
    let (ledger, claim_id, _) = ledger_with_support(&[("a", "legacy-a")]);
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("root", "root", &[])).unwrap();

    let assessment = ledger
        .assess_claim_with_ancestry(&claim_id, &policy(1), &graph, &BTreeMap::new())
        .unwrap();

    assert_eq!(assessment.proven_roots, 0);
    assert_eq!(assessment.distinct_resolved_roots, 0);
    assert_eq!(assessment.unresolved_support, 1);
    assert_ne!(assessment.epistemic, ClaimState::Verified);
    assert!(
        assessment
            .blockers
            .contains(&VerificationBlocker::UnknownAncestry)
    );
}

#[test]
fn derived_ancestry_node_inherits_parent_root() {
    let (ledger, claim_id, ids) = ledger_with_support(&[("derived", "misleading-label")]);
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("root", "primary-artifact", &[])).unwrap();
    graph
        .insert(node("derived-node", "enrichment", &["root"]))
        .unwrap();
    let bindings = BTreeMap::from([(ids[0].clone(), EvidenceNodeId::from("derived-node"))]);

    let assessment = ledger
        .assess_claim_with_ancestry(&claim_id, &policy(1), &graph, &bindings)
        .unwrap();

    assert_eq!(assessment.proven_roots, 1);
    assert_eq!(assessment.distinct_resolved_roots, 1);
    assert_eq!(assessment.unresolved_support, 0);
    assert_eq!(assessment.epistemic, ClaimState::Verified);
}

#[test]
fn ancestry_cycle_fails_closed_instead_of_creating_roots() {
    let (ledger, claim_id, ids) = ledger_with_support(&[("cycle", "legacy-cycle")]);
    let mut graph = EvidenceAncestryGraph::default();
    graph.insert(node("a", "a", &["b"])).unwrap();
    graph.insert(node("b", "b", &["a"])).unwrap();
    let bindings = BTreeMap::from([(ids[0].clone(), EvidenceNodeId::from("a"))]);

    let assessment = ledger
        .assess_claim_with_ancestry(&claim_id, &policy(1), &graph, &bindings)
        .unwrap();

    assert_eq!(assessment.proven_roots, 0);
    assert_eq!(assessment.distinct_resolved_roots, 0);
    assert_eq!(assessment.unresolved_support, 1);
    assert_ne!(assessment.epistemic, ClaimState::Verified);
    assert!(
        assessment
            .blockers
            .contains(&VerificationBlocker::UnknownAncestry)
    );
}
