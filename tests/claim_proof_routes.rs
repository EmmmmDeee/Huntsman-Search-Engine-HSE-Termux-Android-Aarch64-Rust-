use std::collections::{BTreeMap, BTreeSet};

use huntsman_recon::claim_policy::{VerificationBlocker, VerificationPolicy};
use huntsman_recon::evidence_ancestry::{
    EvidenceAncestryGraph, EvidenceAncestryNode, EvidenceNodeId, IndependenceBasis,
    IndependenceEvidence, IndependenceEvidenceSet, MAX_PROOF_ROUTE_ROOTS,
    METHOD_EXPLICIT_UPSTREAM_PROVENANCE_V1,
};
use huntsman_recon::intelligence::{
    Claim, ClaimId, ClaimObject, ClaimState, EvidenceId, EvidenceNature, EvidenceRecord,
    IntelligenceLedger, SourceAuthority, SourceLineage,
};

fn evidence(id: &str) -> EvidenceRecord {
    EvidenceRecord {
        id: EvidenceId::from(id),
        subject_uid: "uid-1".into(),
        summary: format!("evidence-{id}"),
        lineage: SourceLineage {
            source_id: format!("provider-{id}"),
            origin_id: Some(format!("legacy-{id}")),
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

fn node(id: &str) -> EvidenceAncestryNode {
    EvidenceAncestryNode {
        id: EvidenceNodeId::from(id),
        source_family: id.to_owned(),
        parents: BTreeSet::new(),
        derived: false,
    }
}

fn proof(left: &str, right: &str) -> IndependenceEvidence {
    IndependenceEvidence {
        left_root: EvidenceNodeId::from(left),
        right_root: EvidenceNodeId::from(right),
        basis: IndependenceBasis::ExplicitUpstreamProvenance,
        method_id: METHOD_EXPLICIT_UPSTREAM_PROVENANCE_V1.to_owned(),
        method_version: 1,
        supporting_artifact_ids: BTreeSet::from([format!("artifact:{left}:{right}")]),
        observed_at_unix: 1,
    }
}

fn policy(min_proven_roots: usize) -> VerificationPolicy {
    VerificationPolicy {
        id: "claim-proof-route:v1".into(),
        version: 1,
        min_proven_roots,
        require_resolved_ancestry: true,
        required_natures: vec![EvidenceNature::Observed],
    }
}

fn ledger_with_roots(
    roots: &[String],
) -> (
    IntelligenceLedger,
    ClaimId,
    EvidenceAncestryGraph,
    BTreeMap<EvidenceId, EvidenceNodeId>,
) {
    let mut ledger = IntelligenceLedger::default();
    let claim_id = ClaimId::from("claim-proof-route");
    ledger
        .insert_claim(Claim::new(
            claim_id.clone(),
            "uid-1",
            ClaimObject::Narrative("claim".into()),
        ))
        .unwrap();

    let mut graph = EvidenceAncestryGraph::default();
    let mut bindings = BTreeMap::new();
    for root in roots {
        graph.insert(node(root)).unwrap();
        let evidence_id = ledger.insert_evidence(evidence(root)).unwrap();
        ledger.attach_support(&claim_id, &evidence_id).unwrap();
        bindings.insert(evidence_id, EvidenceNodeId(root.clone()));
    }
    (ledger, claim_id, graph, bindings)
}

#[test]
fn disjoint_roots_without_independence_proof_cannot_verify() {
    let roots = vec!["registry".to_owned(), "court".to_owned()];
    let (ledger, claim_id, graph, bindings) = ledger_with_roots(&roots);

    let assessment = ledger
        .assess_claim_with_proof_routes(
            &claim_id,
            &policy(2),
            &graph,
            &bindings,
            &IndependenceEvidenceSet::default(),
        )
        .unwrap();

    assert_eq!(assessment.observed_distinct_roots, 2);
    assert_eq!(assessment.proven_independent_routes, 1);
    assert_eq!(assessment.epistemic, ClaimState::Supported);
    assert!(
        assessment
            .blockers
            .contains(&VerificationBlocker::UnprovenIndependence)
    );
}

#[test]
fn exact_independence_proof_promotes_and_removal_demotes() {
    let roots = vec!["registry".to_owned(), "court".to_owned()];
    let (ledger, claim_id, graph, bindings) = ledger_with_roots(&roots);
    let mut independence = IndependenceEvidenceSet::default();
    independence
        .insert(&graph, proof("registry", "court"))
        .unwrap();

    let verified = ledger
        .assess_claim_with_proof_routes(
            &claim_id,
            &policy(2),
            &graph,
            &bindings,
            &independence,
        )
        .unwrap();
    assert_eq!(verified.proven_independent_routes, 2);
    assert_eq!(verified.epistemic, ClaimState::Verified);

    let demoted = ledger
        .assess_claim_with_proof_routes(
            &claim_id,
            &policy(2),
            &graph,
            &bindings,
            &IndependenceEvidenceSet::default(),
        )
        .unwrap();
    assert_eq!(demoted.epistemic, ClaimState::Supported);
    assert!(
        demoted
            .blockers
            .contains(&VerificationBlocker::UnprovenIndependence)
    );
}

#[test]
fn legacy_ancestry_path_is_diagnostic_only() {
    let roots = vec!["direct".to_owned()];
    let (ledger, claim_id, graph, bindings) = ledger_with_roots(&roots);
    let assessment = ledger
        .assess_claim_with_ancestry(&claim_id, &policy(1), &graph, &bindings)
        .unwrap();

    assert_eq!(assessment.observed_distinct_roots, 1);
    assert_eq!(assessment.proven_independent_routes, 0);
    assert_eq!(assessment.epistemic, ClaimState::Supported);
    assert!(
        assessment
            .blockers
            .contains(&VerificationBlocker::UnprovenIndependence)
    );
}

#[test]
fn proof_route_search_limit_blocks_verification() {
    let roots = (0..=MAX_PROOF_ROUTE_ROOTS)
        .map(|index| format!("root-{index}"))
        .collect::<Vec<_>>();
    let (ledger, claim_id, graph, bindings) = ledger_with_roots(&roots);

    let assessment = ledger
        .assess_claim_with_proof_routes(
            &claim_id,
            &policy(2),
            &graph,
            &bindings,
            &IndependenceEvidenceSet::default(),
        )
        .unwrap();

    assert_eq!(assessment.observed_distinct_roots, MAX_PROOF_ROUTE_ROOTS + 1);
    assert_eq!(assessment.proven_independent_routes, 0);
    assert_ne!(assessment.epistemic, ClaimState::Verified);
    assert!(
        assessment
            .blockers
            .contains(&VerificationBlocker::ProofRouteEvaluationFailed)
    );
}
