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
use huntsman_recon::proof::{AssumptionId, MinimalProofEnvironment, ProofEnvironmentSet};
use huntsman_recon::retrieval_artifact::ArtifactId;

fn evidence(id: &str, attributes: BTreeMap<String, String>) -> EvidenceRecord {
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
        attributes,
        ancestry_root_families: BTreeSet::new(),
    }
}

fn ledger_with_claim() -> (IntelligenceLedger, ClaimId) {
    let mut ledger = IntelligenceLedger::default();
    let claim_id = ClaimId::from("claim-1");
    ledger
        .insert_claim(Claim::new(
            claim_id.clone(),
            "uid-1",
            ClaimObject::Narrative("subject controls account".into()),
        ))
        .unwrap();
    (ledger, claim_id)
}

fn policy(min_proven_roots: usize) -> VerificationPolicy {
    VerificationPolicy {
        id: "identity.account.controlled_by:v3".into(),
        version: 3,
        min_proven_roots,
        require_resolved_ancestry: true,
        required_natures: vec![EvidenceNature::Observed],
        required_attributes: BTreeMap::new(),
    }
}

fn root_graph(
    bindings: &[(&EvidenceId, &str)],
) -> (EvidenceAncestryGraph, BTreeMap<EvidenceId, EvidenceNodeId>) {
    let mut graph = EvidenceAncestryGraph::default();
    let mut map = BTreeMap::new();
    for (evidence_id, root_id) in bindings {
        let node_id = EvidenceNodeId::from(*root_id);
        if graph.get(&node_id).is_none() {
            graph
                .insert(EvidenceAncestryNode {
                    id: node_id.clone(),
                    source_family: format!("family-{root_id}"),
                    parents: BTreeSet::new(),
                    derived: false,
                })
                .unwrap();
        }
        map.insert((*evidence_id).clone(), node_id);
    }
    (graph, map)
}

fn proof(
    assertions: &[EvidenceId],
    roots: &[&str],
    assumptions: &[&str],
    incomplete: bool,
) -> ProofEnvironmentSet {
    ProofEnvironmentSet {
        environments: vec![MinimalProofEnvironment {
            assertions: assertions.iter().cloned().collect(),
            roots: roots.iter().map(|root| (*root).to_owned()).collect(),
            assumptions: assumptions
                .iter()
                .copied()
                .map(AssumptionId::from)
                .collect(),
            ..MinimalProofEnvironment::default()
        }],
        incomplete,
    }
}

fn independence(left: &str, right: &str) -> IndependenceEvidence {
    IndependenceEvidence {
        left_root: EvidenceNodeId::from(left),
        right_root: EvidenceNodeId::from(right),
        basis: IndependenceBasis::ExplicitUpstreamProvenance,
        method_id: "test:explicit-upstream".into(),
        method_version: 1,
        supporting_artifact_ids: [ArtifactId::from("sha256:proof")].into_iter().collect(),
        observed_at_unix: 1,
    }
}

#[test]
fn valid_claim_scoped_proof_can_verify() {
    let (mut ledger, claim_id) = ledger_with_claim();
    let evidence_id = ledger
        .insert_evidence(evidence("a", BTreeMap::new()))
        .unwrap();
    ledger.attach_support(&claim_id, &evidence_id).unwrap();
    let (graph, bindings) = root_graph(&[(&evidence_id, "root-a")]);

    let assessment = ledger
        .assess_claim_with_ancestry_and_proof(
            &claim_id,
            &policy(1),
            &graph,
            &bindings,
            &proof(std::slice::from_ref(&evidence_id), &["root-a"], &[], false),
        )
        .unwrap();

    assert_eq!(assessment.epistemic, ClaimState::Verified);
    assert!(assessment.blockers.is_empty());
    assert_eq!(assessment.proof_environment_count, 1);
}

#[test]
fn forged_root_or_detached_assertion_cannot_verify() {
    let (mut ledger, claim_id) = ledger_with_claim();
    let attached = ledger
        .insert_evidence(evidence("attached", BTreeMap::new()))
        .unwrap();
    ledger.attach_support(&claim_id, &attached).unwrap();
    let detached = ledger
        .insert_evidence(evidence("detached", BTreeMap::new()))
        .unwrap();
    let (graph, bindings) =
        root_graph(&[(&attached, "root-attached"), (&detached, "root-detached")]);

    for invalid in [
        proof(
            std::slice::from_ref(&attached),
            &["fabricated-root"],
            &[],
            false,
        ),
        proof(
            std::slice::from_ref(&detached),
            &["root-detached"],
            &[],
            false,
        ),
    ] {
        let assessment = ledger
            .assess_claim_with_ancestry_and_proof(
                &claim_id,
                &policy(1),
                &graph,
                &bindings,
                &invalid,
            )
            .unwrap();
        assert_eq!(assessment.epistemic, ClaimState::Supported);
        assert!(
            assessment
                .blockers
                .contains(&VerificationBlocker::InvalidProofEnvironment)
        );
    }
}

#[test]
fn assumption_or_incomplete_proof_cannot_verify() {
    let (mut ledger, claim_id) = ledger_with_claim();
    let evidence_id = ledger
        .insert_evidence(evidence("a", BTreeMap::new()))
        .unwrap();
    ledger.attach_support(&claim_id, &evidence_id).unwrap();
    let (graph, bindings) = root_graph(&[(&evidence_id, "root-a")]);

    let assumed = ledger
        .assess_claim_with_ancestry_and_proof(
            &claim_id,
            &policy(1),
            &graph,
            &bindings,
            &proof(
                std::slice::from_ref(&evidence_id),
                &["root-a"],
                &["same-person"],
                false,
            ),
        )
        .unwrap();
    assert_eq!(assumed.epistemic, ClaimState::Supported);
    assert!(
        assumed
            .blockers
            .contains(&VerificationBlocker::UnresolvedProofAssumption)
    );

    let incomplete = ledger
        .assess_claim_with_ancestry_and_proof(
            &claim_id,
            &policy(1),
            &graph,
            &bindings,
            &proof(std::slice::from_ref(&evidence_id), &["root-a"], &[], true),
        )
        .unwrap();
    assert_eq!(incomplete.epistemic, ClaimState::Supported);
    assert!(
        incomplete
            .blockers
            .contains(&VerificationBlocker::IncompleteProof)
    );
}

#[test]
fn empty_proof_environment_set_cannot_verify() {
    let (mut ledger, claim_id) = ledger_with_claim();
    let evidence_id = ledger
        .insert_evidence(evidence("a", BTreeMap::new()))
        .unwrap();
    ledger.attach_support(&claim_id, &evidence_id).unwrap();
    let (graph, bindings) = root_graph(&[(&evidence_id, "root-a")]);

    let assessment = ledger
        .assess_claim_with_ancestry_and_proof(
            &claim_id,
            &policy(1),
            &graph,
            &bindings,
            &ProofEnvironmentSet::default(),
        )
        .unwrap();

    assert_eq!(assessment.epistemic, ClaimState::Supported);
    assert!(
        assessment
            .blockers
            .contains(&VerificationBlocker::MissingProofEnvironment)
    );
}

#[test]
fn semantic_requirement_must_exist_inside_the_sufficient_environment() {
    let (mut ledger, claim_id) = ledger_with_claim();
    let control = ledger
        .insert_evidence(evidence(
            "control",
            BTreeMap::from([("control".into(), "confirmed".into())]),
        ))
        .unwrap();
    let plain = ledger
        .insert_evidence(evidence("plain", BTreeMap::new()))
        .unwrap();
    ledger.attach_support(&claim_id, &control).unwrap();
    ledger.attach_support(&claim_id, &plain).unwrap();
    let (graph, bindings) = root_graph(&[(&control, "root-control"), (&plain, "root-plain")]);

    let mut required = policy(1);
    required.required_attributes =
        BTreeMap::from([("control".into(), BTreeSet::from(["confirmed".into()]))]);

    let missing = ledger
        .assess_claim_with_ancestry_and_proof(
            &claim_id,
            &required,
            &graph,
            &bindings,
            &proof(std::slice::from_ref(&plain), &["root-plain"], &[], false),
        )
        .unwrap();
    assert_eq!(missing.epistemic, ClaimState::Supported);
    assert!(
        missing
            .blockers
            .contains(&VerificationBlocker::MissingRequiredEvidenceAttribute)
    );

    let present = ledger
        .assess_claim_with_ancestry_and_proof(
            &claim_id,
            &required,
            &graph,
            &bindings,
            &proof(
                std::slice::from_ref(&control),
                &["root-control"],
                &[],
                false,
            ),
        )
        .unwrap();
    assert_eq!(present.epistemic, ClaimState::Verified);
}

#[test]
fn two_route_policy_requires_explicit_independence_inside_proof() {
    let (mut ledger, claim_id) = ledger_with_claim();
    let left = ledger
        .insert_evidence(evidence("left", BTreeMap::new()))
        .unwrap();
    let right = ledger
        .insert_evidence(evidence("right", BTreeMap::new()))
        .unwrap();
    ledger.attach_support(&claim_id, &left).unwrap();
    ledger.attach_support(&claim_id, &right).unwrap();
    let (mut graph, bindings) = root_graph(&[(&left, "root-left"), (&right, "root-right")]);
    let environment = proof(
        &[left.clone(), right.clone()],
        &["root-left", "root-right"],
        &[],
        false,
    );

    let before = ledger
        .assess_claim_with_ancestry_and_proof(
            &claim_id,
            &policy(2),
            &graph,
            &bindings,
            &environment,
        )
        .unwrap();
    assert_eq!(before.epistemic, ClaimState::Supported);
    assert!(
        before
            .blockers
            .contains(&VerificationBlocker::InsufficientIndependentSupport)
    );

    graph
        .insert_independence_evidence(independence("root-left", "root-right"))
        .unwrap();
    let after = ledger
        .assess_claim_with_ancestry_and_proof(
            &claim_id,
            &policy(2),
            &graph,
            &bindings,
            &environment,
        )
        .unwrap();
    assert_eq!(after.epistemic, ClaimState::Verified);
}
