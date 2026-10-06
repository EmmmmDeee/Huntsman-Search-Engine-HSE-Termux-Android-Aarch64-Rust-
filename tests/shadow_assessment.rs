use std::collections::{BTreeMap, BTreeSet};

use huntsman_recon::claim_policy::{VerificationBlocker, VerificationPolicy};
use huntsman_recon::evidence_ancestry::{
    EvidenceAncestryGraph, EvidenceAncestryNode, EvidenceNodeId,
};
use huntsman_recon::intelligence::{
    Claim, ClaimId, ClaimObject, ClaimState, EvidenceId, EvidenceNature, EvidenceRecord,
    IntelligenceLedger, SourceAuthority, SourceLineage,
};
use huntsman_recon::proof::{MinimalProofEnvironment, ProofEnvironmentSet};
use huntsman_recon::shadow_assessment::compare_legacy_and_policy;

fn evidence(id: &str, origin: &str) -> EvidenceRecord {
    EvidenceRecord {
        id: EvidenceId::from(id),
        subject_uid: "uid-1".into(),
        summary: format!("evidence-{id}"),
        lineage: SourceLineage {
            source_id: format!("provider-{id}"),
            origin_id: Some(origin.into()),
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

fn policy(min_proven_roots: usize) -> VerificationPolicy {
    VerificationPolicy {
        id: "shadow:v1".into(),
        version: 1,
        min_proven_roots,
        require_resolved_ancestry: true,
        required_natures: vec![EvidenceNature::Observed],
        required_attributes: BTreeMap::new(),
    }
}

fn proof(ids: &[EvidenceId], roots: &[&str], incomplete: bool) -> ProofEnvironmentSet {
    ProofEnvironmentSet {
        environments: vec![MinimalProofEnvironment {
            assertions: ids.iter().cloned().collect(),
            roots: roots.iter().map(|root| (*root).to_owned()).collect(),
            ..MinimalProofEnvironment::default()
        }],
        incomplete,
    }
}

fn root_graph(
    bindings: &[(&EvidenceId, &str)],
) -> (EvidenceAncestryGraph, BTreeMap<EvidenceId, EvidenceNodeId>) {
    let mut graph = EvidenceAncestryGraph::default();
    let mut map = BTreeMap::new();
    let mut inserted = BTreeSet::new();
    for (evidence_id, family) in bindings {
        let root_id = EvidenceNodeId(format!("root-{family}"));
        if inserted.insert(root_id.clone()) {
            graph
                .insert(EvidenceAncestryNode {
                    id: root_id.clone(),
                    source_family: (*family).into(),
                    parents: BTreeSet::new(),
                    derived: false,
                })
                .unwrap();
        }
        map.insert((*evidence_id).clone(), root_id);
    }
    (graph, map)
}

fn ledger_with(ids: &[(&str, &str)]) -> (IntelligenceLedger, ClaimId, Vec<EvidenceId>) {
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
    for (id, origin) in ids {
        let evidence_id = ledger.insert_evidence(evidence(id, origin)).unwrap();
        ledger.attach_support(&claim_id, &evidence_id).unwrap();
        evidence_ids.push(evidence_id);
    }
    (ledger, claim_id, evidence_ids)
}

#[test]
fn direct_primary_evidence_exposes_candidate_to_verified_semantic_difference() {
    let (ledger, claim_id, ids) = ledger_with(&[("direct", "primary")]);
    let (graph, bindings) = root_graph(&[(&ids[0], "primary")]);

    let shadow = compare_legacy_and_policy(
        &ledger,
        &claim_id,
        &policy(1),
        &graph,
        &bindings,
        &proof(&ids, &["primary"], false),
    )
    .unwrap();

    assert_eq!(shadow.legacy_state, ClaimState::Candidate);
    assert_eq!(shadow.policy_state, ClaimState::Verified);
    assert_eq!(shadow.distinct_resolved_roots, 1);
    assert_eq!(shadow.proven_independent_routes, 1);
    assert!(!shadow.independence_incomplete);
    assert!(shadow.reason_codes.contains("state:candidate->verified"));
}

#[test]
fn collapsed_mirrors_surface_the_independence_blocker_even_when_state_matches() {
    let (ledger, claim_id, ids) = ledger_with(&[("a", "legacy-a"), ("b", "legacy-b")]);
    let (graph, bindings) = root_graph(&[(&ids[0], "shared"), (&ids[1], "shared")]);

    let shadow = compare_legacy_and_policy(
        &ledger,
        &claim_id,
        &policy(2),
        &graph,
        &bindings,
        &proof(&ids, &["shared"], false),
    )
    .unwrap();

    assert_eq!(shadow.legacy_state, ClaimState::Supported);
    assert_eq!(shadow.policy_state, ClaimState::Supported);
    assert_eq!(shadow.distinct_resolved_roots, 1);
    assert_eq!(shadow.proven_independent_routes, 1);
    assert!(
        shadow
            .blockers
            .contains(&VerificationBlocker::InsufficientIndependentSupport)
    );
    assert!(
        shadow
            .reason_codes
            .contains("blocker:insufficient_independent_support")
    );
}

#[test]
fn legacy_verified_with_unproven_disjoint_roots_is_demoted_and_explained() {
    let (mut ledger, claim_id, ids) = ledger_with(&[("a", "legacy-a"), ("b", "legacy-b")]);
    ledger.claims.get_mut(&claim_id).unwrap().state = ClaimState::Verified;
    let (graph, bindings) = root_graph(&[(&ids[0], "source-a"), (&ids[1], "source-b")]);

    let shadow = compare_legacy_and_policy(
        &ledger,
        &claim_id,
        &policy(2),
        &graph,
        &bindings,
        &proof(&ids, &["source-a", "source-b"], false),
    )
    .unwrap();

    assert_eq!(shadow.legacy_state, ClaimState::Verified);
    assert_eq!(shadow.policy_state, ClaimState::Supported);
    assert_eq!(shadow.distinct_resolved_roots, 2);
    assert_eq!(shadow.proven_independent_routes, 1);
    assert!(!shadow.independence_incomplete);
    assert!(
        shadow
            .reason_codes
            .contains("blocker:insufficient_independent_support")
    );
    assert!(shadow.reason_codes.contains("state:verified->supported"));
}

#[test]
fn bounded_independence_search_exhaustion_is_visible_and_non_strengthening() {
    let pairs: Vec<(String, String)> = (0..100)
        .map(|index| (format!("e{index}"), format!("source-{index}")))
        .collect();
    let refs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(id, origin)| (id.as_str(), origin.as_str()))
        .collect();
    let (mut ledger, claim_id, ids) = ledger_with(&refs);
    ledger.claims.get_mut(&claim_id).unwrap().state = ClaimState::Verified;

    let binding_pairs: Vec<(&EvidenceId, &str)> = ids
        .iter()
        .zip(pairs.iter())
        .map(|(id, (_, origin))| (id, origin.as_str()))
        .collect();
    let (graph, bindings) = root_graph(&binding_pairs);
    let root_names: Vec<String> = pairs.iter().map(|(_, origin)| origin.clone()).collect();
    let root_refs: Vec<&str> = root_names.iter().map(String::as_str).collect();

    let shadow = compare_legacy_and_policy(
        &ledger,
        &claim_id,
        &policy(2),
        &graph,
        &bindings,
        &proof(&ids, &root_refs, false),
    )
    .unwrap();

    assert_eq!(shadow.policy_state, ClaimState::Supported);
    assert_eq!(shadow.distinct_resolved_roots, 100);
    assert_eq!(shadow.proven_independent_routes, 1);
    assert!(shadow.independence_incomplete);
    assert!(
        shadow
            .blockers
            .contains(&VerificationBlocker::IncompleteIndependenceProof)
    );
    assert!(
        shadow
            .reason_codes
            .contains("blocker:incomplete_independence_proof")
    );
}

#[test]
fn incomplete_proof_is_visible_and_prevents_shadow_verification() {
    let (ledger, claim_id, ids) = ledger_with(&[("direct", "primary")]);
    let (graph, bindings) = root_graph(&[(&ids[0], "primary")]);

    let shadow = compare_legacy_and_policy(
        &ledger,
        &claim_id,
        &policy(1),
        &graph,
        &bindings,
        &proof(&ids, &["primary"], true),
    )
    .unwrap();

    assert_eq!(shadow.policy_state, ClaimState::Supported);
    assert!(
        shadow
            .blockers
            .contains(&VerificationBlocker::IncompleteProof)
    );
    assert!(shadow.reason_codes.contains("blocker:incomplete_proof"));
}
