use std::collections::{BTreeMap, BTreeSet};

use huntsman_recon::claim_policy::{ClaimAssessment, VerificationBlocker, VerificationPolicy};
use huntsman_recon::evidence_ancestry::{
    EvidenceAncestryGraph, EvidenceAncestryNode, EvidenceNodeId,
};
use huntsman_recon::intelligence::{
    Claim, ClaimId, ClaimObject, ClaimState, Defeat, DefeatKind, EvidenceId, EvidenceNature,
    EvidenceRecord, IntelligenceLedger, SourceAuthority, SourceLineage,
};

fn evidence(id: &str, root: &str) -> EvidenceRecord {
    EvidenceRecord {
        id: EvidenceId::from(id),
        subject_uid: "uid-1".into(),
        summary: format!("evidence-{id}"),
        lineage: SourceLineage {
            source_id: format!("provider-{id}"),
            origin_id: Some(root.into()),
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

fn policy() -> VerificationPolicy {
    VerificationPolicy {
        id: "test:v1".into(),
        version: 1,
        min_proven_roots: 1,
        require_resolved_ancestry: true,
        required_natures: vec![EvidenceNature::Observed],
    }
}

fn verified_candidate() -> (
    IntelligenceLedger,
    ClaimId,
    EvidenceAncestryGraph,
    BTreeMap<EvidenceId, EvidenceNodeId>,
) {
    let mut ledger = IntelligenceLedger::default();
    let claim_id = ClaimId::from("claim-1");
    ledger
        .insert_claim(Claim::new(
            claim_id.clone(),
            "uid-1",
            ClaimObject::Narrative("subject resides at A".into()),
        ))
        .unwrap();
    let support = ledger
        .insert_evidence(evidence("support", "root-support"))
        .unwrap();
    ledger.attach_support(&claim_id, &support).unwrap();

    let root_id = EvidenceNodeId::from("root-support-node");
    let mut graph = EvidenceAncestryGraph::default();
    graph
        .insert(EvidenceAncestryNode {
            id: root_id.clone(),
            source_family: "root-support".into(),
            parents: BTreeSet::new(),
            derived: false,
        })
        .unwrap();
    let bindings = BTreeMap::from([(support, root_id)]);

    assert_eq!(
        assess(&ledger, &claim_id, &graph, &bindings).epistemic,
        ClaimState::Verified
    );
    (ledger, claim_id, graph, bindings)
}

fn assess(
    ledger: &IntelligenceLedger,
    claim_id: &ClaimId,
    graph: &EvidenceAncestryGraph,
    bindings: &BTreeMap<EvidenceId, EvidenceNodeId>,
) -> ClaimAssessment {
    ledger
        .assess_claim_with_ancestry(claim_id, &policy(), graph, bindings)
        .unwrap()
}

#[test]
fn compatible_different_time_does_not_block_verification() {
    let (mut ledger, claim_id, graph, bindings) = verified_candidate();
    let other = ledger
        .insert_evidence(evidence("historical", "root-historical"))
        .unwrap();

    ledger
        .attach_defeat(
            &claim_id,
            Defeat {
                evidence_id: other,
                kind: DefeatKind::Compatible,
                temporal_overlap: Some(false),
                rationale: "different validity interval".into(),
            },
        )
        .unwrap();

    let assessment = assess(&ledger, &claim_id, &graph, &bindings);
    assert_eq!(assessment.epistemic, ClaimState::Verified);
    assert!(
        !assessment
            .blockers
            .contains(&VerificationBlocker::UndefeatedDefeater)
    );
}

#[test]
fn non_overlapping_rebuttal_does_not_block_verification() {
    let (mut ledger, claim_id, graph, bindings) = verified_candidate();
    let rebuttal = ledger
        .insert_evidence(evidence("historical-rebuttal", "root-historical"))
        .unwrap();

    ledger
        .attach_defeat(
            &claim_id,
            Defeat {
                evidence_id: rebuttal,
                kind: DefeatKind::Rebut,
                temporal_overlap: Some(false),
                rationale: "incompatible proposition in a non-overlapping interval".into(),
            },
        )
        .unwrap();

    let assessment = assess(&ledger, &claim_id, &graph, &bindings);
    assert_eq!(assessment.epistemic, ClaimState::Verified);
    assert!(
        !assessment
            .blockers
            .contains(&VerificationBlocker::UndefeatedDefeater)
    );
}

#[test]
fn rebuttal_blocks_verification_without_forcing_legacy_rejection() {
    let (mut ledger, claim_id, graph, bindings) = verified_candidate();
    let rebuttal = ledger
        .insert_evidence(evidence("rebuttal", "root-rebuttal"))
        .unwrap();

    ledger
        .attach_defeat(
            &claim_id,
            Defeat {
                evidence_id: rebuttal,
                kind: DefeatKind::Rebut,
                temporal_overlap: Some(true),
                rationale: "same time and mutually exclusive proposition".into(),
            },
        )
        .unwrap();

    let assessment = assess(&ledger, &claim_id, &graph, &bindings);
    assert_eq!(assessment.epistemic, ClaimState::Supported);
    assert!(
        assessment
            .blockers
            .contains(&VerificationBlocker::UndefeatedDefeater)
    );
    assert_ne!(ledger.claims[&claim_id].state, ClaimState::Rejected);
}

#[test]
fn unresolved_defeat_relation_blocks_verification_without_rejection() {
    let (mut ledger, claim_id, graph, bindings) = verified_candidate();
    let unresolved = ledger
        .insert_evidence(evidence("unresolved", "root-unresolved"))
        .unwrap();

    ledger
        .attach_defeat(
            &claim_id,
            Defeat {
                evidence_id: unresolved,
                kind: DefeatKind::UnknownRelation,
                temporal_overlap: None,
                rationale: "material conflict relationship is not yet resolved".into(),
            },
        )
        .unwrap();

    let assessment = assess(&ledger, &claim_id, &graph, &bindings);
    assert_eq!(assessment.epistemic, ClaimState::Supported);
    assert!(
        assessment
            .blockers
            .contains(&VerificationBlocker::UndefeatedDefeater)
    );
    assert_ne!(ledger.claims[&claim_id].state, ClaimState::Rejected);
}

#[test]
fn undercutter_blocks_reasoning_but_does_not_create_support_root() {
    let (mut ledger, claim_id, graph, bindings) = verified_candidate();
    let undercutter = ledger
        .insert_evidence(evidence("undercutter", "root-undercutter"))
        .unwrap();

    ledger
        .attach_defeat(
            &claim_id,
            Defeat {
                evidence_id: undercutter,
                kind: DefeatKind::Undercut,
                temporal_overlap: None,
                rationale: "parser mapping for supporting artifact is invalid".into(),
            },
        )
        .unwrap();

    let assessment = assess(&ledger, &claim_id, &graph, &bindings);
    assert_eq!(assessment.epistemic, ClaimState::Supported);
    assert_eq!(assessment.proven_roots, 1);
    assert!(
        assessment
            .blockers
            .contains(&VerificationBlocker::UndefeatedDefeater)
    );
}
