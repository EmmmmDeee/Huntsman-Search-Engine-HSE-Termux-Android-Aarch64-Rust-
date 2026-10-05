use std::collections::{BTreeMap, BTreeSet};

use huntsman_recon::claim_policy::{VerificationBlocker, VerificationPolicy};
use huntsman_recon::evidence_ancestry::{
    EvidenceAncestryGraph, EvidenceAncestryNode, EvidenceNodeId,
};
use huntsman_recon::intelligence::{
    Claim, ClaimId, ClaimObject, ClaimState, EvidenceId, EvidenceNature, EvidenceRecord,
    IntelligenceLedger, SourceAuthority, SourceLineage,
};

fn policy() -> VerificationPolicy {
    VerificationPolicy {
        id: "identity.account.controlled_by:v2".into(),
        version: 2,
        min_proven_roots: 1,
        require_resolved_ancestry: true,
        required_natures: vec![EvidenceNature::Observed],
        required_attributes: BTreeMap::from([(
            "control".into(),
            BTreeSet::from(["confirmed".into()]),
        )]),
    }
}

fn assess(control: &str) -> huntsman_recon::claim_policy::ClaimAssessment {
    let claim_id = ClaimId::from("claim-control");
    let evidence_id = EvidenceId::from("profile-hit");
    let mut ledger = IntelligenceLedger::default();
    ledger
        .insert_claim(Claim::new(
            claim_id.clone(),
            "subject:1",
            ClaimObject::Relationship {
                relation: "controls_account".into(),
                target_uid: "profile:1".into(),
            },
        ))
        .unwrap();
    ledger
        .insert_evidence(EvidenceRecord {
            id: evidence_id.clone(),
            subject_uid: "subject:1".into(),
            summary: "username profile exists".into(),
            lineage: SourceLineage {
                source_id: "username_search".into(),
                origin_id: Some("profile-page".into()),
                chain: Vec::new(),
                authority: SourceAuthority::Primary,
            },
            observed_at_unix: Some(1),
            recorded_at_unix: 2,
            nature: EvidenceNature::Observed,
            content_digest: Some("sha256:profile".into()),
            attributes: BTreeMap::from([
                ("detection".into(), "body-marker".into()),
                ("control".into(), control.into()),
            ]),
            ancestry_root_families: BTreeSet::new(),
        })
        .unwrap();
    ledger.attach_support(&claim_id, &evidence_id).unwrap();

    let mut graph = EvidenceAncestryGraph::default();
    graph
        .insert(EvidenceAncestryNode {
            id: EvidenceNodeId::from("profile-root"),
            source_family: "profile-page".into(),
            parents: BTreeSet::new(),
            derived: false,
        })
        .unwrap();
    let bindings = BTreeMap::from([(evidence_id, EvidenceNodeId::from("profile-root"))]);

    ledger
        .assess_claim_with_ancestry(&claim_id, &policy(), &graph, &bindings)
        .unwrap()
}

#[test]
fn profile_existence_with_control_absent_cannot_verify_ownership() {
    let assessment = assess("absent");
    assert_eq!(assessment.epistemic, ClaimState::Supported);
    assert!(
        assessment
            .blockers
            .contains(&VerificationBlocker::MissingRequiredEvidenceAttribute)
    );
}

#[test]
fn explicit_control_evidence_can_verify_single_route_ownership_policy() {
    let assessment = assess("confirmed");
    assert_eq!(assessment.epistemic, ClaimState::Verified);
    assert!(assessment.blockers.is_empty());
}
