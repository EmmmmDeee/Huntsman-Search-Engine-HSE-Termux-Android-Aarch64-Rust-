use std::collections::{BTreeMap, BTreeSet};

use huntsman_recon::claim_policy::{VerificationBlocker, VerificationPolicy};
use huntsman_recon::intelligence::{
    Claim, ClaimId, ClaimObject, ClaimState, EvidenceId, EvidenceNature, EvidenceRecord,
    IntelligenceLedger, SourceAuthority, SourceLineage,
};

fn evidence(id: &str, origin: Option<&str>, nature: EvidenceNature) -> EvidenceRecord {
    EvidenceRecord {
        id: EvidenceId::from(id),
        subject_uid: "uid-1".into(),
        summary: format!("evidence-{id}"),
        lineage: SourceLineage {
            source_id: format!("provider-{id}"),
            origin_id: origin.map(str::to_string),
            chain: Vec::new(),
            authority: SourceAuthority::Primary,
        },
        observed_at_unix: Some(1),
        recorded_at_unix: 2,
        nature,
        content_digest: Some(format!("digest-{id}")),
        attributes: BTreeMap::new(),
        ancestry_root_families: BTreeSet::new(),
    }
}

fn ledger_with_claim(id: &str) -> (IntelligenceLedger, ClaimId) {
    let mut ledger = IntelligenceLedger::default();
    let claim_id = ClaimId::from(id);
    let mut claim = Claim::new(
        claim_id.clone(),
        "uid-1",
        ClaimObject::Narrative("subject controls account".into()),
    );
    claim.confidence.conclusion = 1.0;
    ledger.insert_claim(claim).unwrap();
    (ledger, claim_id)
}

fn observed_policy(min_proven_roots: usize, require_resolved_ancestry: bool) -> VerificationPolicy {
    VerificationPolicy {
        id: "identity.account.controlled_by:v1".into(),
        version: 1,
        min_proven_roots,
        require_resolved_ancestry,
        required_natures: vec![EvidenceNature::Observed],
    }
}

#[test]
fn confidence_and_provider_volume_cannot_replace_required_observation() {
    let (mut ledger, claim_id) = ledger_with_claim("claim-provider-only");
    for id in ["a", "b", "c"] {
        let evidence_id = ledger
            .insert_evidence(evidence(id, Some(id), EvidenceNature::Provider))
            .unwrap();
        ledger.attach_support(&claim_id, &evidence_id).unwrap();
    }

    let assessment = ledger
        .assess_claim(&claim_id, &observed_policy(3, true))
        .unwrap();

    assert_eq!(assessment.epistemic, ClaimState::Supported);
    assert!(
        assessment
            .blockers
            .contains(&VerificationBlocker::MissingRequiredEvidenceNature)
    );
    assert_eq!(assessment.proven_roots, 3);
}

#[test]
fn flat_lineage_compatibility_path_cannot_verify_without_canonical_ancestry() {
    let (mut ledger, claim_id) = ledger_with_claim("claim-direct");
    let evidence_id = ledger
        .insert_evidence(evidence(
            "direct",
            Some("primary-artifact"),
            EvidenceNature::Observed,
        ))
        .unwrap();
    ledger.attach_support(&claim_id, &evidence_id).unwrap();

    let assessment = ledger
        .assess_claim(&claim_id, &observed_policy(1, true))
        .unwrap();

    assert_eq!(assessment.epistemic, ClaimState::Supported);
    assert!(
        assessment
            .blockers
            .contains(&VerificationBlocker::CanonicalAncestryRequired)
    );
    assert_eq!(assessment.proven_roots, 1);
    assert_eq!(assessment.unresolved_support, 0);
}

#[test]
fn unresolved_ancestry_blocks_a_policy_that_requires_resolution() {
    let (mut ledger, claim_id) = ledger_with_claim("claim-unknown");
    let evidence_id = ledger
        .insert_evidence(evidence("unknown", None, EvidenceNature::Observed))
        .unwrap();
    ledger.attach_support(&claim_id, &evidence_id).unwrap();

    let assessment = ledger
        .assess_claim(&claim_id, &observed_policy(1, true))
        .unwrap();

    assert_ne!(assessment.epistemic, ClaimState::Verified);
    assert!(
        assessment
            .blockers
            .contains(&VerificationBlocker::UnknownAncestry)
    );
    assert!(
        assessment
            .blockers
            .contains(&VerificationBlocker::InsufficientIndependentSupport)
    );
    assert!(
        assessment
            .blockers
            .contains(&VerificationBlocker::CanonicalAncestryRequired)
    );
    assert_eq!(assessment.proven_roots, 0);
    assert_eq!(assessment.unresolved_support, 1);
}
