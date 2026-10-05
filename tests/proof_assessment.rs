use std::collections::BTreeSet;

use huntsman_recon::claim_policy::{ClaimAssessment, VerificationBlocker};
use huntsman_recon::intelligence::{ClaimState, EvidenceId};
use huntsman_recon::proof::{MinimalProofEnvironment, ProofEnvironmentSet};

fn verified() -> ClaimAssessment {
    ClaimAssessment {
        epistemic: ClaimState::Verified,
        blockers: BTreeSet::new(),
        proven_roots: 1,
        distinct_resolved_roots: 1,
        independence_incomplete: false,
        unresolved_support: 0,
        proof_environment_count: 0,
        proof_incomplete: false,
    }
}

fn one_environment() -> MinimalProofEnvironment {
    MinimalProofEnvironment {
        assertions: BTreeSet::from([EvidenceId::from("evidence-a")]),
        roots: BTreeSet::from(["root-a".to_owned()]),
        ..MinimalProofEnvironment::default()
    }
}

#[test]
fn incomplete_proof_enumeration_can_never_leave_a_claim_verified() {
    let proof = ProofEnvironmentSet {
        environments: vec![one_environment()],
        incomplete: true,
    };

    let assessment = verified().with_proof_environments(&proof);

    assert_eq!(assessment.epistemic, ClaimState::Supported);
    assert!(assessment.proof_incomplete);
    assert_eq!(assessment.proof_environment_count, 1);
    assert!(
        assessment
            .blockers
            .contains(&VerificationBlocker::IncompleteProof)
    );
}

#[test]
fn missing_proof_environment_cannot_leave_a_claim_verified() {
    let assessment = verified().with_proof_environments(&ProofEnvironmentSet::default());

    assert_eq!(assessment.epistemic, ClaimState::Supported);
    assert!(
        assessment
            .blockers
            .contains(&VerificationBlocker::MissingProofEnvironment)
    );
}

#[test]
fn complete_nonempty_proof_preserves_an_otherwise_verified_assessment() {
    let proof = ProofEnvironmentSet {
        environments: vec![one_environment()],
        incomplete: false,
    };

    let assessment = verified().with_proof_environments(&proof);

    assert_eq!(assessment.epistemic, ClaimState::Verified);
    assert!(!assessment.proof_incomplete);
    assert_eq!(assessment.proof_environment_count, 1);
    assert!(assessment.blockers.is_empty());
}
