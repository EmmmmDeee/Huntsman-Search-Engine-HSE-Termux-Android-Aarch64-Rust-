//! The confidence gate on cross-scan bridges: an operator's seed bridges at the 0.25 it is given,
//! while a finding of the same value must reach 0.45. Both sides use the public API only.

use huntsman_recon::cross_scan::is_bridgeable;
use huntsman_recon::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};

/// The evidence a seed carries: the operator's query, not a source's finding. The role is the
/// wire value every scan writes, so this test pins it too.
fn seed_evidence() -> Evidence {
    Evidence::new(
        EvidenceProvenance::new("operator_input"),
        "operator-supplied investigation seed",
    )
    .with_attr("evidence_role", "seed_not_external_verification")
}

#[test]
fn an_operator_seed_bridges_at_the_confidence_it_was_given() {
    let mut seed = Entity::new(EntityKind::Email, "ada@example.com", 0.25, "analyze");
    seed.add_evidence(seed_evidence());

    assert!(is_bridgeable(&seed));
}

#[test]
fn a_low_confidence_finding_does_not_bridge() {
    let finding = Entity::new(EntityKind::Email, "ada@example.com", 0.25, "scan-now");

    assert!(!is_bridgeable(&finding));
}

#[test]
fn a_confident_finding_bridges() {
    let finding = Entity::new(EntityKind::Email, "ada@example.com", 0.9, "scan-now");

    assert!(is_bridgeable(&finding));
}
