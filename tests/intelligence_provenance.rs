use std::collections::{BTreeMap, BTreeSet};

use huntsman_recon::intelligence::{
    Claim, ClaimId, ClaimObject, ClaimState, EvidenceId, EvidenceNature, EvidenceRecord,
    IntelligenceLedger, SourceAuthority, SourceLineage,
};

fn evidence(id: &str, source: &str, origin: Option<&str>, digest: &str) -> EvidenceRecord {
    EvidenceRecord {
        id: EvidenceId::from(id),
        subject_uid: "uid-1".to_string(),
        summary: format!("evidence-{id}"),
        lineage: SourceLineage {
            source_id: source.to_string(),
            origin_id: origin.map(str::to_string),
            chain: vec![source.to_string()],
            authority: SourceAuthority::Primary,
        },
        observed_at_unix: Some(1),
        recorded_at_unix: 2,
        nature: EvidenceNature::Observed,
        content_digest: Some(digest.to_string()),
        attributes: BTreeMap::new(),
        ancestry_root_families: BTreeSet::new(),
    }
}

fn claim(id: &str) -> Claim {
    Claim::new(
        ClaimId::from(id),
        "uid-1",
        ClaimObject::Attribute {
            key: "email".to_string(),
            value: "ada@example.com".to_string(),
        },
    )
}

#[test]
fn unknown_origin_does_not_create_independent_support() {
    let mut ledger = IntelligenceLedger::default();
    let claim_id = ClaimId::from("claim-unknown");
    ledger.insert_claim(claim("claim-unknown")).unwrap();

    let a = ledger
        .insert_evidence(evidence("ev-a", "provider-a", None, "digest-a"))
        .unwrap();
    let b = ledger
        .insert_evidence(evidence("ev-b", "provider-b", None, "digest-b"))
        .unwrap();

    ledger.attach_support(&claim_id, &a).unwrap();
    ledger.attach_support(&claim_id, &b).unwrap();

    assert_eq!(ledger.independent_source_count(&claim_id).unwrap(), 0);
    assert_eq!(ledger.claims[&claim_id].state, ClaimState::Candidate);
}

#[test]
fn mixed_known_and_unknown_support_preserves_only_proven_roots() {
    let mut ledger = IntelligenceLedger::default();
    let claim_id = ClaimId::from("claim-mixed");
    ledger.insert_claim(claim("claim-mixed")).unwrap();

    let known = ledger
        .insert_evidence(evidence(
            "ev-known",
            "provider-a",
            Some("artifact-root-a"),
            "digest-a",
        ))
        .unwrap();
    let unknown = ledger
        .insert_evidence(evidence("ev-unknown", "provider-b", None, "digest-b"))
        .unwrap();

    ledger.attach_support(&claim_id, &known).unwrap();
    ledger.attach_support(&claim_id, &unknown).unwrap();

    assert_eq!(ledger.independent_source_count(&claim_id).unwrap(), 1);
    assert_eq!(ledger.claims[&claim_id].state, ClaimState::Candidate);
}

#[test]
fn shared_known_origin_counts_once() {
    let mut ledger = IntelligenceLedger::default();
    let claim_id = ClaimId::from("claim-shared");
    ledger.insert_claim(claim("claim-shared")).unwrap();

    let a = ledger
        .insert_evidence(evidence(
            "ev-a",
            "provider-a",
            Some("shared-root"),
            "digest-a",
        ))
        .unwrap();
    let b = ledger
        .insert_evidence(evidence(
            "ev-b",
            "provider-b",
            Some("shared-root"),
            "digest-b",
        ))
        .unwrap();

    ledger.attach_support(&claim_id, &a).unwrap();
    ledger.attach_support(&claim_id, &b).unwrap();

    assert_eq!(ledger.independent_source_count(&claim_id).unwrap(), 1);
    assert_eq!(ledger.claims[&claim_id].state, ClaimState::Candidate);
}

#[test]
fn caller_confidence_cannot_verify_a_claim() {
    let mut ledger = IntelligenceLedger::default();
    let claim_id = ClaimId::from("claim-confidence");
    let mut target = claim("claim-confidence");
    target.confidence.conclusion = 1.0;
    ledger.insert_claim(target).unwrap();

    for (id, root) in [
        ("ev-a", "root-a"),
        ("ev-b", "root-b"),
        ("ev-c", "root-c"),
    ] {
        let evidence_id = ledger
            .insert_evidence(evidence(id, id, Some(root), id))
            .unwrap();
        ledger.attach_support(&claim_id, &evidence_id).unwrap();
    }

    assert_eq!(ledger.independent_source_count(&claim_id).unwrap(), 3);
    assert_eq!(ledger.claims[&claim_id].state, ClaimState::Supported);
}
