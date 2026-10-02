use std::collections::{BTreeMap, BTreeSet};

use huntsman_recon::intelligence::{
    Claim, ClaimId, ClaimObject, ClaimState, EvidenceId, EvidenceNature, EvidenceRecord,
    IntelligenceLedger, SourceAuthority, SourceLineage,
};

fn evidence(id: &str, provider: &str, digest: &str, root_families: &[&str]) -> EvidenceRecord {
    EvidenceRecord {
        id: EvidenceId::from(id),
        subject_uid: "subject".into(),
        summary: format!("observation from {provider}"),
        lineage: SourceLineage {
            source_id: provider.into(),
            origin_id: Some(provider.into()),
            chain: vec![provider.into()],
            authority: SourceAuthority::Secondary,
        },
        observed_at_unix: Some(1),
        recorded_at_unix: 2,
        nature: EvidenceNature::Observed,
        content_digest: Some(digest.into()),
        attributes: BTreeMap::new(),
        ancestry_root_families: root_families
            .iter()
            .map(|root| (*root).to_owned())
            .collect::<BTreeSet<_>>(),
    }
}

#[test]
fn redistributed_artifacts_with_shared_root_are_one_witness() {
    let mut ledger = IntelligenceLedger::default();
    let claim_id = ClaimId::from("claim");
    ledger
        .insert_claim(Claim::new(
            claim_id.clone(),
            "subject",
            ClaimObject::Narrative("same underlying assertion".into()),
        ))
        .expect("claim");

    let mirror_a = ledger
        .insert_evidence(evidence(
            "mirror-a",
            "provider-a",
            "digest-a",
            &["breach-dump-2025"],
        ))
        .expect("mirror a");
    let mirror_b = ledger
        .insert_evidence(evidence(
            "mirror-b",
            "provider-b",
            "digest-b",
            &["breach-dump-2025"],
        ))
        .expect("mirror b");

    ledger
        .attach_support(&claim_id, &mirror_a)
        .expect("attach a");
    ledger
        .attach_support(&claim_id, &mirror_b)
        .expect("attach b");

    assert_eq!(ledger.independent_source_count(&claim_id), Ok(1));
    assert_eq!(ledger.claims[&claim_id].state, ClaimState::Candidate);
}

#[test]
fn genuinely_distinct_ancestry_root_adds_independent_support() {
    let mut ledger = IntelligenceLedger::default();
    let claim_id = ClaimId::from("claim");
    ledger
        .insert_claim(Claim::new(
            claim_id.clone(),
            "subject",
            ClaimObject::Narrative("corroborated assertion".into()),
        ))
        .expect("claim");

    let mirror_a = ledger
        .insert_evidence(evidence(
            "mirror-a",
            "provider-a",
            "digest-a",
            &["breach-dump-2025"],
        ))
        .expect("mirror a");
    let mirror_b = ledger
        .insert_evidence(evidence(
            "mirror-b",
            "provider-b",
            "digest-b",
            &["breach-dump-2025"],
        ))
        .expect("mirror b");
    let registry = ledger
        .insert_evidence(evidence(
            "registry",
            "primary-registry",
            "digest-c",
            &["official-registry"],
        ))
        .expect("registry");

    for evidence_id in [&mirror_a, &mirror_b, &registry] {
        ledger
            .attach_support(&claim_id, evidence_id)
            .expect("attach support");
    }

    assert_eq!(ledger.independent_source_count(&claim_id), Ok(2));
    assert_eq!(ledger.claims[&claim_id].state, ClaimState::Supported);
}
