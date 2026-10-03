use huntsman_recon::entity::{Evidence, EvidenceProvenance};
use huntsman_recon::evidence_ancestry::EvidenceNodeId;
use huntsman_recon::identity_resolution::{
    AutoMergePolicy, HoldReason, IdentityResolutionDecision, ResolutionState,
};
use huntsman_recon::lineage::{MergeOutcome, Observation, resolve_with_lineage};

fn observation(id: &str, collector: &str, attrs: &[(&str, &str)]) -> Observation {
    Observation {
        id: id.into(),
        evidence: attrs.iter().fold(
            Evidence::new(EvidenceProvenance::new(collector), format!("record {id}")),
            |e, (k, v)| e.with_attr(*k, *v),
        ),
    }
}

fn candidate(support: &[&str]) -> IdentityResolutionDecision {
    IdentityResolutionDecision {
        left_entity_uid: "email:jane@example.com".into(),
        right_entity_uid: "username:janecitizen".into(),
        state: ResolutionState::Match,
        probability: Some(0.95),
        supporting: support.iter().copied().map(EvidenceNodeId::from).collect(),
        contradicting: vec![],
        temporal_conflict: false,
        geographic_conflict: false,
        decided_at_unix: 1_790_000_000,
    }
}

fn resolve(observations: Vec<Observation>) -> huntsman_recon::lineage::CandidateOutcome {
    let ids: Vec<&str> = observations.iter().map(|o| o.id.0.as_str()).collect();
    let decision = candidate(&ids);
    let mut result =
        resolve_with_lineage(observations, vec![decision], AutoMergePolicy::default()).unwrap();
    result.candidates.remove(0)
}

fn assert_held_for_family_count(out: &huntsman_recon::lineage::CandidateOutcome, found: usize) {
    assert_eq!(out.independent_families.len(), found);
    assert!(
        matches!(
            &out.outcome,
            MergeOutcome::Held { reasons }
                if reasons.iter().any(|reason| matches!(
                    reason,
                    HoldReason::InsufficientIndependentFamilies { found: actual, required: 2 }
                        if *actual == found
                ))
        ),
        "unexpected outcome: {:?}",
        out.outcome
    );
}

#[test]
fn record_urls_cannot_mint_independent_families() {
    for pair in [
        ["https://paste.example/a", "https://paste.example/b"],
        ["http://paste.example/a", "https://paste.example/a"],
        ["https://www.paste.example/a", "https://paste.example/a"],
        ["https://paste.example/a/", "https://paste.example/a"],
    ] {
        let out = resolve(vec![
            observation("row-1", "paste_collector", &[("source_url", pair[0])]),
            observation("row-2", "paste_collector", &[("source_url", pair[1])]),
        ]);
        assert_held_for_family_count(&out, 0);
    }
}

#[test]
fn record_ids_cannot_mint_independent_families() {
    let out = resolve(vec![
        observation("row-1", "dump_collector", &[("source_id", "row-1")]),
        observation("row-2", "dump_collector", &[("source_id", "row-2")]),
    ]);
    assert_held_for_family_count(&out, 0);
}

#[test]
fn registry_field_without_verified_source_class_does_not_create_corroboration() {
    let out = resolve(vec![
        observation("hibp-1", "hibp", &[("breach", "Adobe")]),
        observation("hibp-2", "hibp", &[("registry", "company registry")]),
    ]);
    assert_held_for_family_count(&out, 1);
    assert_eq!(out.independent_families, ["adobe"]);
}

#[test]
fn verified_registry_origin_can_corroborate_a_dataset() {
    let out = resolve(vec![
        observation("dump-1", "hibp", &[("breach", "Adobe")]),
        observation("registry-1", "abn_lookup", &[("registry", "ABR")]),
    ]);
    assert_eq!(out.independent_families, ["abr", "adobe"]);
    assert_eq!(out.outcome, MergeOutcome::AutoMerge);
}

#[test]
fn two_explicit_datasets_from_one_collector_remain_independent() {
    let out = resolve(vec![
        observation("dump-1", "dehashed", &[("dbname", "Adobe")]),
        observation("dump-2", "dehashed", &[("dbname", "LinkedIn")]),
    ]);
    assert_eq!(out.independent_families, ["adobe", "linkedin"]);
    assert_eq!(out.outcome, MergeOutcome::AutoMerge);
}
