use std::collections::BTreeMap;

use huntsman_recon::benchmark::{
    ExpectedPublicFact, ForbiddenPublicFact, score_person_resolution_with_ancestry,
};
use huntsman_recon::collection::{
    CollectionEvent, ObservationBatch, RawObservation, UpstreamIndependenceAssertion, UpstreamOrigin,
};
use huntsman_recon::dependency::{Target, TargetKind};
use huntsman_recon::entity::EntityKind;
use huntsman_recon::evidence_ancestry::IndependenceBasis;
use huntsman_recon::retrieval_artifact::ArtifactId;
use huntsman_recon::pipeline::{PipelineLimits, normalize_observations};
use huntsman_recon::source_outcome::SourceOutcomeKind;

const SCAN_ID: &str = "person-resolution-fixture";

fn target() -> Target {
    Target::new(TargetKind::FullName, "Talia Bacot-Keating")
}

fn origin(provider: &str, dataset: &str, artifact: &str) -> UpstreamOrigin {
    UpstreamOrigin {
        provider: Some(provider.to_string()),
        dataset: Some(dataset.to_string()),
        artifact: Some(artifact.to_string()),
    }
}

fn observation(
    provider_id: &str,
    upstream: UpstreamOrigin,
    kind: EntityKind,
    value: &str,
    summary: &str,
) -> RawObservation {
    RawObservation {
        provider_id: provider_id.to_string(),
        upstream: Some(upstream),
        target: target(),
        kind,
        value: value.to_string(),
        summary: summary.to_string(),
        attributes: BTreeMap::new(),
        observed_at_unix: Some(1_700_000_000),
    }
}

fn event(provider_id: &str, upstream: UpstreamOrigin, finding_count: usize) -> CollectionEvent {
    CollectionEvent {
        scan_id: SCAN_ID.to_string(),
        provider_id: provider_id.to_string(),
        target: target(),
        outcome: SourceOutcomeKind::Success,
        finding_count,
        truncated: false,
        started_at_unix: 1_700_000_000,
        finished_at_unix: 1_700_000_001,
        credential_fingerprint: None,
        upstream: Some(upstream),
    }
}

fn expected(kind: EntityKind, value: &str, source: &str) -> ExpectedPublicFact {
    ExpectedPublicFact {
        entity_kind: kind,
        value: value.to_string(),
        source: source.to_string(),
    }
}

fn captured_public_fixture(include_wrong_identity: bool, include_independence_proof: bool) -> ObservationBatch {
    let profile = origin("public_profile", "professional_profile", "profile-capture");
    let project = origin("project_document", "nook_bess", "nook-project-document");

    let mut observations = vec![
        observation(
            "profile_collector",
            profile.clone(),
            EntityKind::Person,
            "Talia Bacot-Keating",
            "public professional identity",
        ),
        observation(
            "profile_collector",
            profile.clone(),
            EntityKind::Organisation,
            "Anza Power",
            "public professional organisation",
        ),
        observation(
            "project_collector",
            project.clone(),
            EntityKind::Person,
            "Talia Bacot-Keating",
            "named project professional",
        ),
        observation(
            "project_collector",
            project.clone(),
            EntityKind::Document,
            "Nook Battery Energy Storage System",
            "public project document",
        ),
    ];
    if include_wrong_identity {
        observations.push(observation(
            "other_record_collector",
            origin(
                "other_public_record",
                "unrelated_record",
                "unrelated-capture",
            ),
            EntityKind::Person,
            "Different Talia Bacot",
            "deliberately unrelated identity",
        ));
    }

    let independence_assertions = if include_independence_proof {
        vec![UpstreamIndependenceAssertion {
            left: profile.clone(),
            right: project.clone(),
            basis: IndependenceBasis::ExplicitUpstreamProvenance,
            method_id: "captured-fixture-upstream-provenance".to_string(),
            method_version: 1,
            supporting_artifact_ids: [
                ArtifactId::from("profile-capture"),
                ArtifactId::from("nook-project-document"),
            ]
            .into_iter()
            .collect(),
            observed_at_unix: 1_700_000_000,
        }]
    } else {
        Vec::new()
    };

    ObservationBatch {
        events: vec![
            event("profile_collector", profile, 2),
            event("project_collector", project, 2),
        ],
        observations,
        independence_assertions,
        truncated: false,
    }
}

#[test]
fn captured_public_observations_flow_through_real_pipeline_and_pass() {
    let snapshot =
        normalize_observations(captured_public_fixture(false, true), &PipelineLimits::default())
            .expect("captured fixture must normalize");
    let expected = vec![
        expected(
            EntityKind::Person,
            "Talia Bacot-Keating",
            "public_profile professional_profile",
        ),
        expected(
            EntityKind::Person,
            "Talia Bacot-Keating",
            "project_document nook_bess",
        ),
        expected(
            EntityKind::Organisation,
            "Anza Power",
            "public_profile professional_profile",
        ),
        expected(
            EntityKind::Document,
            "Nook Battery Energy Storage System",
            "project_document nook_bess",
        ),
    ];
    let forbidden = vec![ForbiddenPublicFact {
        entity_kind: EntityKind::Person,
        value: "Different Talia Bacot".to_string(),
    }];

    let score = score_person_resolution_with_ancestry(
        &snapshot.entities,
        &expected,
        &forbidden,
        Some(&snapshot.ancestry),
        2,
    );
    assert_eq!(
        snapshot.entities.len(),
        3,
        "duplicate person observations must merge by canonical UID"
    );
    assert!(
        snapshot.ancestry.len() >= 4,
        "two distinct source roots and relays must survive"
    );
    assert_eq!(score.expected_facts, 4);
    assert_eq!(score.matched_facts, 4);
    assert!(score.recall.is_complete());
    assert!(score.precision.is_complete());
    assert!(score.provenance_coverage.is_complete());
    assert_eq!(score.forbidden_facts_emitted, 0);
    assert_eq!(score.proven_independent_person_support, 2);
    assert!(score.independence_check_complete);
    assert!(score.accepted);
}

#[test]
fn real_pipeline_output_with_unrelated_identity_fails_closed() {
    let snapshot =
        normalize_observations(captured_public_fixture(true, false), &PipelineLimits::default())
            .expect("captured fixture must normalize");
    let expected = vec![
        expected(
            EntityKind::Person,
            "Talia Bacot-Keating",
            "public_profile professional_profile",
        ),
        expected(
            EntityKind::Organisation,
            "Anza Power",
            "public_profile professional_profile",
        ),
        expected(
            EntityKind::Document,
            "Nook Battery Energy Storage System",
            "project_document nook_bess",
        ),
    ];
    let forbidden = vec![ForbiddenPublicFact {
        entity_kind: EntityKind::Person,
        value: "Different Talia Bacot".to_string(),
    }];

    let score = score_person_resolution_with_ancestry(
        &snapshot.entities,
        &expected,
        &forbidden,
        Some(&snapshot.ancestry),
        2,
    );
    assert!(score.recall.is_complete(), "target recall remains perfect");
    assert!(
        score.provenance_coverage.is_complete(),
        "wrong identity also has real provenance"
    );
    assert!(!score.precision.is_complete());
    assert_eq!(score.unsupported_person_entities, 1);
    assert_eq!(score.forbidden_facts_emitted, 1);
    assert!(score.proven_independent_person_support < 2);
    assert!(!score.accepted);
}


#[test]
fn distinct_source_labels_without_independence_proof_fail_closed() {
    let snapshot =
        normalize_observations(captured_public_fixture(false, false), &PipelineLimits::default())
            .expect("captured fixture must normalize");
    let expected = vec![
        expected(
            EntityKind::Person,
            "Talia Bacot-Keating",
            "public_profile professional_profile",
        ),
        expected(
            EntityKind::Person,
            "Talia Bacot-Keating",
            "project_document nook_bess",
        ),
        expected(
            EntityKind::Organisation,
            "Anza Power",
            "public_profile professional_profile",
        ),
        expected(
            EntityKind::Document,
            "Nook Battery Energy Storage System",
            "project_document nook_bess",
        ),
    ];

    let score = score_person_resolution_with_ancestry(
        &snapshot.entities,
        &expected,
        &[],
        Some(&snapshot.ancestry),
        2,
    );

    assert!(score.recall.is_complete());
    assert!(score.precision.is_complete());
    assert!(score.provenance_coverage.is_complete());
    assert_eq!(score.proven_independent_person_support, 1);
    assert!(score.independence_check_complete);
    assert!(
        !score.accepted,
        "different source labels and disjoint roots are not proof of independence"
    );
}
