use std::collections::BTreeMap;

use huntsman_recon::collection::{
    CollectionEvent, ObservationBatch, RawObservation, UpstreamOrigin,
};
use huntsman_recon::dependency::{Target, TargetKind};
use huntsman_recon::entity::EntityKind;
use huntsman_recon::pipeline::{
    InvestigationInput, InvestigationMode, NormalizedSeed, PipelineLimits, SeedRejection,
    normalize_observations, normalize_seeds,
};
use huntsman_recon::source_outcome::SourceOutcomeKind;

fn input(seeds: &[&str]) -> InvestigationInput {
    InvestigationInput {
        scan_id: "scan-test".to_string(),
        seeds: seeds.iter().map(|s| (*s).to_string()).collect(),
        mode: InvestigationMode::Offline,
    }
}

fn observation(
    collector: &str,
    upstream: Option<UpstreamOrigin>,
    kind: EntityKind,
    value: &str,
) -> RawObservation {
    RawObservation {
        provider_id: collector.to_string(),
        upstream,
        target: Target::new(TargetKind::Email, "ada@example.com"),
        kind,
        value: value.to_string(),
        summary: "fixture observation".to_string(),
        attributes: BTreeMap::new(),
        observed_at_unix: Some(10),
    }
}

fn batch(observations: Vec<RawObservation>) -> ObservationBatch {
    ObservationBatch {
        events: vec![CollectionEvent {
            scan_id: "scan-test".to_string(),
            provider_id: "seeknow".to_string(),
            target: Target::new(TargetKind::Email, "ada@example.com"),
            outcome: SourceOutcomeKind::Success,
            finding_count: observations.len(),
            truncated: false,
            started_at_unix: 9,
            finished_at_unix: 10,
            credential_fingerprint: None,
            upstream: None,
        }],
        observations,
        independence_assertions: Vec::new(),
        truncated: false,
    }
}

fn origin(provider: &str, dataset: &str) -> UpstreamOrigin {
    UpstreamOrigin {
        provider: Some(provider.to_string()),
        dataset: Some(dataset.to_string()),
        artifact: None,
    }
}

#[test]
fn normalize_seeds_is_deterministic_and_bounded() {
    let limits = PipelineLimits {
        max_targets: 2,
        ..PipelineLimits::default()
    };
    let result = normalize_seeds(
        &input(&["Example.COM", "ada@example.com", "8.8.8.8"]),
        &limits,
    );
    assert_eq!(result.accepted.len(), 2);
    assert!(result.truncated);
    assert_eq!(result.accepted[0].kind, EntityKind::Email);
    assert_eq!(result.accepted[0].value, "ada@example.com");
    assert_eq!(result.accepted[1].kind, EntityKind::Domain);
    assert_eq!(result.accepted[1].value, "example.com");
}

#[test]
fn malformed_and_empty_seeds_are_explicit_rejections() {
    let result = normalize_seeds(
        &input(&["", "   ", "not-a-supported-single-token"]),
        &PipelineLimits::default(),
    );
    assert_eq!(result.accepted, Vec::<NormalizedSeed>::new());
    assert_eq!(result.rejected.len(), 3);
    assert!(matches!(&result.rejected[0].1, SeedRejection::Empty));
    assert!(matches!(&result.rejected[1].1, SeedRejection::Empty));
    assert!(matches!(&result.rejected[2].1, SeedRejection::Unsupported));
}

#[test]
fn unicode_confusable_or_whitespace_only_seed_never_panics() {
    let result = normalize_seeds(
        &input(&["\u{2003}\u{2003}", "ｅxample.com", "@аda"]),
        &PipelineLimits::default(),
    );
    assert_eq!(result.accepted.len() + result.rejected.len(), 3);
}

#[test]
fn duplicate_canonical_seeds_are_deduplicated() {
    let result = normalize_seeds(
        &input(&[
            "Example.COM",
            "example.com.",
            "ADA@EXAMPLE.COM",
            "ada@example.com",
        ]),
        &PipelineLimits::default(),
    );
    assert_eq!(result.accepted.len(), 2);
    assert_eq!(result.accepted[0].kind, EntityKind::Email);
    assert_eq!(result.accepted[0].value, "ada@example.com");
    assert_eq!(result.accepted[1].kind, EntityKind::Domain);
    assert_eq!(result.accepted[1].value, "example.com");
    assert!(!result.truncated);
}

#[test]
fn two_collectors_one_upstream_root_count_once() {
    let snapshot = normalize_observations(
        batch(vec![
            observation(
                "seeknow",
                Some(origin("oathnet", "adobe-2013")),
                EntityKind::Email,
                "ADA@example.com",
            ),
            observation(
                "gateway-b",
                Some(origin("oathnet", "adobe-2013")),
                EntityKind::Email,
                "ada@example.com",
            ),
        ]),
        &PipelineLimits::default(),
    )
    .expect("snapshot");
    assert_eq!(snapshot.entities.len(), 1);
    let entity = &snapshot.entities[0];
    assert_eq!(entity.source_count(), 1);
    let support = entity
        .evidence
        .iter()
        .filter_map(|evidence| evidence.ancestry_node.as_ref())
        .collect::<Vec<_>>();
    assert_eq!(
        snapshot
            .ancestry
            .independent_support_count(support)
            .expect("ancestry"),
        1
    );
}

#[test]
fn independent_upstream_roots_can_raise_corroboration() {
    let snapshot = normalize_observations(
        batch(vec![
            observation(
                "seeknow",
                Some(origin("oathnet", "adobe-2013")),
                EntityKind::Email,
                "ada@example.com",
            ),
            observation(
                "registry",
                Some(origin("company-registry", "asic")),
                EntityKind::Email,
                "ada@example.com",
            ),
        ]),
        &PipelineLimits::default(),
    )
    .expect("snapshot");
    let entity = &snapshot.entities[0];
    assert_eq!(entity.source_count(), 2);
    let support = entity
        .evidence
        .iter()
        .filter_map(|evidence| evidence.ancestry_node.as_ref())
        .collect::<Vec<_>>();
    assert_eq!(
        snapshot
            .ancestry
            .independent_support_count(support)
            .expect("ancestry"),
        2
    );
}

#[test]
fn missing_upstream_origin_stays_unknown_not_independent() {
    let snapshot = normalize_observations(
        batch(vec![
            observation("relay-a", None, EntityKind::Email, "ada@example.com"),
            observation("relay-b", None, EntityKind::Email, "ada@example.com"),
        ]),
        &PipelineLimits::default(),
    )
    .expect("snapshot");
    let entity = &snapshot.entities[0];
    assert_eq!(entity.source_count(), 1);
}

#[test]
fn observation_normalization_wires_structural_relations() {
    let snapshot = normalize_observations(
        batch(vec![
            observation(
                "registry",
                Some(origin("registry", "domain")),
                EntityKind::Domain,
                "example.com",
            ),
            observation(
                "registry",
                Some(origin("registry", "email")),
                EntityKind::Email,
                "ada@example.com",
            ),
        ]),
        &PipelineLimits::default(),
    )
    .expect("snapshot");
    assert!(snapshot.relations.iter().any(|relation| {
        relation.from_uid != relation.to_uid
            && relation.kind == huntsman_recon::graph::RelationKind::AssociatedWith
    }));
}
