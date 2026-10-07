use std::collections::BTreeMap;

use huntsman_recon::collection::{
    CollectionEvent, ObservationBatch, RawObservation, UpstreamOrigin, bounded_batch,
    coverage_events,
};
use huntsman_recon::coverage::{EventKind, ProviderOutcome, provider_coverage_from_events};
use huntsman_recon::dependency::{Target, TargetKind};
use huntsman_recon::entity::EntityKind;
use huntsman_recon::pipeline::PipelineLimits;
use huntsman_recon::source_outcome::SourceOutcomeKind;

fn target() -> Target {
    Target::new(TargetKind::Email, "ada@example.com")
}

fn event(kind: SourceOutcomeKind, findings: usize, truncated: bool) -> CollectionEvent {
    CollectionEvent {
        scan_id: "scan".to_string(),
        provider_id: "provider".to_string(),
        target: target(),
        outcome: kind,
        finding_count: findings,
        truncated,
        started_at_unix: 10,
        finished_at_unix: 11,
        credential_fingerprint: None,
        upstream: None,
    }
}

#[test]
fn failed_timeout_waf_and_auth_required_are_not_clean_negative() {
    for kind in [
        SourceOutcomeKind::TtfbTimeout,
        SourceOutcomeKind::BotWaf,
        SourceOutcomeKind::AuthRequired,
        SourceOutcomeKind::RateLimited,
        SourceOutcomeKind::Inconclusive,
    ] {
        let batch = ObservationBatch {
            events: vec![event(kind, 0, false)],
            observations: vec![],
            independence_assertions: Vec::new(),
            truncated: false,
        };
        let rows = provider_coverage_from_events(&coverage_events(&batch));
        assert_eq!(rows.len(), 1);
        assert!(!matches!(rows[0].outcome, ProviderOutcome::CleanNegative));
    }
}

#[test]
fn valid_zero_is_clean_negative_only_when_not_truncated() {
    let complete = ObservationBatch {
        events: vec![event(SourceOutcomeKind::ValidZero, 0, false)],
        observations: vec![],
        independence_assertions: Vec::new(),
        truncated: false,
    };
    let rows = provider_coverage_from_events(&coverage_events(&complete));
    assert!(matches!(rows[0].outcome, ProviderOutcome::CleanNegative));

    let incomplete = ObservationBatch {
        events: vec![event(SourceOutcomeKind::ValidZero, 0, true)],
        observations: vec![],
        independence_assertions: Vec::new(),
        truncated: true,
    };
    let rows = provider_coverage_from_events(&coverage_events(&incomplete));
    assert!(!matches!(rows[0].outcome, ProviderOutcome::CleanNegative));
}

#[test]
fn upstream_origin_survives_collection_bridge() {
    let origin = UpstreamOrigin {
        provider: Some("oathnet".to_string()),
        dataset: Some("adobe-2013".to_string()),
        artifact: Some("row-42".to_string()),
    };
    let batch = ObservationBatch {
        events: vec![],
        observations: vec![RawObservation {
            provider_id: "seeknow".to_string(),
            upstream: Some(origin.clone()),
            target: target(),
            kind: EntityKind::Email,
            value: "ADA@EXAMPLE.COM".to_string(),
            summary: "observed in upstream breach record".to_string(),
            attributes: BTreeMap::new(),
            observed_at_unix: Some(10),
        }],
        independence_assertions: Vec::new(),
        truncated: false,
    };
    assert_eq!(batch.observations[0].upstream.as_ref(), Some(&origin));
}

#[test]
fn coverage_conversion_is_deterministic() {
    let batch = ObservationBatch {
        events: vec![
            event(SourceOutcomeKind::Success, 2, false),
            event(SourceOutcomeKind::ValidZero, 0, false),
        ],
        observations: vec![],
        independence_assertions: Vec::new(),
        truncated: false,
    };
    assert_eq!(coverage_events(&batch), coverage_events(&batch));
    assert!(matches!(
        coverage_events(&batch)[0].kind,
        EventKind::ModuleDone { .. }
    ));
}

#[test]
fn huge_observation_batch_is_capped_without_false_completeness() {
    let mut observations = Vec::new();
    for index in 0..8 {
        observations.push(RawObservation {
            provider_id: "provider".to_string(),
            upstream: None,
            target: target(),
            kind: EntityKind::Email,
            value: format!("user{index}@example.com"),
            summary: "fixture".to_string(),
            attributes: BTreeMap::new(),
            observed_at_unix: Some(10),
        });
    }
    let limits = PipelineLimits {
        max_entities: 3,
        ..PipelineLimits::default()
    };
    let bounded = bounded_batch(
        ObservationBatch {
            events: vec![event(SourceOutcomeKind::Success, 8, false)],
            observations,
            independence_assertions: Vec::new(),
            truncated: false,
        },
        &limits,
    );
    assert_eq!(bounded.observations.len(), 3);
    assert!(bounded.truncated);
    assert!(bounded.events[0].truncated);
}
