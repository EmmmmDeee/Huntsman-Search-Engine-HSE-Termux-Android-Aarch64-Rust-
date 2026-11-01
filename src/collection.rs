//! Provider-neutral collection envelopes between execution and evidence analysis.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::coverage::{Event, EventKind};
use crate::dependency::Target;
use crate::entity::EntityKind;
use crate::evidence_ancestry::IndependenceBasis;
use crate::pipeline_limits::PipelineLimits;
use crate::retrieval_artifact::ArtifactId;
use crate::source_outcome::SourceOutcomeKind;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamOrigin {
    pub provider: Option<String>,
    pub dataset: Option<String>,
    pub artifact: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionEvent {
    pub scan_id: String,
    pub provider_id: String,
    pub target: Target,
    pub outcome: SourceOutcomeKind,
    pub finding_count: usize,
    pub truncated: bool,
    pub started_at_unix: u64,
    pub finished_at_unix: u64,
    pub credential_fingerprint: Option<String>,
    pub upstream: Option<UpstreamOrigin>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawObservation {
    pub provider_id: String,
    pub upstream: Option<UpstreamOrigin>,
    pub target: Target,
    pub kind: EntityKind,
    pub value: String,
    pub summary: String,
    pub attributes: BTreeMap<String, String>,
    pub observed_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamIndependenceAssertion {
    pub left: UpstreamOrigin,
    pub right: UpstreamOrigin,
    pub basis: IndependenceBasis,
    pub method_id: String,
    pub method_version: u32,
    pub supporting_artifact_ids: Vec<ArtifactId>,
    pub observed_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationBatch {
    pub events: Vec<CollectionEvent>,
    pub observations: Vec<RawObservation>,
    #[serde(default)]
    pub independence_assertions: Vec<UpstreamIndependenceAssertion>,
    pub truncated: bool,
}

#[must_use]
pub fn bounded_batch(mut batch: ObservationBatch, limits: &PipelineLimits) -> ObservationBatch {
    let original_observation_count = batch.observations.len();
    let overflow = batch.observations.len() > limits.max_entities
        || batch.events.len() > limits.max_dispatches;

    // A batch-wide limit does not imply every retained provider was incomplete.
    // Attribute omitted findings only to their originating provider and target.
    // Raw observations have no scan_id, so matching provider/target pairs in
    // different scans are conservatively treated as sharing the truncation.
    let dropped_sources: BTreeSet<_> = batch
        .observations
        .iter()
        .skip(limits.max_entities)
        .map(|observation| {
            (
                observation.provider_id.as_str(),
                observation.target.kind,
                observation.target.value.as_str(),
            )
        })
        .collect();
    for event in batch.events.iter_mut().take(limits.max_dispatches) {
        if dropped_sources.contains(&(
            event.provider_id.as_str(),
            event.target.kind,
            event.target.value.as_str(),
        )) {
            event.truncated = true;
        }
    }
    batch.observations.truncate(limits.max_entities);
    batch.events.truncate(limits.max_dispatches);

    // A retained observation must have a retained execution receipt. Otherwise
    // the evidence pipeline could consume findings from a provider whose outcome
    // disappeared when the dispatch budget was enforced. Raw observations do not
    // carry scan IDs, so match conservatively by provider and target.
    let retained_sources: BTreeSet<_> = batch
        .events
        .iter()
        .map(|event| {
            (
                event.provider_id.as_str(),
                event.target.kind,
                event.target.value.as_str(),
            )
        })
        .collect();
    // Where the execution receipt declares an upstream origin, require an
    // observation with declared provenance to match it. Provider/target alone
    // cannot distinguish two executions of the same source.
    let mut retained_origins: BTreeMap<_, Vec<&UpstreamOrigin>> = BTreeMap::new();
    let mut unprovenanced_sources = BTreeSet::new();
    for event in &batch.events {
        if let Some(origin) = event.upstream.as_ref() {
            retained_origins
                .entry((
                    event.provider_id.as_str(),
                    event.target.kind,
                    event.target.value.as_str(),
                ))
                .or_default()
                .push(origin);
        } else {
            unprovenanced_sources.insert((
                event.provider_id.as_str(),
                event.target.kind,
                event.target.value.as_str(),
            ));
        }
    }
    let before = batch.observations.len();
    batch.observations.retain(|observation| {
        let key = (
            observation.provider_id.as_str(),
            observation.target.kind,
            observation.target.value.as_str(),
        );
        retained_sources.contains(&key)
            && match observation.upstream.as_ref() {
                Some(origin) => retained_origins
                    .get(&key)
                    .is_none_or(|origins| origins.contains(&origin)),
                // An attributed execution receipt must not authorise evidence
                // that omits the provenance necessary to identify its source.
                None => unprovenanced_sources.contains(&key),
            }
    });
    if batch.observations.len() < original_observation_count {
        // An independence assertion cannot survive the removal of the
        // observations establishing either upstream root. Exact provenance
        // matching is conservative: never invent an equivalence between origins.
        let retained_origins: Vec<_> = batch
            .observations
            .iter()
            .filter_map(|observation| observation.upstream.as_ref())
            .collect();
        batch.independence_assertions.retain(|assertion| {
            retained_origins.contains(&&assertion.left)
                && retained_origins.contains(&&assertion.right)
        });
    }
    batch.truncated |= batch.observations.len() != before;
    batch.truncated |= overflow;
    batch
}

fn unresolved_reason(event: &CollectionEvent) -> String {
    if event.truncated {
        return format!(
            "truncated provider execution after {} findings",
            event.finding_count
        );
    }
    format!("provider execution outcome: {:?}", event.outcome)
}

#[must_use]
pub fn coverage_events(batch: &ObservationBatch) -> Vec<Event> {
    batch
        .events
        .iter()
        .map(|event| {
            let kind = match event.outcome {
                SourceOutcomeKind::Success if !event.truncated => EventKind::ModuleDone {
                    module: event.provider_id.clone(),
                    found: event.finding_count,
                },
                SourceOutcomeKind::ValidZero if !event.truncated => EventKind::ModuleDone {
                    module: event.provider_id.clone(),
                    found: 0,
                },
                _ => EventKind::ModuleError {
                    module: event.provider_id.clone(),
                    error: unresolved_reason(event),
                },
            };
            Event {
                scan_id: event.scan_id.clone(),
                ts: event.finished_at_unix,
                kind,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dependency::TargetKind;

    fn target(value: &str) -> Target {
        Target::new(TargetKind::Domain, value)
    }

    fn event(provider: &str, value: &str) -> CollectionEvent {
        CollectionEvent {
            scan_id: "scan".into(),
            provider_id: provider.into(),
            target: target(value),
            outcome: SourceOutcomeKind::Success,
            finding_count: 1,
            truncated: false,
            started_at_unix: 1,
            finished_at_unix: 2,
            credential_fingerprint: None,
            upstream: None,
        }
    }

    fn observation(provider: &str, value: &str) -> RawObservation {
        RawObservation {
            provider_id: provider.into(),
            upstream: None,
            target: target(value),
            kind: EntityKind::Domain,
            value: value.into(),
            summary: "fixture".into(),
            attributes: BTreeMap::new(),
            observed_at_unix: None,
        }
    }

    #[test]
    fn discarded_dispatch_cannot_leave_orphan_evidence() {
        let batch = ObservationBatch {
            events: vec![event("kept", "a.example"), event("dropped", "b.example")],
            observations: vec![
                observation("kept", "a.example"),
                observation("dropped", "b.example"),
            ],
            independence_assertions: Vec::new(),
            truncated: false,
        };
        let limits = PipelineLimits {
            max_dispatches: 1,
            ..PipelineLimits::default()
        };
        let bounded = bounded_batch(batch, &limits);
        assert_eq!(bounded.events.len(), 1);
        assert_eq!(bounded.observations.len(), 1);
        assert_eq!(bounded.observations[0].provider_id, "kept");
        assert!(bounded.truncated);
    }

    #[test]
    fn dropped_observations_cannot_leave_dangling_independence_assertions() {
        fn origin(name: &str) -> UpstreamOrigin {
            UpstreamOrigin {
                provider: Some(name.into()),
                dataset: Some("primary".into()),
                artifact: None,
            }
        }
        fn assertion(left: &str, right: &str) -> UpstreamIndependenceAssertion {
            UpstreamIndependenceAssertion {
                left: origin(left),
                right: origin(right),
                basis: IndependenceBasis::ExplicitUpstreamProvenance,
                method_id: "fixture".into(),
                method_version: 1,
                supporting_artifact_ids: Vec::new(),
                observed_at_unix: 1,
            }
        }
        let mut first = observation("a", "a.example");
        first.upstream = Some(origin("a"));
        let mut second = observation("b", "b.example");
        second.upstream = Some(origin("b"));
        let mut dropped = observation("c", "c.example");
        dropped.upstream = Some(origin("c"));
        let batch = ObservationBatch {
            events: vec![
                event("a", "a.example"),
                event("b", "b.example"),
                event("c", "c.example"),
            ],
            observations: vec![first, second, dropped],
            independence_assertions: vec![assertion("a", "b"), assertion("a", "c")],
            truncated: false,
        };
        let bounded = bounded_batch(
            batch,
            &PipelineLimits {
                max_dispatches: 2,
                ..PipelineLimits::default()
            },
        );
        assert_eq!(bounded.observations.len(), 2);
        assert_eq!(bounded.independence_assertions.len(), 1);
        assert_eq!(bounded.independence_assertions[0].right, origin("b"));
        assert!(bounded.truncated);
    }

    #[test]
    fn dropped_dispatch_cannot_retain_evidence_from_a_different_upstream() {
        fn origin(name: &str) -> UpstreamOrigin {
            UpstreamOrigin {
                provider: Some(name.into()),
                dataset: Some("primary".into()),
                artifact: None,
            }
        }
        let mut kept_event = event("source", "a.example");
        kept_event.upstream = Some(origin("kept"));
        let mut dropped_event = event("source", "a.example");
        dropped_event.scan_id = "different-scan".into();
        dropped_event.upstream = Some(origin("discarded"));

        let mut kept_observation = observation("source", "a.example");
        kept_observation.upstream = Some(origin("kept"));
        let mut dropped_observation = observation("source", "a.example");
        dropped_observation.upstream = Some(origin("discarded"));

        let bounded = bounded_batch(
            ObservationBatch {
                events: vec![kept_event, dropped_event],
                observations: vec![kept_observation, dropped_observation],
                independence_assertions: Vec::new(),
                truncated: false,
            },
            &PipelineLimits {
                max_dispatches: 1,
                ..PipelineLimits::default()
            },
        );
        assert_eq!(bounded.events.len(), 1);
        assert_eq!(bounded.observations.len(), 1);
        assert_eq!(bounded.observations[0].upstream, Some(origin("kept")));
        assert!(bounded.truncated);
    }

    #[test]
    fn attributed_receipt_cannot_authorise_unattributed_observation() {
        let origin = UpstreamOrigin {
            provider: Some("verified_source".into()),
            dataset: Some("dataset".into()),
            artifact: Some("capture".into()),
        };
        let mut receipt = event("source", "a.example");
        receipt.upstream = Some(origin.clone());
        let missing_origin = observation("source", "a.example");
        let mut matching = observation("source", "a.example");
        matching.upstream = Some(origin);
        let bounded = bounded_batch(
            ObservationBatch {
                events: vec![receipt],
                observations: vec![missing_origin, matching],
                independence_assertions: Vec::new(),
                truncated: false,
            },
            &PipelineLimits::default(),
        );
        assert_eq!(bounded.observations.len(), 1);
        assert!(bounded.observations[0].upstream.is_some());
        assert!(bounded.truncated);

        let legacy = bounded_batch(
            ObservationBatch {
                events: vec![event("source", "a.example")],
                observations: vec![observation("source", "a.example")],
                independence_assertions: Vec::new(),
                truncated: false,
            },
            &PipelineLimits::default(),
        );
        assert_eq!(legacy.observations.len(), 1);
        assert!(!legacy.truncated);
    }

    #[test]
    fn unmatched_observation_is_not_accepted_as_evidence() {
        let batch = ObservationBatch {
            events: vec![event("source", "a.example")],
            observations: vec![observation("source", "b.example")],
            independence_assertions: Vec::new(),
            truncated: false,
        };
        let bounded = bounded_batch(batch, &PipelineLimits::default());
        assert!(bounded.observations.is_empty());
        assert!(bounded.truncated);
    }
}
