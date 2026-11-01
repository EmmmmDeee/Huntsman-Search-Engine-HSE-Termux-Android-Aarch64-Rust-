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
    let before = batch.observations.len();
    batch.observations.retain(|observation| {
        retained_sources.contains(&(
            observation.provider_id.as_str(),
            observation.target.kind,
            observation.target.value.as_str(),
        ))
    });
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
