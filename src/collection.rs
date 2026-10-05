//! Provider-neutral collection envelopes between execution and evidence analysis.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::coverage::{Event, EventKind};
use crate::dependency::Target;
use crate::entity::EntityKind;
use crate::pipeline::PipelineLimits;
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
pub struct ObservationBatch {
    pub events: Vec<CollectionEvent>,
    pub observations: Vec<RawObservation>,
    pub truncated: bool,
}

#[must_use]
pub fn bounded_batch(mut batch: ObservationBatch, limits: &PipelineLimits) -> ObservationBatch {
    let overflow = batch.observations.len() > limits.max_entities
        || batch.events.len() > limits.max_dispatches;
    batch.observations.truncate(limits.max_entities);
    batch.events.truncate(limits.max_dispatches);
    if overflow {
        batch.truncated = true;
        for event in &mut batch.events {
            event.truncated = true;
        }
    }
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
