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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

// Keep coverage in sync when evidence is rejected after bounding. The raw
// observation schema has no scan ID, so provider/target is the precise scope
// available for conservative attribution of an incomplete execution.
fn mark_rejected_executions(
    events: &mut [CollectionEvent],
    rejected_sources: &BTreeSet<(String, crate::dependency::TargetKind, String)>,
) {
    for event in events {
        if rejected_sources.contains(&(
            event.provider_id.clone(),
            event.target.kind,
            event.target.value.clone(),
        )) {
            event.truncated = true;
        }
    }
}

#[must_use]
pub fn bounded_batch(mut batch: ObservationBatch, limits: &PipelineLimits) -> ObservationBatch {
    let original_observation_count = batch.observations.len();
    // Raw observations do not identify the execution that produced them.
    // Detect ambiguous sources before dispatch truncation: a dropped receipt
    // must not cause evidence from another scan to inherit the retained scan ID.
    let ambiguous_execution_sources = {
        let mut scan_by_source = BTreeMap::new();
        let mut ambiguous = BTreeSet::new();
        for event in &batch.events {
            let source = (
                event.provider_id.clone(),
                event.target.kind,
                event.target.value.clone(),
                event.upstream.clone(),
            );
            if let Some(previous_scan) =
                scan_by_source.insert(source.clone(), event.scan_id.as_str())
            {
                if previous_scan != event.scan_id.as_str() {
                    ambiguous.insert(source);
                }
            }
        }
        ambiguous
    };
    let overflow = batch.observations.len() > limits.max_entities
        || batch.events.len() > limits.max_dispatches;

    // Bound receipts first; unsupported findings must not consume the evidence budget.
    batch.events.truncate(limits.max_dispatches);

    // A retained observation must have a retained execution receipt. Otherwise
    // the evidence pipeline could consume findings from a provider whose outcome
    // disappeared when the dispatch budget was enforced. Raw observations do not
    // carry scan IDs, so match conservatively by provider and target.
    // Index retained execution receipts by the full source scope. Provenance
    // must match in BOTH directions: an unattributed receipt cannot authorize
    // an attributed finding, and vice versa. A legacy None/None pair remains
    // valid. Do not collapse distinct upstreams behind one provider/target.
    let mut retained_receipts = BTreeMap::<_, Vec<Option<&UpstreamOrigin>>>::new();
    for event in &batch.events {
        retained_receipts
            .entry((
                event.provider_id.as_str(),
                event.target.kind,
                event.target.value.as_str(),
            ))
            .or_default()
            .push(event.upstream.as_ref());
    }
    let mut rejected_sources = BTreeSet::new();
    let mut dropped_sources = BTreeSet::new();
    let mut retained_count = 0;
    batch.observations.retain(|observation| {
        let key = (
            observation.provider_id.as_str(),
            observation.target.kind,
            observation.target.value.as_str(),
        );
        let ambiguous = ambiguous_execution_sources.contains(&(
            observation.provider_id.clone(),
            observation.target.kind,
            observation.target.value.clone(),
            observation.upstream.clone(),
        ));
        let supported = !ambiguous
            && retained_receipts
                .get(&key)
                .is_some_and(|origins| origins.contains(&observation.upstream.as_ref()));
        if !supported {
            rejected_sources.insert((
                observation.provider_id.clone(),
                observation.target.kind,
                observation.target.value.clone(),
            ));
            return false;
        }
        if retained_count >= limits.max_entities {
            dropped_sources.insert((
                observation.provider_id.clone(),
                observation.target.kind,
                observation.target.value.clone(),
            ));
            return false;
        }
        retained_count += 1;
        true
    });
    // Mark retained receipts incomplete if their evidence was rejected or
    // exceeded the budget, without marking unrelated providers incomplete.
    rejected_sources.extend(dropped_sources);
    mark_rejected_executions(&mut batch.events, &rejected_sources);
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
    batch.truncated |= batch.observations.len() != original_observation_count;
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
        // Execution receipts must describe the same upstream as their findings.
        // The old fixture gave all three receipts None, relying on the now
        // forbidden attribution fallback instead of testing dispatch truncation.
        let mut first_receipt = event("a", "a.example");
        first_receipt.upstream = Some(origin("a"));
        let mut second_receipt = event("b", "b.example");
        second_receipt.upstream = Some(origin("b"));
        let mut dropped_receipt = event("c", "c.example");
        dropped_receipt.upstream = Some(origin("c"));
        let batch = ObservationBatch {
            events: vec![first_receipt, second_receipt, dropped_receipt],
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
    fn rejected_evidence_marks_only_its_retained_execution_incomplete() {
        let source_origin = UpstreamOrigin {
            provider: Some("upstream".into()),
            dataset: Some("reference".into()),
            artifact: None,
        };
        let mut source = event("source", "a.example");
        source.upstream = Some(source_origin.clone());
        source.finding_count = 2;
        let unrelated = event("unrelated", "b.example");

        let mut supported = observation("source", "a.example");
        supported.upstream = Some(source_origin);
        let rejected = observation("source", "a.example");
        let bounded = bounded_batch(
            ObservationBatch {
                events: vec![source, unrelated],
                observations: vec![supported, rejected],
                independence_assertions: Vec::new(),
                truncated: false,
            },
            &PipelineLimits::default(),
        );
        assert_eq!(bounded.observations.len(), 1);
        assert!(bounded.truncated);
        assert!(bounded.events[0].truncated);
        assert!(!bounded.events[1].truncated);
        let coverage = coverage_events(&bounded);
        assert!(matches!(coverage[0].kind, EventKind::ModuleError { .. }));
        assert!(matches!(coverage[1].kind, EventKind::ModuleDone { .. }));
        // Reapplying the bounding pass cannot silently turn the execution
        // back into a complete success after the rejected finding is gone.
        let again = bounded_batch(bounded.clone(), &PipelineLimits::default());
        assert_eq!(again, bounded);
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
    #[test]
    fn unattributed_receipt_cannot_authorize_attributed_observation() {
        let mut forged = observation("source", "a.example");
        forged.upstream = Some(UpstreamOrigin {
            provider: Some("unrecorded-provider".into()),
            dataset: Some("unrecorded-dataset".into()),
            artifact: None,
        });
        let bounded = bounded_batch(
            ObservationBatch {
                events: vec![event("source", "a.example")],
                observations: vec![forged],
                independence_assertions: Vec::new(),
                truncated: false,
            },
            &PipelineLimits::default(),
        );
        assert!(bounded.observations.is_empty());
        assert!(bounded.truncated);
        assert!(bounded.events[0].truncated);
        assert!(matches!(
            coverage_events(&bounded)[0].kind,
            EventKind::ModuleError { .. }
        ));
        assert_eq!(
            bounded_batch(bounded.clone(), &PipelineLimits::default()),
            bounded
        );
    }

    #[test]
    fn mixed_receipts_accept_only_matching_origins() {
        let origin = UpstreamOrigin {
            provider: Some("primary".into()),
            dataset: Some("one".into()),
            artifact: None,
        };
        let mut attributed_receipt = event("same", "a.example");
        attributed_receipt.upstream = Some(origin.clone());
        let mut attributed = observation("same", "a.example");
        attributed.upstream = Some(origin);
        let legacy = observation("same", "a.example");
        let mut unknown = observation("same", "a.example");
        unknown.upstream = Some(UpstreamOrigin {
            provider: Some("primary".into()),
            dataset: Some("other".into()),
            artifact: None,
        });
        let bounded = bounded_batch(
            ObservationBatch {
                events: vec![event("same", "a.example"), attributed_receipt],
                observations: vec![legacy, attributed, unknown],
                independence_assertions: Vec::new(),
                truncated: false,
            },
            &PipelineLimits::default(),
        );
        assert_eq!(bounded.observations.len(), 2);
        assert!(bounded.observations[0].upstream.is_none());
        assert!(bounded.observations[1].upstream.is_some());
        assert!(bounded.events.iter().all(|receipt| receipt.truncated));
        assert!(bounded.truncated);
    }
    #[test]
    fn unsupported_observations_do_not_exhaust_the_valid_evidence_budget() {
        let bounded = bounded_batch(
            ObservationBatch {
                events: vec![event("kept", "valid.example")],
                observations: vec![
                    observation("orphan", "unrecorded.example"),
                    observation("kept", "valid.example"),
                ],
                independence_assertions: Vec::new(),
                truncated: false,
            },
            &PipelineLimits {
                max_entities: 1,
                ..PipelineLimits::default()
            },
        );
        assert_eq!(bounded.observations.len(), 1);
        assert_eq!(bounded.observations[0].value, "valid.example");
        assert!(bounded.truncated);
        assert!(!bounded.events[0].truncated);
        assert!(matches!(
            coverage_events(&bounded)[0].kind,
            EventKind::ModuleDone { .. }
        ));
    }

    #[test]
    fn identical_source_in_different_scans_cannot_inherit_the_first_scan_id() {
        let origin = UpstreamOrigin {
            provider: Some("same-upstream".into()),
            dataset: Some("same-dataset".into()),
            artifact: None,
        };
        let mut first = event("shared", "a.example");
        first.scan_id = "scan-one".into();
        first.upstream = Some(origin.clone());
        let mut second = first.clone();
        second.scan_id = "scan-two".into();
        let mut raw = observation("shared", "a.example");
        raw.upstream = Some(origin);

        let bounded = bounded_batch(
            ObservationBatch {
                events: vec![first, second],
                observations: vec![raw],
                independence_assertions: Vec::new(),
                truncated: false,
            },
            &PipelineLimits::default(),
        );
        assert!(bounded.observations.is_empty());
        assert!(bounded.truncated);
        assert!(bounded.events.iter().all(|receipt| receipt.truncated));
        assert!(
            coverage_events(&bounded)
                .iter()
                .all(|event| matches!(&event.kind, EventKind::ModuleError { .. }))
        );
    }

    #[test]
    fn dropped_duplicate_scan_receipt_cannot_relabel_its_observation() {
        let mut first = event("shared", "a.example");
        first.scan_id = "scan-one".into();
        let mut second = first.clone();
        second.scan_id = "scan-two".into();

        let bounded = bounded_batch(
            ObservationBatch {
                events: vec![first, second],
                observations: vec![observation("shared", "a.example")],
                independence_assertions: Vec::new(),
                truncated: false,
            },
            &PipelineLimits {
                max_dispatches: 1,
                ..PipelineLimits::default()
            },
        );
        assert_eq!(bounded.events.len(), 1);
        assert!(bounded.observations.is_empty());
        assert!(bounded.events[0].truncated);
        assert!(bounded.truncated);
    }

    #[test]
    fn duplicate_receipts_in_one_scan_remain_unambiguous() {
        let first = event("shared", "a.example");
        let bounded = bounded_batch(
            ObservationBatch {
                events: vec![first.clone(), first],
                observations: vec![observation("shared", "a.example")],
                independence_assertions: Vec::new(),
                truncated: false,
            },
            &PipelineLimits::default(),
        );
        assert_eq!(bounded.observations.len(), 1);
        assert!(!bounded.truncated);
        assert!(bounded.events.iter().all(|receipt| !receipt.truncated));
    }

    #[test]
    fn valid_evidence_beyond_the_budget_marks_its_provider_incomplete() {
        let bounded = bounded_batch(
            ObservationBatch {
                events: vec![event("kept", "valid.example")],
                observations: vec![
                    observation("orphan", "unrecorded.example"),
                    observation("kept", "valid.example"),
                    observation("kept", "valid.example"),
                ],
                independence_assertions: Vec::new(),
                truncated: false,
            },
            &PipelineLimits {
                max_entities: 1,
                ..PipelineLimits::default()
            },
        );
        assert_eq!(bounded.observations.len(), 1);
        assert!(bounded.truncated);
        assert!(bounded.events[0].truncated);
        assert!(matches!(
            coverage_events(&bounded)[0].kind,
            EventKind::ModuleError { .. }
        ));
    }
}
