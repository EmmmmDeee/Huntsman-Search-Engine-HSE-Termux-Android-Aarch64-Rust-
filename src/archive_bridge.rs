//! Adapter from the pure archive model into the shared collection/evidence pipeline.

use std::collections::BTreeMap;

use crate::archive::{ArchiveInterest, ArchiveRecord, ArchiveSource};
use crate::collection::{CollectionEvent, ObservationBatch, RawObservation, UpstreamOrigin};
use crate::dependency::{Target, TargetKind};
use crate::entity::EntityKind;
use crate::pipeline::PipelineLimits;
use crate::source_outcome::SourceOutcomeKind;

fn source_id(source: ArchiveSource) -> &'static str {
    match source {
        ArchiveSource::Wayback => "wayback",
        ArchiveSource::CommonCrawl => "common_crawl",
    }
}

fn interest_id(interest: ArchiveInterest) -> &'static str {
    match interest {
        ArchiveInterest::Document => "document",
        ArchiveInterest::ArchiveOrBackup => "archive_or_backup",
        ArchiveInterest::ConfigurationLike => "configuration_like",
        ArchiveInterest::ScriptLike => "script_like",
        ArchiveInterest::AdminAuthApiLike => "admin_auth_api_like",
        ArchiveInterest::Parameterized => "parameterized",
    }
}

fn attrs(record: &ArchiveRecord, observation_index: usize) -> BTreeMap<String, String> {
    let observation = &record.observations[observation_index];
    let mut attributes = BTreeMap::new();
    attributes.insert("first_seen".to_string(), observation.first_seen.clone());
    attributes.insert("last_seen".to_string(), observation.last_seen.clone());
    attributes.insert(
        "capture_count".to_string(),
        observation.capture_count.to_string(),
    );
    if !observation.collections.is_empty() {
        attributes.insert(
            "collections".to_string(),
            observation.collections.join("; "),
        );
    }
    if let Some(status) = observation.status {
        attributes.insert("http_status".to_string(), status.to_string());
    }
    if let Some(mime) = &observation.mime {
        attributes.insert("mime".to_string(), mime.clone());
    }
    if !observation.source_urls.is_empty() {
        attributes.insert(
            "source_urls".to_string(),
            observation.source_urls.join("; "),
        );
    }
    if !record.interests.is_empty() {
        attributes.insert(
            "archive_interests".to_string(),
            record
                .interests
                .iter()
                .copied()
                .map(interest_id)
                .collect::<Vec<_>>()
                .join("; "),
        );
    }
    attributes
}

#[must_use]
pub fn records_to_observation_batch(
    records: &[ArchiveRecord],
    scan_id: &str,
    limits: &PipelineLimits,
) -> ObservationBatch {
    let total_observations = records
        .iter()
        .map(|record| record.observations.len())
        .sum::<usize>();
    let truncated = total_observations > limits.max_archive_captures;
    let mut events = Vec::new();
    let mut observations = Vec::new();

    'records: for record in records {
        for index in 0..record.observations.len() {
            if observations.len() >= limits.max_archive_captures {
                break 'records;
            }
            let archived = &record.observations[index];
            let provider_id = source_id(archived.source).to_string();
            let target = Target::new(TargetKind::Domain, record.key.host.clone());
            let upstream = UpstreamOrigin {
                provider: Some(provider_id.clone()),
                dataset: Some(archived.dataset.clone()),
                artifact: archived.digest.clone(),
            };
            events.push(CollectionEvent {
                scan_id: scan_id.to_string(),
                provider_id: provider_id.clone(),
                target: target.clone(),
                outcome: SourceOutcomeKind::Success,
                finding_count: 1,
                truncated,
                started_at_unix: 0,
                finished_at_unix: 0,
                credential_fingerprint: None,
                upstream: Some(upstream.clone()),
            });
            observations.push(RawObservation {
                provider_id,
                upstream: Some(upstream),
                target,
                kind: EntityKind::Url,
                value: record.representative_url.clone(),
                summary: "historical archive capture".to_string(),
                attributes: attrs(record, index),
                observed_at_unix: None,
            });
        }
    }

    ObservationBatch {
        events,
        observations,
        truncated,
    }
}
