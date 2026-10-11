//! L5 collector over [`DehashedClient`]: one selector in, one bounded
//! [`CollectionBatch`] out.
//!
//! The collector opens no sockets and makes exactly one search per call. It
//! follows the `seeknow_collector` contract: entities and pivots come from the
//! response, every record becomes evidence, and the collector name is never an
//! evidence family. Each record's dataset is carried in the `database_name`
//! attribute, which `lineage` reads, so two collectors relaying one dataset
//! share one root family.
//!
//! Passwords and hashes are not copied into entities or evidence. Evidence
//! records only that they exist.
//!
//! Local failures (an unsupported selector, an identifier that fails validation,
//! a zero request budget) return `Err`, because nothing was sent. Network and
//! upstream failures return `Ok` with a `Failed` batch and a receipt naming the
//! outcome, so the audit trail records that the attempt was made.

use std::collections::{BTreeSet, HashMap};

use super::client::{DehashedClient, DehashedError, MAX_PAGE_SIZE, SearchOutcome, SearchRequest};
use super::query::{Field, Purpose, Selector};
use super::types::Entry;
use crate::collector::{
    CollectionBatch, CollectionLimits, CollectionOutcome, CollectorError, CollectorPivot,
    ObservationReceipt,
};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_http_status};

pub const COLLECTOR_ID: &str = "dehashed";
/// Confidence for an entity read from a breach record. Calibrated lower than
/// a first-party identifier because breach data is third-hand.
const ENTITY_CONFIDENCE: f64 = 0.60;

/// Selector kinds this collector accepts, mapped to the field they search.
#[must_use]
pub const fn selector_field(kind: &EntityKind) -> Option<Field> {
    match kind {
        EntityKind::Email => Some(Field::Email),
        EntityKind::Username => Some(Field::Username),
        EntityKind::Domain => Some(Field::Domain),
        _ => None,
    }
}

/// Run one exact-match `DeHashed` collection for `selector`.
///
/// # Errors
/// [`CollectorError::UnsupportedSelector`] for a kind this collector does not
/// search, [`CollectorError::InvalidSelector`] when the value fails validation,
/// and [`CollectorError::Invariant`] when the limits leave no request budget.
/// None of these send a request.
pub fn collect(
    client: &DehashedClient,
    selector: &Entity,
    purpose: Purpose,
    limits: &CollectionLimits,
    now_unix: u64,
) -> Result<CollectionBatch, CollectorError> {
    collect_page(client, selector, purpose, 1, limits, now_unix)
}

/// Like [`collect`] but fetches a specific 1-based `page`. An out-of-range page
/// is rejected by [`SearchRequest::validate`] and surfaces as
/// [`CollectorError::InvalidSelector`] before any entity mapping.
///
/// # Errors
/// As [`collect`], plus the page-bound rejection above.
pub fn collect_page(
    client: &DehashedClient,
    selector: &Entity,
    purpose: Purpose,
    page: u32,
    limits: &CollectionLimits,
    now_unix: u64,
) -> Result<CollectionBatch, CollectorError> {
    let field = selector_field(&selector.kind)
        .ok_or_else(|| CollectorError::UnsupportedSelector(selector.kind.clone()))?;
    if limits.max_requests == 0 {
        return Err(CollectorError::Invariant(
            "max_requests must be at least one".into(),
        ));
    }
    let query = Selector::new(field, &selector.value)
        .map_err(|e| CollectorError::InvalidSelector(e.to_string()))?;
    let size = limits
        .max_records_per_response
        .clamp(1, usize::try_from(MAX_PAGE_SIZE).unwrap_or(usize::MAX));
    let request = SearchRequest {
        selector: query,
        purpose,
        size: u32::try_from(size).unwrap_or(MAX_PAGE_SIZE),
        page,
    };

    let mut batch = CollectionBatch::empty(COLLECTOR_ID, &selector.uid, CollectionOutcome::Failed);
    match client.search(&request) {
        Ok(outcome) => {
            let response_truncated = outcome
                .total
                .is_some_and(|total| total > outcome.entries.len() as u64);
            let kind = if outcome.entries.is_empty() {
                SourceOutcomeKind::ValidZero
            } else {
                SourceOutcomeKind::Success
            };
            // A local cap (max_entities/max_pivots) that drops kept data is a
            // form of truncation too: fold it into the receipt and outcome so a
            // lossy batch is never recorded as complete.
            let dropped = append_entries(&mut batch, selector, &outcome, purpose, limits, now_unix);
            let truncated = response_truncated || dropped;
            batch
                .receipts
                .push(receipt(&outcome, kind, now_unix, truncated));
            batch.outcome = match (kind, truncated) {
                (_, true) => CollectionOutcome::Partial,
                (SourceOutcomeKind::ValidZero, _) => CollectionOutcome::ValidZero,
                _ => CollectionOutcome::Success,
            };
        }
        Err(
            error @ (DehashedError::Query(_)
            | DehashedError::InvalidSize(_)
            | DehashedError::InvalidPage(_)
            | DehashedError::MissingKey
            | DehashedError::KeyFilePermissions),
        ) => {
            return Err(CollectorError::InvalidSelector(error.to_string()));
        }
        Err(error) => {
            batch.receipts.push(failure_receipt(&error, now_unix));
            batch.outcome = CollectionOutcome::Failed;
        }
    }
    batch.pivots.truncate(limits.max_pivots);
    Ok(batch)
}

fn receipt(
    outcome: &SearchOutcome,
    kind: SourceOutcomeKind,
    now_unix: u64,
    truncated: bool,
) -> ObservationReceipt {
    let found = outcome.entries.len();
    let execution = if matches!(kind, SourceOutcomeKind::ValidZero) {
        SourceExecutionOutcome::valid_zero(COLLECTOR_ID, now_unix)
    } else {
        SourceExecutionOutcome::success(COLLECTOR_ID, now_unix, found)
    }
    .with_http_status(200);
    ObservationReceipt {
        source: COLLECTOR_ID.into(),
        dataset: single_dataset(&outcome.entries),
        observed_at_unix: now_unix,
        response_sha256: Some(outcome.response_sha256.clone()),
        outcome: execution,
        parsed_rows: found,
        truncated,
    }
}

/// A receipt for a network or upstream failure. The detail is the error's
/// message, which never contains the identifier or a response body.
fn failure_receipt(error: &DehashedError, now_unix: u64) -> ObservationReceipt {
    let kind = failure_kind(error);
    let status = failure_status(error);
    let execution =
        SourceExecutionOutcome::failed(COLLECTOR_ID, now_unix, kind, status, error.to_string());
    let execution = match error {
        DehashedError::RateLimited {
            retry_after: Some(retry_after),
        } => execution.with_retry_after(retry_after.as_secs()),
        _ => execution,
    };
    ObservationReceipt {
        source: COLLECTOR_ID.into(),
        dataset: None,
        observed_at_unix: now_unix,
        response_sha256: None,
        outcome: execution,
        parsed_rows: 0,
        truncated: false,
    }
}

const fn failure_kind(error: &DehashedError) -> SourceOutcomeKind {
    match error {
        DehashedError::Unauthorized => SourceOutcomeKind::AuthRejected,
        DehashedError::Forbidden => SourceOutcomeKind::EntitlementDenied,
        DehashedError::RateLimited { .. } => SourceOutcomeKind::RateLimited,
        DehashedError::BadRequest => SourceOutcomeKind::Upstream4xx,
        DehashedError::Server(_) => SourceOutcomeKind::Upstream5xx,
        DehashedError::Unexpected(status) => classify_http_status(*status),
        DehashedError::Decode(_) => SourceOutcomeKind::SchemaDrift,
        DehashedError::Transport
        | DehashedError::Query(_)
        | DehashedError::MissingKey
        | DehashedError::KeyFilePermissions
        | DehashedError::InvalidSize(_)
        | DehashedError::InvalidPage(_) => SourceOutcomeKind::Inconclusive,
    }
}

const fn failure_status(error: &DehashedError) -> Option<u16> {
    match error {
        DehashedError::Unauthorized => Some(401),
        DehashedError::Forbidden => Some(403),
        DehashedError::BadRequest => Some(400),
        DehashedError::RateLimited { .. } => Some(429),
        DehashedError::Server(status) | DehashedError::Unexpected(status) => Some(*status),
        _ => None,
    }
}

/// Map a response's entries into entities and pivots. Returns `true` when a
/// limit (`max_entities` or `max_pivots`) forced kept data to be dropped, so
/// the caller can record the batch as truncated rather than complete.
fn append_entries(
    batch: &mut CollectionBatch,
    selector: &Entity,
    outcome: &SearchOutcome,
    purpose: Purpose,
    limits: &CollectionLimits,
    now_unix: u64,
) -> bool {
    let mut dropped = false;
    let mut positions: HashMap<String, usize> = HashMap::new();
    // A value seen across many breach records shares one uid; without this set
    // each repeat would push a duplicate pivot, exhausting max_pivots and
    // crowding out distinct pivots.
    let mut pivoted: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (index, entry) in outcome.entries.iter().enumerate() {
        let values = entry_values(entry);
        for (kind, value) in values {
            let mut entity = Entity::new(
                kind.clone(),
                value.clone(),
                ENTITY_CONFIDENCE,
                &selector.scan_id,
            );
            entity.observed_at_unix = now_unix;
            entity.add_evidence(evidence_for(
                entry,
                index,
                &selector.scan_id,
                purpose,
                now_unix,
            ));
            let uid = entity.uid.clone();
            if let Some(&position) = positions.get(&entity.uid) {
                batch.entities[position].absorb(entity);
            } else if batch.entities.len() < limits.max_entities {
                positions.insert(entity.uid.clone(), batch.entities.len());
                batch.entities.push(entity);
            } else {
                dropped = true;
                continue;
            }
            // Only a genuinely new, selector-distinct value is a candidate pivot.
            if (kind != selector.kind || value != selector.value) && pivoted.insert(uid) {
                if batch.pivots.len() < limits.max_pivots {
                    batch.pivots.push(CollectorPivot {
                        kind,
                        value,
                        parent_observation: None,
                    });
                } else {
                    // A distinct pivot that the budget cannot hold is lost.
                    dropped = true;
                }
            }
        }
    }
    dropped
}

/// Emails and usernames in one record, de-duplicated and blank-free.
fn entry_values(entry: &Entry) -> Vec<(EntityKind, String)> {
    let mut values = BTreeSet::new();
    for email in &entry.email {
        let value = email.trim();
        if !value.is_empty() {
            values.insert((EntityKind::Email, value.to_string()));
        }
    }
    for username in &entry.username {
        let value = username.trim();
        if !value.is_empty() {
            values.insert((EntityKind::Username, value.to_string()));
        }
    }
    values.into_iter().collect()
}

fn evidence_for(
    entry: &Entry,
    index: usize,
    scan_id: &str,
    purpose: Purpose,
    now_unix: u64,
) -> Evidence {
    let mut provenance = EvidenceProvenance::for_scan(COLLECTOR_ID, scan_id);
    provenance.recorded_at_unix = now_unix;
    let mut evidence = Evidence::new(provenance, format!("DeHashed record {}", index + 1))
        .with_attr("purpose", purpose.as_str())
        .with_attr("has_password", entry.has_password().to_string())
        .with_attr(
            "has_hashed_password",
            entry.has_hashed_password().to_string(),
        );
    if let Some(database) = entry
        .database_name
        .as_deref()
        .filter(|d| !d.trim().is_empty())
    {
        evidence = evidence.with_attr("database_name", database);
    }
    evidence
}

/// The dataset shared by every record, or `None` when records disagree or
/// none names one. Lineage reads the per-record attribute; this is only for
/// the receipt.
fn single_dataset(entries: &[Entry]) -> Option<String> {
    let mut names = entries.iter().map(|e| e.database_name.as_deref());
    let first = names.next()??.to_string();
    names
        .all(|name| name == Some(first.as_str()))
        .then_some(first)
}
