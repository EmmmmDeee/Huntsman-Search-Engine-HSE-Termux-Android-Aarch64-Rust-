//! L5 `SeekNow` collector: selector planning, causal fast/deep escalation, entity mapping,
//! and response-derived evidence. This adapter opens no sockets and never treats the
//! collector name as an independent evidence family.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use crate::collector::{
    CollectionBatch, CollectionLimits, CollectionOutcome, CollectorError, CollectorPivot,
    ObservationReceipt,
};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::fetch::Credential;
use crate::http::Transport;
use crate::seeknow::{
    SEARCH_LIMIT_MAX, SeekNowQueryType, SeekNowRow, SeekNowSearch, SeekNowSearchResult,
    search_deep, search_fast,
};
use crate::source_outcome::SourceOutcomeKind;

pub const COLLECTOR_ID: &str = "seeknow";
const ENTITY_CONFIDENCE: f64 = 0.60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeekNowCollectionMode {
    /// Fast first; deep only after a contract-validated fast zero.
    Adaptive,
    /// Execute only the fast endpoint.
    FastOnly,
    /// Operator-requested direct deep query.
    DeepOnly,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SeekNowCollector;

impl SeekNowCollector {
    #[must_use]
    pub const fn id(&self) -> &'static str {
        COLLECTOR_ID
    }

    #[must_use]
    pub const fn accepts(&self, kind: &EntityKind) -> bool {
        matches!(
            kind,
            EntityKind::Email
                | EntityKind::Phone
                | EntityKind::Username
                | EntityKind::IpAddress
                | EntityKind::Domain
                | EntityKind::Person
        )
    }
}

/// Convert a canonical selector into a bounded `SeekNow` query without touching transport.
pub fn plan_selector(
    selector: &Entity,
    limits: &CollectionLimits,
) -> Result<SeekNowSearch, CollectorError> {
    if !SeekNowCollector.accepts(&selector.kind) {
        return Err(CollectorError::UnsupportedSelector(selector.kind.clone()));
    }
    if limits.max_requests == 0 {
        return Err(CollectorError::Invariant(
            "max_requests must be at least one".into(),
        ));
    }

    validate_selector(selector)?;
    let query_type = match selector.kind {
        EntityKind::Email => SeekNowQueryType::Email,
        EntityKind::Phone => SeekNowQueryType::Phone,
        EntityKind::Username => SeekNowQueryType::Username,
        EntityKind::IpAddress => SeekNowQueryType::Ip,
        EntityKind::Domain => SeekNowQueryType::Domain,
        EntityKind::Person => SeekNowQueryType::Auto,
        _ => return Err(CollectorError::UnsupportedSelector(selector.kind.clone())),
    };
    let limit = limits
        .max_records_per_response
        .clamp(1, usize::from(SEARCH_LIMIT_MAX));
    let limit = u16::try_from(limit).unwrap_or(SEARCH_LIMIT_MAX);
    Ok(SeekNowSearch {
        query: selector.value.clone(),
        query_type,
        limit,
    })
}

/// Execute one keyed `SeekNow` collection under explicit operator credential authority.
pub fn collect_with_credential<T: Transport + ?Sized>(
    selector: &Entity,
    transport: &T,
    credential: &Credential,
    limits: &CollectionLimits,
    mode: SeekNowCollectionMode,
    now_unix: u64,
) -> Result<CollectionBatch, CollectorError> {
    let search = plan_selector(selector, limits)?;
    let mut batch = CollectionBatch::empty(COLLECTOR_ID, &selector.uid, CollectionOutcome::Failed);

    match mode {
        SeekNowCollectionMode::DeepOnly => {
            let result = search_deep(transport, credential, &search, now_unix)
                .map_err(|error| CollectorError::Execution(error.to_string()))?;
            append_result(&mut batch, selector, &result, limits, now_unix);
            batch.outcome = outcome_from_single(&batch.receipts[0]);
        }
        SeekNowCollectionMode::FastOnly | SeekNowCollectionMode::Adaptive => {
            let fast = search_fast(transport, credential, &search, now_unix)
                .map_err(|error| CollectorError::Execution(error.to_string()))?;
            let fast_kind = fast.outcome.kind;
            append_result(&mut batch, selector, &fast, limits, now_unix);

            if mode == SeekNowCollectionMode::Adaptive
                && fast_kind == SourceOutcomeKind::ValidZero
                && limits.max_requests >= 2
            {
                let deep = search_deep(transport, credential, &search, now_unix)
                    .map_err(|error| CollectorError::Execution(error.to_string()))?;
                let deep_kind = deep.outcome.kind;
                append_result(&mut batch, selector, &deep, limits, now_unix);
                batch.outcome = match deep_kind {
                    SourceOutcomeKind::Success => CollectionOutcome::Success,
                    SourceOutcomeKind::ValidZero => CollectionOutcome::ValidZero,
                    _ => CollectionOutcome::Partial,
                };
            } else {
                batch.outcome = outcome_from_single(&batch.receipts[0]);
            }
        }
    }

    batch.entities.truncate(limits.max_entities);
    batch.pivots.truncate(limits.max_pivots);
    Ok(batch)
}

fn validate_selector(selector: &Entity) -> Result<(), CollectorError> {
    let value = selector.value.trim();
    if value.is_empty() {
        return Err(CollectorError::InvalidSelector("empty selector".into()));
    }
    let valid = match selector.kind {
        EntityKind::Email => {
            let mut parts = value.split('@');
            matches!((parts.next(), parts.next(), parts.next()), (Some(local), Some(domain), None) if !local.is_empty() && domain.contains('.'))
        }
        EntityKind::Phone => {
            let digits = value.chars().filter(char::is_ascii_digit).count();
            (7..=15).contains(&digits)
        }
        EntityKind::Username => value.trim_start_matches('@').len() >= 2,
        EntityKind::IpAddress => value.parse::<IpAddr>().is_ok(),
        EntityKind::Domain => value.contains('.') && !value.contains(char::is_whitespace),
        EntityKind::Person => value.split_whitespace().count() >= 2,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(CollectorError::InvalidSelector(format!(
            "invalid {} selector",
            selector.kind
        )))
    }
}

fn append_result(
    batch: &mut CollectionBatch,
    selector: &Entity,
    result: &SeekNowSearchResult,
    limits: &CollectionLimits,
    now_unix: u64,
) {
    let dataset = single_dataset(&result.rows);
    batch.receipts.push(ObservationReceipt {
        source: COLLECTOR_ID.into(),
        dataset,
        observed_at_unix: now_unix,
        response_sha256: result.meta.response_sha256.clone(),
        outcome: result.outcome.clone(),
        parsed_rows: result.rows.len(),
        truncated: result.meta.truncated || result.meta.normalized_rows_truncated,
    });

    if result.outcome.kind != SourceOutcomeKind::Success {
        return;
    }
    let mut positions = batch
        .entities
        .iter()
        .enumerate()
        .map(|(index, entity)| (entity.uid.clone(), index))
        .collect::<HashMap<_, _>>();
    for (row_index, row) in result.rows.iter().enumerate() {
        append_row(
            batch,
            selector,
            row,
            row_index,
            limits,
            now_unix,
            &mut positions,
        );
    }
}

fn append_row(
    batch: &mut CollectionBatch,
    selector: &Entity,
    row: &SeekNowRow,
    row_index: usize,
    limits: &CollectionLimits,
    now_unix: u64,
    positions: &mut HashMap<String, usize>,
) {
    for (kind, value) in row_entities(row) {
        let mut entity = Entity::new(
            kind.clone(),
            value.clone(),
            ENTITY_CONFIDENCE,
            &selector.scan_id,
        );
        entity.observed_at_unix = now_unix;
        if entity.value.trim().is_empty() {
            continue;
        }
        entity.add_evidence(evidence_from_row(
            row,
            row_index,
            &selector.scan_id,
            now_unix,
        ));
        if let Some(&index) = positions.get(&entity.uid) {
            batch.entities[index].absorb(entity);
        } else if batch.entities.len() < limits.max_entities {
            positions.insert(entity.uid.clone(), batch.entities.len());
            batch.entities.push(entity);
        } else {
            continue;
        }
        if batch.pivots.len() < limits.max_pivots
            && entity_differs_from_selector(&kind, &value, selector)
        {
            batch.pivots.push(CollectorPivot {
                kind,
                value,
                parent_observation: None,
            });
        }
    }
}

fn row_entities(row: &SeekNowRow) -> Vec<(EntityKind, String)> {
    let mut values = BTreeSet::<(EntityKind, String)>::new();
    for (key, value) in &row.fields {
        let kind = match key.trim().to_ascii_lowercase().as_str() {
            "email" | "email_address" => Some(EntityKind::Email),
            "phone" | "phone_number" | "mobile" => Some(EntityKind::Phone),
            "username" | "user" | "handle" => Some(EntityKind::Username),
            "ip" | "ip_address" => Some(EntityKind::IpAddress),
            "domain" | "hostname" => Some(EntityKind::Domain),
            "name" | "full_name" | "fullname" => Some(EntityKind::Person),
            "url" | "website" => Some(EntityKind::Url),
            "address" | "street_address" => Some(EntityKind::Address),
            _ => None,
        };
        if let Some(kind) = kind {
            values.insert((kind, value.clone()));
        }
    }
    values.into_iter().collect()
}

fn evidence_from_row(row: &SeekNowRow, row_index: usize, scan_id: &str, now_unix: u64) -> Evidence {
    let mut provenance = EvidenceProvenance::for_scan(COLLECTOR_ID, scan_id);
    provenance.recorded_at_unix = now_unix;
    let summary = row.upstream.record_id.as_deref().map_or_else(
        || format!("SeekNow response row {row_index}"),
        |id| format!("SeekNow record {id}"),
    );
    let mut evidence = Evidence::new(provenance, summary);

    for field in [
        "dbname",
        "breach",
        "source_db",
        "database_name",
        "dataset",
        "source",
    ] {
        for value in row.upstream.values(field) {
            evidence = evidence.with_attr(field, value);
        }
    }
    if let Some(record_id) = row.upstream.record_id.as_deref() {
        evidence = evidence.with_attr("record_id", record_id);
    }
    if !row.sensitive_fields.is_empty() {
        evidence = evidence.with_attr(
            "sensitive_fields_present",
            row.sensitive_fields
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    if row.fields_truncated {
        evidence = evidence.with_attr("normalization_truncated", "true");
    }
    evidence
}

fn single_dataset(rows: &[SeekNowRow]) -> Option<String> {
    let mut values = rows.iter().flat_map(|row| {
        [
            &row.upstream.dbname,
            &row.upstream.breach,
            &row.upstream.source_db,
            &row.upstream.database_name,
            &row.upstream.dataset,
        ]
        .into_iter()
        .flat_map(|values| values.iter())
    });
    let first = values.next()?.clone();
    values.all(|value| value == &first).then_some(first)
}

fn entity_differs_from_selector(kind: &EntityKind, value: &str, selector: &Entity) -> bool {
    kind != &selector.kind || value != selector.value
}

fn outcome_from_single(receipt: &ObservationReceipt) -> CollectionOutcome {
    match receipt.outcome.kind {
        SourceOutcomeKind::Success => CollectionOutcome::Success,
        SourceOutcomeKind::ValidZero => CollectionOutcome::ValidZero,
        _ => CollectionOutcome::Failed,
    }
}
