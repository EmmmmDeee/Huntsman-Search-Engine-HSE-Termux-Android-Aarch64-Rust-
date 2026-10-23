//! L5 `SeekNow` collector: selector planning, causal fast/deep escalation, entity mapping,
//! and response-derived evidence. This adapter opens no sockets and never treats the
//! collector name as an independent evidence family.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use crate::collector::{
    CollectionBatch, CollectionLimits, CollectionOutcome, CollectorError, CollectorPivot,
    ObservationReceipt,
};
use crate::credential_origin::{AuthenticationAuthority, OperatorCredentialRef};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::fetch::{AuthStyle, Credential};
use crate::http::Transport;
use crate::keys::Keys;
use crate::seeknow::{
    KEY_SLOT, SEARCH_LIMIT_MAX, SeekNowQueryType, SeekNowRow, SeekNowSearch, SeekNowSearchResult,
    search_deep, search_fast,
};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

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
                | EntityKind::Url
                | EntityKind::DeviceId
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
        EntityKind::Person => SeekNowQueryType::Name,
        EntityKind::Url => SeekNowQueryType::Url,
        EntityKind::DeviceId => SeekNowQueryType::MachineId,
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
            if !search.query_type.supports_stealer() {
                return Err(CollectorError::InvalidSelector(format!(
                    "SeekNow stealer endpoint does not support {} selectors",
                    selector.kind
                )));
            }
            let result = search_deep(transport, credential, &search, now_unix)
                .map_err(|error| CollectorError::Execution(error.to_string()))?;
            append_result(&mut batch, selector, &result, limits, now_unix);
            batch.outcome = outcome_from_single(&batch.receipts[0]);
        }
        SeekNowCollectionMode::FastOnly => {
            if !search.query_type.supports_search() {
                return Err(CollectorError::InvalidSelector(format!(
                    "SeekNow search endpoint does not support {} selectors",
                    selector.kind
                )));
            }
            let fast = search_fast(transport, credential, &search, now_unix)
                .map_err(|error| CollectorError::Execution(error.to_string()))?;
            append_result(&mut batch, selector, &fast, limits, now_unix);
            batch.outcome = outcome_from_single(&batch.receipts[0]);
        }
        SeekNowCollectionMode::Adaptive => {
            if search.query_type.supports_search() {
                let fast = search_fast(transport, credential, &search, now_unix)
                    .map_err(|error| CollectorError::Execution(error.to_string()))?;
                let fast_kind = fast.outcome.kind;
                append_result(&mut batch, selector, &fast, limits, now_unix);

                if fast_kind == SourceOutcomeKind::ValidZero
                    && search.query_type.supports_stealer()
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
            } else if search.query_type.supports_stealer() {
                let deep = search_deep(transport, credential, &search, now_unix)
                    .map_err(|error| CollectorError::Execution(error.to_string()))?;
                append_result(&mut batch, selector, &deep, limits, now_unix);
                batch.outcome = outcome_from_single(&batch.receipts[0]);
            } else {
                return Err(CollectorError::UnsupportedSelector(selector.kind.clone()));
            }
        }
    }

    batch.pivots.truncate(limits.max_pivots);
    Ok(batch)
}

/// Entities and source outcomes from running `SeekNow` as one leg of a lookup.
#[derive(Debug, Default)]
pub struct LookupLeg {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

/// The operator-approved `SeekNow` credential built from `keys`.
///
/// This is the single builder for both the `seeknow` command and the lookup leg, so the
/// credential's authority and wire form have one definition. `provenance` records which path
/// approved it.
///
/// # Errors
/// [`String`] when the key slot is unset, or the authority or credential cannot be built.
pub fn operator_credential(
    keys: &Keys,
    now_unix: u64,
    provenance: &str,
) -> Result<Credential, String> {
    let secret = keys
        .get(KEY_SLOT)
        .ok_or_else(|| format!("credential {KEY_SLOT} is not configured"))?;
    let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
        provider_id: "seeknow".into(),
        credential_slot: KEY_SLOT.into(),
        approved_at_unix: now_unix,
        approval_provenance: provenance.into(),
    })
    .map_err(|error| error.to_string())?;
    Credential::new(authority, secret, AuthStyle::Header("X-API-Key".into()))
        .map_err(|error| error.to_string())
}

/// Run `SeekNow` as one keyed leg of a `kind` lookup for `value`.
///
/// Returns `None` when `HUNTSMAN_SEEKNOW_KEY` is not configured or the kind is not one
/// `SeekNow` accepts, so a lookup without the key is unchanged and makes no request. When the
/// key is set, the leg always runs, as the project requires of a configured keyed source.
///
/// A transport or provider failure is reported as one outcome, never an abort: the leg returns
/// whatever entities it gathered together with the failing source's outcome, so the rest of the
/// lookup still renders. The caller merges `entities` into the report (by uid) and appends
/// `outcomes` to the report's outcomes.
#[must_use]
pub fn collect_for_lookup<T: Transport + ?Sized>(
    transport: &T,
    kind: EntityKind,
    value: &str,
    keys: &Keys,
    now_unix: u64,
) -> Option<LookupLeg> {
    if keys.get(KEY_SLOT).is_none() || !SeekNowCollector.accepts(&kind) {
        return None;
    }
    let credential = operator_credential(keys, now_unix, "huntsman-recon lookup").ok()?;
    let scan_id = crate::entity::scan_id(&kind.to_string(), value);
    let selector = Entity::new(kind, value, 1.0, scan_id);
    let limits = CollectionLimits::default();
    match collect_with_credential(
        &selector,
        transport,
        &credential,
        &limits,
        SeekNowCollectionMode::Adaptive,
        now_unix,
    ) {
        Ok(batch) => Some(LookupLeg {
            outcomes: batch
                .receipts
                .iter()
                .map(|receipt| receipt.outcome.clone())
                .collect(),
            entities: batch.entities,
        }),
        Err(error) => Some(LookupLeg {
            entities: Vec::new(),
            outcomes: vec![SourceExecutionOutcome::inconclusive(
                COLLECTOR_ID,
                now_unix,
                error.to_string(),
            )],
        }),
    }
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
        EntityKind::Url => {
            (value.starts_with("https://") || value.starts_with("http://"))
                && !value.contains(char::is_whitespace)
        }
        EntityKind::DeviceId => (3..=256).contains(&value.chars().count()),
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
            batch.pivots.push(CollectorPivot { kind, value });
        }
    }
}

fn row_entities(row: &SeekNowRow) -> Vec<(EntityKind, String)> {
    let mut values = BTreeSet::<(EntityKind, String)>::new();
    for (key, value) in &row.fields {
        if let Some(kind) = entity_kind_for_field(key) {
            values.insert((kind, value.clone()));
        }
    }
    values.into_iter().collect()
}

/// The entity kind a field name maps to, or `None` when the field carries no entity.
///
/// A trailing `_<digits>` index is stripped before matching, because one `SeekNow` record
/// commonly packs several contacts under enumerated keys (`email_1`, `name_2`, `phone_1`).
/// Without this, every such packed identifier is silently dropped and a record that holds
/// only `email_1`+`email_2` yields no entities at all. Stripping only a purely numeric
/// trailing segment leaves real names intact: `email_address`, `street_address`,
/// `machine_id` and `postal_code_11_characters` keep their non-numeric final segment.
fn entity_kind_for_field(key: &str) -> Option<EntityKind> {
    let key = key.trim().to_ascii_lowercase();
    let base = strip_numeric_index(&key);
    match base {
        "email" | "email_address" => Some(EntityKind::Email),
        "phone" | "phone_number" | "mobile" => Some(EntityKind::Phone),
        "username" | "user" | "handle" => Some(EntityKind::Username),
        "ip" | "ip_address" => Some(EntityKind::IpAddress),
        "domain" | "hostname" => Some(EntityKind::Domain),
        "name" | "full_name" | "fullname" => Some(EntityKind::Person),
        "url" | "website" => Some(EntityKind::Url),
        "machine_id" | "machineid" | "hwid" | "hardware_id" => Some(EntityKind::DeviceId),
        "address" | "street_address" => Some(EntityKind::Address),
        _ => None,
    }
}

/// `key` with one trailing `_<digits>` segment removed, when present; otherwise `key`.
/// The segment after the final `_` must be non-empty and all ASCII digits, and removing
/// it must leave a non-empty base.
fn strip_numeric_index(key: &str) -> &str {
    match key.rsplit_once('_') {
        Some((base, index))
            if !base.is_empty()
                && !index.is_empty()
                && index.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            base
        }
        _ => key,
    }
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
