//! L5 `SeekNow` collector: selector planning, causal fast/deep escalation, entity mapping,
//! and response-derived evidence. This adapter opens no sockets and never treats the
//! collector name as an independent evidence family.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use crate::collector::{
    CollectionBatch, CollectionLimits, CollectionOutcome, CollectorError, CollectorPivot,
    ObservationReceipt, ProviderQuota, differs_from_selector, query_text,
};
use crate::credential_origin::{AuthenticationAuthority, OperatorCredentialRef};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::error::Error;
use crate::fetch::{AuthStyle, Credential};
use crate::http::Transport;
use crate::keys::Keys;
use crate::seeknow::{
    KEY_SLOT, SeekNowQueryType, SeekNowRow, SeekNowSearch, SeekNowSearchResult, effective_limit,
    search_deep, search_fast,
};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const COLLECTOR_ID: &str = "seeknow";
const ENTITY_CONFIDENCE: f64 = 0.60;
/// What one stealer (deep) search costs, in the account's credits.
const STEALER_CREDITS: u64 = 2;

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

/// Convert a selector into a bounded `SeekNow` query, asking for its [`query_text`] (a handle as it
/// was written), without touching transport.
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
    let limit = effective_limit(u16::try_from(limits.max_records_per_response).unwrap_or(u16::MAX));
    Ok(SeekNowSearch {
        query: query_text(selector),
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
            let result =
                search_deep(transport, credential, &search, now_unix).map_err(execution)?;
            append_result(&mut batch, selector, &search, &result, limits, now_unix);
            batch.outcome = outcome_from_single(&batch.receipts[0]);
        }
        SeekNowCollectionMode::FastOnly => {
            if !search.query_type.supports_search() {
                return Err(CollectorError::InvalidSelector(format!(
                    "SeekNow search endpoint does not support {} selectors",
                    selector.kind
                )));
            }
            let fast = search_fast(transport, credential, &search, now_unix).map_err(execution)?;
            append_result(&mut batch, selector, &search, &fast, limits, now_unix);
            batch.outcome = outcome_from_single(&batch.receipts[0]);
        }
        SeekNowCollectionMode::Adaptive => {
            if search.query_type.supports_search() {
                let fast =
                    search_fast(transport, credential, &search, now_unix).map_err(execution)?;
                let fast_kind = fast.outcome.kind;
                append_result(&mut batch, selector, &search, &fast, limits, now_unix);

                // The fast search's own quota report gates the stealer request: with fewer
                // credits left than it costs, escalating would only spend them or be refused.
                let quota_left = batch
                    .receipts
                    .last()
                    .and_then(|receipt| receipt.quota.as_ref())
                    .is_none_or(|quota| quota.covers(STEALER_CREDITS));
                if fast_kind == SourceOutcomeKind::ValidZero
                    && search.query_type.supports_stealer()
                    && limits.max_requests >= 2
                    && quota_left
                {
                    let deep =
                        search_deep(transport, credential, &search, now_unix).map_err(execution)?;
                    let deep_kind = deep.outcome.kind;
                    append_result(&mut batch, selector, &search, &deep, limits, now_unix);
                    batch.outcome = match deep_kind {
                        SourceOutcomeKind::Success => CollectionOutcome::Success,
                        SourceOutcomeKind::ValidZero => CollectionOutcome::ValidZero,
                        _ => CollectionOutcome::Partial,
                    };
                } else {
                    batch.outcome = outcome_from_single(&batch.receipts[0]);
                }
            } else if search.query_type.supports_stealer() {
                let deep =
                    search_deep(transport, credential, &search, now_unix).map_err(execution)?;
                append_result(&mut batch, selector, &search, &deep, limits, now_unix);
                batch.outcome = outcome_from_single(&batch.receipts[0]);
            } else {
                return Err(CollectorError::UnsupportedSelector(selector.kind.clone()));
            }
        }
    }

    batch.pivots.truncate(limits.max_pivots);
    Ok(batch)
}

/// The module an imported bulk export's rows are recorded under: `SeekNow`'s data, read offline.
pub const EXPORT_MODULE: &str = "seeknow_export";

/// What one bulk export yields: its entities (merged by identity across blocks), one outcome per
/// result block, and the pivots its kept rows offer.
#[derive(Debug, Clone, Default)]
pub struct ExportImport {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
    pub pivots: Vec<CollectorPivot>,
    /// Every parsed row of every block, in upload order, so the complete dataset survives import.
    /// Only credential *values* are withheld (held in each row's `sensitive_fields` by name); all
    /// other fields are verbatim. Entities and pivots above are the attributed subset; this is the
    /// whole record set.
    pub records: Vec<crate::seeknow::SeekNowRow>,
}

/// The selector kind an export block's query type stands for; `None` for a type with no single
/// kind (`auto`, `hash`). **Pure.**
const fn selector_kind(query_type: SeekNowQueryType) -> Option<EntityKind> {
    Some(match query_type {
        SeekNowQueryType::Email => EntityKind::Email,
        SeekNowQueryType::Username => EntityKind::Username,
        SeekNowQueryType::Phone => EntityKind::Phone,
        SeekNowQueryType::Ip => EntityKind::IpAddress,
        SeekNowQueryType::Domain => EntityKind::Domain,
        SeekNowQueryType::Name => EntityKind::Person,
        SeekNowQueryType::Url => EntityKind::Url,
        SeekNowQueryType::MachineId => EntityKind::DeviceId,
        SeekNowQueryType::Auto | SeekNowQueryType::Hash => return None,
    })
}

/// Import a `SeekNow` bulk export offline through the same row rules as a live search: a row
/// attributes only when it names its block's target in a field of the target's kind (B27), credential
/// fields never leave the parser, and every row keeps the export's digest, id and line.
/// Repeated target blocks each contribute observations; only resulting entity identities are
/// merged. Skipping later blocks would silently lose their independently supplied evidence.
/// Nothing is sent anywhere. **Pure.**
#[must_use]
pub fn collect_from_export(
    export: &crate::seeknow::BulkExport,
    limits: &CollectionLimits,
    now_unix: u64,
) -> ExportImport {
    let mut import = ExportImport::default();
    for block in &export.results {
        // Preserve every row of every block, before any attribution decision, so the full
        // uploaded dataset survives import whether or not a row names its target.
        import.records.extend(block.rows.iter().cloned());
        let Some(kind) = selector_kind(block.query_type) else {
            import.outcomes.push(SourceExecutionOutcome::inconclusive(
                EXPORT_MODULE,
                now_unix,
                format!(
                    "target {:?}: a {} search names no single identifier kind, so no row can be attributed",
                    block.target,
                    block.query_type.api_value().unwrap_or("auto")
                ),
            ));
            continue;
        };
        let scan_id = crate::entity::scan_id(&kind.to_string(), &block.target);
        let selector = Entity::new(kind, block.target.clone(), 1.0, scan_id);
        let search = SeekNowSearch {
            query: block.target.clone(),
            query_type: block.query_type,
            limit: crate::seeknow::SEARCH_LIMIT_MAX,
        };
        // A positive upstream total with no exported rows is incomplete,
        // never a verified absence. Likewise, rows rejected by the bounded
        // parser cannot justify a clean negative result.
        let incomplete_empty = block.rows.is_empty()
            && (block.reported_total.is_some_and(|total| total > 0) || block.rows_not_read > 0);
        let mut outcome = if incomplete_empty {
            SourceExecutionOutcome::inconclusive(
                EXPORT_MODULE,
                now_unix,
                "export has no readable rows despite reported or unread records",
            )
        } else if block.rows.is_empty() {
            SourceExecutionOutcome::valid_zero(EXPORT_MODULE, now_unix)
        } else {
            SourceExecutionOutcome::success(EXPORT_MODULE, now_unix, block.rows.len())
        };
        let mut notes = vec![format!(
            "bulk export {} sha256 {}",
            export.id.as_deref().unwrap_or("(no id)"),
            export.sha256
        )];
        if let Some(total) = block.reported_total {
            if total > block.rows.len() as u64 {
                notes.push(format!(
                    "the provider reported {total} rows; the export holds {}",
                    block.rows.len()
                ));
            }
        }
        if block.rows_not_read > 0 {
            notes.push(format!("{} rows were not read", block.rows_not_read));
        }
        if incomplete_empty {
            notes.push("no readable rows: cannot establish a valid zero".to_owned());
        }
        outcome.detail = Some(notes.join("; "));
        let result = crate::seeknow::SeekNowSearchResult {
            rows: block.rows.clone(),
            meta: crate::seeknow::SeekNowResponseMeta {
                response_sha256: Some(export.sha256.clone()),
                truncated: block.rows_not_read > 0,
                ..Default::default()
            },
            outcome,
        };
        let mut batch =
            CollectionBatch::empty(COLLECTOR_ID, &selector.uid, CollectionOutcome::Failed);
        append_result(&mut batch, &selector, &search, &result, limits, now_unix);
        import.entities.extend(batch.entities);
        import
            .outcomes
            .extend(batch.receipts.into_iter().map(|receipt| receipt.outcome));
        import.pivots.extend(batch.pivots);
    }
    crate::entity::merge_by_uid(&mut import.entities);
    import.pivots.truncate(limits.max_pivots);
    import
}

/// Map a leg error to a collector error, keeping a request the guarded path refused before sending
/// ([`Error::Network`]) distinct from a failure that reached `SeekNow`, so the `seeknow` command can
/// end 77 (refusal) rather than 69 (no usable response). **Pure.**
fn execution(error: Error) -> CollectorError {
    match error {
        Error::Network(message) => CollectorError::Refused(message),
        other => CollectorError::Execution(other.to_string()),
    }
}

/// Entities and source outcomes from running `SeekNow` as one leg of a lookup.
pub type LookupLeg = crate::lookup_report::LookupReport;

/// The operator-approved `SeekNow` credential built from `keys`.
///
/// This is the single builder for both the `seeknow` command and the lookup leg, so the
/// credential's authority and wire form have one definition. `provenance` records which path
/// approved it.
///
/// The key is read by the same slot rule `credential-status`, the probe and the web UI's key
/// settings report: the `HUNTSMAN_SEEKNOW_KEY` slot (keys file or environment), then `SeekNow`'s
/// own private key file `~/.config/seeknow/api_key` ([`crate::keys::PROVIDER_KEY_FILES`]). Without
/// that file a Termux install, driven through the web UI with no persistent shell environment, had
/// no durable place to hold the key, unlike `DeHashed` and HIBP.
///
/// # Errors
/// [`String`] when the key slot is unset, or the authority or credential cannot be built.
pub fn operator_credential(
    keys: &Keys,
    now_unix: u64,
    provenance: &str,
) -> Result<Credential, String> {
    let secret = crate::provider_credentials::secret_for_slot(keys, KEY_SLOT)
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
    if !SeekNowCollector.accepts(&kind) {
        return None;
    }
    if crate::provider_credentials::secret_for_slot(keys, KEY_SLOT).is_none() {
        // Asked without a key: no request, and the row that says so, as every keyed leg leaves.
        return Some(LookupLeg {
            entities: Vec::new(),
            outcomes: vec![SourceExecutionOutcome::not_configured(
                COLLECTOR_ID,
                now_unix,
            )],
        });
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
        Err(error) => {
            let kind = if matches!(error, CollectorError::Refused(_)) {
                SourceOutcomeKind::RefusedBeforeSending
            } else {
                SourceOutcomeKind::Inconclusive
            };
            Some(LookupLeg {
                entities: Vec::new(),
                outcomes: vec![SourceExecutionOutcome::failed(
                    COLLECTOR_ID,
                    now_unix,
                    kind,
                    None,
                    error.to_string(),
                )],
            })
        }
    }
}

fn validate_selector(selector: &Entity) -> Result<(), CollectorError> {
    let query = query_text(selector);
    let value = query.trim();
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
    search: &SeekNowSearch,
    result: &SeekNowSearchResult,
    limits: &CollectionLimits,
    now_unix: u64,
) {
    let dataset = single_dataset(&result.rows);
    let naming: Vec<bool> = result
        .rows
        .iter()
        .map(|row| row_names_selector(row, selector))
        .collect();
    let elsewhere = naming.iter().filter(|names| !**names).count();
    let mut outcome = result.outcome.clone();
    if elsewhere > 0 {
        let note = format!(
            "{elsewhere} of {} rows matched the query outside a {} field and attribute nothing",
            result.rows.len(),
            selector.kind.as_str()
        );
        outcome.detail = Some(match outcome.detail.take() {
            Some(detail) if !detail.is_empty() => format!("{detail}; {note}"),
            _ => note,
        });
    }
    batch.receipts.push(ObservationReceipt {
        source: COLLECTOR_ID.into(),
        dataset,
        observed_at_unix: now_unix,
        response_sha256: result.meta.response_sha256.clone(),
        outcome,
        parsed_rows: result.rows.len(),
        truncated: result.meta.truncated || result.meta.normalized_rows_truncated,
        quota: ProviderQuota::reported(
            result.meta.rate_limit_limit,
            result.meta.rate_limit_remaining,
            result.meta.rate_limit_reset.clone(),
        ),
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
    let context = RowContext {
        endpoint: &result.outcome.module,
        query_type: search.query_type.api_value(),
        query: &search.query,
        response_sha256: result.meta.response_sha256.as_deref(),
        observed_at_unix: now_unix,
    };
    for (row_index, row) in result.rows.iter().enumerate() {
        // A full-text breach search answers "Dubai" with every row where the word appears, a
        // city field included. Only a row that carries the searched value in a field of its own
        // kind is about the selector; the others are strangers and attribute nothing.
        if !naming[row_index] {
            continue;
        }
        append_row(
            batch,
            selector,
            &context,
            row,
            row_index,
            limits,
            &mut positions,
        );
    }
}

fn append_row(
    batch: &mut CollectionBatch,
    selector: &Entity,
    context: &RowContext<'_>,
    row: &SeekNowRow,
    row_index: usize,
    limits: &CollectionLimits,
    positions: &mut HashMap<String, usize>,
) {
    for (kind, value) in row_entities(row) {
        let mut entity = Entity::new(
            kind.clone(),
            value.clone(),
            ENTITY_CONFIDENCE,
            &selector.scan_id,
        );
        entity.observed_at_unix = context.observed_at_unix;
        if entity.value.trim().is_empty() {
            continue;
        }
        entity.add_evidence(evidence_from_row(
            context,
            row,
            row_index,
            &selector.scan_id,
            context.observed_at_unix,
        ));
        if let Some(&index) = positions.get(&entity.uid) {
            batch.entities[index].absorb(entity);
        } else if batch.entities.len() < limits.max_entities {
            positions.insert(entity.uid.clone(), batch.entities.len());
            batch.entities.push(entity);
        } else {
            continue;
        }
        if batch.pivots.len() < limits.max_pivots && differs_from_selector(&kind, &value, selector)
        {
            batch.pivots.push(CollectorPivot { kind, value });
        }
    }
}

/// Whether `row` carries the selector's value in a field of the selector's kind, compared by the
/// engine's canonical identity key. A domain is named by a domain field or by the host of a URL
/// or email field at that domain or a subdomain of it; a URL also by a field on the same host.
/// A row with no such field matched the query somewhere else. **Pure.**
fn row_names_selector(row: &SeekNowRow, selector: &Entity) -> bool {
    let fields = row_entities(row);
    let host_of = |kind: &EntityKind, value: &str| -> Option<String> {
        match kind {
            EntityKind::Domain => crate::canonical::canonical_domain(value.trim_end_matches('.')),
            EntityKind::Email => value
                .rsplit_once('@')
                .and_then(|(_, domain)| crate::canonical::canonical_domain(domain)),
            EntityKind::Url => crate::entity::link_host(value)
                .filter(|(kind, _)| *kind == EntityKind::Domain)
                .map(|(_, host)| host),
            _ => None,
        }
    };
    let same_identity = |kind: &EntityKind, value: &str| {
        *kind == selector.kind && Entity::new(kind.clone(), value, 0.0, "").uid == selector.uid
    };
    match selector.kind {
        EntityKind::Domain => {
            let Some(domain) = host_of(&EntityKind::Domain, &selector.value) else {
                return false;
            };
            let suffix = format!(".{domain}");
            fields.iter().any(|(kind, value)| {
                host_of(kind, value).is_some_and(|host| host == domain || host.ends_with(&suffix))
            })
        }
        EntityKind::Url => {
            let wanted = host_of(&EntityKind::Url, &selector.value);
            fields.iter().any(|(kind, value)| {
                same_identity(kind, value)
                    || (*kind == EntityKind::Url
                        && wanted.is_some()
                        && host_of(kind, value) == wanted)
            })
        }
        _ => fields
            .iter()
            .any(|(kind, value)| same_identity(kind, value)),
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
        // `pseudo` is the handle column of French-language breach exports.
        "username" | "user" | "handle" | "pseudo" => Some(EntityKind::Username),
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

/// Which request produced a row: the endpoint's module, the query type and text sent, and the
/// digest of the response the row was parsed from. Every row carries it, so a row from the fast
/// search and one from the stealer endpoint stay distinguishable and each traces to its response.
struct RowContext<'a> {
    endpoint: &'a str,
    query_type: Option<&'a str>,
    query: &'a str,
    response_sha256: Option<&'a str>,
    observed_at_unix: u64,
}

fn evidence_from_row(
    context: &RowContext<'_>,
    row: &SeekNowRow,
    row_index: usize,
    scan_id: &str,
    now_unix: u64,
) -> Evidence {
    let mut provenance = EvidenceProvenance::for_scan(COLLECTOR_ID, scan_id);
    provenance.recorded_at_unix = now_unix;
    let summary = row.upstream.record_id.as_deref().map_or_else(
        || format!("SeekNow response row {row_index}"),
        |id| format!("SeekNow record {id}"),
    );
    let mut evidence = Evidence::new(provenance, summary)
        .with_attr("endpoint", context.endpoint)
        .with_attr("query", context.query)
        .with_attr("row_index", row_index.to_string())
        .with_optional_attrs([
            ("query_type", context.query_type),
            ("response_sha256", context.response_sha256),
        ]);

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
    // A parsed provider row is not just a pivot list: retain every bounded,
    // non-credential scalar in the saved evidence. Namespace the keys so a
    // provider cannot override canonical source, dataset or record identity.
    for (key, value) in &row.fields {
        evidence = evidence.with_attr(format!("provider_field.{key}"), value);
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

fn outcome_from_single(receipt: &ObservationReceipt) -> CollectionOutcome {
    match receipt.outcome.kind {
        SourceOutcomeKind::Success => CollectionOutcome::Success,
        SourceOutcomeKind::ValidZero => CollectionOutcome::ValidZero,
        _ => CollectionOutcome::Failed,
    }
}
