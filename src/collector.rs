//! Source-agnostic L5 collection boundary.
//!
//! Collectors turn a canonical selector into bounded source observations and entities.
//! They do not open sockets themselves and they do not decide lineage independence:
//! response-derived evidence attributes remain authoritative for that later decision.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::entity::{Entity, EntityKind};
use crate::graph::EntityRelation;
use crate::source_outcome::SourceExecutionOutcome;

/// What a provider is asked for `selector`: a handle as it was written, without its leading `@`s,
/// because its identity key folds case and separators (`john.doe_99` and `johndoe99` are one
/// entity but two handles, and a provider asked the key answers for the other); every other kind's
/// canonical value, which keeps everything a provider reads (an address in lower case, a number in
/// E.164, a name with its spaces collapsed). **Pure.**
#[must_use]
pub fn query_text(selector: &Entity) -> String {
    match selector.kind {
        EntityKind::Username => selector.raw_value.trim().trim_start_matches('@').to_owned(),
        _ => selector.value.clone(),
    }
}

/// Whether a provider's `value` of `kind` names something other than `selector`: another kind, or
/// another identity of its kind. The selector's own value in another spelling or case is the
/// selector, never a pivot from it. **Pure.**
#[must_use]
pub fn differs_from_selector(kind: &EntityKind, value: &str, selector: &Entity) -> bool {
    *kind != selector.kind || crate::entity::normalise(kind, value) != selector.value
}

/// Hard work limits supplied to one collector invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionLimits {
    pub max_requests: usize,
    pub max_entities: usize,
    pub max_records_per_response: usize,
    pub max_pivots: usize,
}

impl Default for CollectionLimits {
    fn default() -> Self {
        Self {
            max_requests: 8,
            max_entities: 1_000,
            max_records_per_response: 500,
            max_pivots: 256,
        }
    }
}

/// Audit record for one provider execution. It intentionally has no credential field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationReceipt {
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset: Option<String>,
    pub observed_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_sha256: Option<String>,
    pub outcome: SourceExecutionOutcome,
    pub parsed_rows: usize,
    pub truncated: bool,
    /// The provider's own quota report on this response, when it sent one: what the request
    /// left, not an estimate. Absent on older saved receipts and on sources that send none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<ProviderQuota>,
}

/// A provider's quota headers on one response, kept verbatim so consumption is accounted from
/// what the provider said rather than inferred from the requests sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderQuota {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reset: Option<String>,
}

impl ProviderQuota {
    /// The quota a response reported, or `None` when it carried no quota header at all. **Pure.**
    #[must_use]
    pub fn reported(
        limit: Option<u64>,
        remaining: Option<u64>,
        reset: Option<String>,
    ) -> Option<Self> {
        (limit.is_some() || remaining.is_some() || reset.is_some()).then_some(Self {
            limit,
            remaining,
            reset,
        })
    }

    /// Whether the provider said no request is left in the current window. **Pure.**
    #[must_use]
    pub fn exhausted(&self) -> bool {
        self.remaining == Some(0)
    }
}

/// Bounded candidate for a later orchestrator. A pivot never counts as evidence by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorPivot {
    pub kind: EntityKind,
    pub value: String,
}

/// Aggregate state of a collection attempt; per-request causality remains on receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionOutcome {
    Success,
    ValidZero,
    Partial,
    Failed,
}

/// Material produced by one collector invocation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CollectionBatch {
    pub collector_id: String,
    pub selector_uid: String,
    #[serde(default)]
    pub receipts: Vec<ObservationReceipt>,
    #[serde(default)]
    pub entities: Vec<Entity>,
    #[serde(default)]
    pub relations: Vec<EntityRelation>,
    #[serde(default)]
    pub pivots: Vec<CollectorPivot>,
    pub outcome: CollectionOutcome,
}

impl CollectionBatch {
    #[must_use]
    pub fn empty(
        collector_id: impl Into<String>,
        selector_uid: impl Into<String>,
        outcome: CollectionOutcome,
    ) -> Self {
        Self {
            collector_id: collector_id.into(),
            selector_uid: selector_uid.into(),
            receipts: Vec::new(),
            entities: Vec::new(),
            relations: Vec::new(),
            pivots: Vec::new(),
            outcome,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CollectorError {
    #[error("collector does not support selector kind {0}")]
    UnsupportedSelector(EntityKind),
    #[error("invalid selector: {0}")]
    InvalidSelector(String),
    #[error("collection execution failed: {0}")]
    Execution(String),
    #[error("request refused before sending: {0}")]
    Refused(String),
    #[error("collector invariant failed: {0}")]
    Invariant(String),
}
