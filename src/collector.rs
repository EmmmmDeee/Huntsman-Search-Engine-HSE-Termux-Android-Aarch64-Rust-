//! Source-agnostic L5 collection boundary.
//!
//! Collectors turn a canonical selector into bounded source observations and entities.
//! They do not open sockets themselves and they do not decide lineage independence:
//! response-derived evidence attributes remain authoritative for that later decision.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::entity::{Entity, EntityKind};
use crate::evidence_ancestry::EvidenceNodeId;
use crate::graph::EntityRelation;
use crate::http::Transport;
use crate::source_outcome::SourceExecutionOutcome;

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
}

/// Bounded candidate for a later orchestrator. A pivot never counts as evidence by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorPivot {
    pub kind: EntityKind,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_observation: Option<EvidenceNodeId>,
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
    #[error("collector invariant failed: {0}")]
    Invariant(String),
}

/// Minimal synchronous boundary shared by keyless collectors. Keyed collectors may expose
/// an explicit credential-bearing entry point while returning the same `CollectionBatch`.
pub trait Collector {
    fn id(&self) -> &'static str;

    fn accepts(&self, kind: &EntityKind) -> bool;

    fn collect(
        &self,
        selector: &Entity,
        transport: &dyn Transport,
        limits: &CollectionLimits,
        now_unix: u64,
    ) -> Result<CollectionBatch, CollectorError>;
}
