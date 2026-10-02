use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalCondition {
    ManualReplay,
    RetrievalOnly,
    Full,
    Ablation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VisibleCase {
    pub case_id: String,
    pub seed_kind: String,
    pub seed_value: String,
    pub tags: BTreeSet<String>,
}

/// Scorer-only ground truth. Condition runners must accept `VisibleCase`, never
/// this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedTruth {
    pub entity_ids: BTreeSet<String>,
    pub identity_clusters: Vec<IdentityCluster>,
    pub relations: BTreeSet<RelationTruth>,
    pub claims: BTreeSet<ClaimTruth>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityCluster {
    pub cluster_id: String,
    pub members: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RelationTruth {
    pub from: String,
    pub to: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ClaimTruth {
    pub key: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FinalizedConditionResult {
    pub case_id: String,
    pub condition: EvalCondition,
    pub entity_ids: BTreeSet<String>,
    pub identity_clusters: Vec<IdentityCluster>,
    pub relations: BTreeSet<RelationTruth>,
    pub claims: BTreeSet<ClaimTruth>,
    pub evidence_completeness: f64,
    pub request_count: u64,
    pub wall_time_ms: u64,
    pub provider_cost_usd: f64,
    pub completed: bool,
    pub comparable: bool,
}
