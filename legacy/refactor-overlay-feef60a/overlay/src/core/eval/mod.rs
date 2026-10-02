//! Deterministic competitive evaluation core.
//!
//! `hse benchmark` remains the scorecard for one scan. This module provides the
//! pure model/scoring/statistics/verdict machinery for controlled M*/R/F/A
//! comparisons. Runtime orchestration must finalize a condition result before
//! scorer-only truth is opened.

mod integrity;
mod model;
mod score;
mod stats;
mod verdict;

pub use integrity::{ArtifactDigest, digest_json};
pub use model::{
    ClaimTruth, EvalCondition, FinalizedConditionResult, IdentityCluster, RelationTruth,
    SealedTruth, VisibleCase,
};
pub use score::{CaseScore, score_case};
pub use stats::{BootstrapInterval, bootstrap_mean_ci};
pub use verdict::{ComparisonEvidence, Decision, EvalPolicy, decide};
