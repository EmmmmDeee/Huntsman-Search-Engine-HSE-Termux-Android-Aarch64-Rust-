//! Deterministic competitive evaluation core. From refactor overlay feef60a (P7).
//!
//! Pure model, scoring, statistics, and verdict machinery for controlled
//! manual-replay / retrieval-only / full / ablation comparisons. Runtime
//! orchestration must finalize a condition result before scorer-only truth is
//! opened.

mod integrity;
mod model;
mod score;
pub(crate) mod stats;
mod verdict;

pub use integrity::{ArtifactDigest, digest_json};
pub use model::{
    ClaimTruth, EvalCondition, FinalizedConditionResult, IdentityCluster, RelationTruth,
    SealedTruth, VisibleCase,
};
pub use score::{CaseScore, score_case};
pub use stats::{BootstrapInterval, bootstrap_mean_ci};
pub use verdict::{ComparisonEvidence, Decision, EvalPolicy, decide};

/// Count to `f64` for ratios. Exact below 2^53, far beyond any evaluation corpus.
#[allow(clippy::cast_precision_loss)]
pub(crate) fn count_f64(n: usize) -> f64 {
    n as f64
}
