//! The persisted shape of one scan's AI-daemon analysis result.
//!
//! Pure data — no I/O, no Ollama/reqwest reference — exactly like [`crate::core::entity::Entity`]
//! or [`crate::core::relation::Relation`]: the deterministic core defines *what an
//! analysis record looks like*, while `src/ai/` (which depends on `core`, never the
//! reverse — see `core_does_not_import_ai` in `tests/architecture.rs`) is the only
//! place that actually *produces* one, by calling an operator-run local Ollama
//! instance. Storing the type here — rather than in `src/ai/` — is what lets
//! [`crate::core::port::StoragePort`] persist it without core ever importing `ai/`.
//!
//! An analysis is additive, downstream metadata: it is written only after a scan
//! has already reached a terminal state, is never read back by the scan engine,
//! module dispatch, or correlator, and never affects a scan's entities,
//! relations, correlation scores, or exports. See the `Runtime AI-independence`
//! invariant in `src/lib.rs` for the full rationale.

use serde::{Deserialize, Serialize};

/// One AI-daemon finding: a single notable, human-readable observation about a
/// scan's discovered entities, ranked by [`severity`](AnalysisFinding::severity).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisFinding {
    /// Plain-language description of the finding.
    pub description: String,
    /// Exposure severity, 0 (negligible) to 100 (critical). Model-assigned and
    /// therefore advisory, not a deterministic score — unlike
    /// [`crate::core::correlator`]'s confidence scoring, this is not reproducible
    /// across runs or models and must never be treated as such.
    pub severity: u8,
}

/// One scan's persisted AI-daemon analysis result.
///
/// `scan_id` is the [`crate::core::scan::Scan::id`] this analysis was produced
/// for; a scan has at most one current analysis (a re-run overwrites the prior
/// one — see [`crate::core::port::StoragePort::upsert_scan_analysis`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanAnalysis {
    pub scan_id: String,
    /// The Ollama model tag that produced this analysis (e.g. `"qwen2.5:7b"`) —
    /// kept so a stored analysis is never mistaken for the output of a
    /// different model after an operator switches models.
    pub model: String,
    /// Unix seconds when the analysis was generated.
    pub created_at: u64,
    /// Concise plain-language summary of the scan's exposure.
    pub summary: String,
    /// Up to a handful of ranked findings; see [`AnalysisFinding`].
    pub findings: Vec<AnalysisFinding>,
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
