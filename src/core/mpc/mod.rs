//! Multi-Party Computation (MPC) coordination for breach data enrichment.
//!
//! Enables multiple parties to share, merge, and enrich raw breach intelligence
//! data without truncation or redaction. All data is preserved with full fidelity,
//! including all attributes and evidence chains. MPC coordination ensures:
//!
//! - **No data loss**: Every entity and its complete evidence chain is retained
//! - **Full enrichment**: Each party's data enhances all participants' datasets
//! - **Integrity tracking**: Provenance of enriched data is recorded
//! - **Deterministic merging**: GREATEST-semantics ensure confidence only increases

pub mod coordination;
pub mod enrichment;
pub mod protocol;

pub use coordination::Coordinator;
pub use enrichment::Enricher;
pub use protocol::{MPCConfig, MPCPhase, Party, PartyId};

use serde::{Deserialize, Serialize};

/// Configuration for MPC data coordination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentConfig {
    /// Unique identifier for this party
    pub party_id: String,
    /// Maximum number of parties to coordinate with
    pub max_parties: usize,
    /// Enable automatic deduplication across parties
    pub deduplicate: bool,
}

impl Default for EnrichmentConfig {
    fn default() -> Self {
        Self {
            party_id: "local".to_string(),
            max_parties: 255,
            deduplicate: true,
        }
    }
}

/// Result of MPC enrichment operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentResult {
    /// Total entities before enrichment
    pub original_count: usize,
    /// Total unique entities after merging and deduplication
    pub enriched_count: usize,
    /// Number of entities that were enriched with additional data
    pub entities_enriched: usize,
    /// Number of entities added from other parties
    pub entities_added: usize,
    /// Number of duplicate entities merged
    pub duplicates_merged: usize,
    /// Parties that participated in enrichment
    pub parties_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enrichment_config_default() {
        let config = EnrichmentConfig::default();
        assert_eq!(config.party_id, "local");
        assert!(config.deduplicate);
    }
}
