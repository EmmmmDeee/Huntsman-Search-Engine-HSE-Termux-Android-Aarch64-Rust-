//! MPC coordination protocol: party definitions, phases, and message types.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Unique identifier for a party in MPC coordination.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PartyId(pub String);

impl PartyId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn local() -> Self {
        Self("local".to_string())
    }
}

impl std::fmt::Display for PartyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Phase of MPC coordination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MPCPhase {
    /// Parties registering and preparing data
    Registration,
    /// Exchanging dataset summaries
    Discovery,
    /// Coordinating enrichment
    Enrichment,
    /// Finalizing merged datasets
    Completion,
}

impl std::fmt::Display for MPCPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registration => f.write_str("registration"),
            Self::Discovery => f.write_str("discovery"),
            Self::Enrichment => f.write_str("enrichment"),
            Self::Completion => f.write_str("completion"),
        }
    }
}

/// Metadata about a party's dataset for coordination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetMetadata {
    /// Party identifier
    pub party_id: PartyId,
    /// Number of entities in this party's dataset
    pub entity_count: usize,
    /// Entity kinds present in dataset
    pub entity_kinds: HashSet<String>,
    /// Timestamp when metadata was recorded
    pub recorded_at: u64,
}

impl DatasetMetadata {
    pub fn new(party_id: PartyId, entity_count: usize) -> Self {
        Self {
            party_id,
            entity_count,
            entity_kinds: HashSet::new(),
            recorded_at: crate::core::unix_now(),
        }
    }

    pub fn with_kinds(mut self, kinds: HashSet<String>) -> Self {
        self.entity_kinds = kinds;
        self
    }
}

/// A party participating in MPC coordination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Party {
    /// Party identifier
    pub id: PartyId,
    /// Metadata about this party's dataset
    pub metadata: DatasetMetadata,
    /// True if this party has completed the current phase
    pub phase_complete: bool,
}

impl Party {
    pub fn new(id: PartyId, entity_count: usize) -> Self {
        Self {
            id: id.clone(),
            metadata: DatasetMetadata::new(id, entity_count),
            phase_complete: false,
        }
    }

    pub fn mark_complete(&mut self) {
        self.phase_complete = true;
    }
}

/// Configuration for MPC coordination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MPCConfig {
    /// Initiating party
    pub initiator: PartyId,
    /// Minimum parties required for coordination
    pub min_parties: usize,
    /// Maximum parties allowed
    pub max_parties: usize,
    /// Enable entity deduplication
    pub deduplicate: bool,
    /// Enable evidence merging across parties
    pub merge_evidence: bool,
}

impl Default for MPCConfig {
    fn default() -> Self {
        Self {
            initiator: PartyId::local(),
            min_parties: 2,
            max_parties: 255,
            deduplicate: true,
            merge_evidence: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_party_id() {
        let id = PartyId::new("party_a");
        assert_eq!(id.to_string(), "party_a");
    }

    #[test]
    fn test_dataset_metadata() {
        let party = PartyId::new("party_a");
        let meta = DatasetMetadata::new(party, 100);
        assert_eq!(meta.entity_count, 100);
        assert!(meta.entity_kinds.is_empty());
    }

    #[test]
    fn test_party_creation() {
        let party = Party::new(PartyId::new("party_a"), 50);
        assert!(!party.phase_complete);
        assert_eq!(party.metadata.entity_count, 50);
    }

    #[test]
    fn test_party_mark_complete() {
        let mut party = Party::new(PartyId::new("party_a"), 50);
        assert!(!party.phase_complete);
        party.mark_complete();
        assert!(party.phase_complete);
    }

    #[test]
    fn test_mpc_config_default() {
        let config = MPCConfig::default();
        assert_eq!(config.min_parties, 2);
        assert!(config.deduplicate);
        assert!(config.merge_evidence);
    }
}
