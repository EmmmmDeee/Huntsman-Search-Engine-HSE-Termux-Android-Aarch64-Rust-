//! Multi-Party Computation (MPC) for secure breach data correlation.
//!
//! Enables multiple parties to collaboratively analyze breach data and
//! correlate entities without exposing raw data to each other. Built on
//! cryptographic protocols for private set intersection and secure aggregation.
//!
//! # Design
//!
//! MPC coordination allows parties to:
//! - Share breach findings via [`Commitment`] hashes instead of raw data
//! - Correlate entities across datasets using [`PrivateSetIntersection`]
//! - Aggregate breach statistics securely via [`SecureAggregation`]
//! - Prove data authenticity without revealing the data itself
//!
//! # Architecture Invariant
//!
//! - Pure Rust, no unsafe code, no C deps (complies with HSE requirements)
//! - Deterministic cryptographic operations (SHA-256, SHA-512)
//! - No cloud inference or external services

pub mod psi;
pub mod protocol;
pub mod secure_aggregation;

use crate::core::entity::Entity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashSet;

/// A commitment to a breach dataset or entity set, proving the data's integrity
/// without revealing the data itself. Used for multi-party proof-of-knowledge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Commitment {
    /// SHA-256 hash of the committed data (deterministic)
    pub hash: String,
    /// Byte count of original data (metadata only, non-revealing)
    pub size: usize,
    /// Party identifier (non-sensitive indexing)
    pub party_id: String,
}

impl Commitment {
    /// Create a commitment from raw data without revealing it.
    ///
    /// # Arguments
    /// - `data`: The data to commit to (e.g., serialized entity set)
    /// - `party_id`: Identifier for the party making the commitment
    pub fn new(data: &[u8], party_id: impl Into<String>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = format!("{:x}", hasher.finalize());

        Self {
            hash,
            size: data.len(),
            party_id: party_id.into(),
        }
    }

    /// Verify a commitment against provided data.
    pub fn verify(&self, data: &[u8]) -> bool {
        let computed = Commitment::new(data, &self.party_id);
        computed.hash == self.hash && computed.size == self.size
    }
}

/// Configuration for MPC coordination between parties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MPCConfig {
    /// Unique identifier for this party in the coordination
    pub party_id: String,
    /// Minimum threshold of parties required for aggregation
    pub min_parties: usize,
    /// Whether to enable private set intersection
    pub enable_psi: bool,
    /// Whether to enable secure aggregation
    pub enable_aggregation: bool,
}

impl Default for MPCConfig {
    fn default() -> Self {
        Self {
            party_id: "local".to_string(),
            min_parties: 2,
            enable_psi: true,
            enable_aggregation: true,
        }
    }
}

/// Result of MPC coordination for breach data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MPCResult {
    /// Common entities found across parties (from PSI)
    pub common_entities: Vec<String>,
    /// Aggregated breach statistics (from secure aggregation)
    pub aggregated_stats: AggregatedBreachStats,
    /// Parties that participated in this coordination
    pub parties_count: usize,
}

/// Aggregated breach statistics from multiple parties.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AggregatedBreachStats {
    /// Total unique entities across all parties
    pub total_unique_entities: usize,
    /// Sum of breach record counts
    pub total_breach_records: usize,
    /// Count of breaches identified across parties
    pub breach_count: usize,
}

/// Coordinator for multi-party computation on breach data.
pub struct MPCCoordinator {
    config: MPCConfig,
    commitments: Vec<Commitment>,
}

impl MPCCoordinator {
    /// Create a new MPC coordinator.
    pub fn new(config: MPCConfig) -> Self {
        Self {
            config,
            commitments: Vec::new(),
        }
    }

    /// Register a party's commitment to their breach dataset.
    pub fn register_commitment(&mut self, commitment: Commitment) -> Result<(), String> {
        if self.commitments.len() >= 255 {
            return Err("Too many parties registered".to_string());
        }
        self.commitments.push(commitment);
        Ok(())
    }

    /// Get all registered commitments.
    pub fn commitments(&self) -> &[Commitment] {
        &self.commitments
    }

    /// Check if we have enough parties for coordination.
    pub fn is_ready(&self) -> bool {
        self.commitments.len() >= self.config.min_parties
    }

    /// Coordinate breach data analysis across registered parties.
    ///
    /// Returns aggregated results that preserve privacy through:
    /// - PSI: Only revealing common entities, not individual datasets
    /// - Aggregation: Statistics only, not raw records
    pub fn coordinate(
        &self,
        party_datasets: Vec<Vec<String>>,
    ) -> Result<MPCResult, String> {
        if party_datasets.len() < self.config.min_parties {
            return Err("Insufficient parties for coordination".to_string());
        }

        let common_entities = if self.config.enable_psi {
            psi::intersect_private(&party_datasets)?
        } else {
            Vec::new()
        };

        let aggregated_stats = if self.config.enable_aggregation {
            secure_aggregation::aggregate_statistics(&party_datasets)?
        } else {
            AggregatedBreachStats::default()
        };

        Ok(MPCResult {
            common_entities,
            aggregated_stats,
            parties_count: party_datasets.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_creation() {
        let data = b"breach_data_123";
        let commitment = Commitment::new(data, "party_a");
        assert_eq!(commitment.size, 15);
        assert!(!commitment.hash.is_empty());
    }

    #[test]
    fn test_commitment_verification() {
        let data = b"breach_data_123";
        let commitment = Commitment::new(data, "party_a");
        assert!(commitment.verify(data));
        assert!(!commitment.verify(b"wrong_data"));
    }

    #[test]
    fn test_mpc_coordinator_ready() {
        let config = MPCConfig {
            party_id: "local".to_string(),
            min_parties: 2,
            enable_psi: true,
            enable_aggregation: true,
        };
        let mut coordinator = MPCCoordinator::new(config);
        assert!(!coordinator.is_ready());

        coordinator.register_commitment(Commitment::new(b"data1", "party_a")).ok();
        assert!(!coordinator.is_ready());

        coordinator.register_commitment(Commitment::new(b"data2", "party_b")).ok();
        assert!(coordinator.is_ready());
    }

    #[test]
    fn test_mpc_coordination() {
        let config = MPCConfig {
            party_id: "local".to_string(),
            min_parties: 2,
            enable_psi: true,
            enable_aggregation: true,
        };
        let coordinator = MPCCoordinator::new(config);

        let party_a = vec!["entity_1".to_string(), "entity_2".to_string(), "entity_3".to_string()];
        let party_b = vec!["entity_2".to_string(), "entity_3".to_string(), "entity_4".to_string()];

        let result = coordinator.coordinate(vec![party_a, party_b]);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!(result.parties_count, 2);
        // Common entities should be entity_2 and entity_3
        assert!(result.common_entities.contains(&"entity_2".to_string()));
        assert!(result.common_entities.contains(&"entity_3".to_string()));
    }
}
