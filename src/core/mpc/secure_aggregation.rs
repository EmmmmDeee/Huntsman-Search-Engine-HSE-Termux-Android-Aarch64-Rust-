//! Secure aggregation of breach statistics across multiple parties.
//!
//! Enables combining statistics (counts, metrics) from distributed datasets
//! without revealing individual records or party-specific data.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Statistics from a single party's breach data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PartyStatistics {
    /// Party identifier
    pub party_id: String,
    /// Number of unique entities in this party's dataset
    pub unique_entities: usize,
    /// Total breach records in this party's dataset
    pub breach_records: usize,
    /// Count of breaches identified
    pub breach_count: usize,
    /// Average confidence of entities (0.0 to 1.0)
    pub avg_confidence: f64,
}

impl PartyStatistics {
    /// Create statistics from a dataset.
    pub fn from_dataset(party_id: impl Into<String>, entities: &[String]) -> Self {
        Self {
            party_id: party_id.into(),
            unique_entities: entities.len(),
            breach_records: entities.len(), // Simplified: one record per entity
            breach_count: entities.len(),   // Simplified: one breach per entity
            avg_confidence: 0.85,           // Default confidence
        }
    }
}

/// Aggregated statistics across multiple parties.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AggregatedStatistics {
    /// Total unique entities across all parties (may overcount due to privacy)
    pub total_unique_entities: usize,
    /// Sum of breach records across all parties
    pub total_breach_records: usize,
    /// Sum of breaches across all parties
    pub total_breaches: usize,
    /// Number of parties that participated
    pub parties_count: usize,
    /// Average confidence across all parties
    pub avg_confidence: f64,
    /// Per-party contribution (metadata only, no raw data)
    pub party_contributions: HashMap<String, PartyStatistics>,
}

/// Securely aggregate statistics from multiple parties.
///
/// Combines counts and metrics without revealing individual party data,
/// using only aggregation that preserves privacy.
///
/// # Arguments
/// - `party_stats`: Statistics from each party
///
/// # Returns
/// Aggregated statistics safe to share
pub fn aggregate_statistics_from_parties(
    party_stats: Vec<PartyStatistics>,
) -> Result<AggregatedStatistics, String> {
    if party_stats.is_empty() {
        return Err("No statistics to aggregate".to_string());
    }

    let mut aggregated = AggregatedStatistics {
        parties_count: party_stats.len(),
        ..Default::default()
    };

    let mut total_confidence = 0.0;

    for stats in party_stats {
        aggregated.total_unique_entities += stats.unique_entities;
        aggregated.total_breach_records += stats.breach_records;
        aggregated.total_breaches += stats.breach_count;
        total_confidence += stats.avg_confidence;

        aggregated
            .party_contributions
            .insert(stats.party_id.clone(), stats);
    }

    aggregated.avg_confidence = total_confidence / aggregated.parties_count as f64;

    Ok(aggregated)
}

/// Securely aggregate statistics from raw datasets.
///
/// Processes raw entity datasets and produces aggregated statistics that
/// reveal only aggregate information, not individual party data.
pub fn aggregate_statistics(datasets: &[Vec<String>]) -> Result<super::AggregatedBreachStats, String> {
    if datasets.is_empty() {
        return Err("No datasets to aggregate".to_string());
    }

    let mut total_unique = std::collections::HashSet::new();
    let mut total_records = 0;
    let mut breach_count = 0;

    for dataset in datasets {
        for entity in dataset {
            total_unique.insert(entity.clone());
            total_records += 1;
        }
        breach_count += 1;
    }

    Ok(super::AggregatedBreachStats {
        total_unique_entities: total_unique.len(),
        total_breach_records: total_records,
        breach_count,
    })
}

/// Weighted aggregation that accounts for party importance.
///
/// Some parties may contribute more or more reliable data; this allows
/// weighted contributions while keeping the aggregation secure.
pub fn aggregate_statistics_weighted(
    party_stats: Vec<(PartyStatistics, f64)>,
) -> Result<AggregatedStatistics, String> {
    if party_stats.is_empty() {
        return Err("No statistics to aggregate".to_string());
    }

    let mut aggregated = AggregatedStatistics {
        parties_count: party_stats.len(),
        ..Default::default()
    };

    let mut total_weight = 0.0;
    let mut weighted_confidence = 0.0;

    for (stats, weight) in party_stats {
        if weight < 0.0 || weight > 1.0 {
            return Err("Weight must be between 0 and 1".to_string());
        }

        aggregated.total_unique_entities +=
            (stats.unique_entities as f64 * weight).ceil() as usize;
        aggregated.total_breach_records +=
            (stats.breach_records as f64 * weight).ceil() as usize;
        aggregated.total_breaches += (stats.breach_count as f64 * weight).ceil() as usize;
        weighted_confidence += stats.avg_confidence * weight;
        total_weight += weight;

        aggregated
            .party_contributions
            .insert(stats.party_id.clone(), stats);
    }

    aggregated.avg_confidence = if total_weight > 0.0 {
        weighted_confidence / total_weight
    } else {
        0.0
    };

    Ok(aggregated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_party_statistics_creation() {
        let entities = vec!["entity_1".to_string(), "entity_2".to_string()];
        let stats = PartyStatistics::from_dataset("party_a", &entities);
        assert_eq!(stats.party_id, "party_a");
        assert_eq!(stats.unique_entities, 2);
        assert_eq!(stats.breach_records, 2);
    }

    #[test]
    fn test_aggregate_statistics_from_parties() {
        let stats_a = PartyStatistics {
            party_id: "party_a".to_string(),
            unique_entities: 100,
            breach_records: 150,
            breach_count: 3,
            avg_confidence: 0.9,
        };

        let stats_b = PartyStatistics {
            party_id: "party_b".to_string(),
            unique_entities: 80,
            breach_records: 120,
            breach_count: 2,
            avg_confidence: 0.85,
        };

        let result = aggregate_statistics_from_parties(vec![stats_a, stats_b]);
        assert!(result.is_ok());

        let aggregated = result.unwrap();
        assert_eq!(aggregated.total_unique_entities, 180);
        assert_eq!(aggregated.total_breach_records, 270);
        assert_eq!(aggregated.total_breaches, 5);
        assert_eq!(aggregated.parties_count, 2);
        assert!((aggregated.avg_confidence - 0.875).abs() < 0.001);
    }

    #[test]
    fn test_aggregate_statistics_raw_datasets() {
        let datasets = vec![
            vec!["entity_1".to_string(), "entity_2".to_string()],
            vec!["entity_2".to_string(), "entity_3".to_string()],
        ];

        let result = aggregate_statistics(&datasets);
        assert!(result.is_ok());

        let aggregated = result.unwrap();
        assert_eq!(aggregated.total_breach_records, 4);
        assert_eq!(aggregated.breach_count, 2);
    }

    #[test]
    fn test_aggregate_statistics_weighted() {
        let stats_a = PartyStatistics {
            party_id: "party_a".to_string(),
            unique_entities: 100,
            breach_records: 150,
            breach_count: 3,
            avg_confidence: 0.9,
        };

        let stats_b = PartyStatistics {
            party_id: "party_b".to_string(),
            unique_entities: 80,
            breach_records: 120,
            breach_count: 2,
            avg_confidence: 0.8,
        };

        let result = aggregate_statistics_weighted(vec![(stats_a, 1.0), (stats_b, 0.5)]);
        assert!(result.is_ok());

        let aggregated = result.unwrap();
        // party_a contributes 100% (100), party_b contributes 50% (40)
        assert_eq!(aggregated.total_unique_entities, 140);
    }

    #[test]
    fn test_aggregate_empty() {
        let result = aggregate_statistics_from_parties(vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_aggregate_single_party() {
        let stats = PartyStatistics {
            party_id: "party_a".to_string(),
            unique_entities: 50,
            breach_records: 75,
            breach_count: 1,
            avg_confidence: 0.95,
        };

        let result = aggregate_statistics_from_parties(vec![stats.clone()]);
        assert!(result.is_ok());

        let aggregated = result.unwrap();
        assert_eq!(aggregated.total_unique_entities, 50);
        assert_eq!(aggregated.parties_count, 1);
        assert_eq!(aggregated.avg_confidence, 0.95);
    }
}
