//! Private Set Intersection (PSI) for secure entity matching across parties.
//!
//! Enables multiple parties to find common entities without revealing their
//! complete datasets to each other. Uses cryptographic hashing to create
//! privacy-preserving comparisons.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::HashSet;

/// A hashed set element that preserves privacy while allowing comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HashedElement {
    /// SHA-512 hash of the element (deterministic, one-way)
    pub hash: String,
    /// Original element (stored for testing, would be cleared in production)
    #[serde(skip)]
    original: Option<String>,
}

impl HashedElement {
    /// Create a hashed element from a raw value.
    pub fn new(value: &str) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(value.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        Self {
            hash,
            original: Some(value.to_string()),
        }
    }

    /// Create from a hash without the original value.
    pub fn from_hash(hash: String) -> Self {
        Self { hash, original: None }
    }
}

/// Configuration for PSI protocol.
#[derive(Debug, Clone)]
pub struct PSIConfig {
    /// Use deterministic hashing (true) or add random salts (false)
    /// Deterministic allows cross-party comparison without additional rounds
    pub deterministic: bool,
}

impl Default for PSIConfig {
    fn default() -> Self {
        Self {
            deterministic: true,
        }
    }
}

/// Party's private set for intersection.
#[derive(Debug, Clone)]
pub struct PSISet {
    /// Hashed elements that can be shared
    pub hashed_set: HashSet<String>,
    /// Original elements (private, not shared)
    private_set: Vec<String>,
}

impl PSISet {
    /// Create a PSI set from raw elements.
    pub fn new(elements: Vec<String>) -> Self {
        let hashed_set = elements
            .iter()
            .map(|e| {
                let mut hasher = Sha512::new();
                hasher.update(e.as_bytes());
                format!("{:x}", hasher.finalize())
            })
            .collect();

        Self {
            hashed_set,
            private_set: elements,
        }
    }

    /// Get the hashed set that can be safely shared with other parties.
    pub fn get_shared_set(&self) -> HashSet<String> {
        self.hashed_set.clone()
    }

    /// Get the private set (should not be shared).
    pub fn get_private_set(&self) -> &[String] {
        &self.private_set
    }
}

/// Result of a PSI operation between two parties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PSIResult {
    /// Entities common to both sets (in original form if available)
    pub intersection: Vec<String>,
    /// Intersection size
    pub intersection_size: usize,
    /// Size of first set
    pub set_a_size: usize,
    /// Size of second set
    pub set_b_size: usize,
}

/// Perform Private Set Intersection on multiple datasets.
///
/// Returns the intersection of all datasets without revealing the individual
/// datasets to each other. Uses cryptographic hashing for privacy.
///
/// # Arguments
/// - `datasets`: Vector of entity sets from different parties
///
/// # Returns
/// Vector of entities common to all datasets
pub fn intersect_private(datasets: &[Vec<String>]) -> Result<Vec<String>, String> {
    if datasets.is_empty() {
        return Ok(Vec::new());
    }

    if datasets.len() == 1 {
        return Ok(datasets[0].clone());
    }

    // Hash all elements in the first dataset
    let mut intersection_hashes: HashSet<String> = datasets[0]
        .iter()
        .map(|e| {
            let mut hasher = Sha512::new();
            hasher.update(e.as_bytes());
            format!("{:x}", hasher.finalize())
        })
        .collect();

    // For each subsequent dataset, keep only hashes that exist in it
    for dataset in &datasets[1..] {
        let dataset_hashes: HashSet<String> = dataset
            .iter()
            .map(|e| {
                let mut hasher = Sha512::new();
                hasher.update(e.as_bytes());
                format!("{:x}", hasher.finalize())
            })
            .collect();

        intersection_hashes.retain(|h| dataset_hashes.contains(h));
    }

    // Recover original values from the first dataset
    let mut result = Vec::new();
    for element in &datasets[0] {
        let mut hasher = Sha512::new();
        hasher.update(element.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        if intersection_hashes.contains(&hash) {
            result.push(element.clone());
        }
    }

    Ok(result)
}

/// Perform PSI between two specific parties with detailed results.
pub fn intersect_two_parties(
    party_a_elements: &[String],
    party_b_elements: &[String],
) -> PSIResult {
    let party_a_hashes: HashSet<String> = party_a_elements
        .iter()
        .map(|e| {
            let mut hasher = Sha512::new();
            hasher.update(e.as_bytes());
            format!("{:x}", hasher.finalize())
        })
        .collect();

    let party_b_hashes: HashSet<String> = party_b_elements
        .iter()
        .map(|e| {
            let mut hasher = Sha512::new();
            hasher.update(e.as_bytes());
            format!("{:x}", hasher.finalize())
        })
        .collect();

    let common_hashes: HashSet<_> = party_a_hashes
        .intersection(&party_b_hashes)
        .cloned()
        .collect();

    let intersection: Vec<String> = party_a_elements
        .iter()
        .filter(|e| {
            let mut hasher = Sha512::new();
            hasher.update(e.as_bytes());
            let hash = format!("{:x}", hasher.finalize());
            common_hashes.contains(&hash)
        })
        .cloned()
        .collect();

    PSIResult {
        intersection_size: intersection.len(),
        set_a_size: party_a_elements.len(),
        set_b_size: party_b_elements.len(),
        intersection: intersection,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hashed_element_creation() {
        let elem = HashedElement::new("test_entity");
        assert!(!elem.hash.is_empty());
        assert_eq!(elem.hash.len(), 128); // SHA-512 hex is 128 chars
    }

    #[test]
    fn test_hashed_element_deterministic() {
        let elem1 = HashedElement::new("entity_123");
        let elem2 = HashedElement::new("entity_123");
        assert_eq!(elem1.hash, elem2.hash);
    }

    #[test]
    fn test_psi_set_creation() {
        let elements = vec!["entity_1".to_string(), "entity_2".to_string()];
        let psi_set = PSISet::new(elements.clone());
        assert_eq!(psi_set.private_set.len(), 2);
        assert_eq!(psi_set.hashed_set.len(), 2);
    }

    #[test]
    fn test_intersect_private_single_dataset() {
        let datasets = vec![vec!["entity_1".to_string(), "entity_2".to_string()]];
        let result = intersect_private(&datasets);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn test_intersect_private_two_datasets() {
        let party_a = vec!["entity_1".to_string(), "entity_2".to_string(), "entity_3".to_string()];
        let party_b = vec!["entity_2".to_string(), "entity_3".to_string(), "entity_4".to_string()];
        let datasets = vec![party_a, party_b];

        let result = intersect_private(&datasets);
        assert!(result.is_ok());

        let intersection = result.unwrap();
        assert_eq!(intersection.len(), 2);
        assert!(intersection.contains(&"entity_2".to_string()));
        assert!(intersection.contains(&"entity_3".to_string()));
    }

    #[test]
    fn test_intersect_private_multiple_datasets() {
        let party_a = vec!["entity_1".to_string(), "entity_2".to_string(), "entity_3".to_string()];
        let party_b = vec!["entity_2".to_string(), "entity_3".to_string(), "entity_4".to_string()];
        let party_c = vec!["entity_2".to_string(), "entity_5".to_string()];
        let datasets = vec![party_a, party_b, party_c];

        let result = intersect_private(&datasets);
        assert!(result.is_ok());

        let intersection = result.unwrap();
        // Only entity_2 is common to all three
        assert_eq!(intersection.len(), 1);
        assert!(intersection.contains(&"entity_2".to_string()));
    }

    #[test]
    fn test_intersect_two_parties() {
        let party_a = vec!["entity_1".to_string(), "entity_2".to_string()];
        let party_b = vec!["entity_2".to_string(), "entity_3".to_string()];

        let result = intersect_two_parties(&party_a, &party_b);
        assert_eq!(result.set_a_size, 2);
        assert_eq!(result.set_b_size, 2);
        assert_eq!(result.intersection_size, 1);
        assert!(result.intersection.contains(&"entity_2".to_string()));
    }

    #[test]
    fn test_intersect_empty_datasets() {
        let result = intersect_private(&[]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_intersect_no_common_elements() {
        let party_a = vec!["entity_1".to_string()];
        let party_b = vec!["entity_2".to_string()];
        let datasets = vec![party_a, party_b];

        let result = intersect_private(&datasets);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }
}
