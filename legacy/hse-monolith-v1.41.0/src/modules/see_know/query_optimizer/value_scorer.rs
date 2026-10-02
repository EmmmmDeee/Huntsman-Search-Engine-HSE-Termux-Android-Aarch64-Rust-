//! Value scoring for queries - COMPLETE IMPLEMENTATION
//!
//! Assigns value to each query based on:
//! - Entity diversity (how many types discovered)
//! - Hit rate (likelihood of finding data)
//! - Pivot potential (enables cascades)
//! - Freshness (cache age)
//! - Coverage (vs. alternatives)

use serde::{Deserialize, Serialize};

use super::types::EndpointRegistry;
use crate::util::see_know::config;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValueScore {
    pub entity_diversity: f32, // 0-100
    pub hit_rate: f32,         // 0-100
    pub pivot_potential: f32,  // 0-100
    pub freshness: f32,        // 0-100
    pub coverage: f32,         // 0-100
    pub composite: f32,        // 0-100 (weighted avg)
    pub reasoning: String,
}

impl Default for ValueScore {
    fn default() -> Self {
        Self::new()
    }
}

impl ValueScore {
    pub fn new() -> Self {
        Self {
            entity_diversity: 0.0,
            hit_rate: 0.0,
            pivot_potential: 0.0,
            freshness: 0.0,
            coverage: 0.0,
            composite: 0.0,
            reasoning: String::new(),
        }
    }

    pub fn is_high_value(&self) -> bool {
        self.composite >= 70.0
    }

    pub fn is_medium_value(&self) -> bool {
        self.composite >= 40.0 && self.composite < 70.0
    }

    pub fn is_low_value(&self) -> bool {
        self.composite < 40.0
    }
}

pub struct ValueScorer {
    /// Single source of truth for per-endpoint diversity + pivot signals.
    registry: EndpointRegistry,
}

impl Default for ValueScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl ValueScorer {
    pub fn new() -> Self {
        Self {
            registry: EndpointRegistry::new(),
        }
    }

    /// Score query on entity diversity (0-100), sourced from the registry.
    pub fn score_entity_diversity(&self, endpoint: &str) -> f32 {
        let count = self.registry.entity_type_count(endpoint);
        // Normalize to 0-100 scale (17 types = 100)
        ((count as f32 / 17.0) * 100.0).min(100.0)
    }

    /// Score query on historical hit rate (0-100)
    pub fn score_hit_rate(&self, endpoint: &str, target_type: &str, specificity: f32) -> f32 {
        // Base hit rates by endpoint and target type
        let base_rate = match (endpoint, target_type) {
            ("/search", "email") => 75.0,
            ("/search", "username") => 45.0,
            ("/search", "phone") => 30.0,
            ("/search", "domain") => 50.0,
            ("/search", "ip") => 40.0,
            ("/search", "name") => 35.0,

            ("/username/social", "username") => 80.0,
            ("/username/history", "username") => 60.0,
            ("/network/email-check", "email") => 85.0,
            ("/network/ip", "ip") => 75.0,
            ("/domain/whois", "domain") => 90.0,
            ("/discord/user", "discord_id") => 70.0,

            _ => 50.0, // Default
        };

        // Adjust by specificity (how specific is the query target)
        // Generic targets: low hit rate, specific targets: high hit rate
        let adjusted = base_rate * specificity;
        adjusted.min(100.0)
    }

    /// Score query on cascade/pivot potential (0-100), sourced from the registry.
    pub fn score_pivot_potential(&self, endpoint: &str) -> f32 {
        self.registry.pivot_potential(endpoint)
    }

    /// Score based on cache age (0-100)
    pub fn score_freshness(&self, cache_age_hours: Option<f32>) -> f32 {
        match cache_age_hours {
            None => 100.0, // Cache miss = fresh
            Some(age) if age < 1.0 => 95.0,
            Some(age) if age < 6.0 => 80.0,
            Some(age) if age < 12.0 => 60.0,
            Some(age) if age < 24.0 => 30.0,
            Some(_) => 5.0, // >24h cache = very stale
        }
    }

    /// Score query coverage vs. alternatives (0-100)
    pub fn score_coverage(&self, endpoint: &str, target_type: &str) -> f32 {
        match (endpoint, target_type) {
            // Primary endpoints get highest score
            ("/search", _) => 100.0,
            ("/username/social", "username") => 100.0,
            ("/network/email-check", "email") => 100.0,
            ("/domain/whois", "domain") => 100.0,
            ("/network/ip", "ip") => 100.0,

            // Secondary endpoints get medium score
            ("/username/history", "username") => 50.0,
            ("/search/deep", _) => 50.0,
            ("/domain/intel", "domain") => 60.0,

            // Tertiary/specialized endpoints
            ("/gaming/steam", "username") => 30.0,
            ("/discord/user", "discord_id") => 40.0,

            _ => 25.0,
        }
    }

    /// Calculate composite value score (COMPLETE IMPLEMENTATION)
    pub fn calculate_composite_value(
        &self,
        endpoint: &str,
        target_type: &str,
        cache_age: Option<f32>,
        target_specificity: f32,
    ) -> ValueScore {
        let diversity = self.score_entity_diversity(endpoint);
        let hit_rate = self.score_hit_rate(endpoint, target_type, target_specificity);
        let pivot = self.score_pivot_potential(endpoint);
        let freshness = self.score_freshness(cache_age);
        let coverage = self.score_coverage(endpoint, target_type);

        // Weighted composite calculation. The weights are the canonical
        // `config::VALUE_*_WEIGHT` constants — the single source of truth the
        // module doc advertises as "configurable" — not re-hardcoded literals,
        // so editing a weight in `config.rs` actually changes the scoring
        // (previously the constants were inert and these literals were a silent
        // divergence trap). Byte-identical to the prior literals (0.25/0.30/
        // 0.25/0.10/0.10 in the same order), so scoring is unchanged today.
        let weights = [
            (
                "diversity",
                diversity,
                config::VALUE_ENTITY_DIVERSITY_WEIGHT,
            ),
            ("hit_rate", hit_rate, config::VALUE_HIT_RATE_WEIGHT),
            ("pivot", pivot, config::VALUE_PIVOT_POTENTIAL_WEIGHT),
            ("freshness", freshness, config::VALUE_FRESHNESS_WEIGHT),
            ("coverage", coverage, config::VALUE_COVERAGE_WEIGHT),
        ];

        let composite = weights
            .iter()
            .map(|(_, score, weight)| score * weight)
            .sum::<f32>();

        let reasoning = format!(
            "Composite score: diversity={diversity:.1}/25% + hit_rate={hit_rate:.1}/30% + pivot={pivot:.1}/25% + freshness={freshness:.1}/10% + coverage={coverage:.1}/10% = {composite:.1}"
        );

        ValueScore {
            entity_diversity: diversity,
            hit_rate,
            pivot_potential: pivot,
            freshness,
            coverage,
            composite,
            reasoning,
        }
    }

    /// Batch score multiple candidates
    pub fn score_candidates(
        &self,
        endpoints: Vec<&str>,
        target_type: &str,
        cache_ages: Option<Vec<Option<f32>>>,
        specificity: f32,
    ) -> Vec<(String, ValueScore)> {
        endpoints
            .iter()
            .enumerate()
            .map(|(idx, endpoint)| {
                let cache_age = cache_ages
                    .as_ref()
                    .and_then(|ages| ages.get(idx))
                    .copied()
                    .flatten();

                let score =
                    self.calculate_composite_value(endpoint, target_type, cache_age, specificity);
                (endpoint.to_string(), score)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entity_diversity_scoring() {
        let scorer = ValueScorer::new();

        // /search has 17 types -> should score near 100
        assert!(scorer.score_entity_diversity("/search") > 95.0);

        // /discord/user has 2 types -> should score lower
        assert!(scorer.score_entity_diversity("/discord/user") < 20.0);
    }

    #[test]
    fn test_hit_rate_scoring() {
        let scorer = ValueScorer::new();

        // Email with high specificity on /network/email-check
        let high_hit = scorer.score_hit_rate("/network/email-check", "email", 0.9);
        assert!(high_hit > 70.0);

        // Random name on /search
        let low_hit = scorer.score_hit_rate("/search", "name", 0.3);
        assert!(low_hit < 50.0);
    }

    #[test]
    fn test_pivot_potential_scoring() {
        let scorer = ValueScorer::new();

        // Discord user can pivot
        assert_eq!(scorer.score_pivot_potential("/discord/user"), 80.0);

        // Email check has high pivot potential
        assert_eq!(scorer.score_pivot_potential("/network/email-check"), 75.0);
    }

    #[test]
    fn test_freshness_scoring() {
        let scorer = ValueScorer::new();

        // Cache miss = max freshness
        assert_eq!(scorer.score_freshness(None), 100.0);

        // Fresh cache (2 hours old)
        assert!(scorer.score_freshness(Some(2.0)) > 70.0);

        // Stale cache (20 hours old)
        assert!(scorer.score_freshness(Some(20.0)) < 35.0);
    }

    #[test]
    fn test_composite_value_calculation() {
        let scorer = ValueScorer::new();

        let score = scorer.calculate_composite_value("/search", "email", None, 0.8);

        // Should be high value (search is primary, email is good specificity)
        assert!(score.composite > 60.0);
        assert!(score.is_high_value());
    }

    #[test]
    fn composite_weights_are_the_canonical_config_constants_summing_to_one() {
        // The scorer consumes `config::VALUE_*_WEIGHT` directly (single source of
        // truth), so the weights must be a true convex combination. If a future
        // edit to `config.rs` breaks the normalisation, this fails loudly rather
        // than silently rescaling every composite score.
        let sum = config::VALUE_ENTITY_DIVERSITY_WEIGHT
            + config::VALUE_HIT_RATE_WEIGHT
            + config::VALUE_PIVOT_POTENTIAL_WEIGHT
            + config::VALUE_FRESHNESS_WEIGHT
            + config::VALUE_COVERAGE_WEIGHT;
        assert!(
            (sum - 1.0).abs() < 1e-6,
            "value weights must sum to 1.0, got {sum}"
        );

        // Pin the exact composite for a known input so the config→scorer wiring
        // stays byte-identical to the prior hardcoded literals:
        // diversity 100·0.25 + hit_rate 60·0.30 + pivot 65·0.25 + freshness
        // 100·0.10 + coverage 100·0.10 = 79.25.
        let scorer = ValueScorer::new();
        let score = scorer.calculate_composite_value("/search", "email", None, 0.8);
        assert!(
            (score.composite - 79.25).abs() < 1e-4,
            "composite must be 79.25, got {}",
            score.composite
        );
    }

    #[test]
    fn test_batch_scoring() {
        let scorer = ValueScorer::new();

        let candidates = vec!["/search", "/username/social", "/search/deep"];
        let results = scorer.score_candidates(candidates, "email", None, 0.8);

        assert_eq!(results.len(), 3);

        // /search should score highest
        let search_score = results
            .iter()
            .find(|(ep, _)| ep == "/search")
            .map_or(0.0, |(_, score)| score.composite);

        assert!(search_score > 50.0);
    }

    #[test]
    fn test_value_score_classifications() {
        let high = ValueScore {
            composite: 85.0,
            ..ValueScore::new()
        };
        assert!(high.is_high_value());

        let medium = ValueScore {
            composite: 50.0,
            ..ValueScore::new()
        };
        assert!(medium.is_medium_value());

        let low = ValueScore {
            composite: 20.0,
            ..ValueScore::new()
        };
        assert!(low.is_low_value());
    }
}
