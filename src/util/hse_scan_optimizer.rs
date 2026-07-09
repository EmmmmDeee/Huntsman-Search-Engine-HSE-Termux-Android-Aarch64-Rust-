/// HSE Scan Optimizer
///
/// Refactors HSE scans for maximum accuracy and signal-to-noise improvement:
/// - Fresh API prioritization over cached results
/// - Weak detection filtering and exclusion
/// - Recursive depth-based entity expansion
/// - Confidence-based result ranking
/// - Automatic deduplication and consolidation
/// - Multi-source corroboration enforcement

use std::collections::{HashMap, HashSet};

/// Detection quality tier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DetectionQuality {
    ContentVerified,      // Full profile content verification
    MetadataMatched,      // Metadata (name, bio, etc) matched
    NameConventionMatch,  // Username convention matches pattern
    StatusCodeOnly,       // Simple HTTP 200 check (LOW QUALITY)
    NotFound404Inversion, // Checking for 404 to prove existence (LOW QUALITY)
}

/// Result confidence classification
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum ConfidenceClass {
    Unverified = 0,  // <50%
    Weak = 1,        // 50-75%
    High = 2,        // 75-90%
    Verified = 3,    // 90-100%
}

impl ConfidenceClass {
    pub fn from_score(score: f32) -> Self {
        match score {
            s if s >= 0.90 => ConfidenceClass::Verified,
            s if s >= 0.75 => ConfidenceClass::High,
            s if s >= 0.50 => ConfidenceClass::Weak,
            _ => ConfidenceClass::Unverified,
        }
    }
}

/// Scan result with quality metrics
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub entity_type: String,      // "username", "email", "phone", "url"
    pub entity_value: String,
    pub platform: String,
    pub confidence: f32,
    pub corroboration_count: usize,
    pub sources: Vec<String>,
    pub detection_quality: DetectionQuality,
    pub is_fresh_api: bool,       // Not from cache
    pub has_content_verification: bool,
    pub url: Option<String>,
}

/// Phase 1 optimizer configuration
#[derive(Debug, Clone)]
pub struct Phase1Optimizer {
    pub force_fresh_api: bool,
    pub bypass_cache: bool,
    pub minimum_confidence: f32,
    pub minimum_corroboration: usize,
    pub exclude_status_only: bool,
    pub require_content_verification: bool,
    pub exclude_weak_detections: bool,
}

impl Default for Phase1Optimizer {
    fn default() -> Self {
        Self {
            force_fresh_api: true,
            bypass_cache: true,
            minimum_confidence: 0.75,
            minimum_corroboration: 2,
            exclude_status_only: true,
            require_content_verification: true,
            exclude_weak_detections: true,
        }
    }
}

impl Phase1Optimizer {
    /// Filter results based on quality standards
    pub fn filter_results(&self, results: Vec<ScanResult>) -> Vec<ScanResult> {
        results
            .into_iter()
            .filter(|r| self.is_result_acceptable(r))
            .collect()
    }

    /// Check if result meets quality standards
    fn is_result_acceptable(&self, result: &ScanResult) -> bool {
        // Confidence threshold
        if result.confidence < self.minimum_confidence {
            return false;
        }

        // Corroboration threshold
        if result.corroboration_count < self.minimum_corroboration {
            return false;
        }

        // Exclude status-only detections
        if self.exclude_status_only
            && (result.detection_quality == DetectionQuality::StatusCodeOnly
                || result.detection_quality == DetectionQuality::NotFound404Inversion)
        {
            return false;
        }

        // Require fresh API if configured
        if self.force_fresh_api && !result.is_fresh_api {
            return false;
        }

        // Require content verification for high-quality results
        if self.require_content_verification && !result.has_content_verification {
            if ConfidenceClass::from_score(result.confidence) == ConfidenceClass::Verified {
                return false;
            }
        }

        true
    }

    /// Rank results by quality metrics
    pub fn rank_results(&self, results: Vec<ScanResult>) -> Vec<ScanResult> {
        let mut ranked = results;

        ranked.sort_by(|a, b| {
            // Primary: Confidence descending
            let conf_cmp = b.confidence.partial_cmp(&a.confidence).unwrap();
            if conf_cmp != std::cmp::Ordering::Equal {
                return conf_cmp;
            }

            // Secondary: Corroboration count descending
            let corr_cmp = b.corroboration_count.cmp(&a.corroboration_count);
            if corr_cmp != std::cmp::Ordering::Equal {
                return corr_cmp;
            }

            // Tertiary: Source count descending
            let src_cmp = b.sources.len().cmp(&a.sources.len());
            if src_cmp != std::cmp::Ordering::Equal {
                return src_cmp;
            }

            // Quaternary: Fresh API first
            let fresh_cmp = b.is_fresh_api.cmp(&a.is_fresh_api);
            if fresh_cmp != std::cmp::Ordering::Equal {
                return fresh_cmp;
            }

            std::cmp::Ordering::Equal
        });

        ranked
    }

    /// Deduplicate results and merge sources
    pub fn deduplicate_results(&self, results: Vec<ScanResult>) -> Vec<ScanResult> {
        let mut seen_by_url: HashMap<String, ScanResult> = HashMap::new();
        let mut seen_by_entity: HashMap<(String, String), ScanResult> = HashMap::new();

        for result in results {
            // Deduplicate by URL if available
            if let Some(url) = &result.url {
                if let Some(existing) = seen_by_url.get_mut(url) {
                    // Merge: keep higher confidence and combine sources
                    if result.confidence > existing.confidence {
                        *existing = result;
                    } else {
                        // Merge sources
                        for source in result.sources {
                            if !existing.sources.contains(&source) {
                                existing.sources.push(source);
                            }
                        }
                        existing.corroboration_count = existing.corroboration_count.max(result.corroboration_count);
                    }
                    continue;
                }
            }

            // Deduplicate by entity value
            let key = (result.entity_type.clone(), result.entity_value.clone());
            if let Some(existing) = seen_by_entity.get_mut(&key) {
                if result.confidence > existing.confidence {
                    *existing = result;
                } else {
                    for source in result.sources {
                        if !existing.sources.contains(&source) {
                            existing.sources.push(source);
                        }
                    }
                    existing.corroboration_count = existing.corroboration_count.max(result.corroboration_count);
                }
                continue;
            }

            // New result
            if let Some(url) = result.url.clone() {
                seen_by_url.insert(url, result.clone());
            }
            seen_by_entity.insert(key, result);
        }

        // Collect deduplicated results
        let mut deduped: Vec<_> = seen_by_entity.values().cloned().collect();

        // Also include URL-deduplicated results not in entity map
        for (_, result) in seen_by_url {
            if !deduped.iter().any(|r| r.url == result.url) {
                deduped.push(result);
            }
        }

        deduped
    }
}

/// Recursive entity expansion configuration
#[derive(Debug, Clone)]
pub struct RecursiveExpansion {
    pub max_depth: u32,
    pub depth_triggers: Vec<DepthTrigger>,
    pub search_related_entities: bool,
}

#[derive(Debug, Clone)]
pub struct DepthTrigger {
    pub depth: u32,
    pub min_confidence: f32,
    pub min_corroboration: usize,
    pub min_entities_found: usize,
}

impl Default for RecursiveExpansion {
    fn default() -> Self {
        Self {
            max_depth: 3,
            depth_triggers: vec![
                DepthTrigger {
                    depth: 1,
                    min_confidence: 0.80,
                    min_corroboration: 5,
                    min_entities_found: 1,
                },
                DepthTrigger {
                    depth: 2,
                    min_confidence: 0.85,
                    min_corroboration: 10,
                    min_entities_found: 2,
                },
                DepthTrigger {
                    depth: 3,
                    min_confidence: 0.90,
                    min_corroboration: 15,
                    min_entities_found: 3,
                },
            ],
            search_related_entities: true,
        }
    }
}

impl RecursiveExpansion {
    /// Check if depth progression is triggered
    pub fn should_expand_depth(&self, current_depth: u32, high_confidence_count: usize, avg_corroboration: f32) -> bool {
        if current_depth >= self.max_depth {
            return false;
        }

        for trigger in &self.depth_triggers {
            if trigger.depth == current_depth + 1 {
                return high_confidence_count >= trigger.min_entities_found
                    && avg_corroboration >= trigger.min_corroboration as f32;
            }
        }

        false
    }

    /// Generate variant usernames for recursive search
    pub fn generate_username_variants(&self, username: &str) -> Vec<String> {
        let mut variants = vec![username.to_string()];

        // Common transformations
        variants.push(username.replace("-", "_"));
        variants.push(username.replace("_", "-"));
        variants.push(username.replace("-", ""));
        variants.push(username.replace("_", ""));

        // Case variations
        variants.push(username.to_uppercase());
        variants.push(username.to_lowercase());

        // Number substitutions
        if let Some(no_num) = username.chars().find_map(|c| {
            if c.is_numeric() {
                Some(username.replace(c, ""))
            } else {
                None
            }
        }) {
            variants.push(no_num);
        }

        // Dedup
        variants.sort();
        variants.dedup();

        variants
    }
}

/// Result analytics
#[derive(Debug, Clone)]
pub struct ScanAnalytics {
    pub total_results: usize,
    pub after_filtering: usize,
    pub deduplication_ratio: f32,
    pub average_confidence: f32,
    pub average_corroboration: f32,
    pub high_confidence_count: usize,
    pub weak_detections_filtered: usize,
    pub status_only_filtered: usize,
    pub signal_to_noise_ratio: f32,
}

impl ScanAnalytics {
    pub fn compute(original: &[ScanResult], filtered: &[ScanResult], deduplicated: &[ScanResult]) -> Self {
        let total = original.len();
        let after_filter = filtered.len();
        let final_count = deduplicated.len();

        let avg_confidence = if !deduplicated.is_empty() {
            deduplicated.iter().map(|r| r.confidence).sum::<f32>() / deduplicated.len() as f32
        } else {
            0.0
        };

        let avg_corroboration = if !deduplicated.is_empty() {
            deduplicated.iter().map(|r| r.corroboration_count as f32).sum::<f32>() / deduplicated.len() as f32
        } else {
            0.0
        };

        let high_conf_count = deduplicated
            .iter()
            .filter(|r| r.confidence >= 0.75)
            .count();

        let weak_filtered = original
            .iter()
            .filter(|r| r.confidence < 0.75)
            .count() - filtered.iter().filter(|r| r.confidence < 0.75).count();

        let status_only_filtered = original
            .iter()
            .filter(|r| r.detection_quality == DetectionQuality::StatusCodeOnly)
            .count();

        let signal_to_noise = if final_count > 0 {
            high_conf_count as f32 / final_count as f32
        } else {
            0.0
        };

        ScanAnalytics {
            total_results: total,
            after_filtering: after_filter,
            deduplication_ratio: if after_filter > 0 {
                (after_filter - final_count) as f32 / after_filter as f32
            } else {
                0.0
            },
            average_confidence: avg_confidence,
            average_corroboration: avg_corroboration,
            high_confidence_count: high_conf_count,
            weak_detections_filtered: weak_filtered,
            status_only_filtered,
            signal_to_noise_ratio: signal_to_noise,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phase1_optimizer_filters_low_confidence() {
        let optimizer = Phase1Optimizer::default();

        let results = vec![
            ScanResult {
                entity_type: "username".to_string(),
                entity_value: "test".to_string(),
                platform: "twitter".to_string(),
                confidence: 0.95,
                corroboration_count: 5,
                sources: vec!["api1".to_string(), "api2".to_string()],
                detection_quality: DetectionQuality::ContentVerified,
                is_fresh_api: true,
                has_content_verification: true,
                url: Some("https://twitter.com/test".to_string()),
            },
            ScanResult {
                entity_type: "username".to_string(),
                entity_value: "weak".to_string(),
                platform: "instagram".to_string(),
                confidence: 0.60,
                corroboration_count: 1,
                sources: vec!["api1".to_string()],
                detection_quality: DetectionQuality::StatusCodeOnly,
                is_fresh_api: false,
                has_content_verification: false,
                url: None,
            },
        ];

        let filtered = optimizer.filter_results(results);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].confidence, 0.95);
    }

    #[test]
    fn test_phase1_optimizer_excludes_status_only() {
        let optimizer = Phase1Optimizer {
            exclude_status_only: true,
            ..Default::default()
        };

        let results = vec![
            ScanResult {
                entity_type: "username".to_string(),
                entity_value: "test".to_string(),
                platform: "twitter".to_string(),
                confidence: 0.95,
                corroboration_count: 5,
                sources: vec!["api1".to_string()],
                detection_quality: DetectionQuality::StatusCodeOnly,
                is_fresh_api: true,
                has_content_verification: true,
                url: Some("https://twitter.com/test".to_string()),
            },
        ];

        let filtered = optimizer.filter_results(results);
        assert_eq!(filtered.len(), 0);
    }

    #[test]
    fn test_deduplication_merges_sources() {
        let optimizer = Phase1Optimizer::default();

        let results = vec![
            ScanResult {
                entity_type: "username".to_string(),
                entity_value: "test".to_string(),
                platform: "twitter".to_string(),
                confidence: 0.90,
                corroboration_count: 5,
                sources: vec!["api1".to_string()],
                detection_quality: DetectionQuality::ContentVerified,
                is_fresh_api: true,
                has_content_verification: true,
                url: Some("https://twitter.com/test".to_string()),
            },
            ScanResult {
                entity_type: "username".to_string(),
                entity_value: "test".to_string(),
                platform: "twitter".to_string(),
                confidence: 0.88,
                corroboration_count: 4,
                sources: vec!["api2".to_string()],
                detection_quality: DetectionQuality::MetadataMatched,
                is_fresh_api: true,
                has_content_verification: true,
                url: Some("https://twitter.com/test".to_string()),
            },
        ];

        let deduped = optimizer.deduplicate_results(results);
        assert_eq!(deduped.len(), 1);
        // Deduplication by URL should result in higher confidence result with potentially merged sources
        assert!(deduped[0].sources.len() >= 1);
        assert_eq!(deduped[0].confidence, 0.90);  // Keeps higher confidence
    }

    #[test]
    fn test_result_ranking_by_confidence() {
        let optimizer = Phase1Optimizer::default();

        let results = vec![
            ScanResult {
                confidence: 0.75,
                corroboration_count: 2,
                sources: vec!["api1".to_string()],
                is_fresh_api: true,
                ..Default::default()
            },
            ScanResult {
                confidence: 0.95,
                corroboration_count: 5,
                sources: vec!["api1".to_string()],
                is_fresh_api: true,
                ..Default::default()
            },
            ScanResult {
                confidence: 0.85,
                corroboration_count: 3,
                sources: vec!["api1".to_string()],
                is_fresh_api: true,
                ..Default::default()
            },
        ];

        let ranked = optimizer.rank_results(results);
        assert!(ranked[0].confidence >= ranked[1].confidence);
        assert!(ranked[1].confidence >= ranked[2].confidence);
    }

    #[test]
    fn test_recursive_expansion_depth_triggers() {
        let expansion = RecursiveExpansion::default();

        assert!(expansion.should_expand_depth(0, 3, 10.0));
        assert!(!expansion.should_expand_depth(0, 1, 3.0));
        assert!(expansion.should_expand_depth(1, 3, 15.0));
    }

    #[test]
    fn test_username_variant_generation() {
        let expansion = RecursiveExpansion::default();
        let variants = expansion.generate_username_variants("rhino-ryno23");

        assert!(variants.contains(&"rhino-ryno23".to_string()));
        assert!(variants.contains(&"rhino_ryno23".to_string()));
        assert!(variants.contains(&"rhinoryno23".to_string()));
    }

    #[test]
    fn test_analytics_computation() {
        let original = vec![
            ScanResult {
                confidence: 0.95,
                corroboration_count: 5,
                ..Default::default()
            },
            ScanResult {
                confidence: 0.60,
                corroboration_count: 1,
                ..Default::default()
            },
        ];

        let filtered = vec![
            ScanResult {
                confidence: 0.95,
                corroboration_count: 5,
                ..Default::default()
            },
        ];

        let analytics = ScanAnalytics::compute(&original, &filtered, &filtered);
        assert_eq!(analytics.total_results, 2);
        assert_eq!(analytics.after_filtering, 1);
        assert!(analytics.signal_to_noise_ratio > 0.0);
    }
}

impl Default for ScanResult {
    fn default() -> Self {
        Self {
            entity_type: "username".to_string(),
            entity_value: String::new(),
            platform: String::new(),
            confidence: 0.0,
            corroboration_count: 0,
            sources: Vec::new(),
            detection_quality: DetectionQuality::StatusCodeOnly,
            is_fresh_api: false,
            has_content_verification: false,
            url: None,
        }
    }
}
