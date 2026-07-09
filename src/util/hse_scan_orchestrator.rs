/// HSE Scan Orchestration
///
/// Real-time optimization for HSE's search workflows:
/// - Breach database coordination
/// - Cross-platform correlation with confidence thresholds
/// - Geolocation enrichment
/// - API key resource allocation
/// - Progressive expansion (depth 0 → 1 → 2)

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::util::hse_autonomous_batch_queries::{HseAutonomousBatchQueries, SeedType};

/// Scan phase
#[derive(Debug, Clone, PartialEq)]
pub enum ScanPhase {
    Initial,           // Direct username search
    Correlation,       // Cross-platform correlation
    HighValue,         // Premium APIs (OathNet, etc)
    Expansion,         // Depth 1+ recursive searches
    Enrichment,        // Geolocation & metadata
    Reporting,         // Final synthesis
}

/// Confidence level
#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord)]
pub enum ConfidenceLevel {
    Low,      // <60% - single source
    Medium,   // 60-80% - 2 sources
    High,     // 80-95% - 3+ sources
    Verified, // 95%+ - fully corroborated
}

/// Entity correlation
#[derive(Debug, Clone)]
pub struct EntityCorrelation {
    pub entity_value: String,
    pub source_count: usize,
    pub sources: Vec<String>,
    pub confidence: ConfidenceLevel,
    pub first_seen_ms: u64,
    pub correlation_type: String,
}

/// Scan context
#[derive(Debug, Clone)]
pub struct ScanContext {
    pub scan_id: String,
    pub query: String,
    pub query_type: String,
    pub phase: ScanPhase,
    pub depth: u32,
    pub max_depth: u32,
    pub entities_found: usize,
    pub correlations_found: usize,
    pub apis_used: Vec<String>,
    pub apis_failed: Vec<String>,
}

/// Scan resource allocation
#[derive(Debug, Clone)]
pub struct ResourceAllocation {
    pub phase: ScanPhase,
    pub breach_db_calls: u32,
    pub social_api_calls: u32,
    pub geolocation_calls: u32,
    pub high_value_calls: u32,
    pub expansion_budget: u32,
}

/// HSE Scan Orchestrator
pub struct HseScanOrchestrator {
    pub context: ScanContext,
    pub correlations: HashMap<String, EntityCorrelation>,
    pub phase_history: Vec<(ScanPhase, u64)>,
    pub resource_allocation: ResourceAllocation,
    pub confidence_threshold: f32,
    pub batch_query_engine: HseAutonomousBatchQueries,
}

impl HseScanOrchestrator {
    /// Create new scan orchestrator
    pub fn new(query: &str, query_type: &str) -> Self {
        let scan_id = format!("scan-{}-{}", query, current_time_ms());

        Self {
            context: ScanContext {
                scan_id,
                query: query.to_string(),
                query_type: query_type.to_string(),
                phase: ScanPhase::Initial,
                depth: 0,
                max_depth: 3,
                entities_found: 0,
                correlations_found: 0,
                apis_used: Vec::new(),
                apis_failed: Vec::new(),
            },
            correlations: HashMap::new(),
            phase_history: Vec::new(),
            resource_allocation: ResourceAllocation {
                phase: ScanPhase::Initial,
                breach_db_calls: 0,
                social_api_calls: 0,
                geolocation_calls: 0,
                high_value_calls: 0,
                expansion_budget: 10,
            },
            confidence_threshold: 0.60,
            batch_query_engine: HseAutonomousBatchQueries::new(),
        }
    }

    /// Progress to next phase
    pub fn advance_phase(&mut self, next_phase: ScanPhase) {
        self.context.phase = next_phase.clone();
        self.phase_history
            .push((next_phase, current_time_ms()));
    }

    /// Record entity finding
    pub fn record_entity(&mut self, entity: &str, source: &str) {
        let key = entity.to_string();
        let mut new_source_count = 1;

        if let Some(corr) = self.correlations.get_mut(&key) {
            corr.source_count += 1;
            corr.sources.push(source.to_string());
            new_source_count = corr.source_count;
        } else {
            self.correlations.insert(
                key.clone(),
                EntityCorrelation {
                    entity_value: entity.to_string(),
                    source_count: 1,
                    sources: vec![source.to_string()],
                    confidence: ConfidenceLevel::Low,
                    first_seen_ms: current_time_ms(),
                    correlation_type: "username".to_string(),
                },
            );
        }

        // Calculate confidence outside of borrow scope
        let confidence = self.calculate_confidence(new_source_count);
        if let Some(corr) = self.correlations.get_mut(&key) {
            corr.confidence = confidence;
        }

        self.context.entities_found += 1;
    }

    /// Evaluate if high-value APIs should trigger
    pub fn should_trigger_high_value_apis(&self) -> bool {
        let highly_correlated = self
            .correlations
            .values()
            .filter(|c| c.source_count >= 2)
            .count();

        // Trigger when ≥1 entity has ≥2 corroborating sources
        highly_correlated >= 1 && self.context.phase == ScanPhase::Correlation
    }

    /// Calculate confidence based on source count
    fn calculate_confidence(&self, source_count: usize) -> ConfidenceLevel {
        match source_count {
            0 => ConfidenceLevel::Low,
            1 => ConfidenceLevel::Low,
            2 => ConfidenceLevel::Medium,
            3..=4 => ConfidenceLevel::High,
            _ => ConfidenceLevel::Verified,
        }
    }

    /// Get recommended APIs for current phase
    pub fn get_recommended_apis(&self) -> Vec<String> {
        match self.context.phase {
            ScanPhase::Initial => vec![
                "search_engines".to_string(),
                "username_search".to_string(),
                "social_probe".to_string(),
            ],
            ScanPhase::Correlation => vec![
                "username_variants".to_string(),
                "streaming_probe".to_string(),
                "social_probe".to_string(),
            ],
            ScanPhase::HighValue => vec![
                "oathnet_pro".to_string(),
                "hibp".to_string(),
                "dehashed".to_string(),
                "leakdb".to_string(),
            ],
            ScanPhase::Expansion => vec![
                "breach_timezone".to_string(),
                "dns_axfr".to_string(),
                "whoisxml".to_string(),
                "hunter_io".to_string(),
            ],
            ScanPhase::Enrichment => vec![
                "ip_reputation".to_string(),
                "geolocation_api".to_string(),
                "carrier_lookup".to_string(),
            ],
            ScanPhase::Reporting => vec![],
        }
    }

    /// Allocate resources based on phase
    pub fn allocate_resources(&mut self) {
        self.resource_allocation.phase = self.context.phase.clone();

        match self.context.phase {
            ScanPhase::Initial => {
                self.resource_allocation.social_api_calls = 20;
                self.resource_allocation.breach_db_calls = 3;
            }
            ScanPhase::Correlation => {
                self.resource_allocation.social_api_calls = 10;
                self.resource_allocation.breach_db_calls = 5;
            }
            ScanPhase::HighValue => {
                self.resource_allocation.high_value_calls = 5;
                self.resource_allocation.breach_db_calls = 10;
            }
            ScanPhase::Expansion => {
                self.resource_allocation.geolocation_calls = 20;
                self.resource_allocation.expansion_budget = 20;
            }
            ScanPhase::Enrichment => {
                self.resource_allocation.geolocation_calls = 50;
            }
            ScanPhase::Reporting => {}
        }
    }

    /// Get scan summary
    pub fn get_scan_summary(&self) -> String {
        let avg_confidence = self
            .correlations
            .values()
            .map(|c| match c.confidence {
                ConfidenceLevel::Low => 0.5,
                ConfidenceLevel::Medium => 0.7,
                ConfidenceLevel::High => 0.87,
                ConfidenceLevel::Verified => 0.95,
            })
            .sum::<f32>()
            / self.correlations.len().max(1) as f32;

        format!(
            "HSE Scan Summary\n\
             ===============\n\
             Query: {}\n\
             Phase: {:?}\n\
             Depth: {}/{}\n\
             Entities Found: {}\n\
             Correlations: {}\n\
             Avg Confidence: {:.1}%\n\
             APIs Used: {}\n\
             APIs Failed: {}\n\
             High-Value Ready: {}\n",
            self.context.query,
            self.context.phase,
            self.context.depth,
            self.context.max_depth,
            self.context.entities_found,
            self.correlations.len(),
            avg_confidence * 100.0,
            self.context.apis_used.join(", "),
            self.context.apis_failed.join(", "),
            self.should_trigger_high_value_apis()
        )
    }

    /// Get correlations by confidence level
    pub fn get_correlations_by_confidence(&self, level: ConfidenceLevel) -> Vec<EntityCorrelation> {
        self.correlations
            .values()
            .filter(|c| c.confidence == level)
            .cloned()
            .collect()
    }

    /// Get high-confidence entities for expansion
    pub fn get_high_confidence_entities(&self) -> Vec<EntityCorrelation> {
        self.correlations
            .values()
            .filter(|c| c.confidence >= ConfidenceLevel::High)
            .cloned()
            .collect()
    }

    /// Record API usage
    pub fn record_api_usage(&mut self, api_name: &str, success: bool) {
        if success {
            self.context.apis_used.push(api_name.to_string());
        } else {
            self.context.apis_failed.push(api_name.to_string());
        }
    }

    /// Check if expansion depth available
    pub fn can_expand(&self) -> bool {
        self.context.depth < self.context.max_depth
    }

    /// Get breach database priority order
    pub fn get_breach_db_chain(&self) -> Vec<&'static str> {
        vec![
            "hibp",      // Primary
            "leakdb",    // Secondary
            "dehashed",  // Tertiary
            "niamonx",   // Backup
        ]
    }

    /// Get social platform priority
    pub fn get_social_platform_priority(&self) -> Vec<&'static str> {
        vec![
            "twitter",
            "instagram",
            "tiktok",
            "linkedin",
            "github",
            "reddit",
        ]
    }

    /// Extract high-value seeds from discovered entities for autonomous batch processing
    pub fn extract_seeds_for_batch_processing(&mut self) -> usize {
        let mut seeds = Vec::new();

        // Extract seeds from high-confidence correlations
        for corr in self.correlations.values() {
            if corr.source_count >= 2 && corr.confidence != ConfidenceLevel::Low {
                let confidence = match corr.confidence {
                    ConfidenceLevel::Low => 0.50,
                    ConfidenceLevel::Medium => 0.70,
                    ConfidenceLevel::High => 0.87,
                    ConfidenceLevel::Verified => 0.95,
                };

                seeds.push((
                    corr.entity_value.clone(),
                    corr.correlation_type.clone(),
                    confidence,
                ));
            }
        }

        // Submit seeds to batch query engine
        if !seeds.is_empty() {
            self.batch_query_engine.extract_seeds_from_results(seeds)
        } else {
            0
        }
    }

    /// Get active batches from the autonomous query engine
    pub fn get_active_batches_count(&self) -> usize {
        self.batch_query_engine.get_active_batches().len()
    }

    /// Process batch query results and integrate findings into scan
    pub fn integrate_batch_results(&mut self, batch_results: Vec<(String, String, f32)>) {
        for (entity_value, source, confidence) in batch_results {
            if confidence >= self.confidence_threshold {
                self.record_entity(&entity_value, &source);
                self.context.correlations_found += 1;
            }
        }
    }

    /// Check if Phase 2 expansion via batch queries should trigger
    pub fn should_execute_batch_expansion(&self) -> bool {
        // Trigger when:
        // - Phase is Correlation or HighValue
        // - At least 2 high-confidence entities exist
        // - At least 1 active batch is ready
        let high_conf_count = self
            .correlations
            .values()
            .filter(|c| c.source_count >= 2)
            .count();

        (self.context.phase == ScanPhase::Correlation || self.context.phase == ScanPhase::HighValue)
            && high_conf_count >= 2
    }

    /// Get batch query statistics for monitoring
    pub fn get_batch_query_stats(&self) -> String {
        let stats = self.batch_query_engine.get_statistics();
        format!(
            "Batch Query Statistics\n\
             =====================\n\
             Total Seeds Discovered: {}\n\
             Seeds Queued: {}\n\
             Seeds Processed: {}\n\
             Batches Created: {}\n\
             Batches Completed: {}\n\
             Queries Executed: {}\n\
             Entities Found: {}\n\
             Total Cost: ${:.2}\n\
             Avg Confidence: {:.1}%\n",
            stats.total_seeds_discovered,
            stats.seeds_queued,
            stats.seeds_processed,
            stats.batches_created,
            stats.batches_completed,
            stats.total_queries_executed,
            stats.entities_found,
            stats.total_cost_spent,
            stats.average_discovery_confidence * 100.0
        )
    }
}

/// Get current time in milliseconds
fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orchestrator_creation() {
        let orch = HseScanOrchestrator::new("rhino-ryno23", "username");
        assert_eq!(orch.context.query, "rhino-ryno23");
        assert_eq!(orch.context.phase, ScanPhase::Initial);
    }

    #[test]
    fn test_phase_advancement() {
        let mut orch = HseScanOrchestrator::new("rhino-ryno23", "username");
        orch.advance_phase(ScanPhase::Correlation);

        assert_eq!(orch.context.phase, ScanPhase::Correlation);
        assert!(!orch.phase_history.is_empty());
    }

    #[test]
    fn test_entity_recording() {
        let mut orch = HseScanOrchestrator::new("rhino-ryno23", "username");

        orch.record_entity("rhino-ryno23", "instagram");
        assert_eq!(orch.context.entities_found, 1);
        assert_eq!(orch.correlations.len(), 1);
    }

    #[test]
    fn test_correlation_confidence() {
        let mut orch = HseScanOrchestrator::new("rhino-ryno23", "username");

        orch.record_entity("rhino-ryno23", "twitter");
        orch.record_entity("rhino-ryno23", "instagram");
        orch.record_entity("rhino-ryno23", "tiktok");

        let entity = orch.correlations.get("rhino-ryno23").unwrap();
        assert_eq!(entity.source_count, 3);
        assert!(entity.confidence >= ConfidenceLevel::High);
    }

    #[test]
    fn test_high_value_api_triggering() {
        let mut orch = HseScanOrchestrator::new("rhino-ryno23", "username");
        orch.advance_phase(ScanPhase::Correlation);

        orch.record_entity("user1", "source1");
        orch.record_entity("user1", "source2");

        assert!(orch.should_trigger_high_value_apis());
    }

    #[test]
    fn test_resource_allocation() {
        let mut orch = HseScanOrchestrator::new("rhino-ryno23", "username");
        orch.advance_phase(ScanPhase::Expansion);
        orch.allocate_resources();

        assert!(orch.resource_allocation.geolocation_calls > 0);
    }

    #[test]
    fn test_get_recommended_apis() {
        let mut orch = HseScanOrchestrator::new("rhino-ryno23", "username");
        orch.advance_phase(ScanPhase::HighValue);

        let apis = orch.get_recommended_apis();
        assert!(apis.contains(&"oathnet_pro".to_string()));
        assert!(apis.contains(&"hibp".to_string()));
    }

    #[test]
    fn test_breach_db_chain() {
        let orch = HseScanOrchestrator::new("rhino-ryno23", "username");
        let chain = orch.get_breach_db_chain();

        assert_eq!(chain[0], "hibp");
        assert_eq!(chain[1], "leakdb");
    }

    #[test]
    fn test_social_platform_priority() {
        let orch = HseScanOrchestrator::new("rhino-ryno23", "username");
        let priority = orch.get_social_platform_priority();

        assert_eq!(priority[0], "twitter");
        assert_eq!(priority[1], "instagram");
    }

    #[test]
    fn test_expansion_depth_check() {
        let orch = HseScanOrchestrator::new("rhino-ryno23", "username");
        assert!(orch.can_expand());
    }

    #[test]
    fn test_scan_summary() {
        let mut orch = HseScanOrchestrator::new("rhino-ryno23", "username");
        orch.record_entity("user", "twitter");

        let summary = orch.get_scan_summary();
        assert!(summary.contains("HSE Scan Summary"));
        assert!(summary.contains("rhino-ryno23"));
    }

    #[test]
    fn test_high_confidence_entity_filtering() {
        let mut orch = HseScanOrchestrator::new("rhino-ryno23", "username");

        orch.record_entity("highly_corr", "s1");
        orch.record_entity("highly_corr", "s2");
        orch.record_entity("highly_corr", "s3");
        orch.record_entity("lowly_corr", "s1");

        let high_conf = orch.get_high_confidence_entities();
        assert!(high_conf.len() >= 1);
    }
}
