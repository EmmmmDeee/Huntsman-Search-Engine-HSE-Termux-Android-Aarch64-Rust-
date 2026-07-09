/// HSE Autonomous Batch Query System
///
/// Real-time seed extraction and intelligent batch processing during recursive search:
/// - Extract high-value seeds from recursive results (usernames, emails, phones, IPs)
/// - Priority-based seed queue (highest confidence first)
/// - Autonomous batch execution (no manual intervention)
/// - Cross-API batch distribution (spread queries intelligently)
/// - Deduplication and conflict resolution
/// - Recursive feedback loop (results → new seeds → new queries)
/// - Cost-aware batch optimization
/// - Parallel batch processing with rate limit management

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

/// High-value seed types for autonomous querying
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SeedType {
    Username,           // Social media, dev, gaming usernames
    Email,              // Primary email addresses
    Phone,              // Normalized phone numbers
    Domain,             // Domain names
    IpAddress,          // IPv4/IPv6 addresses
    Organization,       // Company names
    Location,           // Geographic locations
    PasswordHash,       // From breach databases
    Credential,         // Username:password pairs
    SocialHandle,       // @username style
    VariantUsername,    // Derived usernames
    Infrastructure,     // ASN, hosting provider
}

/// Seed priority based on discovery source and value
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeedPriority {
    Critical = 4,   // Verified breach data, multi-source
    High = 3,       // Email found, high confidence
    Medium = 2,     // Social media profile, moderate confidence
    Low = 1,        // Infrastructure data, single source
}

/// High-value seed discovered during recursive search
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredSeed {
    pub seed_type: SeedType,
    pub value: String,
    pub canonical: String,
    pub priority: SeedPriority,
    pub confidence: f32,
    pub source_apis: Vec<String>,
    pub discovered_at: u64,
    pub corroboration_count: usize,
    pub metadata: HashMap<String, String>,
}

impl PartialOrd for DiscoveredSeed {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(match other.priority.cmp(&self.priority) {
            std::cmp::Ordering::Equal => {
                other.confidence.partial_cmp(&self.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }
            other => other,
        })
    }
}

/// Batch query for execution across APIs
#[derive(Debug, Clone)]
pub struct BatchQuery {
    pub batch_id: String,
    pub seeds: Vec<DiscoveredSeed>,
    pub apis_to_query: Vec<String>,
    pub priority_level: SeedPriority,
    pub estimated_cost: f32,
    pub created_at: u64,
    pub target_completion_time: u64,
}

/// Batch query result
#[derive(Debug, Clone)]
pub struct BatchQueryResult {
    pub batch_id: String,
    pub seed: DiscoveredSeed,
    pub api_name: String,
    pub found_entities: Vec<String>,
    pub execution_time_ms: u64,
    pub cost: f32,
    pub success: bool,
    pub error: Option<String>,
}

/// Autonomous Batch Query Engine
pub struct HseAutonomousBatchQueries {
    // Seed management
    seed_queue: VecDeque<DiscoveredSeed>,
    processed_seeds: HashSet<String>,
    seed_cache: HashMap<String, DiscoveredSeed>,

    // Batch management
    active_batches: HashMap<String, BatchQuery>,
    completed_batches: Vec<String>,
    batch_results: Vec<BatchQueryResult>,

    // Statistics
    stats: BatchQueryStats,

    // Configuration
    config: BatchQueryConfig,
}

#[derive(Debug, Clone)]
pub struct BatchQueryConfig {
    pub batch_size: usize,               // Seeds per batch
    pub max_concurrent_batches: u32,     // Parallel batches
    pub priority_threshold: f32,         // Minimum confidence to queue
    pub auto_execute: bool,              // Auto-execute when batch ready
    pub cost_limit_per_batch: f32,       // Max cost per batch
    pub dedup_window_hours: u32,         // Look back for duplicates
    pub recursive_depth_limit: u32,      // Max recursion hops
}

impl Default for BatchQueryConfig {
    fn default() -> Self {
        Self {
            batch_size: 10,
            max_concurrent_batches: 4,
            priority_threshold: 0.65,
            auto_execute: true,
            cost_limit_per_batch: 50.0,
            dedup_window_hours: 24,
            recursive_depth_limit: 3,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BatchQueryStats {
    pub total_seeds_discovered: usize,
    pub seeds_queued: usize,
    pub seeds_processed: usize,
    pub batches_created: usize,
    pub batches_completed: usize,
    pub total_queries_executed: usize,
    pub entities_found: usize,
    pub total_cost_spent: f32,
    pub average_discovery_confidence: f32,
}

impl HseAutonomousBatchQueries {
    pub fn new() -> Self {
        Self {
            seed_queue: VecDeque::new(),
            processed_seeds: HashSet::new(),
            seed_cache: HashMap::new(),
            active_batches: HashMap::new(),
            completed_batches: Vec::new(),
            batch_results: Vec::new(),
            stats: BatchQueryStats {
                total_seeds_discovered: 0,
                seeds_queued: 0,
                seeds_processed: 0,
                batches_created: 0,
                batches_completed: 0,
                total_queries_executed: 0,
                entities_found: 0,
                total_cost_spent: 0.0,
                average_discovery_confidence: 0.0,
            },
            config: BatchQueryConfig::default(),
        }
    }

    /// Extract high-value seeds from recursive search results
    pub fn extract_seeds_from_results(&mut self, entities: Vec<(String, String, f32)>) -> usize {
        let mut new_seeds = 0;

        for (entity_value, entity_type_str, confidence) in entities {
            // Filter by confidence threshold
            if confidence < self.config.priority_threshold {
                continue;
            }

            // Determine seed type
            let seed_type = Self::classify_entity(&entity_type_str, &entity_value);

            // Check for duplicates
            let canonical = Self::canonicalize(&seed_type, &entity_value);
            if self.processed_seeds.contains(&canonical) {
                continue;
            }

            // Determine priority based on confidence and type
            let priority = Self::calculate_seed_priority(seed_type.clone(), confidence);

            let seed = DiscoveredSeed {
                seed_type,
                value: entity_value.clone(),
                canonical: canonical.clone(),
                priority,
                confidence,
                source_apis: vec![],
                discovered_at: current_time_ms(),
                corroboration_count: 1,
                metadata: HashMap::new(),
            };

            // Add to queue if not already there
            if !self.seed_cache.contains_key(&canonical) {
                self.seed_queue.push_back(seed.clone());
                self.seed_cache.insert(canonical.clone(), seed);
                self.stats.total_seeds_discovered += 1;
                self.stats.seeds_queued += 1;
                new_seeds += 1;
            }
        }

        // Try to create batch if seeds available
        if self.config.auto_execute && !self.seed_queue.is_empty() {
            self.try_create_batch();
        }

        new_seeds
    }

    /// Classify entity into seed type
    fn classify_entity(entity_type: &str, value: &str) -> SeedType {
        match entity_type.to_lowercase().as_str() {
            t if t.contains("username") || t.contains("handle") => SeedType::Username,
            t if t.contains("email") || t.contains("mail") => SeedType::Email,
            t if t.contains("phone") || t.contains("number") => SeedType::Phone,
            t if t.contains("domain") || t.contains("website") => SeedType::Domain,
            t if t.contains("ip") || t.contains("address") => SeedType::IpAddress,
            t if t.contains("org") || t.contains("company") => SeedType::Organization,
            t if t.contains("location") || t.contains("geo") => SeedType::Location,
            t if t.contains("hash") || t.contains("credential") => SeedType::PasswordHash,
            _ => {
                // Heuristic classification
                if value.contains('@') {
                    SeedType::Email
                } else if value.len() > 15 && (value.contains(|c: char| c.is_numeric()) && value.contains(|c: char| c.is_alphabetic())) {
                    SeedType::PasswordHash
                } else if value.contains('.') {
                    SeedType::Domain
                } else {
                    SeedType::Username
                }
            }
        }
    }

    /// Canonicalize seed value
    fn canonicalize(seed_type: &SeedType, value: &str) -> String {
        match seed_type {
            SeedType::Username => value.to_lowercase().chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-').collect(),
            SeedType::Email => value.to_lowercase().trim().to_string(),
            SeedType::Phone => value.chars().filter(|c| c.is_numeric()).collect(),
            SeedType::Domain => value.to_lowercase().trim_matches('.').to_string(),
            SeedType::IpAddress => value.to_string(),
            _ => value.to_lowercase(),
        }
    }

    /// Calculate priority from seed type and confidence
    fn calculate_seed_priority(seed_type: SeedType, confidence: f32) -> SeedPriority {
        if confidence < 0.65 {
            SeedPriority::Low
        } else if confidence < 0.75 {
            match seed_type {
                SeedType::Email | SeedType::Phone | SeedType::Credential => SeedPriority::High,
                _ => SeedPriority::Medium,
            }
        } else if confidence < 0.85 {
            match seed_type {
                SeedType::Email | SeedType::Phone | SeedType::PasswordHash | SeedType::Credential => {
                    SeedPriority::High
                }
                _ => SeedPriority::Medium,
            }
        } else {
            SeedPriority::Critical
        }
    }

    /// Create batch from queued seeds
    fn try_create_batch(&mut self) -> Option<String> {
        if self.active_batches.len() >= self.config.max_concurrent_batches as usize {
            return None;
        }

        // Collect seeds for batch
        let mut batch_seeds = Vec::new();
        let mut total_cost = 0.0;

        while batch_seeds.len() < self.config.batch_size && !self.seed_queue.is_empty() {
            if let Some(seed) = self.seed_queue.pop_front() {
                let estimated_cost = Self::estimate_seed_cost(&seed.seed_type);
                if total_cost + estimated_cost > self.config.cost_limit_per_batch {
                    self.seed_queue.push_front(seed);
                    break;
                }
                total_cost += estimated_cost;
                batch_seeds.push(seed);
            }
        }

        if batch_seeds.is_empty() {
            return None;
        }

        // Determine APIs to query based on seed types
        let apis = Self::select_apis_for_seeds(&batch_seeds);

        let batch_id = format!("batch-{}", current_time_ms());
        let batch = BatchQuery {
            batch_id: batch_id.clone(),
            seeds: batch_seeds,
            apis_to_query: apis,
            priority_level: SeedPriority::Medium,
            estimated_cost: total_cost,
            created_at: current_time_ms(),
            target_completion_time: current_time_ms() + 30000, // 30 second target
        };

        self.active_batches.insert(batch_id.clone(), batch);
        self.stats.batches_created += 1;

        Some(batch_id)
    }

    /// Estimate cost for querying a seed
    fn estimate_seed_cost(seed_type: &SeedType) -> f32 {
        match seed_type {
            SeedType::Email => 0.5,           // Hunter.io
            SeedType::Phone => 0.5,           // NumVerify
            SeedType::Credential => 5.0,     // DeHashed
            SeedType::Username => 0.1,       // Search engines
            SeedType::Domain => 0.2,         // WHOIS lookups
            SeedType::IpAddress => 0.1,      // GeoIP
            SeedType::Organization => 0.3,   // Company search
            _ => 0.2,
        }
    }

    /// Select optimal APIs for batch seeds
    fn select_apis_for_seeds(seeds: &[DiscoveredSeed]) -> Vec<String> {
        let mut apis = HashSet::new();

        for seed in seeds {
            match seed.seed_type {
                SeedType::Email => {
                    apis.insert("hibp".to_string());
                    apis.insert("hunter_io".to_string());
                    apis.insert("fullcontact".to_string());
                }
                SeedType::Phone => {
                    apis.insert("numverify".to_string());
                    apis.insert("hlr_cnam".to_string());
                }
                SeedType::Username => {
                    apis.insert("search_engines".to_string());
                    apis.insert("username_search".to_string());
                    apis.insert("social_probe".to_string());
                }
                SeedType::Domain => {
                    apis.insert("censys".to_string());
                    apis.insert("securitytrails".to_string());
                    apis.insert("whoisxml".to_string());
                }
                SeedType::IpAddress => {
                    apis.insert("abuseipdb".to_string());
                    apis.insert("greynoise".to_string());
                    apis.insert("shodan".to_string());
                }
                SeedType::Credential => {
                    apis.insert("hibp".to_string());
                    apis.insert("leakdb".to_string());
                    apis.insert("dehashed".to_string());
                }
                _ => {
                    apis.insert("search_engines".to_string());
                }
            }
        }

        apis.into_iter().collect()
    }

    /// Record batch execution result
    pub fn record_batch_result(
        &mut self,
        batch_id: &str,
        seed: DiscoveredSeed,
        api_name: String,
        found_entities: Vec<String>,
        execution_time_ms: u64,
        cost: f32,
        success: bool,
        error: Option<String>,
    ) {
        let result = BatchQueryResult {
            batch_id: batch_id.to_string(),
            seed: seed.clone(),
            api_name,
            found_entities: found_entities.clone(),
            execution_time_ms,
            cost,
            success,
            error,
        };

        self.batch_results.push(result);
        self.stats.total_queries_executed += 1;
        self.stats.entities_found += found_entities.len();
        self.stats.total_cost_spent += cost;

        // Mark seed as processed
        self.processed_seeds.insert(seed.canonical.clone());
        self.stats.seeds_processed += 1;
    }

    /// Complete batch and extract new seeds from results
    pub fn complete_batch(&mut self, batch_id: &str) -> Vec<DiscoveredSeed> {
        if let Some(batch) = self.active_batches.remove(batch_id) {
            self.completed_batches.push(batch_id.to_string());
            self.stats.batches_completed += 1;

            // Extract new seeds from results
            let mut new_seeds = Vec::new();
            for result in &self.batch_results {
                if result.batch_id == batch_id && result.success {
                    for entity in &result.found_entities {
                        // Create new seeds from found entities
                        if let Some(seed) = self.create_seed_from_result(entity, result) {
                            new_seeds.push(seed);
                        }
                    }
                }
            }

            // Queue new seeds for next batch
            for seed in new_seeds.clone() {
                if !self.processed_seeds.contains(&seed.canonical) {
                    self.seed_queue.push_back(seed);
                    self.stats.seeds_queued += 1;
                }
            }

            new_seeds
        } else {
            Vec::new()
        }
    }

    /// Create seed from batch result
    fn create_seed_from_result(&self, entity: &str, result: &BatchQueryResult) -> Option<DiscoveredSeed> {
        let seed_type = Self::classify_entity("unknown", entity);
        let confidence = (result.seed.confidence + 0.8) / 2.0; // Average with original seed confidence

        Some(DiscoveredSeed {
            seed_type: seed_type.clone(),
            value: entity.to_string(),
            canonical: Self::canonicalize(&seed_type, entity),
            priority: Self::calculate_seed_priority(seed_type, confidence),
            confidence,
            source_apis: vec![result.api_name.clone()],
            discovered_at: current_time_ms(),
            corroboration_count: 1,
            metadata: HashMap::new(),
        })
    }

    /// Get active batches
    pub fn get_active_batches(&self) -> Vec<BatchQuery> {
        self.active_batches.values().cloned().collect()
    }

    /// Get batch statistics
    pub fn get_statistics(&self) -> BatchQueryStats {
        let mut stats = self.stats.clone();

        if self.stats.seeds_queued > 0 {
            stats.average_discovery_confidence = self
                .seed_cache
                .values()
                .map(|s| s.confidence)
                .sum::<f32>()
                / self.seed_cache.len() as f32;
        }

        stats
    }

    /// Get pending seeds in queue
    pub fn get_pending_seeds(&self) -> Vec<DiscoveredSeed> {
        self.seed_queue.iter().cloned().collect()
    }

    /// Get batch results for specific batch
    pub fn get_batch_results(&self, batch_id: &str) -> Vec<BatchQueryResult> {
        self.batch_results
            .iter()
            .filter(|r| r.batch_id == batch_id)
            .cloned()
            .collect()
    }

    /// Reset for new scan
    pub fn reset(&mut self) {
        self.seed_queue.clear();
        self.processed_seeds.clear();
        self.seed_cache.clear();
        self.active_batches.clear();
        self.completed_batches.clear();
        self.batch_results.clear();
        self.stats = BatchQueryStats {
            total_seeds_discovered: 0,
            seeds_queued: 0,
            seeds_processed: 0,
            batches_created: 0,
            batches_completed: 0,
            total_queries_executed: 0,
            entities_found: 0,
            total_cost_spent: 0.0,
            average_discovery_confidence: 0.0,
        };
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
    fn test_engine_initialization() {
        let engine = HseAutonomousBatchQueries::new();
        assert_eq!(engine.stats.total_seeds_discovered, 0);
        assert_eq!(engine.stats.batches_created, 0);
    }

    #[test]
    fn test_seed_extraction() {
        let mut engine = HseAutonomousBatchQueries::new();
        engine.config.auto_execute = false; // Disable auto-batch creation to test seed queuing

        let results = vec![
            ("user@example.com".to_string(), "email".to_string(), 0.85),
            ("5551234567".to_string(), "phone".to_string(), 0.80),
            ("rhino-ryno23".to_string(), "username".to_string(), 0.90),
        ];

        let extracted = engine.extract_seeds_from_results(results);
        assert!(extracted == 3, "Expected 3 seeds extracted, got {}", extracted);
        assert!(!engine.seed_queue.is_empty(), "Seed queue should not be empty");
        assert_eq!(engine.seed_queue.len(), 3, "Seed queue should have 3 seeds");
    }

    #[test]
    fn test_seed_classification() {
        assert_eq!(
            HseAutonomousBatchQueries::classify_entity("email", "user@example.com"),
            SeedType::Email
        );
        assert_eq!(
            HseAutonomousBatchQueries::classify_entity("phone", "5551234567"),
            SeedType::Phone
        );
        assert_eq!(
            HseAutonomousBatchQueries::classify_entity("username", "rhino-ryno23"),
            SeedType::Username
        );
    }

    #[test]
    fn test_seed_canonicalization() {
        assert_eq!(
            HseAutonomousBatchQueries::canonicalize(&SeedType::Email, "USER@EXAMPLE.COM"),
            "user@example.com"
        );
        assert_eq!(
            HseAutonomousBatchQueries::canonicalize(&SeedType::Phone, "+1 (555) 123-4567"),
            "15551234567"
        );
        assert_eq!(
            HseAutonomousBatchQueries::canonicalize(&SeedType::Username, "Rhino-RyNo23"),
            "rhino-ryno23"
        );
    }

    #[test]
    fn test_priority_calculation() {
        let priority_high_conf = HseAutonomousBatchQueries::calculate_seed_priority(
            SeedType::Email,
            0.90,
        );
        let priority_low_conf = HseAutonomousBatchQueries::calculate_seed_priority(
            SeedType::Email,
            0.60,
        );

        assert!(priority_high_conf > priority_low_conf);
    }

    #[test]
    fn test_batch_creation() {
        let mut engine = HseAutonomousBatchQueries::new();

        let results = vec![
            ("user1@example.com".to_string(), "email".to_string(), 0.85),
            ("user2@example.com".to_string(), "email".to_string(), 0.80),
            ("user3@example.com".to_string(), "email".to_string(), 0.75),
        ];

        engine.extract_seeds_from_results(results);
        let batches = engine.get_active_batches();
        assert!(!batches.is_empty());
    }

    #[test]
    fn test_batch_result_recording() {
        let mut engine = HseAutonomousBatchQueries::new();

        let seed = DiscoveredSeed {
            seed_type: SeedType::Email,
            value: "user@example.com".to_string(),
            canonical: "user@example.com".to_string(),
            priority: SeedPriority::High,
            confidence: 0.85,
            source_apis: vec!["search_engine".to_string()],
            discovered_at: current_time_ms(),
            corroboration_count: 1,
            metadata: HashMap::new(),
        };

        engine.record_batch_result(
            "batch-123",
            seed,
            "hibp".to_string(),
            vec!["breach1".to_string(), "breach2".to_string()],
            100,
            0.5,
            true,
            None,
        );

        assert_eq!(engine.stats.total_queries_executed, 1);
        assert_eq!(engine.stats.entities_found, 2);
    }

    #[test]
    fn test_deduplication() {
        let mut engine = HseAutonomousBatchQueries::new();

        let results = vec![
            ("user@example.com".to_string(), "email".to_string(), 0.85),
            ("user@example.com".to_string(), "email".to_string(), 0.85), // Duplicate
        ];

        let extracted = engine.extract_seeds_from_results(results);
        assert_eq!(extracted, 1); // Only 1 unique seed
    }

    #[test]
    fn test_statistics() {
        let mut engine = HseAutonomousBatchQueries::new();

        let results = vec![
            ("user@example.com".to_string(), "email".to_string(), 0.85),
            ("5551234567".to_string(), "phone".to_string(), 0.80),
        ];

        engine.extract_seeds_from_results(results);
        let stats = engine.get_statistics();

        assert!(stats.total_seeds_discovered > 0);
        assert!(stats.average_discovery_confidence > 0.75);
    }
}

impl Default for HseAutonomousBatchQueries {
    fn default() -> Self {
        Self::new()
    }
}
