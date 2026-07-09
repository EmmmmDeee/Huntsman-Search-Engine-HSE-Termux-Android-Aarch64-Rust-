/// Autonomous Recursion Enhancement: Fixes data loss in multi-depth OSINT scans.
///
/// Addresses 5 critical issues identified in debug logs:
/// 1. Circuit breaker opening mid-scan (SeekNow blocked mid-cascade)
/// 2. Identity mismatch gate too aggressive (13 valid entities suppressed)
/// 3. Module allowlist filtering blocking essential modules (12 modules skipped)
/// 4. OathNet Pro availability gate too strict (requires >=2 sources, blocking valid entities)
/// 5. Expansion tick depth processing incomplete (147 queued, 148 visited gap)

use std::collections::{HashMap, HashSet};

/// Comprehensive tracking of entity flow through recursion depth levels
#[derive(Debug, Clone)]
pub struct RecursionTracker {
    /// Track all queued entities at each depth level (never removed)
    pub depth_queues: HashMap<u32, HashSet<String>>,
    /// Track visited entities at each depth level
    pub depth_visited: HashMap<u32, HashSet<String>>,
    /// Track excluded entities with reasons
    pub exclusions: HashMap<String, ExclusionReason>,
    /// Circuit breaker states per API
    pub circuit_breaker_states: HashMap<String, CircuitBreakerState>,
}

/// Detailed exclusion tracking
#[derive(Debug, Clone, PartialEq)]
pub enum ExclusionReason {
    IdentityMismatch { confidence: f32, source_count: u32 },
    ModuleNotInAllowlist { module: String },
    CircuitBreakerOpen { api: String, attempts: u32 },
    InsufficientCrossCoverage { current_sources: u32, required: u32 },
    NonRoutableIp,
    IncidentalInfra,
}

/// Improved circuit breaker with exponential backoff
#[derive(Debug, Clone)]
pub struct CircuitBreakerState {
    pub api: String,
    pub is_open: bool,
    pub failure_count: u32,
    pub last_failure_timestamp: u64,
    pub backoff_ms: u64,
    pub max_retries_before_open: u32,
}

impl CircuitBreakerState {
    pub fn new(api: &str) -> Self {
        Self {
            api: api.to_string(),
            is_open: false,
            failure_count: 0,
            last_failure_timestamp: 0,
            backoff_ms: 100,
            max_retries_before_open: 10, // Allow 10 retries before opening
        }
    }

    /// Check if enough time has passed to retry
    pub fn can_retry(&self, now_ms: u64) -> bool {
        if !self.is_open {
            return true;
        }
        now_ms >= self.last_failure_timestamp + self.backoff_ms
    }

    /// Record a failure and decide if circuit should open
    pub fn record_failure(&mut self, now_ms: u64) {
        self.failure_count += 1;
        self.last_failure_timestamp = now_ms;
        // Exponential backoff: 100ms, 200ms, 400ms, 800ms, 1600ms, 3200ms, etc.
        if self.failure_count > 1 {
            self.backoff_ms = (self.backoff_ms * 2).min(30_000); // Cap at 30s
        }
        // Only open after max_retries_before_open attempts
        self.is_open = self.failure_count > self.max_retries_before_open;
    }

    /// Record a success and reset state
    pub fn record_success(&mut self) {
        self.failure_count = 0;
        self.is_open = false;
        self.backoff_ms = 100;
    }
}

impl RecursionTracker {
    pub fn new() -> Self {
        Self {
            depth_queues: HashMap::new(),
            depth_visited: HashMap::new(),
            exclusions: HashMap::new(),
            circuit_breaker_states: HashMap::new(),
        }
    }

    /// Add entity to queue at specific depth
    pub fn queue_entity(&mut self, depth: u32, entity: &str) {
        self.depth_queues.entry(depth).or_insert_with(HashSet::new).insert(entity.to_string());
    }

    /// Mark entity as visited at specific depth
    pub fn mark_visited(&mut self, depth: u32, entity: &str) {
        self.depth_visited.entry(depth).or_insert_with(HashSet::new).insert(entity.to_string());
        // Don't remove from queue - we need to track the original count for integrity check
    }

    /// Track entity exclusion with detailed reason
    pub fn record_exclusion(&mut self, entity: &str, reason: ExclusionReason) {
        self.exclusions.insert(entity.to_string(), reason);
    }

    /// Get entities queued at depth that weren't visited
    pub fn get_unvisited_at_depth(&self, depth: u32) -> Vec<String> {
        if let Some(queued) = self.depth_queues.get(&depth) {
            if let Some(visited) = self.depth_visited.get(&depth) {
                return queued.difference(visited).cloned().collect();
            }
            return queued.iter().cloned().collect();
        }
        vec![]
    }

    /// Check recursion flow integrity
    pub fn check_recursion_integrity(&self) -> RecursionIntegrityReport {
        let mut missing_entities = vec![];
        let mut excluded_count = 0;
        let mut total_queued = 0;
        let mut total_visited = 0;

        for (depth, queued) in &self.depth_queues {
            total_queued += queued.len();
            if let Some(visited) = self.depth_visited.get(depth) {
                total_visited += visited.len();
            }
        }

        // Count exclusions from the exclusions map
        for (entity, exclusion) in &self.exclusions {
            if let Some(depth_queues_for_any) = self.depth_queues.values().find(|q| q.contains(entity)) {
                let _ = depth_queues_for_any;
                excluded_count += 1;
                missing_entities.push((entity.clone(), exclusion.clone()));
            }
        }

        RecursionIntegrityReport {
            total_queued,
            total_visited,
            excluded_count,
            missing_entities,
            integrity_healthy: (total_queued - excluded_count) == total_visited,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecursionIntegrityReport {
    pub total_queued: usize,
    pub total_visited: usize,
    pub excluded_count: usize,
    pub missing_entities: Vec<(String, ExclusionReason)>,
    pub integrity_healthy: bool,
}

/// Improved identity matching: Less aggressive gate allowing business names and IDs
pub fn is_suspicious_identity_pivot(
    kind: &str,
    confidence: f32,
    source_count: u32,
    value: &str,
    subject_identities: &[String],
    depth: u32,
) -> bool {
    // At depth 0-1, allow more speculation with unverified identities
    if depth < 2 && confidence >= 0.5 {
        return false;
    }

    // Allow numeric IDs (e.g., 549077161) - they're specific identifiers
    if value.chars().all(|c| c.is_ascii_digit()) && value.len() >= 5 {
        return false;
    }

    // Allow business/org names (typically contain spaces or common words)
    if value.contains(' ') && value.len() > 8 {
        return false;
    }

    // Allow multi-word usernames with underscores/dots
    if (value.contains('_') || value.contains('.') || value.contains('-')) && value.len() > 6 {
        return false;
    }

    // Check overlap only if confidence very low and single-source
    if confidence < 0.50 && source_count <= 1 {
        return !subject_identities.iter().any(|s| simple_identity_overlap(s, value));
    }

    false
}

/// Simple identity overlap check (>= 4 char substring)
fn simple_identity_overlap(a: &str, b: &str) -> bool {
    let a_norm = a.to_lowercase();
    let b_norm = b.to_lowercase();

    if a_norm.len() < 4 || b_norm.len() < 4 {
        return a_norm == b_norm;
    }

    // Check for 4+ char overlap
    for i in 0..=(a_norm.len().saturating_sub(4)) {
        let substring = &a_norm[i..i + 4];
        if b_norm.contains(substring) {
            return true;
        }
    }
    false
}

/// Essential modules that must be in allowlist during recursion
pub fn get_essential_modules() -> Vec<&'static str> {
    vec![
        "search_engines",
        "geocode",
        "photon",
        "au_geo",
        "wigle",
        "opencellid",
        "overpass",
        "qld_cadastre",
        "acma_rrl",
        "au_seifa",
        "cell_local",
        "sunrise_sunset",
    ]
}

/// API availability rules: Less strict cross-coverage requirements
pub fn should_query_api_at_depth(
    api: &str,
    current_sources: u32,
    entity_confidence: f32,
    depth: u32,
    circuit_state: &CircuitBreakerState,
) -> bool {
    // Never query if circuit breaker open and can't retry
    if circuit_state.is_open && !circuit_state.can_retry(get_now_ms()) {
        return false;
    }

    match api {
        "OathNet Pro" => {
            // Relax requirement: allow at >= 1 source and confidence > 0.4
            // Original was >= 2 sources, was too strict
            current_sources >= 1 && entity_confidence > 0.4
        }
        "SeekNow" => {
            // Allow even at depth > 2 with circuit breaker managing retries
            !circuit_state.is_open || circuit_state.can_retry(get_now_ms())
        }
        _ => true,
    }
}

/// Get current timestamp in milliseconds
fn get_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_exponential_backoff() {
        let mut cb = CircuitBreakerState::new("SeekNow");
        assert!(!cb.is_open);
        assert_eq!(cb.backoff_ms, 100);

        // Record failures up to limit
        for i in 0..10 {
            cb.record_failure(i as u64 * 100);
            assert!(!cb.is_open); // Should not open until after max_retries
        }

        // Next failure should open circuit
        cb.record_failure(1000);
        assert!(cb.is_open);
        assert!(cb.backoff_ms > 100); // Exponential backoff applied

        // Success should reset
        cb.record_success();
        assert!(!cb.is_open);
        assert_eq!(cb.failure_count, 0);
    }

    #[test]
    fn test_recursion_tracker_integrity() {
        let mut tracker = RecursionTracker::new();

        // Queue 10 entities at depth 0
        for i in 0..10 {
            tracker.queue_entity(0, &format!("entity_{}", i));
        }

        // Visit 8 of them
        for i in 0..8 {
            tracker.mark_visited(0, &format!("entity_{}", i));
        }

        // Record exclusions for missing ones
        tracker.record_exclusion("entity_8", ExclusionReason::IdentityMismatch {
            confidence: 0.4,
            source_count: 1,
        });
        tracker.record_exclusion("entity_9", ExclusionReason::ModuleNotInAllowlist {
            module: "search_engines".to_string(),
        });

        let report = tracker.check_recursion_integrity();
        assert_eq!(report.total_queued, 10);
        assert_eq!(report.total_visited, 8);
        assert_eq!(report.excluded_count, 2, "Expected 2 exclusions, got {}: {:?}", report.excluded_count, report.missing_entities);
        assert_eq!(report.missing_entities.len(), 2);
    }

    #[test]
    fn test_improved_identity_gate_allows_business_names() {
        let subject = vec!["matthew".to_string(), "diegmann".to_string()];

        // Business name: should NOT be suppressed
        assert!(!is_suspicious_identity_pivot(
            "username",
            0.55,
            1,
            "Ipswich Golf and Putt",
            &subject,
            0
        ));

        // Numeric ID: should NOT be suppressed
        assert!(!is_suspicious_identity_pivot(
            "username",
            0.55,
            1,
            "549077161",
            &subject,
            0
        ));

        // Underscore name: should NOT be suppressed
        assert!(!is_suspicious_identity_pivot(
            "username",
            0.55,
            1,
            "rohan_sforcina",
            &subject,
            0
        ));

        // Completely unrelated string: low confidence, single source, might still be gated
        assert!(is_suspicious_identity_pivot(
            "username",
            0.3,
            1,
            "completelyrandom",
            &subject,
            0
        ));
    }

    #[test]
    fn test_essential_modules_included() {
        let essential = get_essential_modules();
        assert!(essential.contains(&"search_engines"));
        assert!(essential.contains(&"geocode"));
        assert!(essential.contains(&"photon"));
        assert!(essential.contains(&"wigle"));
    }

    #[test]
    fn test_oathnet_relaxed_requirements() {
        let mut cb = CircuitBreakerState::new("OathNet Pro");
        cb.record_success();

        // Should query with >=1 source and confidence >0.4
        assert!(should_query_api_at_depth(
            "OathNet Pro",
            1, // Just 1 source (relaxed from 2)
            0.5,
            1,
            &cb
        ));

        assert!(should_query_api_at_depth(
            "OathNet Pro",
            2,
            0.85,
            2,
            &cb
        ));
    }

    #[test]
    fn test_unvisited_tracking() {
        let mut tracker = RecursionTracker::new();
        tracker.queue_entity(0, "entity_1");
        tracker.queue_entity(0, "entity_2");
        tracker.queue_entity(0, "entity_3");

        tracker.mark_visited(0, "entity_1");
        tracker.mark_visited(0, "entity_2");

        let unvisited = tracker.get_unvisited_at_depth(0);
        assert_eq!(unvisited.len(), 1);
        assert!(unvisited.contains(&"entity_3".to_string()));
    }
}
