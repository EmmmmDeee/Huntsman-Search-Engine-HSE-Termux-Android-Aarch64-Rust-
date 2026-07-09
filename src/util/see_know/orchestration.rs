/// Enterprise orchestration logic: coordinates workflow execution, endpoint routing,
/// budget management, force-multiplier cascade, and monitoring for hardcoded optimization.

use super::enterprise_config::*;
use super::endpoint_matrix::*;
use super::force_multiplier::*;

/// Scan execution plan (hardcoded based on target type and available budget).
pub struct ExecutionPlan {
    pub target_type: &'static str,
    pub workflow_profile: &'static str,
    pub endpoints: Vec<EndpointCall>,
    pub estimated_duration_secs: u32,
    pub estimated_cost: u32,
    pub expected_entities: u32,
}

/// Individual endpoint call in the execution plan.
pub struct EndpointCall {
    pub endpoint_name: &'static str,
    pub endpoint_path: &'static str,
    pub credit_cost: u32,
    pub priority: u32, // 1-100, higher = call first
    pub retry_count: u32,
    pub timeout_ms: u32,
}

/// Auto-plan generation: given target type and budget, generate optimal execution plan.
pub fn generate_execution_plan(
    target_type: &'static str,
    available_budget: u32,
) -> Option<ExecutionPlan> {
    // Find the routing for this target type
    let routing = TARGET_TYPE_ROUTING
        .iter()
        .find(|r| r.target_type == target_type)?;

    // Select primary endpoints (always included)
    let mut endpoints: Vec<EndpointCall> = routing
        .primary_endpoints
        .iter()
        .enumerate()
        .map(|(idx, endpoint_name)| {
            let spec = ALL_ENDPOINTS
                .iter()
                .find(|e| e.name == *endpoint_name)
                .unwrap();
            EndpointCall {
                endpoint_name: spec.name,
                endpoint_path: spec.path,
                credit_cost: spec.credits,
                priority: 100 - (idx as u32 * 10), // primary endpoints higher priority
                retry_count: if spec.credits <= 1 { 2 } else { 1 },
                timeout_ms: 10_000,
            }
        })
        .collect();

    // Add expansion endpoints if budget allows
    let primary_cost: u32 = endpoints.iter().map(|e| e.credit_cost).sum();
    let remaining_budget = available_budget.saturating_sub(primary_cost);

    if remaining_budget > 0 {
        for endpoint_name in routing.expansion_endpoints {
            if let Some(spec) = ALL_ENDPOINTS.iter().find(|e| e.name == *endpoint_name) {
                if remaining_budget >= spec.credits {
                    endpoints.push(EndpointCall {
                        endpoint_name: spec.name,
                        endpoint_path: spec.path,
                        credit_cost: spec.credits,
                        priority: 50,
                        retry_count: 1,
                        timeout_ms: 15_000,
                    });
                }
            }
        }
    }

    // Sort by priority (descending)
    endpoints.sort_by(|a, b| b.priority.cmp(&a.priority));

    let total_cost: u32 = endpoints.iter().map(|e| e.credit_cost).sum();
    let workflow = WORKFLOWS
        .iter()
        .find(|w| w.name == target_type)
        .unwrap_or(&WORKFLOWS[0]);

    Some(ExecutionPlan {
        target_type,
        workflow_profile: workflow.name,
        endpoints,
        estimated_duration_secs: workflow.estimated_time_secs,
        estimated_cost: total_cost,
        expected_entities: workflow.typical_entities,
    })
}

/// Scan strategy (hardcoded decision tree for enterprise operations).
pub enum ScanStrategy {
    /// Quick verification (depth 1): fast, low budget, high confidence
    QuickVerify,
    /// Balanced reconnaissance (depth 2): good coverage, moderate budget
    Balanced,
    /// Deep infrastructure assessment (depth 3): max coverage, high budget
    DeepAssessment,
    /// Threat hunting with cascade (depth 3+): force-multiplier priority
    ThreatHunting,
}

/// Auto-select scan strategy based on target type and available budget.
pub fn select_scan_strategy(target_type: &str, budget: u32) -> ScanStrategy {
    match (target_type, budget) {
        (_, 0..=100) => ScanStrategy::QuickVerify,
        ("email" | "phone" | "ip", 101..=300) => ScanStrategy::QuickVerify,
        ("username" | "domain" | "name", 101..=299) => ScanStrategy::Balanced,
        (_, 300..=749) => ScanStrategy::Balanced,
        ("domain" | "name", 750..=1499) => ScanStrategy::DeepAssessment,
        ("username", 750..=1999) => ScanStrategy::ThreatHunting,
        (_, 1500..=u32::MAX) => ScanStrategy::DeepAssessment,
        _ => ScanStrategy::Balanced,
    }
}

/// Monitoring alerts triggered during scan execution.
pub enum MonitoringAlert {
    QuotaWarning80Percent,
    QuotaWarning50Percent,
    SlowResponse,
    HighErrorRate,
    CacheMiss,
    ForceMultiplierFound,
    InvalidKey,
}

/// Alert thresholds for real-time monitoring (hardcoded from enterprise config).
pub struct AlertThresholds {
    pub quota_warning_percent: u32,
    pub response_time_warn_ms: u32,
    pub error_rate_warn_percent: u32,
    pub cache_hit_rate_min_percent: u32,
}

pub const ALERT_THRESHOLDS: AlertThresholds = AlertThresholds {
    quota_warning_percent: 80,
    response_time_warn_ms: 30_000,
    error_rate_warn_percent: 20,
    cache_hit_rate_min_percent: 10,
};

/// Optimization recommendations (hardcoded from cost analytics).
pub enum OptimizationRecommendation {
    IncreaseDepthForROI,          // your cost per entity is high, try deeper scan
    ReduceDepthToSaveQuota,        // cost per entity is low at current depth, stop there
    BatchMultipleTargets,          // similar targets, batch them for cache efficiency
    FocusOnForceMultiplier,        // API keys found, prioritize cascading
    UseQuickVerifyOnly,            // budget is tight, use depth 1
    MixApproach,                   // balanced depth 2 approach is optimal
}

pub fn recommend_optimization(target_type: &str, cost_per_entity: f32) -> OptimizationRecommendation {
    match (target_type, cost_per_entity) {
        // Email: 0.17 is already good, no change
        ("email", 0.10..=0.25) => OptimizationRecommendation::MixApproach,
        ("email", cost) if cost < 0.10 => OptimizationRecommendation::IncreaseDepthForROI,
        ("email", _) => OptimizationRecommendation::ReduceDepthToSaveQuota,

        // Domain: 0.06 is excellent, already optimal
        ("domain", 0.01..=0.10) => OptimizationRecommendation::MixApproach,
        ("domain", cost) if cost > 0.10 => OptimizationRecommendation::ReduceDepthToSaveQuota,

        // Username: 0.20 is good at depth 2
        ("username", 0.15..=0.30) => OptimizationRecommendation::MixApproach,
        ("username", cost) if cost < 0.15 => OptimizationRecommendation::IncreaseDepthForROI,
        ("username", _) => OptimizationRecommendation::ReduceDepthToSaveQuota,

        _ => OptimizationRecommendation::MixApproach,
    }
}

/// Concurrent execution profile (hardcoded parallelism settings for enterprise plan).
pub struct ConcurrencyProfile {
    pub name: &'static str,
    pub max_concurrent_endpoints: u32,
    pub max_concurrent_scans: u32,
    pub queue_depth: u32,
}

pub const CONCURRENCY_PROFILES: &[ConcurrencyProfile] = &[
    ConcurrencyProfile {
        name: "sequential",
        max_concurrent_endpoints: 1,
        max_concurrent_scans: 1,
        queue_depth: 1,
    },
    ConcurrencyProfile {
        name: "balanced",
        max_concurrent_endpoints: 4,
        max_concurrent_scans: 2,
        queue_depth: 8,
    },
    ConcurrencyProfile {
        name: "aggressive",
        max_concurrent_endpoints: 8,
        max_concurrent_scans: 4,
        queue_depth: 16,
    },
];

pub fn select_concurrency_profile(daily_budget: u32) -> &'static ConcurrencyProfile {
    match daily_budget {
        0..=1000 => &CONCURRENCY_PROFILES[0],      // sequential
        1001..=5000 => &CONCURRENCY_PROFILES[1],   // balanced
        _ => &CONCURRENCY_PROFILES[2],             // aggressive (15k plan)
    }
}

/// Entity correlation rules (hardcoded for deduplication).
pub struct CorrelationRule {
    pub entity_type1: &'static str,
    pub entity_type2: &'static str,
    pub correlation_strength: f32, // 0.0-1.0
}

pub const CORRELATION_RULES: &[CorrelationRule] = &[
    CorrelationRule {
        entity_type1: "email",
        entity_type2: "username",
        correlation_strength: 0.95,
    },
    CorrelationRule {
        entity_type1: "email",
        entity_type2: "person",
        correlation_strength: 0.90,
    },
    CorrelationRule {
        entity_type1: "domain",
        entity_type2: "ip_address",
        correlation_strength: 0.85,
    },
    CorrelationRule {
        entity_type1: "api_key",
        entity_type2: "domain",
        correlation_strength: 0.80,
    },
    CorrelationRule {
        entity_type1: "credentials",
        entity_type2: "email",
        correlation_strength: 0.95,
    },
];

/// Hardcoded response time SLA expectations per endpoint category.
pub struct SLAExpectation {
    pub category: &'static str,
    pub p50_ms: u32,
    pub p95_ms: u32,
}

pub const SLA_EXPECTATIONS: &[SLAExpectation] = &[
    SLAExpectation { category: "search_fast", p50_ms: 2_000, p95_ms: 5_000 },
    SLAExpectation { category: "search_deep", p50_ms: 20_000, p95_ms: 40_000 },
    SLAExpectation { category: "network_lookups", p50_ms: 800, p95_ms: 2_000 },
    SLAExpectation { category: "domain_intel", p50_ms: 1_500, p95_ms: 4_000 },
];

/// Orchestration state machine: scan execution progression (hardcoded).
pub enum OrchestrationState {
    Initializing,          // loading config, checking credentials
    ProbingQuota,          // calling /credits endpoint
    PlanningEndpoints,     // selecting endpoints based on budget
    ExecutingPrimary,      // calling primary endpoints
    ExecutingExpansion,    // calling expansion endpoints if budget allows
    ExtractingEntities,    // extracting 17 entity types
    CascadingForceMulti,   // validating API keys, unlocking downstream
    Correlating,           // deduplicating and linking entities
    Monitoring,            // logging metrics and alerts
    Complete,              // scan finished
}

/// Hardcoded retry strategy (backoff parameters for transient errors).
pub struct RetryStrategy {
    pub max_attempts: u32,
    pub initial_backoff_ms: u32,
    pub max_backoff_ms: u32,
    pub jitter: bool,
}

pub const RETRY_STRATEGY: RetryStrategy = RetryStrategy {
    max_attempts: 3,
    initial_backoff_ms: 2_000,
    max_backoff_ms: 8_000,
    jitter: true,
};

/// Fallback behavior when an endpoint fails (hardcoded per endpoint type).
pub enum FallbackBehavior {
    SkipEndpoint,           // skip this endpoint, continue with others
    RetryWithBackoff,       // retry with exponential backoff
    FallbackToSearchFast,   // fallback to /search endpoint
    GracefulDegradation,    // continue without this data
}

pub fn select_fallback_behavior(endpoint_category: &str) -> FallbackBehavior {
    match endpoint_category {
        "search_fast" => FallbackBehavior::SkipEndpoint,
        "search_deep" => FallbackBehavior::FallbackToSearchFast,
        "network_" => FallbackBehavior::RetryWithBackoff,
        "domain_" => FallbackBehavior::RetryWithBackoff,
        "social_" => FallbackBehavior::GracefulDegradation,
        "gaming_" => FallbackBehavior::GracefulDegradation,
        "enterprise_" => FallbackBehavior::SkipEndpoint,
        _ => FallbackBehavior::GracefulDegradation,
    }
}
