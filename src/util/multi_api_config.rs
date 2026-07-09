/// Exhaustive multi-API orchestration configuration.
/// Coordinates 12+ paid APIs with unified budget, credit tracking, intelligent chaining,
/// and automatic cost optimization across all intelligence sources.

/// All paid APIs integrated into HSE (hardcoded registry).
pub enum PaidApi {
    SeekNow,           // 212M+ breach/stealer/OSINT (15k credits/day)
    Shodan,            // Infrastructure/IoT intelligence
    Censys,            // Certificates/infrastructure
    SecurityTrails,    // DNS/domain history
    OathNetPro,        // Breach data (5k credits/day)
    HunterIO,          // Email/employee discovery
    AbuseIPDB,         // IP reputation/threat intel
    GreyNoise,         // Network threat intelligence
    Leakix,            // Exposed data discovery
    Netlas,            // Network intelligence/search
    HIBP,              // Password breach database
    FullContact,       // People data/enrichment
}

/// API metadata and configuration (hardcoded).
pub struct ApiSpec {
    pub name: &'static str,
    pub api_enum: PaidApi,
    pub priority: u32,         // Higher = prefer this API
    pub daily_budget: u32,     // Daily credits/quota
    pub per_query_cost: u32,   // Cost per query
    pub best_for: &'static [&'static str],  // Target types this API excels at
    pub supports_async: bool,
    pub rate_limit_per_sec: u32,
    pub timeout_secs: u32,
}

/// All 12 paid APIs with specifications (hardcoded for auto-registration).
pub const ALL_PAID_APIS: &[ApiSpec] = &[
    // Priority 1: Breach/OSINT mega-source
    ApiSpec {
        name: "SeekNow",
        api_enum: PaidApi::SeekNow,
        priority: 255,
        daily_budget: 15_000,
        per_query_cost: 1,         // Most queries 1 credit, stealer 2, enterprise 5
        best_for: &["email", "username", "domain", "ip", "phone", "name"],
        supports_async: true,
        rate_limit_per_sec: 60,    // Unlimited on enterprise plan
        timeout_secs: 80,          // /search/deep up to 55s
    },

    // Priority 2: Infrastructure intelligence
    ApiSpec {
        name: "Shodan",
        api_enum: PaidApi::Shodan,
        priority: 240,
        daily_budget: 10_000,      // Typical subscription
        per_query_cost: 1,
        best_for: &["ip", "domain", "port", "service"],
        supports_async: true,
        rate_limit_per_sec: 60,
        timeout_secs: 30,
    },

    // Priority 3: Certificate/infrastructure
    ApiSpec {
        name: "Censys",
        api_enum: PaidApi::Censys,
        priority: 230,
        daily_budget: 120,         // Typical API quota
        per_query_cost: 1,
        best_for: &["domain", "ip", "certificate"],
        supports_async: true,
        rate_limit_per_sec: 1,
        timeout_secs: 30,
    },

    // Priority 4: DNS/domain history
    ApiSpec {
        name: "SecurityTrails",
        api_enum: PaidApi::SecurityTrails,
        priority: 220,
        daily_budget: 250,         // Typical subscription
        per_query_cost: 1,
        best_for: &["domain", "ip"],
        supports_async: true,
        rate_limit_per_sec: 1,
        timeout_secs: 15,
    },

    // Priority 5: Breach data
    ApiSpec {
        name: "OathNet Pro",
        api_enum: PaidApi::OathNetPro,
        priority: 200,
        daily_budget: 5_000,
        per_query_cost: 1,
        best_for: &["email", "username", "password"],
        supports_async: true,
        rate_limit_per_sec: 60,
        timeout_secs: 30,
    },

    // Priority 6: Email/employee discovery
    ApiSpec {
        name: "Hunter.io",
        api_enum: PaidApi::HunterIO,
        priority: 190,
        daily_budget: 500,         // API quota
        per_query_cost: 1,
        best_for: &["email", "domain", "person"],
        supports_async: true,
        rate_limit_per_sec: 2,
        timeout_secs: 10,
    },

    // Priority 7: IP reputation
    ApiSpec {
        name: "AbuseIPDB",
        api_enum: PaidApi::AbuseIPDB,
        priority: 180,
        daily_budget: 100_000,     // High daily quota
        per_query_cost: 1,
        best_for: &["ip"],
        supports_async: true,
        rate_limit_per_sec: 30,
        timeout_secs: 10,
    },

    // Priority 8: Network threat intel
    ApiSpec {
        name: "GreyNoise",
        api_enum: PaidApi::GreyNoise,
        priority: 170,
        daily_budget: 1_000,       // Typical quota
        per_query_cost: 1,
        best_for: &["ip"],
        supports_async: true,
        rate_limit_per_sec: 10,
        timeout_secs: 15,
    },

    // Priority 9: Exposed data
    ApiSpec {
        name: "Leakix",
        api_enum: PaidApi::Leakix,
        priority: 160,
        daily_budget: 5_000,
        per_query_cost: 1,
        best_for: &["domain", "ip", "email"],
        supports_async: true,
        rate_limit_per_sec: 60,
        timeout_secs: 20,
    },

    // Priority 10: Network search
    ApiSpec {
        name: "Netlas",
        api_enum: PaidApi::Netlas,
        priority: 150,
        daily_budget: 1_000,
        per_query_cost: 1,
        best_for: &["ip", "domain", "certificate"],
        supports_async: true,
        rate_limit_per_sec: 1,
        timeout_secs: 15,
    },

    // Priority 11: Password breaches
    ApiSpec {
        name: "HIBP",
        api_enum: PaidApi::HIBP,
        priority: 140,
        daily_budget: 100_000,     // High quota for password checks
        per_query_cost: 1,
        best_for: &["email", "password"],
        supports_async: true,
        rate_limit_per_sec: 10,
        timeout_secs: 5,
    },

    // Priority 12: People enrichment
    ApiSpec {
        name: "FullContact",
        api_enum: PaidApi::FullContact,
        priority: 130,
        daily_budget: 10_000,
        per_query_cost: 1,
        best_for: &["email", "name", "person"],
        supports_async: true,
        rate_limit_per_sec: 10,
        timeout_secs: 10,
    },
];

/// Multi-API cost-efficiency profiles (hardcoded optimal routing).
pub struct CostProfile {
    pub target_type: &'static str,
    pub apis_in_order: &'static [(&'static str, u32)], // (api_name, priority)
}

pub const COST_PROFILES: &[CostProfile] = &[
    // Email: fast + comprehensive breach + people data
    CostProfile {
        target_type: "email",
        apis_in_order: &[
            ("SeekNow", 1),        // Check breach database
            ("Hunter.io", 2),      // Check company email
            ("HIBP", 3),           // Check password breaches
            ("FullContact", 4),    // Enrich person data
        ],
    },

    // Domain: infrastructure + DNS + breach
    CostProfile {
        target_type: "domain",
        apis_in_order: &[
            ("SeekNow", 1),           // Breach/stealer
            ("SecurityTrails", 2),    // DNS history
            ("Censys", 3),            // Certificates
            ("Shodan", 4),            // Infrastructure
            ("Hunter.io", 5),         // Employee emails
        ],
    },

    // IP: infrastructure + threat intel + reputation
    CostProfile {
        target_type: "ip",
        apis_in_order: &[
            ("SeekNow", 1),        // Breach/stealer
            ("Shodan", 2),         // Infrastructure
            ("Censys", 3),         // Certificates
            ("AbuseIPDB", 4),      // Reputation
            ("GreyNoise", 5),      // Threat intel
            ("SecurityTrails", 6), // Reverse DNS
        ],
    },

    // Username: social platforms + breach + person
    CostProfile {
        target_type: "username",
        apis_in_order: &[
            ("SeekNow", 1),           // Breach/stealer
            ("FullContact", 2),       // Person enrichment
            ("Hunter.io", 3),         // Email association
        ],
    },

    // Name: person data + breach + email
    CostProfile {
        target_type: "name",
        apis_in_order: &[
            ("SeekNow", 1),           // Breach/stealer
            ("FullContact", 2),       // Comprehensive person data
            ("Hunter.io", 3),         // Email/company association
        ],
    },

    // Phone: reputation + breach
    CostProfile {
        target_type: "phone",
        apis_in_order: &[
            ("SeekNow", 1),        // Breach database
            ("AbuseIPDB", 2),      // Reputation (if IP associated)
        ],
    },
];

/// API chaining rules (how to pivot from one API result to another).
pub struct ChainRule {
    pub source_api: &'static str,
    pub entity_type_found: &'static str,
    pub chain_to_api: &'static str,
    pub depth_increase: u32,
}

pub const CHAINING_RULES: &[ChainRule] = &[
    // SeekNow discoveries chain to specialized APIs
    ChainRule { source_api: "SeekNow", entity_type_found: "domain", chain_to_api: "SecurityTrails", depth_increase: 1 },
    ChainRule { source_api: "SeekNow", entity_type_found: "domain", chain_to_api: "Shodan", depth_increase: 1 },
    ChainRule { source_api: "SeekNow", entity_type_found: "ip", chain_to_api: "Shodan", depth_increase: 1 },
    ChainRule { source_api: "SeekNow", entity_type_found: "ip", chain_to_api: "AbuseIPDB", depth_increase: 1 },
    ChainRule { source_api: "SeekNow", entity_type_found: "email", chain_to_api: "Hunter.io", depth_increase: 1 },

    // Shodan discoveries chain
    ChainRule { source_api: "Shodan", entity_type_found: "domain", chain_to_api: "SecurityTrails", depth_increase: 1 },
    ChainRule { source_api: "Shodan", entity_type_found: "certificate", chain_to_api: "Censys", depth_increase: 1 },

    // SecurityTrails discoveries chain
    ChainRule { source_api: "SecurityTrails", entity_type_found: "ip", chain_to_api: "Shodan", depth_increase: 1 },
    ChainRule { source_api: "SecurityTrails", entity_type_found: "ip", chain_to_api: "AbuseIPDB", depth_increase: 1 },
    ChainRule { source_api: "SecurityTrails", entity_type_found: "subdomain", chain_to_api: "Censys", depth_increase: 1 },

    // Hunter.io discoveries chain
    ChainRule { source_api: "Hunter.io", entity_type_found: "email", chain_to_api: "HIBP", depth_increase: 1 },
    ChainRule { source_api: "Hunter.io", entity_type_found: "email", chain_to_api: "FullContact", depth_increase: 1 },
    ChainRule { source_api: "Hunter.io", entity_type_found: "domain", chain_to_api: "Shodan", depth_increase: 1 },

    // AbuseIPDB discoveries
    ChainRule { source_api: "AbuseIPDB", entity_type_found: "ip", chain_to_api: "Shodan", depth_increase: 1 },
    ChainRule { source_api: "AbuseIPDB", entity_type_found: "ip", chain_to_api: "GreyNoise", depth_increase: 1 },
];

/// Cost-aware API selection (pick the cheapest API for a given operation).
pub struct CostOptimization {
    pub operation: &'static str,
    pub recommended_api: &'static str,
    pub estimated_cost: u32,
    pub estimated_time_secs: u32,
}

pub const COST_OPTIMIZATIONS: &[CostOptimization] = &[
    // Email operations
    CostOptimization { operation: "email_breach_check", recommended_api: "SeekNow", estimated_cost: 2, estimated_time_secs: 8 },
    CostOptimization { operation: "email_enumerate_company", recommended_api: "Hunter.io", estimated_cost: 1, estimated_time_secs: 3 },
    CostOptimization { operation: "email_password_breach", recommended_api: "HIBP", estimated_cost: 1, estimated_time_secs: 2 },
    CostOptimization { operation: "email_person_enrichment", recommended_api: "FullContact", estimated_cost: 1, estimated_time_secs: 2 },

    // Domain operations
    CostOptimization { operation: "domain_infrastructure", recommended_api: "Shodan", estimated_cost: 1, estimated_time_secs: 5 },
    CostOptimization { operation: "domain_dns_history", recommended_api: "SecurityTrails", estimated_cost: 1, estimated_time_secs: 3 },
    CostOptimization { operation: "domain_certificates", recommended_api: "Censys", estimated_cost: 1, estimated_time_secs: 5 },
    CostOptimization { operation: "domain_breach_check", recommended_api: "SeekNow", estimated_cost: 1, estimated_time_secs: 3 },

    // IP operations
    CostOptimization { operation: "ip_infrastructure", recommended_api: "Shodan", estimated_cost: 1, estimated_time_secs: 5 },
    CostOptimization { operation: "ip_reputation", recommended_api: "AbuseIPDB", estimated_cost: 1, estimated_time_secs: 2 },
    CostOptimization { operation: "ip_threat_intel", recommended_api: "GreyNoise", estimated_cost: 1, estimated_time_secs: 3 },
    CostOptimization { operation: "ip_reverse_dns", recommended_api: "SecurityTrails", estimated_cost: 1, estimated_time_secs: 2 },
];

/// Total daily budget across ALL APIs (hardcoded).
pub struct MultiApiBudget {
    pub total_daily_credits: u32,
    pub seeknow_percent: f32,
    pub shodan_percent: f32,
    pub censys_percent: f32,
    pub securitytrails_percent: f32,
    pub oathnet_percent: f32,
    pub other_percent: f32,
}

pub const BUDGET_ALLOCATION: MultiApiBudget = MultiApiBudget {
    total_daily_credits: 31_250, // 15k SeekNow + 10k Shodan + other budgets
    seeknow_percent: 48.0,       // 15,000 of 31,250
    shodan_percent: 32.0,        // 10,000 of 31,250
    censys_percent: 5.0,
    securitytrails_percent: 4.0,
    oathnet_percent: 6.0,
    other_percent: 5.0,
};

/// Concurrent execution constraints (hardcoded for rate limiting).
pub struct ConcurrencyConstraints {
    pub max_concurrent_queries: u32,
    pub max_concurrent_per_api: u32,
    pub queue_depth: u32,
}

pub const CONCURRENCY: ConcurrencyConstraints = ConcurrencyConstraints {
    max_concurrent_queries: 16,
    max_concurrent_per_api: 4,
    queue_depth: 32,
};

/// Entity deduplication strategy across all APIs (hardcoded).
pub struct DeduplicationStrategy {
    pub method: &'static str,
    pub hash_algorithm: &'static str,
    pub merge_threshold: f32,
}

pub const DEDUPLICATION: DeduplicationStrategy = DeduplicationStrategy {
    method: "fuzzy_hash",
    hash_algorithm: "sha256",
    merge_threshold: 0.95,
};

/// Cross-API correlation scoring (how strongly entities from different APIs match).
pub struct CorrelationScore {
    pub api1: &'static str,
    pub api2: &'static str,
    pub entity_type: &'static str,
    pub match_confidence: f32,
}

pub const CORRELATION_SCORES: &[CorrelationScore] = &[
    // Email correlations
    CorrelationScore { api1: "SeekNow", api2: "Hunter.io", entity_type: "email", match_confidence: 0.95 },
    CorrelationScore { api1: "SeekNow", api2: "HIBP", entity_type: "email", match_confidence: 0.95 },
    CorrelationScore { api1: "Hunter.io", api2: "FullContact", entity_type: "email", match_confidence: 0.92 },

    // Domain correlations
    CorrelationScore { api1: "SeekNow", api2: "Shodan", entity_type: "domain", match_confidence: 0.90 },
    CorrelationScore { api1: "Shodan", api2: "SecurityTrails", entity_type: "domain", match_confidence: 0.95 },
    CorrelationScore { api1: "SecurityTrails", api2: "Censys", entity_type: "domain", match_confidence: 0.88 },

    // IP correlations
    CorrelationScore { api1: "SeekNow", api2: "Shodan", entity_type: "ip", match_confidence: 0.90 },
    CorrelationScore { api1: "Shodan", api2: "AbuseIPDB", entity_type: "ip", match_confidence: 0.85 },
    CorrelationScore { api1: "AbuseIPDB", api2: "GreyNoise", entity_type: "ip", match_confidence: 0.80 },
    CorrelationScore { api1: "SecurityTrails", api2: "Shodan", entity_type: "ip", match_confidence: 0.90 },
];

/// Unified multi-API scan profile (coordinates all APIs for a target).
pub struct UnifiedScanProfile {
    pub name: &'static str,
    pub apis: &'static [&'static str],
    pub total_estimated_cost: u32,
    pub total_estimated_time_secs: u32,
}

pub const UNIFIED_SCAN_PROFILES: &[UnifiedScanProfile] = &[
    // Fast verification
    UnifiedScanProfile {
        name: "quick_verification",
        apis: &["SeekNow"],
        total_estimated_cost: 100,
        total_estimated_time_secs: 30,
    },

    // Comprehensive person profile
    UnifiedScanProfile {
        name: "person_comprehensive",
        apis: &["SeekNow", "FullContact", "Hunter.io", "HIBP"],
        total_estimated_cost: 200,
        total_estimated_time_secs: 60,
    },

    // Full infrastructure assessment
    UnifiedScanProfile {
        name: "infrastructure_deep",
        apis: &["SeekNow", "Shodan", "SecurityTrails", "Censys", "Hunter.io"],
        total_estimated_cost: 500,
        total_estimated_time_secs: 180,
    },

    // Complete threat assessment
    UnifiedScanProfile {
        name: "threat_complete",
        apis: &["SeekNow", "Shodan", "SecurityTrails", "Censys", "AbuseIPDB", "GreyNoise", "Leakix"],
        total_estimated_cost: 800,
        total_estimated_time_secs: 300,
    },

    // Maximum coverage OSINT
    UnifiedScanProfile {
        name: "osint_maximum",
        apis: &["SeekNow", "Shodan", "SecurityTrails", "Censys", "AbuseIPDB", "GreyNoise", "Hunter.io", "FullContact", "HIBP", "Leakix"],
        total_estimated_cost: 1200,
        total_estimated_time_secs: 600,
    },
];

/// API reliability and monitoring (hardcoded SLA expectations).
pub struct ApiReliability {
    pub api: &'static str,
    pub sla_uptime_percent: f32,
    pub response_time_p95_ms: u32,
    pub error_rate_percent: f32,
}

pub const API_RELIABILITY: &[ApiReliability] = &[
    ApiReliability { api: "SeekNow", sla_uptime_percent: 99.97, response_time_p95_ms: 5_000, error_rate_percent: 0.5 },
    ApiReliability { api: "Shodan", sla_uptime_percent: 99.9, response_time_p95_ms: 3_000, error_rate_percent: 1.0 },
    ApiReliability { api: "Censys", sla_uptime_percent: 99.5, response_time_p95_ms: 5_000, error_rate_percent: 1.5 },
    ApiReliability { api: "SecurityTrails", sla_uptime_percent: 99.9, response_time_p95_ms: 2_000, error_rate_percent: 0.8 },
    ApiReliability { api: "Hunter.io", sla_uptime_percent: 99.9, response_time_p95_ms: 1_500, error_rate_percent: 0.5 },
    ApiReliability { api: "AbuseIPDB", sla_uptime_percent: 99.95, response_time_p95_ms: 800, error_rate_percent: 0.3 },
    ApiReliability { api: "GreyNoise", sla_uptime_percent: 99.9, response_time_p95_ms: 2_000, error_rate_percent: 1.0 },
];

/// Intelligent fallback strategy when an API is down or quota exhausted.
pub enum FallbackStrategy {
    UseNextCheapestApi,
    UseNextMostReliable,
    UseAlternativeMethod,
    SkipAndContinue,
    AbortScan,
}

pub struct ApiFallback {
    pub api: &'static str,
    pub fallback_apis: &'static [&'static str],
    pub strategy: FallbackStrategy,
}

pub const API_FALLBACKS: &[ApiFallback] = &[
    ApiFallback {
        api: "SeekNow",
        fallback_apis: &["OathNet", "Leakix"],
        strategy: FallbackStrategy::UseAlternativeMethod,
    },
    ApiFallback {
        api: "Shodan",
        fallback_apis: &["SecurityTrails", "Netlas"],
        strategy: FallbackStrategy::UseAlternativeMethod,
    },
    ApiFallback {
        api: "SecurityTrails",
        fallback_apis: &["Shodan", "Censys"],
        strategy: FallbackStrategy::UseAlternativeMethod,
    },
    ApiFallback {
        api: "Hunter.io",
        fallback_apis: &["Leakix"],
        strategy: FallbackStrategy::UseNextCheapestApi,
    },
];
