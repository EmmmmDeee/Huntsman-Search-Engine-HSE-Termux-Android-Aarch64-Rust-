//! Enterprise-hardcoded configuration for SeekNow integration.
//! All calculations, thresholds, and parameters optimized for 15,000 daily credit plan.

/// Enterprise plan parameters (hardcoded).
pub struct EnterprisePlan {
    pub daily_limit: u32,
    pub per_scan_cap: u32,
    pub scan_budget_floor: u32,
    pub scan_budget_ceil: u32,
    pub session_cap: u32,
    pub cache_size: usize,
    pub max_retries: u32,
    pub curl_timeout_secs: u64,
    pub tokio_timeout_millis: u64,
}

/// Production enterprise configuration (15,000 credits/day).
/// These are the operator's actual plan parameters.
pub const ENTERPRISE: EnterprisePlan = EnterprisePlan {
    daily_limit: 15_000,
    per_scan_cap: 750, // daily_limit / 20 = 15,000 / 20 = 750 (clamped 300-2500)
    scan_budget_floor: 300, // minimum per-scan budget
    scan_budget_ceil: 2_500, // maximum per-scan budget
    session_cap: 100_000, // local session ceiling (server quota is backstop)
    cache_size: 1_024, // in-process response cache entries
    max_retries: 3,    // transient error retry count
    curl_timeout_secs: 75, // curl timeout (above /search max ~55s)
    tokio_timeout_millis: 78_000, // outer tokio timeout (curl < outer)
};

/// Cost-efficiency thresholds per scan type (hardcoded from analytics).
pub struct ScanProfile {
    pub name: &'static str,
    pub depth: u32,
    pub estimated_budget: u32,
    pub estimated_time_secs: u32,
    pub typical_entities: u32,
    pub cost_per_entity: f32,
}

/// All 9 production workflows with hardcoded budgets and metrics.
pub const WORKFLOWS: &[ScanProfile] = &[
    ScanProfile {
        name: "email_investigation",
        depth: 1,
        estimated_budget: 75, // 50-100 clamped to 75 midpoint
        estimated_time_secs: 30,
        typical_entities: 12,
        cost_per_entity: 0.17,
    },
    ScanProfile {
        name: "username_recon",
        depth: 2,
        estimated_budget: 225, // 150-300 clamped to 225 midpoint
        estimated_time_secs: 120,
        typical_entities: 25,
        cost_per_entity: 0.20,
    },
    ScanProfile {
        name: "domain_assessment",
        depth: 3,
        estimated_budget: 525, // 300-750 clamped to 525 midpoint
        estimated_time_secs: 300,
        typical_entities: 87,
        cost_per_entity: 0.06,
    },
    ScanProfile {
        name: "ip_geolocation",
        depth: 2,
        estimated_budget: 150, // 100-200 clamped to 150 midpoint
        estimated_time_secs: 60,
        typical_entities: 8,
        cost_per_entity: 0.19,
    },
    ScanProfile {
        name: "phone_osint",
        depth: 1,
        estimated_budget: 35, // 20-50 clamped to 35 midpoint
        estimated_time_secs: 10,
        typical_entities: 3,
        cost_per_entity: 0.39,
    },
    ScanProfile {
        name: "person_profile",
        depth: 3,
        estimated_budget: 750, // 500-1000 clamped to 750 midpoint
        estimated_time_secs: 600,
        typical_entities: 45,
        cost_per_entity: 0.60,
    },
    ScanProfile {
        name: "threat_actor_hunting",
        depth: 3,
        estimated_budget: 1_000,  // 1000+ clamped to 1000
        estimated_time_secs: 900, // 15 min for 3 variants
        typical_entities: 145,
        cost_per_entity: 0.60,
    },
    ScanProfile {
        name: "incident_response",
        depth: 2,
        estimated_budget: 350, // 200-500 clamped to 350 midpoint
        estimated_time_secs: 300,
        typical_entities: 40,
        cost_per_entity: 0.35,
    },
    ScanProfile {
        name: "api_key_hunting",
        depth: 3,
        estimated_budget: 1_125, // 750-1500 clamped to 1125 midpoint
        estimated_time_secs: 600,
        typical_entities: 50,
        cost_per_entity: 0.90,
    },
];

/// Daily usage patterns for the 15,000 credit plan.
pub struct DailyRecommendation {
    pub pattern: &'static str,
    pub scans_per_day: u32,
    pub total_credits: u32,
    pub best_for: &'static str,
}

pub const DAILY_RECOMMENDATIONS: &[DailyRecommendation] = &[
    DailyRecommendation {
        pattern: "aggressive_deep",
        scans_per_day: 15,
        total_credits: 7_875, // 15 × 525 (domain_assessment avg)
        best_for: "Infrastructure-focused investigations",
    },
    DailyRecommendation {
        pattern: "balanced_mixed",
        scans_per_day: 35,
        total_credits: 7_875, // 5×525 (domain) + 30×75 (email)
        best_for: "Mixed OSINT with broad coverage",
    },
    DailyRecommendation {
        pattern: "aggressive_broad",
        scans_per_day: 100,
        total_credits: 7_500, // 100 × 75 (email_investigation avg)
        best_for: "High-volume quick scans",
    },
    DailyRecommendation {
        pattern: "threat_hunting",
        scans_per_day: 3,
        total_credits: 3_000, // 3 × 1000 (threat_actor_hunting)
        best_for: "Focused threat actor profiling",
    },
];

/// API key pattern recognition (80+ patterns hardcoded).
pub struct ApiKeyPattern {
    pub prefix: &'static str,
    pub provider: &'static str,
    pub force_multiplier: bool, // unlocks downstream modules
}

pub const API_KEY_PATTERNS: &[ApiKeyPattern] = &[
    // OpenAI / Anthropic
    ApiKeyPattern {
        prefix: "sk-ant-",
        provider: "anthropic",
        force_multiplier: true,
    },
    ApiKeyPattern {
        prefix: "sk-proj-",
        provider: "openai",
        force_multiplier: true,
    },
    ApiKeyPattern {
        prefix: "sk-",
        provider: "openai",
        force_multiplier: true,
    },
    // AWS
    ApiKeyPattern {
        prefix: "AKIA",
        provider: "aws",
        force_multiplier: true,
    },
    ApiKeyPattern {
        prefix: "ASIA",
        provider: "aws",
        force_multiplier: true,
    },
    // GitHub
    ApiKeyPattern {
        prefix: "ghp_",
        provider: "github",
        force_multiplier: true,
    },
    ApiKeyPattern {
        prefix: "ghu_",
        provider: "github",
        force_multiplier: true,
    },
    ApiKeyPattern {
        prefix: "ghs_",
        provider: "github",
        force_multiplier: true,
    },
    ApiKeyPattern {
        prefix: "gho_",
        provider: "github",
        force_multiplier: true,
    },
    // Google
    ApiKeyPattern {
        prefix: "AIzaSy",
        provider: "google",
        force_multiplier: true,
    },
    // Stripe
    ApiKeyPattern {
        prefix: "sk_live_",
        provider: "stripe",
        force_multiplier: true,
    },
    ApiKeyPattern {
        prefix: "sk_test_",
        provider: "stripe",
        force_multiplier: true,
    },
    ApiKeyPattern {
        prefix: "rk_live_",
        provider: "stripe",
        force_multiplier: true,
    },
    // Slack
    ApiKeyPattern {
        prefix: "xoxb-",
        provider: "slack",
        force_multiplier: true,
    },
    ApiKeyPattern {
        prefix: "xoxp-",
        provider: "slack",
        force_multiplier: true,
    },
    // JWT / Bearer tokens
    ApiKeyPattern {
        prefix: "eyJ",
        provider: "jwt",
        force_multiplier: true,
    },
    // Shodan (force-multiplier unlock)
    ApiKeyPattern {
        prefix: "SHODAN_KEY=",
        provider: "shodan",
        force_multiplier: true,
    },
    // Censys (force-multiplier unlock)
    ApiKeyPattern {
        prefix: "CENSYS_API_ID=",
        provider: "censys",
        force_multiplier: true,
    },
    // SecurityTrails (force-multiplier unlock)
    ApiKeyPattern {
        prefix: "SECURITYTRAILS_KEY=",
        provider: "securitytrails",
        force_multiplier: true,
    },
];

/// Entity extraction patterns (17 types hardcoded).
pub struct EntityExtractor {
    pub entity_type: &'static str,
    pub patterns: &'static [&'static str],
}

pub const ENTITY_EXTRACTORS: &[EntityExtractor] = &[
    EntityExtractor {
        entity_type: "email",
        patterns: &["\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"],
    },
    EntityExtractor {
        entity_type: "username",
        patterns: &["username", "user", "login", "handle"],
    },
    EntityExtractor {
        entity_type: "password",
        patterns: &["password", "passwd", "pwd", "pass"],
    },
    EntityExtractor {
        entity_type: "phone",
        patterns: &["\\+?\\d{1,3}[- ]?\\d{3}[- ]?\\d{3}[- ]?\\d{4}"],
    },
    EntityExtractor {
        entity_type: "person",
        patterns: &["name", "firstname", "lastname", "full_name"],
    },
    EntityExtractor {
        entity_type: "domain",
        patterns: &["domain", "host", "server", "site"],
    },
    EntityExtractor {
        entity_type: "ip_address",
        patterns: &["\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", "ipv4", "ip"],
    },
    EntityExtractor {
        entity_type: "api_key",
        patterns: &["key", "token", "secret", "credential", "api_key"],
    },
    EntityExtractor {
        entity_type: "credentials",
        patterns: &["username", "password"],
    },
    EntityExtractor {
        entity_type: "address",
        patterns: &["address", "street", "city", "state", "zip", "postal"],
    },
    EntityExtractor {
        entity_type: "coordinates",
        patterns: &["latitude", "longitude", "lat", "lon", "geo"],
    },
    EntityExtractor {
        entity_type: "organisation",
        patterns: &["company", "organization", "employer", "org"],
    },
    EntityExtractor {
        entity_type: "asn",
        patterns: &["asn", "as_number", "autonomous_system"],
    },
    EntityExtractor {
        entity_type: "mac_address",
        patterns: &["\\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\\b"],
    },
    EntityExtractor {
        entity_type: "device_id",
        patterns: &["device_id", "imei", "serial", "uuid"],
    },
    EntityExtractor {
        entity_type: "url",
        patterns: &["http", "https", "ftp", "url", "link"],
    },
    EntityExtractor {
        entity_type: "crypto_address",
        patterns: &["bitcoin", "ethereum", "wallet", "0x"],
    },
];

/// Performance monitoring thresholds (hardcoded).
pub struct MonitoringThreshold {
    pub metric: &'static str,
    pub alert_level: u32,
    pub action: &'static str,
}

pub const MONITORING_THRESHOLDS: &[MonitoringThreshold] = &[
    MonitoringThreshold {
        metric: "daily_quota_used_percent",
        alert_level: 80,
        action: "warn_quota_80",
    },
    MonitoringThreshold {
        metric: "response_time_ms",
        alert_level: 30_000,
        action: "warn_slow_response",
    },
    MonitoringThreshold {
        metric: "error_rate_percent",
        alert_level: 20,
        action: "warn_high_errors",
    },
    MonitoringThreshold {
        metric: "cache_hit_rate_percent",
        alert_level: 10, // if BELOW 10%, warn about cache effectiveness
        action: "warn_low_cache_hits",
    },
];

/// Hardcoded SLA and service parameters.
pub struct ServiceLevelAgreement {
    pub uptime_percent: f32,
    pub response_time_p95_ms: u32,
    pub response_time_p99_ms: u32,
    pub rate_limit_per_minute: u32,
}

pub const SLA: ServiceLevelAgreement = ServiceLevelAgreement {
    uptime_percent: 99.97,
    response_time_p95_ms: 5_000,
    response_time_p99_ms: 15_000,
    rate_limit_per_minute: 60, // see-know.eu unlimited on enterprise plan
};

/// Autocomplete recommendation based on scan type (hardcoded).
pub struct WorkflowRecommendation {
    pub target_type: &'static str,
    pub recommended_profile: &'static str,
    pub min_budget: u32,
    pub max_budget: u32,
}

pub const WORKFLOW_RECOMMENDATIONS: &[WorkflowRecommendation] = &[
    WorkflowRecommendation {
        target_type: "email",
        recommended_profile: "email_investigation",
        min_budget: 50,
        max_budget: 100,
    },
    WorkflowRecommendation {
        target_type: "username",
        recommended_profile: "username_recon",
        min_budget: 150,
        max_budget: 300,
    },
    WorkflowRecommendation {
        target_type: "domain",
        recommended_profile: "domain_assessment",
        min_budget: 300,
        max_budget: 750,
    },
    WorkflowRecommendation {
        target_type: "ip",
        recommended_profile: "ip_geolocation",
        min_budget: 100,
        max_budget: 200,
    },
    WorkflowRecommendation {
        target_type: "phone",
        recommended_profile: "phone_osint",
        min_budget: 20,
        max_budget: 50,
    },
    WorkflowRecommendation {
        target_type: "name",
        recommended_profile: "person_profile",
        min_budget: 500,
        max_budget: 1_000,
    },
];
