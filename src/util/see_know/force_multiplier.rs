/// Force-multiplier cascade: automatically discover and validate API keys from breach data,
/// unlock downstream paid modules (Shodan, Censys, SecurityTrails), and feed results recursively.

use crate::core::entity::{Entity, EntityKind};

/// Downstream modules that can be unlocked by force-multiplier API keys.
pub enum DownstreamModule {
    Shodan,
    Censys,
    SecurityTrails,
    GitHub,
}

/// Force-multiplier effect: when a valid API key is discovered, it unlocks a downstream module.
pub struct ForceMultiplierEffect {
    pub key_provider: &'static str,
    pub key_pattern_prefix: &'static str,
    pub unlocks_module: DownstreamModule,
    pub priority: u32, // higher = more valuable (Shodan=100, Censys=90, etc.)
}

/// All force-multiplier cascades (hardcoded priority order).
pub const FORCE_MULTIPLIER_CASCADES: &[ForceMultiplierEffect] = &[
    ForceMultiplierEffect {
        key_provider: "shodan",
        key_pattern_prefix: "SHODAN_KEY=",
        unlocks_module: DownstreamModule::Shodan,
        priority: 100,
    },
    ForceMultiplierEffect {
        key_provider: "censys",
        key_pattern_prefix: "CENSYS_API_ID=",
        unlocks_module: DownstreamModule::Censys,
        priority: 90,
    },
    ForceMultiplierEffect {
        key_provider: "securitytrails",
        key_pattern_prefix: "SECURITYTRAILS_KEY=",
        unlocks_module: DownstreamModule::SecurityTrails,
        priority: 85,
    },
    ForceMultiplierEffect {
        key_provider: "github",
        key_pattern_prefix: "ghp_",
        unlocks_module: DownstreamModule::GitHub,
        priority: 80,
    },
];

/// Configuration profiles for force-multiplier cascade (hardcoded orchestration).
pub struct CascadeProfile {
    pub name: &'static str,
    pub max_depth: u32,
    pub max_api_keys_to_validate: u32,
    pub max_downstream_scans_per_key: u32,
    pub retry_invalid_keys: bool,
}

pub const CASCADE_PROFILES: &[CascadeProfile] = &[
    // Conservative: validate 1-2 keys, max 1 downstream scan each
    CascadeProfile {
        name: "conservative",
        max_depth: 2,
        max_api_keys_to_validate: 2,
        max_downstream_scans_per_key: 1,
        retry_invalid_keys: false,
    },
    // Balanced: validate 5 keys, max 2 downstream scans each (recommended for 15k plan)
    CascadeProfile {
        name: "balanced",
        max_depth: 3,
        max_api_keys_to_validate: 5,
        max_downstream_scans_per_key: 2,
        retry_invalid_keys: false,
    },
    // Aggressive: validate 10+ keys, max 5 downstream scans each
    CascadeProfile {
        name: "aggressive",
        max_depth: 4,
        max_api_keys_to_validate: 10,
        max_downstream_scans_per_key: 5,
        retry_invalid_keys: true,
    },
];

/// Metric tracking for force-multiplier cascade orchestration.
pub struct CascadeMetrics {
    pub total_keys_discovered: u32,
    pub keys_validated: u32,
    pub keys_failed: u32,
    pub modules_unlocked: u32,
    pub downstream_entities_extracted: u32,
    pub total_credits_spent_in_cascade: u32,
}

/// Validation strategies for discovered API keys (hardcoded orchestration logic).
pub enum KeyValidationStrategy {
    /// Call the service's API with a minimal test query (uses 1 credit).
    LiveTest,
    /// Check for known invalidation patterns (no API call, instant).
    PatternMatch,
    /// Hybrid: pattern check first, live test if pattern unclear.
    Hybrid,
}

pub const KEY_VALIDATION_STRATEGY: KeyValidationStrategy = KeyValidationStrategy::Hybrid;

/// Cascade stage progression (hardcoded state machine).
pub enum CascadeStage {
    /// Scan source (initial SeekNow query).
    DiscoverKeys,
    /// Extract and deduplicate keys from results.
    ExtractKeys,
    /// Validate keys and group by provider.
    ValidateKeys,
    /// Unlock downstream modules and prioritize scans.
    UnlockModules,
    /// Execute downstream scans and feed results back.
    ExecuteDownstream,
    /// Recursively re-scan with new entities from downstream.
    ReexpandSeekNow,
    /// Complete and summarize cascade.
    Complete,
}

/// Deduplication strategy for force-multiplier (prevents redundant validation).
pub struct DeduplicationStrategy {
    pub deduplicate_by: &'static str, // "sha256" or "prefix"
    pub prefix_length: usize,
    pub skip_if_seen: bool,
}

pub const DEDUPLICATION: DeduplicationStrategy = DeduplicationStrategy {
    deduplicate_by: "sha256",
    prefix_length: 20, // enough to distinguish Shodan from Censys from Slack
    skip_if_seen: true,
};

/// Auto-prioritization for cascade discovered entities (hardcoded ranking).
pub struct EntityPriority {
    pub entity_kind: &'static str,
    pub priority: u32, // 1-100, higher = investigate first
}

pub const ENTITY_DISCOVERY_PRIORITY: &[EntityPriority] = &[
    EntityPriority { entity_kind: "api_key", priority: 100 },
    EntityPriority { entity_kind: "credentials", priority: 90 },
    EntityPriority { entity_kind: "domain", priority: 80 },
    EntityPriority { entity_kind: "ip_address", priority: 75 },
    EntityPriority { entity_kind: "email", priority: 70 },
    EntityPriority { entity_kind: "username", priority: 60 },
    EntityPriority { entity_kind: "person", priority: 50 },
];

/// Config file paths that commonly leak API keys (hardcoded from OSINT best practices).
pub const LEAKED_CONFIG_PATHS: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "config.json",
    "settings.json",
    "credentials.json",
    ".git/config",
    ".aws/credentials",
    ".ssh/config",
    "package.json",
    "docker-compose.yml",
    ".dockerignore",
    "Dockerfile",
    "docker.env",
    ".gitlab-ci.yml",
    ".github/workflows/*.yml",
    "terraform.tfvars",
    "secrets.yml",
    "config/secrets.yml",
    "config/database.yml",
    "config/cable.yml",
    ".travis.yml",
    "Jenkinsfile",
    "buildspec.yml",
    ".circleci/config.yml",
    "kubeconfig",
    "helm-values.yaml",
    "nginx.conf",
    "apache.conf",
    "httpd.conf",
    "application.properties",
    "application.yml",
    "web.config",
    "web.xml",
    "pom.xml",
    "build.gradle",
    "requirements.txt",
    "setup.py",
    "go.mod",
    "Cargo.toml",
    "Gemfile",
    "composer.json",
];

/// Auto-expansion rules: when these entity types are discovered, automatically re-scan.
pub struct AutoExpansionRule {
    pub discovered_entity_kind: &'static str,
    pub triggers_rescan_with_kind: &'static str,
    pub depth_increase: u32,
}

pub const AUTO_EXPANSION_RULES: &[AutoExpansionRule] = &[
    // API keys found → unlock downstream + re-scan
    AutoExpansionRule {
        discovered_entity_kind: "api_key",
        triggers_rescan_with_kind: "api_key",
        depth_increase: 2,
    },
    // Domain found → domain intel + web_crawler (103 config paths)
    AutoExpansionRule {
        discovered_entity_kind: "domain",
        triggers_rescan_with_kind: "domain",
        depth_increase: 1,
    },
    // Email found → email verification + username extraction
    AutoExpansionRule {
        discovered_entity_kind: "email",
        triggers_rescan_with_kind: "email",
        depth_increase: 1,
    },
    // IP found → IP geolocation + reverse DNS
    AutoExpansionRule {
        discovered_entity_kind: "ip_address",
        triggers_rescan_with_kind: "ip",
        depth_increase: 1,
    },
    // Username found → username recon (70+ platforms)
    AutoExpansionRule {
        discovered_entity_kind: "username",
        triggers_rescan_with_kind: "username",
        depth_increase: 1,
    },
];

/// Cascade termination conditions (hardcoded early-exit rules).
pub struct TerminationCondition {
    pub condition: &'static str,
    pub stop_cascade: bool,
}

pub const TERMINATION_CONDITIONS: &[TerminationCondition] = &[
    TerminationCondition {
        condition: "daily_quota_exhausted",
        stop_cascade: true,
    },
    TerminationCondition {
        condition: "session_quota_exhausted",
        stop_cascade: true,
    },
    TerminationCondition {
        condition: "max_depth_reached",
        stop_cascade: true,
    },
    TerminationCondition {
        condition: "no_new_entities",
        stop_cascade: true,
    },
    TerminationCondition {
        condition: "all_keys_validated",
        stop_cascade: false, // continue re-scanning
    },
];

/// Recommendation engine: suggest cascade strategy based on initial findings.
pub fn recommend_cascade_strategy(
    keys_discovered: u32,
    total_budget_remaining: u32,
) -> &'static str {
    match (keys_discovered, total_budget_remaining) {
        (0, _) => "skip_cascade", // no keys found, no point cascading
        (1..=2, 1000..=u32::MAX) => "balanced", // few keys, enough budget, balanced approach
        (1..=2, 500..=999) => "conservative", // few keys, tight budget, be conservative
        (3..=10, 2000..=u32::MAX) => "balanced", // many keys, good budget, balanced
        (3..=10, 1000..=1999) => "conservative", // many keys, tight budget, be selective
        (11..=u32::MAX, _) => "aggressive", // lots of keys, go all-in
        _ => "conservative",
    }
}

/// Auto-select force-multiplier cascade parameters based on enterprise plan.
pub fn enterprise_cascade_config() -> &'static CascadeProfile {
    // Enterprise plan (15,000 credits/day) can afford balanced cascade (most common scenario)
    &CASCADE_PROFILES[1] // "balanced" profile
}

/// Maximum recommended API keys to validate in a single scan for 15k plan.
pub const MAX_KEYS_PER_SCAN: u32 = 5;

/// Maximum recommended downstream scans per validated key for 15k plan.
pub const MAX_DOWNSTREAM_SCANS_PER_KEY: u32 = 2;

/// Cost estimation for cascade orchestration.
pub struct CascadeCostEstimate {
    pub keys_to_validate: u32,
    pub estimated_validation_cost: u32,
    pub max_downstream_scans: u32,
    pub estimated_downstream_cost: u32,
    pub total_estimated_cost: u32,
}

pub fn estimate_cascade_cost(keys_discovered: u32, downstream_scan_budget: u32) -> CascadeCostEstimate {
    let keys_to_validate = keys_discovered.min(MAX_KEYS_PER_SCAN);
    let validation_cost = keys_to_validate; // 1 credit per key validation (live test)
    let max_downstream_scans = keys_to_validate * MAX_DOWNSTREAM_SCANS_PER_KEY;
    let downstream_cost = max_downstream_scans * downstream_scan_budget;
    let total = validation_cost + downstream_cost;

    CascadeCostEstimate {
        keys_to_validate,
        estimated_validation_cost: validation_cost,
        max_downstream_scans,
        estimated_downstream_cost: downstream_cost,
        total_estimated_cost: total,
    }
}
