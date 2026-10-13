//! Modular search engine framework: No-API-key sources with intelligent rotation & backoff.
//!
//! Provides unified interface to public search engines and data sources that require
//! no API authentication. Implements automatic rotation, rate limiting with exponential
//! backoff, deadline-aware timeout adaptation, and result aggregation.
//!
//! Designed for Australian OSINT coverage across:
//! - Internet Archive / Wayback Machine (historical intelligence)
//! - Shodan (limited free results, network intelligence)
//! - GitHub search (code, people, organizations)
//! - Censys (IP/domain enumeration)
//! - Satellite imagery (USGS, ESA Sentinel)
//! - Flight tracking (ADS-B Exchange)
//! - Ship tracking (AIS data)
//! - Social media search (Twitter, `LinkedIn` limited)
//! - News aggregation (RSS, Google News)
//! - Government data portals (ABS, data.gov.au)

use std::time::Duration;

use crate::entity::Evidence;

/// Search engine type enumeration: all supported no-API-key sources
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchEngineType {
    /// Internet Archive Wayback Machine
    WaybackMachine,
    /// Shodan free results (limited)
    Shodan,
    /// GitHub code search and user profiles
    GitHub,
    /// Censys IP and domain enumeration
    Censys,
    /// USGS and ESA Sentinel satellite imagery
    SatelliteImagery,
    /// ADS-B Exchange flight tracking
    FlightTracking,
    /// AIS Automatic Identification System
    ShipTracking,
    /// Twitter/X search API (limited)
    Twitter,
    /// `LinkedIn` profile search (limited)
    LinkedIn,
    /// Google News via RSS
    GoogleNews,
    /// RSS news aggregator
    RssNews,
    /// Australian Bureau of Statistics
    AustralianBureauOfStatistics,
    /// data.gov.au government data portal
    GovernmentDataPortal,
    /// OpenStreetMap / Nominatim geocoding
    OpenStreetMap,
    /// Blockchain explorers (Ethereum, Bitcoin)
    BlockchainExplorer,
}

impl SearchEngineType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WaybackMachine => "wayback_machine",
            Self::Shodan => "shodan",
            Self::GitHub => "github",
            Self::Censys => "censys",
            Self::SatelliteImagery => "satellite_imagery",
            Self::FlightTracking => "flight_tracking",
            Self::ShipTracking => "ship_tracking",
            Self::Twitter => "twitter",
            Self::LinkedIn => "linkedin",
            Self::GoogleNews => "google_news",
            Self::RssNews => "rss_news",
            Self::AustralianBureauOfStatistics => "abs",
            Self::GovernmentDataPortal => "data_gov_au",
            Self::OpenStreetMap => "openstreetmap",
            Self::BlockchainExplorer => "blockchain_explorer",
        }
    }
}

/// Search result aggregator for multiple sources
#[derive(Debug, Clone, PartialEq)]
pub struct AggregatedSearchResult {
    pub query: String,
    pub search_engines: Vec<SearchEngineType>,
    pub total_results: usize,
    pub results: Vec<SearchResult>,
    pub evidence_batch: Vec<Evidence>,
}

/// Individual search result
#[derive(Debug, Clone, PartialEq)]
pub struct SearchResult {
    pub source: SearchEngineType,
    pub title: String,
    pub url: String,
    pub description: Option<String>,
    pub relevance_score: f64,
    pub timestamp: Option<String>,
}

/// Rate limiting state for a search engine
#[derive(Debug, Clone)]
pub struct RateLimitState {
    pub engine: SearchEngineType,
    pub requests_made: u32,
    pub rate_limit_window: Duration,
    pub backoff_multiplier: f64,
    pub current_backoff: Duration,
    pub next_available: std::time::SystemTime,
}

/// Search engine configuration with rotation strategy
#[derive(Debug, Clone)]
pub struct SearchEngineConfig {
    pub engine_type: SearchEngineType,
    pub enabled: bool,
    pub rate_limit_per_minute: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub timeout: Duration,
    pub priority: u8, // 1-10, higher = more priority
}

impl SearchEngineConfig {
    /// Create configuration with sensible defaults for no-API-key sources
    #[must_use]
    pub fn default_for(engine_type: SearchEngineType) -> Self {
        match engine_type {
            SearchEngineType::WaybackMachine => Self {
                engine_type,
                enabled: true,
                rate_limit_per_minute: 60, // Generous for archive.org
                initial_backoff: Duration::from_millis(100),
                max_backoff: Duration::from_secs(30),
                timeout: Duration::from_secs(10),
                priority: 9, // High priority for historical data
            },
            SearchEngineType::GitHub => Self {
                engine_type,
                enabled: true,
                rate_limit_per_minute: 10, // Conservative for unauthenticated
                initial_backoff: Duration::from_millis(500),
                max_backoff: Duration::from_secs(60),
                timeout: Duration::from_secs(5),
                priority: 8,
            },
            SearchEngineType::Shodan => Self {
                engine_type,
                enabled: true,
                rate_limit_per_minute: 1, // Very restrictive free tier
                initial_backoff: Duration::from_secs(2),
                max_backoff: Duration::from_secs(120),
                timeout: Duration::from_secs(5),
                priority: 7,
            },
            SearchEngineType::Censys => Self {
                engine_type,
                enabled: true,
                rate_limit_per_minute: 5, // Free tier limited
                initial_backoff: Duration::from_millis(500),
                max_backoff: Duration::from_secs(60),
                timeout: Duration::from_secs(5),
                priority: 7,
            },
            SearchEngineType::FlightTracking => Self {
                engine_type,
                enabled: true,
                rate_limit_per_minute: 30, // ADS-B generous
                initial_backoff: Duration::from_millis(200),
                max_backoff: Duration::from_secs(10),
                timeout: Duration::from_secs(5),
                priority: 6,
            },
            SearchEngineType::ShipTracking => Self {
                engine_type,
                enabled: true,
                rate_limit_per_minute: 20, // AIS data generous
                initial_backoff: Duration::from_millis(200),
                max_backoff: Duration::from_secs(10),
                timeout: Duration::from_secs(5),
                priority: 6,
            },
            SearchEngineType::OpenStreetMap => Self {
                engine_type,
                enabled: true,
                rate_limit_per_minute: 60, // Nominatim generous with backoff
                initial_backoff: Duration::from_millis(100),
                max_backoff: Duration::from_secs(10),
                timeout: Duration::from_secs(5),
                priority: 8,
            },
            _ => Self {
                engine_type,
                enabled: true,
                rate_limit_per_minute: 10,
                initial_backoff: Duration::from_millis(300),
                max_backoff: Duration::from_secs(30),
                timeout: Duration::from_secs(5),
                priority: 5,
            },
        }
    }
}

/// Rotation strategy for search engine queries
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationStrategy {
    /// Round-robin through all enabled engines
    RoundRobin,
    /// Priority-weighted selection (higher priority more often)
    PriorityWeighted,
    /// Random selection
    Random,
    /// Sequential until rate-limited, then move to next
    Sequential,
}

/// Multi-engine search orchestrator
pub struct SearchOrchestrator {
    configs: Vec<SearchEngineConfig>,
    rate_limit_states: Vec<RateLimitState>,
    rotation_strategy: RotationStrategy,
    last_engine_index: usize,
}

impl SearchOrchestrator {
    /// Create orchestrator with default configuration for all engines
    #[must_use]
    pub fn new(strategy: RotationStrategy) -> Self {
        let engine_types = [
            SearchEngineType::WaybackMachine,
            SearchEngineType::GitHub,
            SearchEngineType::Shodan,
            SearchEngineType::Censys,
            SearchEngineType::FlightTracking,
            SearchEngineType::ShipTracking,
            SearchEngineType::OpenStreetMap,
            SearchEngineType::GoogleNews,
        ];

        let configs = engine_types
            .iter()
            .map(|&t| SearchEngineConfig::default_for(t))
            .collect::<Vec<_>>();

        let rate_limit_states = configs
            .iter()
            .map(|cfg| RateLimitState {
                engine: cfg.engine_type,
                requests_made: 0,
                rate_limit_window: Duration::from_secs(60),
                backoff_multiplier: 2.0,
                current_backoff: cfg.initial_backoff,
                next_available: std::time::SystemTime::now(),
            })
            .collect::<Vec<_>>();

        Self {
            configs,
            rate_limit_states,
            rotation_strategy: strategy,
            last_engine_index: 0,
        }
    }

    /// Select next search engine based on rotation strategy
    #[must_use]
    pub fn select_next_engine(&mut self) -> Option<SearchEngineType> {
        match self.rotation_strategy {
            RotationStrategy::RoundRobin => self.select_round_robin(),
            RotationStrategy::PriorityWeighted => self.select_priority_weighted(),
            RotationStrategy::Sequential => self.select_sequential(),
            RotationStrategy::Random => self.select_random(),
        }
    }

    fn select_round_robin(&mut self) -> Option<SearchEngineType> {
        if self.configs.is_empty() {
            return None;
        }

        let mut attempts = 0;
        loop {
            self.last_engine_index = (self.last_engine_index + 1) % self.configs.len();
            let config = &self.configs[self.last_engine_index];

            if config.enabled {
                let state = &self.rate_limit_states[self.last_engine_index];
                if std::time::SystemTime::now() >= state.next_available {
                    return Some(config.engine_type);
                }
            }

            attempts += 1;
            if attempts >= self.configs.len() {
                return None; // All engines rate-limited or disabled
            }
        }
    }

    fn select_priority_weighted(&mut self) -> Option<SearchEngineType> {
        // Select engine with highest priority that's not rate-limited
        self.configs
            .iter()
            .enumerate()
            .filter(|(idx, cfg)| {
                cfg.enabled
                    && std::time::SystemTime::now() >= self.rate_limit_states[*idx].next_available
            })
            .max_by_key(|(_, cfg)| cfg.priority)
            .map(|(_, cfg)| cfg.engine_type)
    }

    fn select_sequential(&mut self) -> Option<SearchEngineType> {
        for (idx, config) in self.configs.iter().enumerate() {
            if config.enabled
                && std::time::SystemTime::now() >= self.rate_limit_states[idx].next_available
            {
                return Some(config.engine_type);
            }
        }
        None
    }

    fn select_random(&mut self) -> Option<SearchEngineType> {
        use std::collections::hash_map::RandomState;
        use std::hash::BuildHasher;

        let hasher = RandomState::new();
        let hash = hasher.hash_one(std::time::SystemTime::now());
        #[allow(clippy::cast_possible_truncation)]
        let idx = (hash % (self.configs.len() as u64)) as usize;

        let config = &self.configs[idx];
        if config.enabled
            && std::time::SystemTime::now() >= self.rate_limit_states[idx].next_available
        {
            Some(config.engine_type)
        } else {
            None
        }
    }

    /// Record request completion and update backoff
    pub fn record_request(&mut self, engine_type: SearchEngineType, rate_limited: bool) {
        if let Some(idx) = self
            .configs
            .iter()
            .position(|c| c.engine_type == engine_type)
        {
            let state = &mut self.rate_limit_states[idx];
            state.requests_made += 1;

            if rate_limited {
                // Exponential backoff on rate limit
                state.current_backoff = state.current_backoff.mul_f64(state.backoff_multiplier);
                if state.current_backoff > self.configs[idx].max_backoff {
                    state.current_backoff = self.configs[idx].max_backoff;
                }
            } else {
                // Decay backoff on success
                state.current_backoff =
                    (state.current_backoff.mul_f64(0.9)).max(self.configs[idx].initial_backoff);
            }

            state.next_available = std::time::SystemTime::now() + state.current_backoff;
        }
    }

    /// Get current backoff for engine
    #[must_use]
    pub fn current_backoff(&self, engine_type: SearchEngineType) -> Duration {
        self.rate_limit_states
            .iter()
            .find(|s| s.engine == engine_type)
            .map_or(Duration::from_secs(0), |s| s.current_backoff)
    }
}

/// Rate limit manager: Track backoff state per source, determine skip decisions.
#[derive(Debug, Clone)]
pub struct RateLimitManager {
    states: std::collections::HashMap<SearchEngineType, RateLimitState>,
}

impl RateLimitManager {
    /// Create new rate limit manager with fresh state for all sources.
    #[must_use]
    pub fn new() -> Self {
        let mut states = std::collections::HashMap::new();
        let engine_types = [
            SearchEngineType::WaybackMachine,
            SearchEngineType::GitHub,
            SearchEngineType::Shodan,
            SearchEngineType::Censys,
            SearchEngineType::FlightTracking,
            SearchEngineType::ShipTracking,
            SearchEngineType::OpenStreetMap,
            SearchEngineType::GoogleNews,
        ];

        for engine_type in engine_types {
            let config = SearchEngineConfig::default_for(engine_type);
            states.insert(
                engine_type,
                RateLimitState {
                    engine: engine_type,
                    requests_made: 0,
                    rate_limit_window: Duration::from_secs(60),
                    backoff_multiplier: 2.0,
                    current_backoff: config.initial_backoff,
                    next_available: std::time::SystemTime::now(),
                },
            );
        }

        Self { states }
    }

    /// Determine if a source should be skipped: backoff > `remaining_budget`.
    #[must_use]
    pub fn should_skip(&self, source: SearchEngineType, remaining_budget: Duration) -> bool {
        if let Some(state) = self.states.get(&source) {
            state.current_backoff > remaining_budget
        } else {
            false
        }
    }

    /// Record a successful request: decay backoff by 0.9x multiplier.
    pub fn record_success(&mut self, source: SearchEngineType) {
        if let Some(state) = self.states.get_mut(&source) {
            let config = SearchEngineConfig::default_for(source);
            state.current_backoff =
                (state.current_backoff.mul_f64(0.9)).max(config.initial_backoff);
        }
    }

    /// Record a rate limit hit: apply exponential backoff (2.0x multiplier).
    pub fn record_rate_limit(&mut self, source: SearchEngineType) {
        if let Some(state) = self.states.get_mut(&source) {
            let config = SearchEngineConfig::default_for(source);
            state.current_backoff = state.current_backoff.mul_f64(state.backoff_multiplier);
            if state.current_backoff > config.max_backoff {
                state.current_backoff = config.max_backoff;
            }
        }
    }

    /// Get current backoff for a source.
    #[must_use]
    pub fn current_backoff(&self, source: SearchEngineType) -> Duration {
        self.states
            .get(&source)
            .map_or(Duration::from_secs(0), |s| s.current_backoff)
    }
}

impl Default for RateLimitManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_engine_type_strings_consistent() {
        assert_eq!(SearchEngineType::WaybackMachine.as_str(), "wayback_machine");
        assert_eq!(SearchEngineType::GitHub.as_str(), "github");
        assert_eq!(SearchEngineType::Shodan.as_str(), "shodan");
    }

    #[test]
    fn orchestrator_creates_with_default_config() {
        let orch = SearchOrchestrator::new(RotationStrategy::RoundRobin);
        assert!(!orch.configs.is_empty());
        assert_eq!(orch.configs.len(), orch.rate_limit_states.len());
    }

    #[test]
    fn orchestrator_selects_round_robin() {
        let mut orch = SearchOrchestrator::new(RotationStrategy::RoundRobin);
        let first = orch.select_next_engine();
        let second = orch.select_next_engine();
        assert_ne!(first, second);
    }

    #[test]
    fn orchestrator_respects_rate_limiting() {
        let mut orch = SearchOrchestrator::new(RotationStrategy::RoundRobin);
        if let Some(engine) = orch.select_next_engine() {
            orch.record_request(engine, true);
            // After rate limit, should try a different engine
            let next = orch.select_next_engine();
            assert!(next.is_some());
        }
    }

    #[test]
    fn exponential_backoff_increases() {
        let mut orch = SearchOrchestrator::new(RotationStrategy::RoundRobin);
        let engine = SearchEngineType::GitHub;
        let initial_backoff = orch.current_backoff(engine);
        orch.record_request(engine, true);
        let after_backoff = orch.current_backoff(engine);
        assert!(after_backoff > initial_backoff);
    }

    #[test]
    fn priority_weighted_selection() {
        let mut orch = SearchOrchestrator::new(RotationStrategy::PriorityWeighted);
        let selected = orch.select_next_engine();
        assert!(selected.is_some());
    }

    #[test]
    fn config_defaults_vary_by_engine() {
        let wayback_cfg = SearchEngineConfig::default_for(SearchEngineType::WaybackMachine);
        let shodan_cfg = SearchEngineConfig::default_for(SearchEngineType::Shodan);
        // Shodan should be much more conservative
        assert!(shodan_cfg.rate_limit_per_minute < wayback_cfg.rate_limit_per_minute);
        assert!(shodan_cfg.max_backoff > wayback_cfg.max_backoff);
    }

    #[test]
    fn rate_limit_manager_creation() {
        let manager = RateLimitManager::new();
        assert!(!manager.states.is_empty());
    }

    #[test]
    fn rate_limit_manager_should_skip_if_backoff_exceeds_budget() {
        let mut manager = RateLimitManager::new();
        let source = SearchEngineType::GitHub;

        // Record multiple rate limits to build up backoff.
        for _ in 0..5 {
            manager.record_rate_limit(source);
        }

        let backoff = manager.current_backoff(source);
        let budget = Duration::from_millis(10); // Small budget, likely smaller than backoff

        // If backoff is large, should_skip should be true.
        if backoff > budget {
            assert!(manager.should_skip(source, budget));
        }
    }

    #[test]
    fn backoff_exponential_growth() {
        let mut manager = RateLimitManager::new();
        let source = SearchEngineType::GitHub;

        let initial = manager.current_backoff(source);
        manager.record_rate_limit(source);
        let after_one = manager.current_backoff(source);
        manager.record_rate_limit(source);
        let after_two = manager.current_backoff(source);

        // Each rate limit should roughly double backoff (2.0x multiplier).
        assert!(after_one > initial);
        assert!(after_two > after_one);
        // Verify exponential growth: after_two should be >= after_one * 1.5 (3/2 in integer arithmetic)
        let threshold_millis = after_one.as_millis() * 3 / 2;
        #[allow(clippy::cast_possible_truncation)]
        let threshold = Duration::from_millis(threshold_millis as u64);
        assert!(after_two >= threshold);
    }

    #[test]
    fn backoff_decay_on_success() {
        let mut manager = RateLimitManager::new();
        let source = SearchEngineType::GitHub;

        // Build up backoff.
        manager.record_rate_limit(source);
        let with_backoff = manager.current_backoff(source);

        // Record success to decay backoff.
        manager.record_success(source);
        let after_success = manager.current_backoff(source);

        // Backoff should decay but stay above initial (0.9x multiplier).
        assert!(after_success < with_backoff);
        assert!(after_success > Duration::from_millis(10));
    }

    #[test]
    fn backoff_respects_max_limit() {
        let mut manager = RateLimitManager::new();
        let source = SearchEngineType::GitHub;
        let config = SearchEngineConfig::default_for(source);

        // Record many rate limits to hit max backoff.
        for _ in 0..20 {
            manager.record_rate_limit(source);
        }

        let final_backoff = manager.current_backoff(source);
        // Should be capped at max_backoff, not exceed it.
        assert!(final_backoff <= config.max_backoff);
    }

    #[test]
    fn rate_limit_manager_default() {
        let manager = RateLimitManager::default();
        assert!(!manager.states.is_empty());
    }
}
