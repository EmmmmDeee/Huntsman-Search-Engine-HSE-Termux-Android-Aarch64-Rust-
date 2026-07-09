/// HSE Comprehensive API Key Hardwiring - REAL-TIME IMPLEMENTATION
///
/// Complete hardwired configuration for ALL 174 HSE modules + 46+ API integrations
/// - Identity & Breach: HIBP, DeHashed, OathNet Pro, Hunter.io, IntelX
/// - Infrastructure & Threat: Shodan, SecurityTrails, Censys, AbuseIPDB, GreyNoise
/// - Enrichment & Validation: NumVerify, HLR, OpenCNAM, Epieos, SEON, Proxycurl
/// - Specialized: WiGLE, OpenCorporates, Trove, EXA, LeakIX, Netlas, and 30+ more
///
/// HARDCODED DEFAULTS (from util/keys/constants.rs):
/// - HIBP: 42587552dce6424a87312941c8a2c3c5
/// - OathNet: 1f8097bdbf7dc68619857861adbc4343ddb490a1d72ae890551409e4b47116f2
/// - SeekNow: seek-fd18f1db9afdce325c90b8d0d27e8ebc02af489c95d0a9eb
/// - WiGLE User: AID4493a33e2df9d07ab9666a27c8aead17
/// - WiGLE Token: 1aedb7ad0171ff3d6be5a844cca5d977

use std::collections::HashMap;
use std::env;

/// Maximum API execution priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ApiExecutionPriority {
    Phase1Critical = 5,  // 0-config must-have: HIBP, OathNet, SeekNow, WiGLE
    Phase1Essential = 4, // Phase 1 core: Hunter, Dehashed, Censys, NumVerify, Shodan
    Phase2High = 3,      // Expansion: SecurityTrails, AbuseIPDB, GreyNoise, IntelX
    Phase2Medium = 2,    // Enhancement: SEON, Epieos, WhoisXML, Netlas, Proxycurl
    Phase3Optional = 1,  // Specialization: OpenCorporates, Trove, Criminalip, Ipqs
}

/// API module with full configuration
#[derive(Debug, Clone)]
pub struct ApiModuleConfig {
    pub env_key: String,
    pub module_name: String,
    pub priority: ApiExecutionPriority,
    pub category: &'static str,
    pub hardcoded_default: Option<&'static str>,
    pub has_fallback: bool,
    pub rate_limit_per_minute: u32,
    pub cost_per_call: f32,
    pub required_for_phase1: bool,
}

/// Comprehensive API key manager with real-time configuration
pub struct HseApiKeysComprehensive {
    // All 46+ API modules
    pub modules: HashMap<String, ApiModuleConfig>,

    // Resolved keys (env or hardcoded)
    pub keys: HashMap<String, String>,

    // Statistics
    pub stats: ApiKeyStats,
}

#[derive(Debug, Clone)]
pub struct ApiKeyStats {
    pub total_modules: usize,
    pub configured_keys: usize,
    pub hardcoded_fallbacks: usize,
    pub phase1_coverage_percent: f32,
    pub total_potential_cost: f32,
}

impl HseApiKeysComprehensive {
    /// Initialize with ALL hardcoded keys and module definitions
    pub fn new() -> Self {
        let mut manager = Self {
            modules: HashMap::new(),
            keys: HashMap::new(),
            stats: ApiKeyStats {
                total_modules: 0,
                configured_keys: 0,
                hardcoded_fallbacks: 0,
                phase1_coverage_percent: 0.0,
                total_potential_cost: 0.0,
            },
        };

        // Register ALL 46+ API modules
        manager.register_all_modules();
        manager.load_all_keys();
        manager.calculate_stats();

        manager
    }

    /// Register all 46+ API module configurations
    fn register_all_modules(&mut self) {
        // PHASE 1 CRITICAL (0-config, embedded defaults, must-have for Phase 1).
        // Key literals reference the single-source-of-truth in `util::keys` so an
        // embedded default can never drift between this table and the canonical
        // registry (a rotation in `keys::constants` propagates here automatically).
        use crate::util::keys::{
            HIBP_DEFAULT_KEY, OATHNET_DEFAULT_KEY, SEEKNOW_DEFAULT_KEY, WIGLE_DEFAULT_TOKEN,
            WIGLE_DEFAULT_USER,
        };
        self.register("HUNTSMAN_HIBP_KEY", "hibp", ApiExecutionPriority::Phase1Critical,
            "breach", Some(HIBP_DEFAULT_KEY), true, 60, 0.0, true);
        self.register("HUNTSMAN_OATHNET_KEY", "oathnet_pro", ApiExecutionPriority::Phase1Critical,
            "breach", Some(OATHNET_DEFAULT_KEY), true, 30, 10.0, true);
        self.register("HUNTSMAN_SEEKNOW_KEY", "see_know", ApiExecutionPriority::Phase1Critical,
            "orchestration", Some(SEEKNOW_DEFAULT_KEY), true, 50, 0.0, true);
        self.register("HUNTSMAN_WIGLE_USER", "wigle", ApiExecutionPriority::Phase1Critical,
            "geolocation", Some(WIGLE_DEFAULT_USER), true, 100, 0.0, true);
        self.register("HUNTSMAN_WIGLE_TOKEN", "wifi_intel", ApiExecutionPriority::Phase1Critical,
            "geolocation", Some(WIGLE_DEFAULT_TOKEN), true, 100, 0.0, true);

        // PHASE 1 ESSENTIAL (High priority, Phase 1 core functionality)
        self.register("HUNTSMAN_DEHASHED_KEY", "dehashed", ApiExecutionPriority::Phase1Essential,
            "breach", None, false, 10, 5.0, true);
        self.register("HUNTSMAN_HUNTER_KEY", "hunter_io", ApiExecutionPriority::Phase1Essential,
            "enrichment", None, false, 120, 1.0, true);
        self.register("HUNTSMAN_NUMVERIFY_KEY", "numverify", ApiExecutionPriority::Phase1Essential,
            "validation", None, false, 250, 0.5, true);
        self.register("HUNTSMAN_CENSYS_ID", "censys", ApiExecutionPriority::Phase1Essential,
            "infrastructure", None, false, 100, 0.0, true);
        self.register("HUNTSMAN_CENSYS_SECRET", "censys", ApiExecutionPriority::Phase1Essential,
            "infrastructure", None, false, 100, 0.0, true);
        self.register("HUNTSMAN_SHODAN_KEY", "shodan", ApiExecutionPriority::Phase1Essential,
            "infrastructure", None, false, 60, 0.0, true);

        // PHASE 2 HIGH (Expansion APIs)
        self.register("HUNTSMAN_SECTRAILS_KEY", "securitytrails", ApiExecutionPriority::Phase2High,
            "infrastructure", None, false, 100, 0.0, false);
        self.register("HUNTSMAN_ABUSEIPDB_KEY", "abuseipdb", ApiExecutionPriority::Phase2High,
            "threat_intel", None, false, 1000, 0.0, false);
        self.register("HUNTSMAN_GREYNOISE_KEY", "greynoise", ApiExecutionPriority::Phase2High,
            "threat_intel", None, false, 500, 0.0, false);
        self.register("HUNTSMAN_INTELX_KEY", "intelx", ApiExecutionPriority::Phase2High,
            "breach", None, false, 50, 3.0, false);
        self.register("HUNTSMAN_LEAKIX_KEY", "leakix", ApiExecutionPriority::Phase2High,
            "breach", None, false, 200, 0.0, false);
        self.register("HUNTSMAN_CRIMINALIP_KEY", "criminal_ip", ApiExecutionPriority::Phase2High,
            "threat_intel", None, false, 100, 0.0, false);

        // PHASE 2 MEDIUM (Enhancement APIs)
        self.register("HUNTSMAN_WHOISXML_KEY", "whoisxml", ApiExecutionPriority::Phase2Medium,
            "domain", None, false, 500, 0.1, false);
        self.register("HUNTSMAN_NETLAS_KEY", "netlas", ApiExecutionPriority::Phase2Medium,
            "infrastructure", None, false, 150, 0.0, false);
        self.register("HUNTSMAN_ONYPHE_KEY", "onyphe", ApiExecutionPriority::Phase2Medium,
            "threat_intel", None, false, 100, 0.0, false);
        self.register("HUNTSMAN_EMAILREP_KEY", "emailrep", ApiExecutionPriority::Phase2Medium,
            "validation", None, false, 150, 0.0, false);
        self.register("HUNTSMAN_HLR_KEY", "hlr_cnam", ApiExecutionPriority::Phase2Medium,
            "validation", None, false, 100, 0.5, false);
        self.register("HUNTSMAN_OPENCNAM_KEY", "hlr_cnam", ApiExecutionPriority::Phase2Medium,
            "validation", None, false, 100, 0.1, false);
        self.register("HUNTSMAN_SEON_KEY", "seon", ApiExecutionPriority::Phase2Medium,
            "enrichment", None, false, 100, 0.0, false);
        self.register("HUNTSMAN_EPIEOS_KEY", "epieos", ApiExecutionPriority::Phase2Medium,
            "enrichment", None, false, 100, 0.0, false);
        self.register("HUNTSMAN_PROXYCURL_KEY", "proxycurl", ApiExecutionPriority::Phase2Medium,
            "enrichment", None, false, 100, 0.5, false);

        // PHASE 3 OPTIONAL (Specialized APIs)
        self.register("HUNTSMAN_IPQS_KEY", "ipqs", ApiExecutionPriority::Phase3Optional,
            "threat_intel", None, false, 100, 0.0, false);
        self.register("HUNTSMAN_VIRUSTOTAL_KEY", "virustotal", ApiExecutionPriority::Phase3Optional,
            "threat_intel", None, false, 100, 0.0, false);
        self.register("HUNTSMAN_THREATFOX_KEY", "threatfox", ApiExecutionPriority::Phase3Optional,
            "threat_intel", None, false, 100, 0.0, false);
        self.register("HUNTSMAN_ABUSECH_KEY", "urlhaus", ApiExecutionPriority::Phase3Optional,
            "threat_intel", None, false, 100, 0.0, false);
        self.register("HUNTSMAN_EXA_KEY", "exa_search", ApiExecutionPriority::Phase3Optional,
            "search", None, false, 100, 0.0, false);
        self.register("HUNTSMAN_ZOOMEYE_KEY", "zoomeye", ApiExecutionPriority::Phase3Optional,
            "infrastructure", None, false, 100, 0.0, false);
        self.register("HUNTSMAN_FOFA_KEY", "fofa", ApiExecutionPriority::Phase3Optional,
            "infrastructure", None, false, 100, 0.0, false);
        self.register("HUNTSMAN_BINARYEDGE_KEY", "binaryedge", ApiExecutionPriority::Phase3Optional,
            "infrastructure", None, false, 100, 0.0, false);
        self.register("HUNTSMAN_FULLHUNT_KEY", "fullhunt", ApiExecutionPriority::Phase3Optional,
            "infrastructure", None, false, 100, 0.0, false);
        self.register("HUNTSMAN_URLSCAN_KEY", "urlscan", ApiExecutionPriority::Phase3Optional,
            "infrastructure", None, false, 100, 0.0, false);
        self.register("HUNTSMAN_PASSIVETOTAL_KEY", "passivetotal", ApiExecutionPriority::Phase3Optional,
            "infrastructure", None, false, 100, 0.0, false);
        self.register("HUNTSMAN_PULSEDIVE_KEY", "pulsedive", ApiExecutionPriority::Phase3Optional,
            "threat_intel", None, false, 100, 0.0, false);
        self.register("HUNTSMAN_BUILTWITH_KEY", "builtwith", ApiExecutionPriority::Phase3Optional,
            "infrastructure", None, false, 100, 0.0, false);

        // AUSTRALIAN & SPECIALIZED
        self.register("HUNTSMAN_TROVE_KEY", "trove_au", ApiExecutionPriority::Phase3Optional,
            "archive", None, false, 100, 0.0, false);
        self.register("HUNTSMAN_OPENCORP_KEY", "opencorporates", ApiExecutionPriority::Phase3Optional,
            "enrichment", None, false, 100, 0.0, false);
        self.register("HUNTSMAN_ABR_GUID", "abn_lookup", ApiExecutionPriority::Phase3Optional,
            "australian", None, false, 100, 0.0, false);
        self.register("HUNTSMAN_OPENCELLID_KEY", "opencellid", ApiExecutionPriority::Phase3Optional,
            "geolocation", None, false, 100, 0.0, false);
        self.register("HUNTSMAN_MLS_KEY", "mls", ApiExecutionPriority::Phase3Optional,
            "enrichment", None, false, 100, 0.0, false);
        self.register("HUNTSMAN_OSINTCAT_KEY", "osintcat", ApiExecutionPriority::Phase3Optional,
            "orchestration", None, false, 100, 0.0, false);

        self.stats.total_modules = self.modules.len();
    }

    /// Register a single API module
    fn register(&mut self, env_key: &str, module_name: &str, priority: ApiExecutionPriority,
        category: &'static str, hardcoded: Option<&'static str>, has_fallback: bool,
        rate_limit: u32, cost: f32, required: bool) {

        let config = ApiModuleConfig {
            env_key: env_key.to_string(),
            module_name: module_name.to_string(),
            priority,
            category,
            hardcoded_default: hardcoded,
            has_fallback,
            rate_limit_per_minute: rate_limit,
            cost_per_call: cost,
            required_for_phase1: required,
        };
        self.modules.insert(env_key.to_string(), config);
    }

    /// Load all keys from environment and hardcoded defaults
    fn load_all_keys(&mut self) {
        for (env_key, config) in &self.modules {
            // Try environment first
            let key_value = env::var(env_key).ok().or_else(|| {
                // Fall back to hardcoded default if available
                config.hardcoded_default.map(|s| s.to_string())
            });

            if let Some(key) = key_value {
                if !key.is_empty() {
                    self.keys.insert(env_key.clone(), key);
                    self.stats.configured_keys += 1;
                    if config.hardcoded_default.is_some() {
                        self.stats.hardcoded_fallbacks += 1;
                    }
                }
            }
        }
    }

    /// Calculate comprehensive statistics
    fn calculate_stats(&mut self) {
        // Phase 1 coverage
        let phase1_modules: Vec<_> = self.modules.values()
            .filter(|m| m.required_for_phase1)
            .collect();
        let phase1_available = phase1_modules.iter()
            .filter(|m| self.keys.contains_key(&m.env_key))
            .count();

        self.stats.phase1_coverage_percent = if phase1_modules.is_empty() {
            0.0
        } else {
            (phase1_available as f32 / phase1_modules.len() as f32) * 100.0
        };

        // Total estimated cost
        self.stats.total_potential_cost = self.modules.values()
            .filter(|m| self.keys.contains_key(&m.env_key))
            .map(|m| m.cost_per_call * 10.0) // Estimate 10 calls per module
            .sum();
    }

    /// Get execution plan for phase
    pub fn get_phase_execution_plan(&self, phase: &str) -> Vec<(String, String, f32)> {
        let priorities = match phase {
            "phase1" => vec![ApiExecutionPriority::Phase1Critical, ApiExecutionPriority::Phase1Essential],
            "phase2" => vec![ApiExecutionPriority::Phase1Critical, ApiExecutionPriority::Phase1Essential,
                           ApiExecutionPriority::Phase2High, ApiExecutionPriority::Phase2Medium],
            "phase3" => vec![ApiExecutionPriority::Phase1Critical, ApiExecutionPriority::Phase1Essential,
                           ApiExecutionPriority::Phase2High, ApiExecutionPriority::Phase2Medium,
                           ApiExecutionPriority::Phase3Optional],
            _ => return Vec::new(),
        };

        self.modules.values()
            .filter(|m| priorities.contains(&m.priority) && self.keys.contains_key(&m.env_key))
            .map(|m| (m.module_name.clone(), m.category.to_string(), m.cost_per_call))
            .collect()
    }

    /// Generate comprehensive status report
    pub fn get_status_report(&self) -> String {
        let phase1_apis = self.get_phase_execution_plan("phase1");
        let phase2_apis = self.get_phase_execution_plan("phase2");
        let phase3_apis = self.get_phase_execution_plan("phase3");

        let status = if self.stats.phase1_coverage_percent >= 80.0 {
            "✓ READY FOR PHASE 1 EXECUTION"
        } else {
            "✗ PHASE 1 NOT READY - Missing critical keys"
        };

        format!(
            "HSE Comprehensive API Key Management\n\
             =====================================\n\
             Total API Modules: {}\n\
             Configured Keys: {} ({:.1}%)\n\
             Hardcoded Fallbacks: {}\n\
             \n\
             Phase 1 Coverage: {:.1}%\n\
             Phase 1 Status: {}\n\
             \n\
             Available APIs by Phase:\n\
             Phase 1: {} modules ({})\n\
             Phase 2: {} modules ({})\n\
             Phase 3: {} modules ({})\n\
             \n\
             Estimated Cost (10 calls/API): ${:.2}\n\
             \n\
             Execution Status:\n\
             - Phase 1: {}\n\
             - Phase 2: Ready to expand with {} additional APIs\n\
             - Phase 3: {} specialized APIs available\n",
            self.stats.total_modules,
            self.stats.configured_keys,
            (self.stats.configured_keys as f32 / self.stats.total_modules as f32) * 100.0,
            self.stats.hardcoded_fallbacks,
            self.stats.phase1_coverage_percent,
            status,
            phase1_apis.len(),
            phase1_apis.iter().map(|(n, _, _)| n).cloned().collect::<Vec<_>>().join(", "),
            phase2_apis.len(),
            phase2_apis.iter().map(|(n, _, _)| n).cloned().collect::<Vec<_>>().join(", "),
            phase3_apis.len(),
            phase3_apis.iter().map(|(n, _, _)| n).cloned().collect::<Vec<_>>().join(", "),
            self.stats.total_potential_cost,
            if self.stats.phase1_coverage_percent >= 80.0 { "✓ Ready" } else { "⚠ Incomplete" },
            phase2_apis.len(),
            phase3_apis.len()
        )
    }

    /// Get detailed module inventory
    pub fn get_module_inventory(&self) -> String {
        let mut inventory = String::from("Module Inventory (46+ APIs)\n=============================\n\n");

        for priority in [
            ApiExecutionPriority::Phase1Critical,
            ApiExecutionPriority::Phase1Essential,
            ApiExecutionPriority::Phase2High,
            ApiExecutionPriority::Phase2Medium,
            ApiExecutionPriority::Phase3Optional,
        ].iter() {
            let modules: Vec<_> = self.modules.values()
                .filter(|m| m.priority == *priority)
                .collect();

            if !modules.is_empty() {
                let phase = match priority {
                    ApiExecutionPriority::Phase1Critical => "PHASE 1 CRITICAL (0-config)",
                    ApiExecutionPriority::Phase1Essential => "PHASE 1 ESSENTIAL",
                    ApiExecutionPriority::Phase2High => "PHASE 2 HIGH",
                    ApiExecutionPriority::Phase2Medium => "PHASE 2 MEDIUM",
                    ApiExecutionPriority::Phase3Optional => "PHASE 3 OPTIONAL",
                };

                inventory.push_str(&format!("{}\n", phase));
                inventory.push_str(&format!("{}\n", "-".repeat(phase.len())));

                for m in modules {
                    let status = if self.keys.contains_key(&m.env_key) { "✓" } else { "✗" };
                    let default_note = if m.hardcoded_default.is_some() { " [hardcoded]" } else { "" };
                    inventory.push_str(&format!(
                        "{} {} - {} (${:.1}/call, {} req/min){}\n",
                        status, m.env_key, m.module_name, m.cost_per_call,
                        m.rate_limit_per_minute, default_note
                    ));
                }
                inventory.push_str("\n");
            }
        }

        inventory
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialization() {
        let manager = HseApiKeysComprehensive::new();
        assert!(manager.modules.len() > 40); // 46+ modules
        assert!(manager.keys.len() > 0); // At least hardcoded defaults
    }

    #[test]
    fn test_phase_planning() {
        let manager = HseApiKeysComprehensive::new();
        let phase1 = manager.get_phase_execution_plan("phase1");
        let phase2 = manager.get_phase_execution_plan("phase2");
        let phase3 = manager.get_phase_execution_plan("phase3");

        assert!(phase1.len() > 0);
        assert!(phase2.len() >= phase1.len());
        assert!(phase3.len() >= phase2.len());
    }

    #[test]
    fn test_hardcoded_defaults_loaded() {
        let manager = HseApiKeysComprehensive::new();
        // At minimum, the 5 phase1-critical 0-config keys should be loaded
        assert!(manager.keys.contains_key("HUNTSMAN_HIBP_KEY"));
        assert!(manager.keys.contains_key("HUNTSMAN_SEEKNOW_KEY"));
        assert!(manager.keys.len() >= 5);
    }

    #[test]
    fn test_status_report() {
        let manager = HseApiKeysComprehensive::new();
        let report = manager.get_status_report();
        assert!(report.contains("API Key Management"));
        assert!(report.contains("Phase 1"));
        assert!(report.contains("Estimated Cost"));
    }
}
