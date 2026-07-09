/// API Key Management Startup Initialization
///
/// Handles:
/// - Auto-discovery and loading of all API keys at startup
/// - Key validation and health checks
/// - Configuration from environment and remote sources
/// - Secure storage in encrypted vault
/// - Error recovery and fallback strategies
/// - Progress tracking and diagnostics

use crate::util::api_key_manager::{ApiKeyManager, AuthType};
use crate::util::api_key_retriever::{
    ApiKeyRetriever, KeyRetrievalConfig, KeySourceType, RetrievedKey, StartupInitResult,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// Startup initialization options
#[derive(Debug, Clone)]
pub struct StartupOptions {
    pub validate_keys: bool,
    pub validate_timeout_seconds: u64,
    pub max_parallel_validations: usize,
    pub enable_aws_secrets_manager: bool,
    pub enable_vault: bool,
    pub enable_remote_config: bool,
    pub fail_on_critical_keys: bool,
    pub critical_api_names: Vec<String>,
}

/// Startup initialization engine
pub struct ApiKeyStartupEngine {
    pub key_manager: ApiKeyManager,
    pub key_retriever: ApiKeyRetriever,
    pub options: StartupOptions,
}

/// Per-API initialization result
#[derive(Debug, Clone)]
pub struct ApiInitResult {
    pub api_name: String,
    pub key_loaded: bool,
    pub key_validated: bool,
    pub validation_error: Option<String>,
    pub source: KeySourceType,
    pub initialization_time_ms: u64,
}

impl StartupOptions {
    /// Create default startup options
    pub fn default() -> Self {
        Self {
            validate_keys: true,
            validate_timeout_seconds: 5,
            max_parallel_validations: 4,
            enable_aws_secrets_manager: false,
            enable_vault: false,
            enable_remote_config: false,
            fail_on_critical_keys: false,
            critical_api_names: vec![
                "SeekNow".to_string(),
                "OathNet Pro".to_string(),
                "HIBP".to_string(),
            ],
        }
    }

    /// Create aggressive validation options
    pub fn aggressive_validation() -> Self {
        Self {
            validate_keys: true,
            validate_timeout_seconds: 10,
            max_parallel_validations: 8,
            enable_aws_secrets_manager: true,
            enable_vault: true,
            enable_remote_config: true,
            fail_on_critical_keys: true,
            critical_api_names: vec![
                "SeekNow".to_string(),
                "OathNet Pro".to_string(),
                "HIBP".to_string(),
                "Hunter.io".to_string(),
                "FullContact".to_string(),
            ],
        }
    }

    /// Create lightweight options for development
    pub fn lightweight() -> Self {
        Self {
            validate_keys: false,
            validate_timeout_seconds: 2,
            max_parallel_validations: 1,
            enable_aws_secrets_manager: false,
            enable_vault: false,
            enable_remote_config: false,
            fail_on_critical_keys: false,
            critical_api_names: vec![],
        }
    }
}

impl ApiKeyStartupEngine {
    /// Create new startup engine with configuration
    pub fn new(key_manager: ApiKeyManager, options: StartupOptions) -> Self {
        let retrieval_config = Self::create_retrieval_config(&options);
        let key_retriever = ApiKeyRetriever::new(retrieval_config);

        Self {
            key_manager,
            key_retriever,
            options,
        }
    }

    /// Create key retrieval configuration from startup options
    fn create_retrieval_config(options: &StartupOptions) -> KeyRetrievalConfig {
        let mut config = KeyRetrievalConfig::production();

        if options.enable_aws_secrets_manager {
            config = KeyRetrievalConfig::with_aws("us-east-1".to_string());
        }

        if options.enable_vault {
            if let Ok(vault_addr) = std::env::var("VAULT_ADDR") {
                if let Ok(vault_token) = std::env::var("VAULT_TOKEN") {
                    config = KeyRetrievalConfig::with_vault(vault_addr, vault_token);
                }
            }
        }

        if options.enable_remote_config {
            if let Ok(config_url) = std::env::var("HUNTSMAN_CONFIG_SERVER_URL") {
                if let Ok(config_token) = std::env::var("HUNTSMAN_CONFIG_TOKEN") {
                    config = KeyRetrievalConfig::with_remote_server(config_url, config_token);
                }
            }
        }

        config
    }

    /// Execute full startup initialization
    pub fn initialize(&mut self) -> StartupInitResult {
        let start_time = current_time_ms();

        let mut results = Vec::new();
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Get all configured API names
        let api_names: Vec<String> = self
            .key_manager
            .configuration_templates
            .keys()
            .cloned()
            .collect();

        let total_apis = api_names.len();

        // Load and validate each API key
        for api_name in api_names {
            match self.initialize_api_key(&api_name) {
                Ok(result) => {
                    if !result.key_loaded {
                        let error_msg = result.validation_error.clone().unwrap_or_default();
                        warnings.push(format!(
                            "Key not found for {}: {}",
                            api_name,
                            error_msg
                        ));
                    }
                    results.push(result);
                }
                Err(e) => {
                    if self.options.critical_api_names.contains(&api_name) {
                        if self.options.fail_on_critical_keys {
                            errors.push(format!("Critical API {} initialization failed: {}", api_name, e));
                        } else {
                            warnings.push(format!(
                                "Critical API {} initialization failed (non-fatal): {}",
                                api_name, e
                            ));
                        }
                    } else {
                        warnings.push(format!("API {} initialization failed: {}", api_name, e));
                    }
                }
            }
        }

        let keys_loaded = results.iter().filter(|r| r.key_loaded).count();
        let keys_validated = results.iter().filter(|r| r.key_validated).count();
        let initialization_time_ms = current_time_ms() - start_time;

        StartupInitResult {
            total_apis_configured: total_apis,
            keys_loaded,
            keys_validated,
            initialization_time_ms,
            errors: if self.options.fail_on_critical_keys {
                errors
            } else {
                Vec::new()
            },
            warnings,
        }
    }

    /// Initialize a single API key
    fn initialize_api_key(&mut self, api_name: &str) -> Result<ApiInitResult, String> {
        let start_time = current_time_ms();

        // Try to retrieve the key
        let retrieved_key = match self.key_retriever.retrieve_key(api_name) {
            Ok(key) => key,
            Err(e) => {
                return Ok(ApiInitResult {
                    api_name: api_name.to_string(),
                    key_loaded: false,
                    key_validated: false,
                    validation_error: Some(e),
                    source: KeySourceType::Environment,
                    initialization_time_ms: current_time_ms() - start_time,
                });
            }
        };

        // Store the key
        self.store_key(api_name, &retrieved_key)?;

        // Validate if enabled
        let key_validated = if self.options.validate_keys {
            self.validate_key(api_name)
                .map_err(|e| format!("Validation failed: {}", e))
                .unwrap_or(false)
        } else {
            false
        };

        Ok(ApiInitResult {
            api_name: api_name.to_string(),
            key_loaded: true,
            key_validated,
            validation_error: None,
            source: retrieved_key.source,
            initialization_time_ms: current_time_ms() - start_time,
        })
    }

    /// Store retrieved key in key manager
    fn store_key(&mut self, api_name: &str, retrieved_key: &RetrievedKey) -> Result<(), String> {
        use crate::util::api_key_manager::ApiKeyConfig;

        let auth_type = if retrieved_key.api_secret.is_some() {
            AuthType::MultiKey(vec![
                retrieved_key.key_value.clone(),
                retrieved_key.api_secret.clone().unwrap_or_default(),
            ])
        } else {
            AuthType::ApiKey
        };

        let config = self
            .key_manager
            .configuration_templates
            .get(api_name)
            .ok_or_else(|| format!("No template found for API: {}", api_name))?
            .clone();

        let key_config = ApiKeyConfig {
            api_name: api_name.to_string(),
            api_key: retrieved_key.key_value.clone(),
            api_secret: retrieved_key.api_secret.clone(),
            auth_type,
            base_url: config.default_base_url,
            rate_limit_key: Some(api_name.to_string()),
            account_id: retrieved_key.account_id.clone(),
            workspace_id: None,
            configured_at_ms: current_time_ms(),
            expires_at_ms: retrieved_key.expires_at_ms,
            rotation_interval_days: Some(30),
        };

        self.key_manager.keys.insert(api_name.to_string(), key_config);
        Ok(())
    }

    /// Validate a stored key
    fn validate_key(&self, api_name: &str) -> Result<bool, String> {
        let config = self
            .key_manager
            .keys
            .get(api_name)
            .ok_or_else(|| format!("Key not found for API: {}", api_name))?;

        // In production, this would make a test API call
        // For now, just check that the key is not empty
        Ok(!config.api_key.is_empty())
    }

    /// Get detailed initialization report
    pub fn get_initialization_report(&self) -> String {
        let stats = self.key_retriever.get_retrieval_stats();
        let (cache_size, cache_hits, cache_misses) = self.key_retriever.get_cache_stats();

        format!(
            "API Key Retrieval Report:\n\
             - Total Retrievals: {}\n\
             - Successful: {}\n\
             - Failed: {}\n\
             - Cache Hits: {}\n\
             - Cache Misses: {}\n\
             - Cached Keys: {}\n\
             - Environment Source Hits: {}\n\
             - AWS Source Hits: {}\n\
             - Vault Source Hits: {}\n\
             - Remote Server Hits: {}\n\
             - Fallback Activations: {}",
            stats.total_retrievals,
            stats.successful_retrievals,
            stats.failed_retrievals,
            cache_hits,
            cache_misses,
            cache_size,
            stats.env_source_hits,
            stats.aws_source_hits,
            stats.vault_source_hits,
            stats.remote_source_hits,
            stats.fallback_activations
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
    fn test_startup_options_default() {
        let options = StartupOptions::default();
        assert!(options.validate_keys);
        assert!(!options.enable_aws_secrets_manager);
        assert_eq!(options.critical_api_names.len(), 3);
    }

    #[test]
    fn test_startup_options_aggressive() {
        let options = StartupOptions::aggressive_validation();
        assert!(options.validate_keys);
        assert!(options.enable_aws_secrets_manager);
        assert!(options.enable_vault);
        assert!(options.fail_on_critical_keys);
        assert_eq!(options.critical_api_names.len(), 5);
    }

    #[test]
    fn test_startup_options_lightweight() {
        let options = StartupOptions::lightweight();
        assert!(!options.validate_keys);
        assert!(!options.enable_aws_secrets_manager);
        assert_eq!(options.critical_api_names.len(), 0);
    }

    #[test]
    fn test_startup_engine_creation() {
        let key_manager = ApiKeyManager::new();
        let options = StartupOptions::lightweight();
        let engine = ApiKeyStartupEngine::new(key_manager, options);

        assert_eq!(engine.key_manager.keys.len(), 0);
        assert!(!engine.options.validate_keys);
    }

    #[test]
    fn test_critical_api_validation() {
        let mut options = StartupOptions::default();
        assert!(options.critical_api_names.contains(&"SeekNow".to_string()));

        let options_agg = StartupOptions::aggressive_validation();
        assert!(options_agg.fail_on_critical_keys);
        assert_eq!(options_agg.critical_api_names.len(), 5);
    }

    #[test]
    fn test_initialization_report_generation() {
        let key_manager = ApiKeyManager::new();
        let options = StartupOptions::lightweight();
        let engine = ApiKeyStartupEngine::new(key_manager, options);

        let report = engine.get_initialization_report();
        assert!(report.contains("API Key Retrieval Report"));
        assert!(report.contains("Total Retrievals"));
        assert!(report.contains("Cache Hits"));
    }

    #[test]
    fn test_api_init_result_structure() {
        let result = ApiInitResult {
            api_name: "TestAPI".to_string(),
            key_loaded: true,
            key_validated: true,
            validation_error: None,
            source: KeySourceType::Environment,
            initialization_time_ms: 100,
        };

        assert_eq!(result.api_name, "TestAPI");
        assert!(result.key_loaded);
        assert!(result.key_validated);
        assert_eq!(result.initialization_time_ms, 100);
    }

    #[test]
    fn test_critical_api_tracking() {
        let options = StartupOptions::default();
        assert!(options.critical_api_names.contains(&"SeekNow".to_string()));
        assert!(options.critical_api_names.contains(&"OathNet Pro".to_string()));
        assert!(options.critical_api_names.contains(&"HIBP".to_string()));
    }
}
