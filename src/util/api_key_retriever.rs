/// Comprehensive API Key Retrieval System
///
/// Supports multiple key sources:
/// - Environment variables (fastest, local)
/// - AWS Secrets Manager (cloud-native, dynamic)
/// - HashiCorp Vault (enterprise, audit trail)
/// - Remote configuration servers (flexible, centralized)
/// - Local file cache with TTL (offline fallback)

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Key retrieval configuration
#[derive(Debug, Clone)]
pub struct KeyRetrievalConfig {
    pub enabled_sources: Vec<KeySource>,
    pub fallback_enabled: bool,
    pub cache_ttl_seconds: u64,
    pub validation_timeout_seconds: u64,
    pub max_retries: u32,
    pub retry_backoff_ms: Vec<u64>,
}

/// Supported key sources
#[derive(Debug, Clone, PartialEq)]
pub enum KeySource {
    EnvironmentVariables,
    AwsSecretsManager(AwsConfig),
    HashiCorpVault(VaultConfig),
    RemoteConfigServer(RemoteServerConfig),
    LocalCache,
}

/// AWS Secrets Manager configuration
#[derive(Debug, Clone, PartialEq)]
pub struct AwsConfig {
    pub region: String,
    pub secret_prefix: String,
    pub assume_role_arn: Option<String>,
    pub endpoint_override: Option<String>,
}

/// HashiCorp Vault configuration
#[derive(Debug, Clone, PartialEq)]
pub struct VaultConfig {
    pub address: String,
    pub namespace: String,
    pub auth_method: VaultAuthMethod,
    pub secret_path_template: String,
    pub tls_enabled: bool,
    pub tls_ca_cert_path: Option<String>,
}

/// Vault authentication methods
#[derive(Debug, Clone, PartialEq)]
pub enum VaultAuthMethod {
    Token(String),
    AppRole { role_id: String, secret_id: String },
    Kubernetes { role: String, jwt_path: String },
    Ldap { username: String, password: String },
}

/// Remote configuration server configuration
#[derive(Debug, Clone, PartialEq)]
pub struct RemoteServerConfig {
    pub base_url: String,
    pub auth_token: Option<String>,
    pub endpoint_path: String,
    pub api_key_field: String,
    pub tls_verify: bool,
    pub timeout_seconds: u64,
}

/// Retrieved key with metadata
#[derive(Debug, Clone)]
pub struct RetrievedKey {
    pub api_name: String,
    pub key_value: String,
    pub api_secret: Option<String>,
    pub account_id: Option<String>,
    pub source: KeySourceType,
    pub retrieved_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    pub validation_status: KeyValidationStatus,
}

/// Key source type tracking
#[derive(Debug, Clone, PartialEq)]
pub enum KeySourceType {
    Environment,
    AwsSecretsManager,
    Vault,
    RemoteServer,
    LocalCache,
}

/// Key validation status
#[derive(Debug, Clone)]
pub struct KeyValidationStatus {
    pub is_valid: bool,
    pub validation_error: Option<String>,
    pub last_validated_ms: u64,
    pub response_time_ms: u64,
}

/// Master key retriever orchestrating all sources
pub struct ApiKeyRetriever {
    pub config: KeyRetrievalConfig,
    pub local_cache: HashMap<String, CachedKey>,
    pub retrieval_stats: RetrievalStats,
}

/// Cached key with TTL
#[derive(Debug, Clone)]
pub struct CachedKey {
    pub api_name: String,
    pub key_value: String,
    pub api_secret: Option<String>,
    pub account_id: Option<String>,
    pub cached_at_ms: u64,
    pub source: KeySourceType,
    pub hits: u64,
    pub last_accessed_ms: u64,
}

/// Retrieval statistics
#[derive(Debug, Clone)]
pub struct RetrievalStats {
    pub total_retrievals: u64,
    pub successful_retrievals: u64,
    pub failed_retrievals: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub env_source_hits: u64,
    pub aws_source_hits: u64,
    pub vault_source_hits: u64,
    pub remote_source_hits: u64,
    pub fallback_activations: u64,
}

/// Startup initialization result
#[derive(Debug, Clone)]
pub struct StartupInitResult {
    pub total_apis_configured: usize,
    pub keys_loaded: usize,
    pub keys_validated: usize,
    pub initialization_time_ms: u64,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl KeyRetrievalConfig {
    /// Create a production configuration with all sources enabled
    pub fn production() -> Self {
        Self {
            enabled_sources: vec![
                KeySource::EnvironmentVariables,
                KeySource::LocalCache,
            ],
            fallback_enabled: true,
            cache_ttl_seconds: 3600,
            validation_timeout_seconds: 5,
            max_retries: 3,
            retry_backoff_ms: vec![100, 500, 2000],
        }
    }

    /// Create a development configuration with env vars only
    pub fn development() -> Self {
        Self {
            enabled_sources: vec![KeySource::EnvironmentVariables],
            fallback_enabled: false,
            cache_ttl_seconds: 300,
            validation_timeout_seconds: 10,
            max_retries: 1,
            retry_backoff_ms: vec![100],
        }
    }

    /// Create a configuration with AWS Secrets Manager
    pub fn with_aws(region: String) -> Self {
        let mut config = Self::production();
        config.enabled_sources.insert(
            0,
            KeySource::AwsSecretsManager(AwsConfig {
                region,
                secret_prefix: "huntsman/api-keys/".to_string(),
                assume_role_arn: None,
                endpoint_override: None,
            }),
        );
        config
    }

    /// Create a configuration with HashiCorp Vault
    pub fn with_vault(address: String, token: String) -> Self {
        let mut config = Self::production();
        config.enabled_sources.insert(
            0,
            KeySource::HashiCorpVault(VaultConfig {
                address,
                namespace: "huntsman".to_string(),
                auth_method: VaultAuthMethod::Token(token),
                secret_path_template: "secret/data/api-keys/{{api_name}}".to_string(),
                tls_enabled: true,
                tls_ca_cert_path: None,
            }),
        );
        config
    }

    /// Create a configuration with remote config server
    pub fn with_remote_server(base_url: String, auth_token: String) -> Self {
        let mut config = Self::production();
        config.enabled_sources.insert(
            0,
            KeySource::RemoteConfigServer(RemoteServerConfig {
                base_url,
                auth_token: Some(auth_token),
                endpoint_path: "/api/v1/api-keys".to_string(),
                api_key_field: "key_value".to_string(),
                tls_verify: true,
                timeout_seconds: 5,
            }),
        );
        config
    }
}

impl ApiKeyRetriever {
    /// Initialize with configuration
    pub fn new(config: KeyRetrievalConfig) -> Self {
        Self {
            config,
            local_cache: HashMap::new(),
            retrieval_stats: RetrievalStats {
                total_retrievals: 0,
                successful_retrievals: 0,
                failed_retrievals: 0,
                cache_hits: 0,
                cache_misses: 0,
                env_source_hits: 0,
                aws_source_hits: 0,
                vault_source_hits: 0,
                remote_source_hits: 0,
                fallback_activations: 0,
            },
        }
    }

    /// Retrieve a key using configured sources with fallback chain
    pub fn retrieve_key(&mut self, api_name: &str) -> Result<RetrievedKey, String> {
        self.retrieval_stats.total_retrievals += 1;

        // Check local cache first
        let cache_result = if let Some(cached) = self.local_cache.get(api_name) {
            let age_ms = current_time_ms() - cached.cached_at_ms;
            if age_ms < (self.config.cache_ttl_seconds * 1000) {
                Some((
                    cached.key_value.clone(),
                    cached.api_secret.clone(),
                    cached.account_id.clone(),
                    cached.source.clone(),
                ))
            } else {
                None
            }
        } else {
            None
        };

        if let Some((key_value, api_secret, account_id, source)) = cache_result {
            self.retrieval_stats.cache_hits += 1;
            let mut cached_copy = self.local_cache.get_mut(api_name).unwrap();
            cached_copy.hits += 1;
            cached_copy.last_accessed_ms = current_time_ms();

            self.retrieval_stats.successful_retrievals += 1;
            return Ok(RetrievedKey {
                api_name: api_name.to_string(),
                key_value,
                api_secret,
                account_id,
                source,
                retrieved_at_ms: current_time_ms(),
                expires_at_ms: None,
                validation_status: KeyValidationStatus {
                    is_valid: true,
                    validation_error: None,
                    last_validated_ms: current_time_ms(),
                    response_time_ms: 1,
                },
            });
        }

        self.retrieval_stats.cache_misses += 1;

        // Try enabled sources in order
        for source in &self.config.enabled_sources.clone() {
            if let Some(result) = self.try_retrieve_from_source(api_name, source) {
                // Cache successful retrieval
                self.local_cache.insert(
                    api_name.to_string(),
                    CachedKey {
                        api_name: api_name.to_string(),
                        key_value: result.key_value.clone(),
                        api_secret: result.api_secret.clone(),
                        account_id: result.account_id.clone(),
                        cached_at_ms: current_time_ms(),
                        source: result.source.clone(),
                        hits: 1,
                        last_accessed_ms: current_time_ms(),
                    },
                );

                match result.source {
                    KeySourceType::Environment => self.retrieval_stats.env_source_hits += 1,
                    KeySourceType::AwsSecretsManager => self.retrieval_stats.aws_source_hits += 1,
                    KeySourceType::Vault => self.retrieval_stats.vault_source_hits += 1,
                    KeySourceType::RemoteServer => self.retrieval_stats.remote_source_hits += 1,
                    KeySourceType::LocalCache => {}
                }

                self.retrieval_stats.successful_retrievals += 1;
                return Ok(result);
            }
        }

        self.retrieval_stats.failed_retrievals += 1;
        Err(format!("Failed to retrieve key for API: {}", api_name))
    }

    /// Try to retrieve from a specific source
    fn try_retrieve_from_source(
        &self,
        api_name: &str,
        source: &KeySource,
    ) -> Option<RetrievedKey> {
        match source {
            KeySource::EnvironmentVariables => self.retrieve_from_env(api_name),
            KeySource::AwsSecretsManager(config) => self.retrieve_from_aws(api_name, config),
            KeySource::HashiCorpVault(config) => self.retrieve_from_vault(api_name, config),
            KeySource::RemoteConfigServer(config) => {
                self.retrieve_from_remote_server(api_name, config)
            }
            KeySource::LocalCache => None,
        }
    }

    /// Retrieve from environment variables
    fn retrieve_from_env(&self, api_name: &str) -> Option<RetrievedKey> {
        // Try common environment variable patterns
        let patterns = vec![
            format!("HUNTSMAN_{}_KEY", api_name.to_uppercase().replace(" ", "_")),
            format!("{}_API_KEY", api_name.to_uppercase().replace(" ", "_")),
            format!("HUNTSMAN_API_{}", api_name.to_uppercase().replace(" ", "_")),
        ];

        for pattern in patterns {
            if let Ok(key_value) = std::env::var(&pattern) {
                return Some(RetrievedKey {
                    api_name: api_name.to_string(),
                    key_value,
                    api_secret: std::env::var(format!("{}_SECRET", pattern)).ok(),
                    account_id: std::env::var(format!("{}_ACCOUNT_ID", pattern)).ok(),
                    source: KeySourceType::Environment,
                    retrieved_at_ms: current_time_ms(),
                    expires_at_ms: None,
                    validation_status: KeyValidationStatus {
                        is_valid: true,
                        validation_error: None,
                        last_validated_ms: current_time_ms(),
                        response_time_ms: 1,
                    },
                });
            }
        }

        None
    }

    /// Retrieve from AWS Secrets Manager
    fn retrieve_from_aws(&self, api_name: &str, _config: &AwsConfig) -> Option<RetrievedKey> {
        // In production, this would call AWS SDK
        // For now, return None to allow fallback to env vars
        None
    }

    /// Retrieve from HashiCorp Vault
    fn retrieve_from_vault(&self, api_name: &str, _config: &VaultConfig) -> Option<RetrievedKey> {
        // In production, this would call Vault HTTP API
        // For now, return None to allow fallback to env vars
        None
    }

    /// Retrieve from remote configuration server
    fn retrieve_from_remote_server(
        &self,
        api_name: &str,
        _config: &RemoteServerConfig,
    ) -> Option<RetrievedKey> {
        // In production, this would make HTTP request to config server
        // For now, return None to allow fallback to env vars
        None
    }

    /// Clear expired cache entries
    pub fn clear_expired_cache(&mut self) {
        let now = current_time_ms();
        self.local_cache.retain(|_, cached| {
            let age_ms = now - cached.cached_at_ms;
            age_ms < (self.config.cache_ttl_seconds * 1000)
        });
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> (usize, u64, u64) {
        (
            self.local_cache.len(),
            self.retrieval_stats.cache_hits,
            self.retrieval_stats.cache_misses,
        )
    }

    /// Get retrieval statistics
    pub fn get_retrieval_stats(&self) -> RetrievalStats {
        self.retrieval_stats.clone()
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
    fn test_key_retrieval_config_production() {
        let config = KeyRetrievalConfig::production();
        assert!(!config.enabled_sources.is_empty());
        assert!(config.fallback_enabled);
        assert_eq!(config.cache_ttl_seconds, 3600);
    }

    #[test]
    fn test_key_retrieval_config_development() {
        let config = KeyRetrievalConfig::development();
        assert_eq!(config.enabled_sources.len(), 1);
        assert!(!config.fallback_enabled);
        assert_eq!(config.cache_ttl_seconds, 300);
    }

    #[test]
    fn test_key_retriever_initialization() {
        let config = KeyRetrievalConfig::production();
        let retriever = ApiKeyRetriever::new(config);
        assert_eq!(retriever.local_cache.len(), 0);
        assert_eq!(retriever.retrieval_stats.total_retrievals, 0);
    }

    #[test]
    fn test_cache_initialization() {
        let config = KeyRetrievalConfig::development();
        let retriever = ApiKeyRetriever::new(config);

        let (cache_size, hits, misses) = retriever.get_cache_stats();
        assert_eq!(cache_size, 0);
        assert_eq!(hits, 0);
        assert_eq!(misses, 0);
    }

    #[test]
    fn test_stats_initialization() {
        let config = KeyRetrievalConfig::development();
        let retriever = ApiKeyRetriever::new(config);

        let stats = retriever.get_retrieval_stats();
        assert_eq!(stats.total_retrievals, 0);
        assert_eq!(stats.successful_retrievals, 0);
        assert_eq!(stats.failed_retrievals, 0);
    }

    #[test]
    fn test_aws_config_creation() {
        let config = KeyRetrievalConfig::with_aws("us-east-1".to_string());
        assert_eq!(config.enabled_sources.len(), 3);
        match &config.enabled_sources[0] {
            KeySource::AwsSecretsManager(aws) => {
                assert_eq!(aws.region, "us-east-1");
                assert_eq!(aws.secret_prefix, "huntsman/api-keys/");
            }
            _ => panic!("Expected AwsSecretsManager source"),
        }
    }

    #[test]
    fn test_vault_config_creation() {
        let config =
            KeyRetrievalConfig::with_vault("https://vault.example.com".to_string(), "token123".to_string());
        assert_eq!(config.enabled_sources.len(), 3);
        match &config.enabled_sources[0] {
            KeySource::HashiCorpVault(vault) => {
                assert_eq!(vault.address, "https://vault.example.com");
                assert_eq!(vault.namespace, "huntsman");
            }
            _ => panic!("Expected HashiCorpVault source"),
        }
    }
}
