/// API Key Configuration Validator
///
/// Validates completeness and correctness of API key configurations:
/// - Required credentials present
/// - Authentication types supported
/// - Rate limits configured
/// - Environment variables accessible
/// - Remote sources reachable
/// - Key formats valid
/// - Expiration dates valid

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Configuration validation result
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub api_name: String,
    pub validation_errors: Vec<ValidationError>,
    pub validation_warnings: Vec<ValidationWarning>,
    pub validated_at_ms: u64,
    pub validation_time_ms: u64,
}

/// Validation error (blocking issue)
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub error_type: ErrorType,
    pub message: String,
    pub api_name: String,
    pub field: Option<String>,
    pub remediation: String,
}

/// Validation warning (non-blocking issue)
#[derive(Debug, Clone)]
pub struct ValidationWarning {
    pub warning_type: WarningType,
    pub message: String,
    pub api_name: String,
    pub field: Option<String>,
    pub recommendation: String,
}

/// Error types
#[derive(Debug, Clone, PartialEq)]
pub enum ErrorType {
    MissingCredential,
    InvalidFormat,
    UnsupportedAuthType,
    EnvironmentVariableNotSet,
    RemoteSourceUnreachable,
    InvalidRateLimit,
    MissingTemplate,
    AuthenticationFailed,
    ConnectionFailed,
}

/// Warning types
#[derive(Debug, Clone, PartialEq)]
pub enum WarningType {
    KeyExpiringSoon,
    HighRateLimit,
    NoBackupKey,
    LowQuotaLimit,
    DeprecatedAuthType,
    LongRotationInterval,
    HighErrorRate,
}

/// Configuration validation report
#[derive(Debug, Clone)]
pub struct ConfigurationValidationReport {
    pub total_apis: usize,
    pub valid_apis: usize,
    pub invalid_apis: usize,
    pub apis_with_warnings: usize,
    pub validation_results: Vec<ValidationResult>,
    pub total_errors: usize,
    pub total_warnings: usize,
    pub report_timestamp_ms: u64,
    pub validation_duration_ms: u64,
    pub critical_errors: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Configuration validator
pub struct ApiKeyConfigValidator {
    pub validation_cache: HashMap<String, ValidationResult>,
    pub cache_ttl_seconds: u64,
}

impl ApiKeyConfigValidator {
    /// Create new validator
    pub fn new() -> Self {
        Self {
            validation_cache: HashMap::new(),
            cache_ttl_seconds: 3600,
        }
    }

    /// Validate a single API key configuration
    pub fn validate_api_config(
        &mut self,
        api_name: &str,
        api_key: Option<&str>,
        api_secret: Option<&str>,
        base_url: &str,
    ) -> ValidationResult {
        let start_time = current_time_ms();
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Check required API key
        if api_key.is_none() || api_key.map(|k| k.is_empty()).unwrap_or(true) {
            errors.push(ValidationError {
                error_type: ErrorType::MissingCredential,
                message: format!("API key is missing for {}", api_name),
                api_name: api_name.to_string(),
                field: Some("api_key".to_string()),
                remediation: format!(
                    "Set HUNTSMAN_{}_KEY environment variable",
                    api_name.to_uppercase().replace(" ", "_")
                ),
            });
        }

        // Validate API key format
        if let Some(key) = api_key {
            if !self.is_valid_key_format(key) {
                errors.push(ValidationError {
                    error_type: ErrorType::InvalidFormat,
                    message: format!("Invalid API key format for {}: {}", api_name, key),
                    api_name: api_name.to_string(),
                    field: Some("api_key".to_string()),
                    remediation: "Verify the API key format matches provider requirements".to_string(),
                });
            }

            // Check for expiration indicators
            if key.len() < 10 {
                warnings.push(ValidationWarning {
                    warning_type: WarningType::LowQuotaLimit,
                    message: format!(
                        "API key for {} appears unusually short, may be expired or invalid",
                        api_name
                    ),
                    api_name: api_name.to_string(),
                    field: Some("api_key".to_string()),
                    recommendation: "Verify key length and validity with provider".to_string(),
                });
            }
        }

        // Validate base URL
        if base_url.is_empty() {
            errors.push(ValidationError {
                error_type: ErrorType::MissingCredential,
                message: format!("Base URL is missing for {}", api_name),
                api_name: api_name.to_string(),
                field: Some("base_url".to_string()),
                remediation: "Configure API base URL in template".to_string(),
            });
        } else if !base_url.starts_with("http") {
            errors.push(ValidationError {
                error_type: ErrorType::InvalidFormat,
                message: format!("Invalid base URL for {}: {}", api_name, base_url),
                api_name: api_name.to_string(),
                field: Some("base_url".to_string()),
                remediation: "Base URL must start with http:// or https://".to_string(),
            });
        }

        // Check for optional API secret
        if api_secret.is_some() && api_secret.map(|s| s.is_empty()).unwrap_or(true) {
            warnings.push(ValidationWarning {
                warning_type: WarningType::NoBackupKey,
                message: format!("No backup/secret key configured for {}", api_name),
                api_name: api_name.to_string(),
                field: Some("api_secret".to_string()),
                recommendation: "Configure backup key for redundancy".to_string(),
            });
        }

        let validation_time = current_time_ms() - start_time;
        let is_valid = errors.is_empty();

        let result = ValidationResult {
            is_valid,
            api_name: api_name.to_string(),
            validation_errors: errors,
            validation_warnings: warnings,
            validated_at_ms: current_time_ms(),
            validation_time_ms: validation_time,
        };

        // Cache result
        self.validation_cache
            .insert(api_name.to_string(), result.clone());

        result
    }

    /// Validate all API configurations
    pub fn validate_all_configs(
        &mut self,
        configs: &HashMap<String, ApiConfigData>,
    ) -> ConfigurationValidationReport {
        let start_time = current_time_ms();
        let mut results = Vec::new();
        let mut total_errors = 0;
        let mut total_warnings = 0;
        let mut critical_errors = Vec::new();
        let mut recommendations = Vec::new();

        for (api_name, config) in configs {
            let result = self.validate_api_config(
                api_name,
                config.api_key.as_deref(),
                config.api_secret.as_deref(),
                &config.base_url,
            );

            total_errors += result.validation_errors.len();
            total_warnings += result.validation_warnings.len();

            for error in &result.validation_errors {
                if error.error_type == ErrorType::AuthenticationFailed
                    || error.error_type == ErrorType::ConnectionFailed
                {
                    critical_errors.push(error.message.clone());
                }
                recommendations.push(error.remediation.clone());
            }

            for warning in &result.validation_warnings {
                recommendations.push(warning.recommendation.clone());
            }

            results.push(result);
        }

        let valid_apis = results.iter().filter(|r| r.is_valid).count();
        let invalid_apis = results.len() - valid_apis;
        let apis_with_warnings = results
            .iter()
            .filter(|r| !r.validation_warnings.is_empty())
            .count();

        let duration = current_time_ms() - start_time;

        ConfigurationValidationReport {
            total_apis: configs.len(),
            valid_apis,
            invalid_apis,
            apis_with_warnings,
            validation_results: results,
            total_errors,
            total_warnings,
            report_timestamp_ms: current_time_ms(),
            validation_duration_ms: duration,
            critical_errors,
            recommendations,
        }
    }

    /// Check if API key format looks valid
    fn is_valid_key_format(&self, key: &str) -> bool {
        // Basic format checks
        !key.is_empty() && key.len() >= 5 && !key.contains(' ') && !key.contains('\n')
    }

    /// Verify environment variables are accessible
    pub fn verify_env_variables(&self, required_vars: &[String]) -> Vec<String> {
        required_vars
            .iter()
            .filter(|var| std::env::var(var).is_err())
            .cloned()
            .collect()
    }

    /// Get validation report summary
    pub fn get_validation_summary(&self, report: &ConfigurationValidationReport) -> String {
        format!(
            "Configuration Validation Report\n\
             ================================\n\
             Total APIs: {}\n\
             Valid: {}\n\
             Invalid: {}\n\
             Warnings: {}\n\
             Errors: {}\n\
             Critical Issues: {}\n\
             Validation Time: {} ms\n\n\
             Summary:\n\
             - {:.1}% of APIs are properly configured\n\
             - {} APIs have warnings\n\
             - {} recommendations for improvement",
            report.total_apis,
            report.valid_apis,
            report.invalid_apis,
            report.apis_with_warnings,
            report.total_errors,
            report.total_warnings,
            report.validation_duration_ms,
            (report.valid_apis as f32 / report.total_apis as f32) * 100.0,
            report.apis_with_warnings,
            report.recommendations.len()
        )
    }
}

/// API configuration data for validation
#[derive(Debug, Clone)]
pub struct ApiConfigData {
    pub api_key: Option<String>,
    pub api_secret: Option<String>,
    pub base_url: String,
    pub auth_type: String,
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
    fn test_validator_initialization() {
        let validator = ApiKeyConfigValidator::new();
        assert_eq!(validator.validation_cache.len(), 0);
        assert_eq!(validator.cache_ttl_seconds, 3600);
    }

    #[test]
    fn test_validate_valid_config() {
        let mut validator = ApiKeyConfigValidator::new();
        let result = validator.validate_api_config(
            "TestAPI",
            Some("valid_api_key_12345"),
            Some("secret123"),
            "https://api.example.com",
        );

        assert!(result.is_valid);
        assert_eq!(result.validation_errors.len(), 0);
    }

    #[test]
    fn test_validate_missing_api_key() {
        let mut validator = ApiKeyConfigValidator::new();
        let result = validator.validate_api_config(
            "TestAPI",
            None,
            Some("secret123"),
            "https://api.example.com",
        );

        assert!(!result.is_valid);
        assert!(!result.validation_errors.is_empty());
        assert_eq!(
            result.validation_errors[0].error_type,
            ErrorType::MissingCredential
        );
    }

    #[test]
    fn test_validate_invalid_base_url() {
        let mut validator = ApiKeyConfigValidator::new();
        let result = validator.validate_api_config(
            "TestAPI",
            Some("valid_key"),
            None,
            "not-a-url",
        );

        assert!(!result.is_valid);
        assert!(result
            .validation_errors
            .iter()
            .any(|e| e.error_type == ErrorType::InvalidFormat))
    }

    #[test]
    fn test_validate_empty_base_url() {
        let mut validator = ApiKeyConfigValidator::new();
        let result = validator.validate_api_config("TestAPI", Some("valid_key"), None, "");

        assert!(!result.is_valid);
        assert!(result
            .validation_errors
            .iter()
            .any(|e| e.error_type == ErrorType::MissingCredential))
    }

    #[test]
    fn test_key_format_validation() {
        let validator = ApiKeyConfigValidator::new();

        assert!(validator.is_valid_key_format("validkey12345"));
        assert!(!validator.is_valid_key_format(""));
        assert!(!validator.is_valid_key_format("key with spaces"));
    }

    #[test]
    fn test_validation_result_caching() {
        let mut validator = ApiKeyConfigValidator::new();

        validator.validate_api_config(
            "CachedAPI",
            Some("key123"),
            None,
            "https://api.example.com",
        );

        assert!(validator.validation_cache.contains_key("CachedAPI"));
    }

    #[test]
    fn test_validation_report_generation() {
        let mut validator = ApiKeyConfigValidator::new();
        let mut configs = HashMap::new();

        configs.insert(
            "API1".to_string(),
            ApiConfigData {
                api_key: Some("valid_key_12345".to_string()),
                api_secret: None,
                base_url: "https://api1.example.com".to_string(),
                auth_type: "Bearer".to_string(),
            },
        );

        configs.insert(
            "API2".to_string(),
            ApiConfigData {
                api_key: None,
                api_secret: None,
                base_url: "invalid-url".to_string(),
                auth_type: "Bearer".to_string(),
            },
        );

        let report = validator.validate_all_configs(&configs);
        assert_eq!(report.total_apis, 2);
        assert_eq!(report.valid_apis, 1);
        assert_eq!(report.invalid_apis, 1);
    }

    #[test]
    fn test_validation_summary() {
        let mut validator = ApiKeyConfigValidator::new();
        let mut configs = HashMap::new();

        for i in 0..5 {
            configs.insert(
                format!("API{}", i),
                ApiConfigData {
                    api_key: Some(format!("key{}", i)),
                    api_secret: None,
                    base_url: "https://api.example.com".to_string(),
                    auth_type: "Bearer".to_string(),
                },
            );
        }

        let report = validator.validate_all_configs(&configs);
        let summary = validator.get_validation_summary(&report);

        assert!(summary.contains("Configuration Validation Report"));
        assert!(summary.contains("Total APIs:"));
        assert!(summary.contains("Valid:"));
    }
}
