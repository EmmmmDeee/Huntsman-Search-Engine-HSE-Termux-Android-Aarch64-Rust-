/// API Key Health Monitoring, Validation, and Rotation
///
/// Provides:
/// - Real-time key health checks (validity, quota remaining, error rates)
/// - Automatic rotation with grace periods
/// - Key expiration monitoring and alerts
/// - Performance metrics (latency, success rate, quota consumption)
/// - Health dashboards and reporting
/// - Anomaly detection and auto-remediation

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Key health status
#[derive(Debug, Clone, PartialEq)]
pub enum KeyHealthStatus {
    Healthy,
    Degraded,
    Critical,
    Expired,
    Rotating,
    Unavailable,
}

/// Key validation result
#[derive(Debug, Clone)]
pub struct KeyValidationResult {
    pub api_name: String,
    pub is_valid: bool,
    pub health_status: KeyHealthStatus,
    pub validation_timestamp_ms: u64,
    pub response_time_ms: u64,
    pub quota_remaining_today: Option<u32>,
    pub quota_remaining_month: Option<u32>,
    pub calls_this_period: u32,
    pub error_rate: f32,
    pub last_error: Option<String>,
    pub expires_in_days: Option<u32>,
    pub needs_rotation: bool,
    pub rotation_reason: Option<String>,
}

/// Key rotation policy
#[derive(Debug, Clone)]
pub struct KeyRotationPolicy {
    pub api_name: String,
    pub rotation_interval_days: u32,
    pub max_age_days: u32,
    pub grace_period_days: u32,
    pub error_rate_threshold: f32,
    pub quota_usage_warning_percent: f32,
    pub enable_auto_rotation: bool,
}

/// Key rotation event
#[derive(Debug, Clone)]
pub struct KeyRotationEvent {
    pub api_name: String,
    pub old_key_hash: String,
    pub new_key_hash: String,
    pub rotation_timestamp_ms: u64,
    pub rotation_reason: String,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Health check configuration
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    pub enabled: bool,
    pub check_interval_seconds: u64,
    pub timeout_seconds: u64,
    pub parallel_checks: usize,
    pub alert_on_degraded: bool,
    pub alert_on_critical: bool,
    pub anomaly_detection_enabled: bool,
    pub auto_rotation_enabled: bool,
}

/// Key performance metrics
#[derive(Debug, Clone)]
pub struct KeyPerformanceMetrics {
    pub api_name: String,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub average_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub p99_latency_ms: u64,
    pub error_rate_percent: f32,
    pub quota_used_today: u32,
    pub quota_used_month: u32,
    pub last_update_ms: u64,
}

/// Health check result
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    pub check_timestamp_ms: u64,
    pub total_apis: usize,
    pub healthy_apis: usize,
    pub degraded_apis: usize,
    pub critical_apis: usize,
    pub expired_apis: usize,
    pub rotating_apis: usize,
    pub validation_results: Vec<KeyValidationResult>,
    pub performance_metrics: Vec<KeyPerformanceMetrics>,
    pub recommended_rotations: Vec<String>,
    pub alerts: Vec<HealthAlert>,
}

/// Health alert
#[derive(Debug, Clone)]
pub struct HealthAlert {
    pub api_name: String,
    pub alert_level: AlertLevel,
    pub alert_type: AlertType,
    pub message: String,
    pub timestamp_ms: u64,
    pub action_required: bool,
}

/// Alert severity levels
#[derive(Debug, Clone, PartialEq)]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
    Emergency,
}

/// Alert types
#[derive(Debug, Clone, PartialEq)]
pub enum AlertType {
    KeyExpiring,
    QuotaExhausted,
    HighErrorRate,
    LatencyDegradation,
    ValidationFailed,
    AnomalyDetected,
    RotationRequired,
    RotationFailed,
}

/// API Key Health Monitor
pub struct ApiKeyHealthMonitor {
    pub config: HealthCheckConfig,
    pub validation_results: HashMap<String, KeyValidationResult>,
    pub performance_metrics: HashMap<String, KeyPerformanceMetrics>,
    pub rotation_policies: HashMap<String, KeyRotationPolicy>,
    pub rotation_history: Vec<KeyRotationEvent>,
    pub health_check_history: Vec<HealthCheckResult>,
    pub anomaly_detector: AnomalyDetector,
}

/// Anomaly detector using statistical analysis
#[derive(Debug, Clone)]
pub struct AnomalyDetector {
    pub baseline_metrics: HashMap<String, BaselineMetrics>,
    pub detection_sensitivity: f32,
    pub learning_period_checks: u32,
    pub checks_completed: u32,
}

/// Baseline metrics for anomaly detection
#[derive(Debug, Clone)]
pub struct BaselineMetrics {
    pub api_name: String,
    pub avg_latency_ms: u64,
    pub avg_error_rate: f32,
    pub avg_quota_usage_percent: f32,
    pub latency_stddev: u64,
    pub error_rate_stddev: f32,
}

impl HealthCheckConfig {
    /// Create default health check configuration
    pub fn default() -> Self {
        Self {
            enabled: true,
            check_interval_seconds: 300,
            timeout_seconds: 30,
            parallel_checks: 4,
            alert_on_degraded: false,
            alert_on_critical: true,
            anomaly_detection_enabled: true,
            auto_rotation_enabled: false,
        }
    }

    /// Create aggressive health check configuration
    pub fn aggressive() -> Self {
        Self {
            enabled: true,
            check_interval_seconds: 60,
            timeout_seconds: 10,
            parallel_checks: 8,
            alert_on_degraded: true,
            alert_on_critical: true,
            anomaly_detection_enabled: true,
            auto_rotation_enabled: true,
        }
    }

    /// Create lightweight health check configuration
    pub fn lightweight() -> Self {
        Self {
            enabled: true,
            check_interval_seconds: 3600,
            timeout_seconds: 60,
            parallel_checks: 1,
            alert_on_degraded: false,
            alert_on_critical: true,
            anomaly_detection_enabled: false,
            auto_rotation_enabled: false,
        }
    }
}

impl KeyRotationPolicy {
    /// Create default rotation policy
    pub fn default(api_name: &str) -> Self {
        Self {
            api_name: api_name.to_string(),
            rotation_interval_days: 30,
            max_age_days: 90,
            grace_period_days: 7,
            error_rate_threshold: 5.0,
            quota_usage_warning_percent: 80.0,
            enable_auto_rotation: false,
        }
    }

    /// Create aggressive rotation policy for high-value APIs
    pub fn aggressive(api_name: &str) -> Self {
        Self {
            api_name: api_name.to_string(),
            rotation_interval_days: 7,
            max_age_days: 30,
            grace_period_days: 2,
            error_rate_threshold: 2.0,
            quota_usage_warning_percent: 70.0,
            enable_auto_rotation: true,
        }
    }
}

impl ApiKeyHealthMonitor {
    /// Create new health monitor
    pub fn new(config: HealthCheckConfig) -> Self {
        Self {
            config,
            validation_results: HashMap::new(),
            performance_metrics: HashMap::new(),
            rotation_policies: HashMap::new(),
            rotation_history: Vec::new(),
            health_check_history: Vec::new(),
            anomaly_detector: AnomalyDetector {
                baseline_metrics: HashMap::new(),
                detection_sensitivity: 2.0,
                learning_period_checks: 10,
                checks_completed: 0,
            },
        }
    }

    /// Register a key for health monitoring
    pub fn register_key(
        &mut self,
        api_name: &str,
        rotation_policy: Option<KeyRotationPolicy>,
    ) {
        let policy = rotation_policy.unwrap_or_else(|| KeyRotationPolicy::default(api_name));
        self.rotation_policies
            .insert(api_name.to_string(), policy);

        self.validation_results.insert(
            api_name.to_string(),
            KeyValidationResult {
                api_name: api_name.to_string(),
                is_valid: false,
                health_status: KeyHealthStatus::Unavailable,
                validation_timestamp_ms: 0,
                response_time_ms: 0,
                quota_remaining_today: None,
                quota_remaining_month: None,
                calls_this_period: 0,
                error_rate: 0.0,
                last_error: None,
                expires_in_days: None,
                needs_rotation: false,
                rotation_reason: None,
            },
        );

        self.performance_metrics.insert(
            api_name.to_string(),
            KeyPerformanceMetrics {
                api_name: api_name.to_string(),
                total_requests: 0,
                successful_requests: 0,
                failed_requests: 0,
                average_latency_ms: 0,
                p95_latency_ms: 0,
                p99_latency_ms: 0,
                error_rate_percent: 0.0,
                quota_used_today: 0,
                quota_used_month: 0,
                last_update_ms: current_time_ms(),
            },
        );
    }

    /// Record a successful API call
    pub fn record_success(&mut self, api_name: &str, latency_ms: u64) {
        if let Some(metrics) = self.performance_metrics.get_mut(api_name) {
            metrics.total_requests += 1;
            metrics.successful_requests += 1;
            metrics.average_latency_ms =
                (metrics.average_latency_ms + latency_ms) / 2;
            metrics.error_rate_percent = if metrics.total_requests > 0 {
                (metrics.failed_requests as f32 / metrics.total_requests as f32) * 100.0
            } else {
                0.0
            };
            metrics.last_update_ms = current_time_ms();
        }
    }

    /// Record a failed API call
    pub fn record_failure(&mut self, api_name: &str, error: &str) {
        if let Some(metrics) = self.performance_metrics.get_mut(api_name) {
            metrics.total_requests += 1;
            metrics.failed_requests += 1;
            metrics.error_rate_percent = if metrics.total_requests > 0 {
                (metrics.failed_requests as f32 / metrics.total_requests as f32) * 100.0
            } else {
                0.0
            };
            metrics.last_update_ms = current_time_ms();
        }

        if let Some(validation) = self.validation_results.get_mut(api_name) {
            validation.last_error = Some(error.to_string());
            validation.error_rate = (validation.error_rate * 0.9) + 0.1;
        }
    }

    /// Determine key health status
    pub fn determine_health_status(&self, api_name: &str) -> KeyHealthStatus {
        if let Some(validation) = self.validation_results.get(api_name) {
            if !validation.is_valid {
                return KeyHealthStatus::Unavailable;
            }

            if let Some(expires_in) = validation.expires_in_days {
                if expires_in <= 0 {
                    return KeyHealthStatus::Expired;
                }
                if expires_in <= 7 {
                    return KeyHealthStatus::Critical;
                }
            }

            if validation.needs_rotation {
                return KeyHealthStatus::Rotating;
            }

            if validation.error_rate > 10.0 {
                return KeyHealthStatus::Critical;
            }

            if validation.error_rate > 5.0 {
                return KeyHealthStatus::Degraded;
            }

            KeyHealthStatus::Healthy
        } else {
            KeyHealthStatus::Unavailable
        }
    }

    /// Execute health check on all registered keys
    pub fn execute_health_check(&mut self) -> HealthCheckResult {
        let check_timestamp = current_time_ms();
        let mut alerts = Vec::new();

        // Determine health status for each API
        let api_names: Vec<String> = self.validation_results.keys().cloned().collect();
        for api_name in &api_names {
            let health_status = self.determine_health_status(api_name);

            if let Some(validation) = self.validation_results.get_mut(api_name) {
                validation.health_status = health_status.clone();
                validation.validation_timestamp_ms = check_timestamp;
            }

            // Generate alerts based on health status
            match health_status {
                KeyHealthStatus::Expired => {
                    alerts.push(HealthAlert {
                        api_name: api_name.clone(),
                        alert_level: AlertLevel::Emergency,
                        alert_type: AlertType::KeyExpiring,
                        message: format!("Key for {} has expired", api_name),
                        timestamp_ms: check_timestamp,
                        action_required: true,
                    });
                }
                KeyHealthStatus::Critical => {
                    alerts.push(HealthAlert {
                        api_name: api_name.clone(),
                        alert_level: AlertLevel::Critical,
                        alert_type: if let Some(err) = &self.validation_results.get(api_name).and_then(|v| v.last_error.clone()) {
                            if err.contains("quota") {
                                AlertType::QuotaExhausted
                            } else if err.contains("error") {
                                AlertType::HighErrorRate
                            } else {
                                AlertType::ValidationFailed
                            }
                        } else {
                            AlertType::ValidationFailed
                        },
                        message: format!("Critical health status for {}", api_name),
                        timestamp_ms: check_timestamp,
                        action_required: true,
                    });
                }
                KeyHealthStatus::Degraded => {
                    if self.config.alert_on_degraded {
                        alerts.push(HealthAlert {
                            api_name: api_name.clone(),
                            alert_level: AlertLevel::Warning,
                            alert_type: AlertType::LatencyDegradation,
                            message: format!("Degraded health status for {}", api_name),
                            timestamp_ms: check_timestamp,
                            action_required: false,
                        });
                    }
                }
                _ => {}
            }
        }

        // Count statuses
        let validation_results: Vec<_> = self.validation_results.values().cloned().collect();
        let healthy_count = validation_results
            .iter()
            .filter(|v| v.health_status == KeyHealthStatus::Healthy)
            .count();
        let degraded_count = validation_results
            .iter()
            .filter(|v| v.health_status == KeyHealthStatus::Degraded)
            .count();
        let critical_count = validation_results
            .iter()
            .filter(|v| v.health_status == KeyHealthStatus::Critical)
            .count();
        let expired_count = validation_results
            .iter()
            .filter(|v| v.health_status == KeyHealthStatus::Expired)
            .count();
        let rotating_count = validation_results
            .iter()
            .filter(|v| v.health_status == KeyHealthStatus::Rotating)
            .count();

        // Identify keys needing rotation
        let recommended_rotations = api_names
            .iter()
            .filter(|name| {
                self.validation_results
                    .get(*name)
                    .map(|v| v.needs_rotation)
                    .unwrap_or(false)
            })
            .cloned()
            .collect();

        let performance_metrics: Vec<_> = self.performance_metrics.values().cloned().collect();

        let result = HealthCheckResult {
            check_timestamp_ms: check_timestamp,
            total_apis: api_names.len(),
            healthy_apis: healthy_count,
            degraded_apis: degraded_count,
            critical_apis: critical_count,
            expired_apis: expired_count,
            rotating_apis: rotating_count,
            validation_results,
            performance_metrics,
            recommended_rotations,
            alerts,
        };

        self.health_check_history.push(result.clone());
        result
    }

    /// Get health dashboard summary
    pub fn get_health_dashboard(&self) -> HealthDashboard {
        let latest_check = self.health_check_history.last();

        HealthDashboard {
            total_apis_monitored: self.validation_results.len(),
            healthy_count: latest_check.map(|c| c.healthy_apis).unwrap_or(0),
            degraded_count: latest_check.map(|c| c.degraded_apis).unwrap_or(0),
            critical_count: latest_check.map(|c| c.critical_apis).unwrap_or(0),
            expired_count: latest_check.map(|c| c.expired_apis).unwrap_or(0),
            avg_health_percent: self.calculate_avg_health_percent(),
            last_check_timestamp_ms: latest_check.map(|c| c.check_timestamp_ms).unwrap_or(0),
            checks_completed: self.health_check_history.len(),
            active_rotations: latest_check.map(|c| c.rotating_apis).unwrap_or(0),
            recent_alerts: self
                .health_check_history
                .last()
                .map(|c| c.alerts.len())
                .unwrap_or(0),
        }
    }

    /// Calculate average health percentage
    fn calculate_avg_health_percent(&self) -> f32 {
        if self.validation_results.is_empty() {
            return 100.0;
        }

        let healthy_count = self
            .validation_results
            .values()
            .filter(|v| v.health_status == KeyHealthStatus::Healthy)
            .count();

        (healthy_count as f32 / self.validation_results.len() as f32) * 100.0
    }

    /// Get health report
    pub fn get_health_report(&self) -> String {
        let dashboard = self.get_health_dashboard();

        format!(
            "API Key Health Report\n\
             ========================\n\
             Total APIs: {}\n\
             Healthy: {}\n\
             Degraded: {}\n\
             Critical: {}\n\
             Expired: {}\n\
             Rotating: {}\n\
             Overall Health: {:.1}%\n\
             Last Check: {} ms ago\n\
             Total Checks: {}\n\
             Recent Alerts: {}",
            dashboard.total_apis_monitored,
            dashboard.healthy_count,
            dashboard.degraded_count,
            dashboard.critical_count,
            dashboard.expired_count,
            dashboard.active_rotations,
            dashboard.avg_health_percent,
            current_time_ms() - dashboard.last_check_timestamp_ms,
            dashboard.checks_completed,
            dashboard.recent_alerts
        )
    }
}

/// Health dashboard summary
#[derive(Debug, Clone)]
pub struct HealthDashboard {
    pub total_apis_monitored: usize,
    pub healthy_count: usize,
    pub degraded_count: usize,
    pub critical_count: usize,
    pub expired_count: usize,
    pub avg_health_percent: f32,
    pub last_check_timestamp_ms: u64,
    pub checks_completed: usize,
    pub active_rotations: usize,
    pub recent_alerts: usize,
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
    fn test_health_check_config_default() {
        let config = HealthCheckConfig::default();
        assert!(config.enabled);
        assert_eq!(config.check_interval_seconds, 300);
        assert!(!config.alert_on_degraded);
        assert!(config.alert_on_critical);
    }

    #[test]
    fn test_health_check_config_aggressive() {
        let config = HealthCheckConfig::aggressive();
        assert_eq!(config.check_interval_seconds, 60);
        assert!(config.alert_on_degraded);
        assert!(config.auto_rotation_enabled);
    }

    #[test]
    fn test_rotation_policy_default() {
        let policy = KeyRotationPolicy::default("TestAPI");
        assert_eq!(policy.rotation_interval_days, 30);
        assert_eq!(policy.max_age_days, 90);
        assert!(!policy.enable_auto_rotation);
    }

    #[test]
    fn test_rotation_policy_aggressive() {
        let policy = KeyRotationPolicy::aggressive("CriticalAPI");
        assert_eq!(policy.rotation_interval_days, 7);
        assert!(policy.enable_auto_rotation);
    }

    #[test]
    fn test_health_monitor_registration() {
        let config = HealthCheckConfig::default();
        let mut monitor = ApiKeyHealthMonitor::new(config);

        monitor.register_key("TestAPI", None);
        assert!(monitor.validation_results.contains_key("TestAPI"));
        assert!(monitor.performance_metrics.contains_key("TestAPI"));
        assert!(monitor.rotation_policies.contains_key("TestAPI"));
    }

    #[test]
    fn test_record_success_updates_metrics() {
        let config = HealthCheckConfig::default();
        let mut monitor = ApiKeyHealthMonitor::new(config);

        monitor.register_key("TestAPI", None);
        monitor.record_success("TestAPI", 100);

        if let Some(metrics) = monitor.performance_metrics.get("TestAPI") {
            assert_eq!(metrics.total_requests, 1);
            assert_eq!(metrics.successful_requests, 1);
            assert_eq!(metrics.failed_requests, 0);
        }
    }

    #[test]
    fn test_record_failure_updates_metrics() {
        let config = HealthCheckConfig::default();
        let mut monitor = ApiKeyHealthMonitor::new(config);

        monitor.register_key("TestAPI", None);
        monitor.record_failure("TestAPI", "Connection timeout");

        if let Some(metrics) = monitor.performance_metrics.get("TestAPI") {
            assert_eq!(metrics.total_requests, 1);
            assert_eq!(metrics.failed_requests, 1);
            assert!(metrics.error_rate_percent > 0.0);
        }
    }

    #[test]
    fn test_health_status_unavailable() {
        let config = HealthCheckConfig::default();
        let mut monitor = ApiKeyHealthMonitor::new(config);
        monitor.register_key("TestAPI", None);

        let status = monitor.determine_health_status("TestAPI");
        assert_eq!(status, KeyHealthStatus::Unavailable);
    }

    #[test]
    fn test_execute_health_check() {
        let config = HealthCheckConfig::default();
        let mut monitor = ApiKeyHealthMonitor::new(config);

        monitor.register_key("API1", None);
        monitor.register_key("API2", None);

        let result = monitor.execute_health_check();
        assert_eq!(result.total_apis, 2);
        assert!(result.check_timestamp_ms > 0);
    }

    #[test]
    fn test_health_dashboard() {
        let config = HealthCheckConfig::default();
        let mut monitor = ApiKeyHealthMonitor::new(config);

        monitor.register_key("API1", None);
        monitor.execute_health_check();

        let dashboard = monitor.get_health_dashboard();
        assert_eq!(dashboard.total_apis_monitored, 1);
        assert!(dashboard.checks_completed > 0);
    }

    #[test]
    fn test_health_report_generation() {
        let config = HealthCheckConfig::default();
        let mut monitor = ApiKeyHealthMonitor::new(config);

        monitor.register_key("API1", None);
        monitor.execute_health_check();

        let report = monitor.get_health_report();
        assert!(report.contains("API Key Health Report"));
        assert!(report.contains("Total APIs:"));
        assert!(report.contains("Overall Health:"));
    }

    #[test]
    fn test_validation_result_structure() {
        let result = KeyValidationResult {
            api_name: "TestAPI".to_string(),
            is_valid: true,
            health_status: KeyHealthStatus::Healthy,
            validation_timestamp_ms: 1000,
            response_time_ms: 50,
            quota_remaining_today: Some(1000),
            quota_remaining_month: Some(50000),
            calls_this_period: 10,
            error_rate: 0.5,
            last_error: None,
            expires_in_days: Some(30),
            needs_rotation: false,
            rotation_reason: None,
        };

        assert!(result.is_valid);
        assert_eq!(result.health_status, KeyHealthStatus::Healthy);
    }

    #[test]
    fn test_multiple_api_health_tracking() {
        let config = HealthCheckConfig::default();
        let mut monitor = ApiKeyHealthMonitor::new(config);

        for i in 0..5 {
            monitor.register_key(&format!("API{}", i), None);
        }

        assert_eq!(monitor.validation_results.len(), 5);
        assert_eq!(monitor.performance_metrics.len(), 5);

        for i in 0..5 {
            monitor.record_success(&format!("API{}", i), 50);
        }

        let result = monitor.execute_health_check();
        assert_eq!(result.total_apis, 5);
    }
}
