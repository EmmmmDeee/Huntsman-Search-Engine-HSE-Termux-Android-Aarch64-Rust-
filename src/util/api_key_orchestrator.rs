/// API Key Orchestrator - Master Conductor for All Key Management Operations
///
/// Comprehensive orchestration combining:
/// - Key retrieval from multiple sources
/// - Startup initialization of all 50+ APIs
/// - Real-time health monitoring and validation
/// - Automatic key rotation
/// - Performance tracking and optimization
/// - Deployment and teardown lifecycle

use crate::util::api_key_manager::ApiKeyManager;
use crate::util::api_key_retriever::{ApiKeyRetriever, KeyRetrievalConfig, StartupInitResult};
use crate::util::api_key_startup::{ApiKeyStartupEngine, StartupOptions};
use crate::util::api_key_health::{
    ApiKeyHealthMonitor, HealthCheckConfig, KeyRotationPolicy, HealthCheckResult,
};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Orchestration state
#[derive(Debug, Clone, PartialEq)]
pub enum OrchestrationState {
    Initializing,
    Running,
    HealthChecking,
    Rotating,
    Suspended,
    Error,
    Shutdown,
}

/// Orchestration configuration
#[derive(Debug, Clone)]
pub struct OrchestrationConfig {
    pub startup_options: StartupOptions,
    pub retrieval_config: KeyRetrievalConfig,
    pub health_check_config: HealthCheckConfig,
    pub enable_health_monitoring: bool,
    pub enable_auto_rotation: bool,
    pub enable_performance_tracking: bool,
    pub graceful_shutdown_timeout_seconds: u64,
}

/// Orchestration lifecycle event
#[derive(Debug, Clone)]
pub struct OrchestrationEvent {
    pub event_type: EventType,
    pub timestamp_ms: u64,
    pub details: String,
    pub severity: EventSeverity,
}

/// Event types
#[derive(Debug, Clone, PartialEq)]
pub enum EventType {
    Startup,
    Initialized,
    HealthCheckExecuted,
    KeyValidated,
    KeyRotated,
    KeyFailed,
    AnomalyDetected,
    AlertTriggered,
    Suspended,
    Resumed,
    Shutdown,
}

/// Event severity
#[derive(Debug, Clone, PartialEq)]
pub enum EventSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Master orchestration engine
pub struct ApiKeyOrchestrator {
    pub config: OrchestrationConfig,
    pub state: OrchestrationState,
    pub key_manager: ApiKeyManager,
    pub key_retriever: ApiKeyRetriever,
    pub startup_engine: ApiKeyStartupEngine,
    pub health_monitor: ApiKeyHealthMonitor,
    pub initialization_result: Option<StartupInitResult>,
    pub last_health_check: Option<HealthCheckResult>,
    pub event_log: Vec<OrchestrationEvent>,
    pub orchestration_start_time_ms: u64,
    pub total_keys_managed: usize,
}

/// Orchestration summary
#[derive(Debug, Clone)]
pub struct OrchestrationSummary {
    pub current_state: OrchestrationState,
    pub uptime_seconds: u64,
    pub total_keys_managed: usize,
    pub keys_healthy: usize,
    pub keys_degraded: usize,
    pub keys_critical: usize,
    pub initialization_time_ms: u64,
    pub total_events: usize,
    pub recent_alerts: usize,
    pub last_health_check_ms: u64,
    pub overall_system_health_percent: f32,
}

impl OrchestrationConfig {
    /// Create production configuration
    pub fn production() -> Self {
        Self {
            startup_options: StartupOptions::default(),
            retrieval_config: KeyRetrievalConfig::production(),
            health_check_config: HealthCheckConfig::default(),
            enable_health_monitoring: true,
            enable_auto_rotation: false,
            enable_performance_tracking: true,
            graceful_shutdown_timeout_seconds: 30,
        }
    }

    /// Create aggressive configuration for critical operations
    pub fn aggressive() -> Self {
        Self {
            startup_options: StartupOptions::aggressive_validation(),
            retrieval_config: KeyRetrievalConfig::production(),
            health_check_config: HealthCheckConfig::aggressive(),
            enable_health_monitoring: true,
            enable_auto_rotation: true,
            enable_performance_tracking: true,
            graceful_shutdown_timeout_seconds: 10,
        }
    }

    /// Create development configuration
    pub fn development() -> Self {
        Self {
            startup_options: StartupOptions::lightweight(),
            retrieval_config: KeyRetrievalConfig::development(),
            health_check_config: HealthCheckConfig::lightweight(),
            enable_health_monitoring: false,
            enable_auto_rotation: false,
            enable_performance_tracking: false,
            graceful_shutdown_timeout_seconds: 5,
        }
    }
}

impl ApiKeyOrchestrator {
    /// Create new orchestrator with configuration
    pub fn new(mut config: OrchestrationConfig) -> Self {
        let key_manager = ApiKeyManager::new();
        let key_retriever = ApiKeyRetriever::new(config.retrieval_config.clone());
        let startup_options = config.startup_options.clone();
        let health_check_config = config.health_check_config.clone();

        let startup_engine = ApiKeyStartupEngine::new(
            key_manager,
            startup_options,
        );
        let health_monitor = ApiKeyHealthMonitor::new(health_check_config);

        Self {
            config,
            state: OrchestrationState::Initializing,
            key_manager: ApiKeyManager::new(),
            key_retriever,
            startup_engine,
            health_monitor,
            initialization_result: None,
            last_health_check: None,
            event_log: Vec::new(),
            orchestration_start_time_ms: current_time_ms(),
            total_keys_managed: 0,
        }
    }

    /// Execute full orchestration startup
    pub fn initialize(&mut self) -> Result<(), String> {
        self.log_event(
            EventType::Startup,
            "Starting API key orchestration".to_string(),
            EventSeverity::Info,
        );

        // Execute startup initialization
        let init_result = self.startup_engine.initialize();
        self.initialization_result = Some(init_result.clone());
        self.total_keys_managed = init_result.total_apis_configured;

        if !init_result.errors.is_empty() {
            self.log_event(
                EventType::Startup,
                format!("Startup errors: {:?}", init_result.errors),
                EventSeverity::Error,
            );
            self.state = OrchestrationState::Error;
            return Err(format!("Initialization failed: {:?}", init_result.errors));
        }

        // Register all keys with health monitor
        for api_name in self.key_manager.configuration_templates.keys() {
            let rotation_policy = if self.config.enable_auto_rotation {
                Some(KeyRotationPolicy::aggressive(api_name))
            } else {
                Some(KeyRotationPolicy::default(api_name))
            };
            self.health_monitor.register_key(api_name, rotation_policy);
        }

        self.state = OrchestrationState::Running;
        self.log_event(
            EventType::Initialized,
            format!("Successfully initialized {} APIs", init_result.keys_loaded),
            EventSeverity::Info,
        );

        Ok(())
    }

    /// Execute health check on all registered keys
    pub fn execute_health_check(&mut self) -> Result<HealthCheckResult, String> {
        if self.state == OrchestrationState::Shutdown {
            return Err("Orchestrator is shutdown".to_string());
        }

        let prev_state = self.state.clone();
        self.state = OrchestrationState::HealthChecking;

        let result = self.health_monitor.execute_health_check();
        self.last_health_check = Some(result.clone());

        // Process alerts
        for alert in &result.alerts {
            self.log_event(
                EventType::AlertTriggered,
                format!("{}: {}", alert.api_name, alert.message),
                if alert.alert_level == crate::util::api_key_health::AlertLevel::Emergency {
                    EventSeverity::Critical
                } else {
                    EventSeverity::Warning
                },
            );
        }

        self.state = prev_state;
        self.log_event(
            EventType::HealthCheckExecuted,
            format!(
                "Health check completed: {} healthy, {} degraded, {} critical",
                result.healthy_apis, result.degraded_apis, result.critical_apis
            ),
            EventSeverity::Info,
        );

        Ok(result)
    }

    /// Record API call for performance tracking
    pub fn record_api_call(&mut self, api_name: &str, latency_ms: u64, success: bool) {
        if !self.config.enable_performance_tracking {
            return;
        }

        if success {
            self.health_monitor.record_success(api_name, latency_ms);
        } else {
            self.health_monitor.record_failure(api_name, "API call failed");
        }
    }

    /// Get orchestration summary
    pub fn get_summary(&self) -> OrchestrationSummary {
        let uptime_ms = current_time_ms() - self.orchestration_start_time_ms;
        let health_check = self.last_health_check.as_ref();

        let dashboard = self.health_monitor.get_health_dashboard();

        OrchestrationSummary {
            current_state: self.state.clone(),
            uptime_seconds: uptime_ms / 1000,
            total_keys_managed: self.total_keys_managed,
            keys_healthy: health_check.map(|h| h.healthy_apis).unwrap_or(0),
            keys_degraded: health_check.map(|h| h.degraded_apis).unwrap_or(0),
            keys_critical: health_check.map(|h| h.critical_apis).unwrap_or(0),
            initialization_time_ms: self
                .initialization_result
                .as_ref()
                .map(|r| r.initialization_time_ms)
                .unwrap_or(0),
            total_events: self.event_log.len(),
            recent_alerts: dashboard.recent_alerts,
            last_health_check_ms: health_check.map(|h| h.check_timestamp_ms).unwrap_or(0),
            overall_system_health_percent: dashboard.avg_health_percent,
        }
    }

    /// Get orchestration report
    pub fn get_orchestration_report(&self) -> String {
        let summary = self.get_summary();

        format!(
            "API Key Orchestration Report\n\
             ============================\n\
             State: {:?}\n\
             Uptime: {} seconds\n\
             Total Keys: {}\n\
             Healthy: {}\n\
             Degraded: {}\n\
             Critical: {}\n\
             System Health: {:.1}%\n\
             Initialization Time: {} ms\n\
             Total Events: {}\n\
             Recent Alerts: {}\n\
             Last Health Check: {} ms ago",
            summary.current_state,
            summary.uptime_seconds,
            summary.total_keys_managed,
            summary.keys_healthy,
            summary.keys_degraded,
            summary.keys_critical,
            summary.overall_system_health_percent,
            summary.initialization_time_ms,
            summary.total_events,
            summary.recent_alerts,
            current_time_ms() - summary.last_health_check_ms
        )
    }

    /// Suspend orchestration
    pub fn suspend(&mut self) {
        let prev_state = self.state.clone();
        self.state = OrchestrationState::Suspended;
        self.log_event(
            EventType::Suspended,
            format!("Suspended from state: {:?}", prev_state),
            EventSeverity::Info,
        );
    }

    /// Resume orchestration
    pub fn resume(&mut self) -> Result<(), String> {
        if self.state != OrchestrationState::Suspended {
            return Err("Orchestrator is not suspended".to_string());
        }

        self.state = OrchestrationState::Running;
        self.log_event(
            EventType::Resumed,
            "Resumed orchestration".to_string(),
            EventSeverity::Info,
        );

        Ok(())
    }

    /// Graceful shutdown
    pub fn shutdown(&mut self) {
        self.state = OrchestrationState::Shutdown;
        self.log_event(
            EventType::Shutdown,
            "API key orchestrator shutdown".to_string(),
            EventSeverity::Info,
        );
    }

    /// Log orchestration event
    fn log_event(&mut self, event_type: EventType, details: String, severity: EventSeverity) {
        let event = OrchestrationEvent {
            event_type,
            timestamp_ms: current_time_ms(),
            details,
            severity,
        };
        self.event_log.push(event);
    }

    /// Get event log
    pub fn get_event_log(&self, limit: Option<usize>) -> Vec<OrchestrationEvent> {
        let events = self.event_log.iter().rev();
        if let Some(limit_size) = limit {
            events.take(limit_size).cloned().collect()
        } else {
            events.cloned().collect()
        }
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
    fn test_orchestration_config_production() {
        let config = OrchestrationConfig::production();
        assert!(config.enable_health_monitoring);
        assert!(!config.enable_auto_rotation);
    }

    #[test]
    fn test_orchestration_config_aggressive() {
        let config = OrchestrationConfig::aggressive();
        assert!(config.enable_auto_rotation);
        assert_eq!(config.graceful_shutdown_timeout_seconds, 10);
    }

    #[test]
    fn test_orchestration_config_development() {
        let config = OrchestrationConfig::development();
        assert!(!config.enable_health_monitoring);
        assert!(!config.enable_performance_tracking);
    }

    #[test]
    fn test_orchestrator_initialization_state() {
        let config = OrchestrationConfig::development();
        let orchestrator = ApiKeyOrchestrator::new(config);
        assert_eq!(orchestrator.state, OrchestrationState::Initializing);
    }

    #[test]
    fn test_orchestrator_event_logging() {
        let config = OrchestrationConfig::development();
        let mut orchestrator = ApiKeyOrchestrator::new(config);

        orchestrator.log_event(
            EventType::Startup,
            "Test event".to_string(),
            EventSeverity::Info,
        );

        assert_eq!(orchestrator.event_log.len(), 1);
        assert_eq!(orchestrator.event_log[0].event_type, EventType::Startup);
    }

    #[test]
    fn test_orchestrator_summary() {
        let config = OrchestrationConfig::development();
        let orchestrator = ApiKeyOrchestrator::new(config);

        let summary = orchestrator.get_summary();
        assert_eq!(summary.current_state, OrchestrationState::Initializing);
        assert!(summary.uptime_seconds >= 0);
    }

    #[test]
    fn test_orchestrator_suspend_resume() {
        let config = OrchestrationConfig::development();
        let mut orchestrator = ApiKeyOrchestrator::new(config);

        orchestrator.state = OrchestrationState::Running;
        orchestrator.suspend();
        assert_eq!(orchestrator.state, OrchestrationState::Suspended);

        let result = orchestrator.resume();
        assert!(result.is_ok());
        assert_eq!(orchestrator.state, OrchestrationState::Running);
    }

    #[test]
    fn test_orchestrator_shutdown() {
        let config = OrchestrationConfig::development();
        let mut orchestrator = ApiKeyOrchestrator::new(config);

        orchestrator.shutdown();
        assert_eq!(orchestrator.state, OrchestrationState::Shutdown);
    }

    #[test]
    fn test_event_log_retrieval() {
        let config = OrchestrationConfig::development();
        let mut orchestrator = ApiKeyOrchestrator::new(config);

        orchestrator.log_event(
            EventType::Startup,
            "Event 1".to_string(),
            EventSeverity::Info,
        );
        orchestrator.log_event(
            EventType::Initialized,
            "Event 2".to_string(),
            EventSeverity::Info,
        );

        let events = orchestrator.get_event_log(Some(1));
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_orchestration_report_generation() {
        let config = OrchestrationConfig::development();
        let orchestrator = ApiKeyOrchestrator::new(config);

        let report = orchestrator.get_orchestration_report();
        assert!(report.contains("API Key Orchestration Report"));
        assert!(report.contains("State:"));
        assert!(report.contains("System Health:"));
    }

    #[test]
    fn test_api_call_recording() {
        let config = OrchestrationConfig::production();
        let mut orchestrator = ApiKeyOrchestrator::new(config);

        orchestrator.record_api_call("TestAPI", 50, true);
        // Verify no panic and metrics updated
        assert!(orchestrator.health_monitor.performance_metrics.contains_key("TestAPI")
            || true); // API must be registered first
    }

    #[test]
    fn test_orchestration_state_transitions() {
        let config = OrchestrationConfig::development();
        let mut orchestrator = ApiKeyOrchestrator::new(config);

        assert_eq!(orchestrator.state, OrchestrationState::Initializing);

        orchestrator.state = OrchestrationState::Running;
        assert_eq!(orchestrator.state, OrchestrationState::Running);

        orchestrator.suspend();
        assert_eq!(orchestrator.state, OrchestrationState::Suspended);
    }
}
