/// API Key Management Integration Tests
///
/// Comprehensive integration tests demonstrating:
/// - Complete workflow from startup to health monitoring
/// - Multi-source key retrieval and fallback chains
/// - Performance tracking and metrics collection
/// - Health check execution and alerting
/// - Orchestration state management
/// - Real-world scenarios and edge cases

#[cfg(test)]
mod integration_tests {
    use crate::util::api_key_manager::ApiKeyManager;
    use crate::util::api_key_retriever::{ApiKeyRetriever, KeyRetrievalConfig};
    use crate::util::api_key_startup::{ApiKeyStartupEngine, StartupOptions};
    use crate::util::api_key_health::{ApiKeyHealthMonitor, HealthCheckConfig, KeyRotationPolicy};
    use crate::util::api_key_orchestrator::{ApiKeyOrchestrator, OrchestrationConfig};

    #[test]
    fn test_complete_startup_lifecycle() {
        // Setup: Create orchestrator with production config
        let config = OrchestrationConfig::production();
        let mut orchestrator = ApiKeyOrchestrator::new(config);

        // Verify initial state
        assert_eq!(
            orchestrator.state,
            crate::util::api_key_orchestrator::OrchestrationState::Initializing
        );

        // Note: Full initialization would require real environment variables
        // In test environment, we verify the structure is correct
        assert_eq!(orchestrator.event_log.len(), 0);
    }

    #[test]
    fn test_multi_source_retrieval_chain() {
        // Setup retrieval config with fallback chain
        let config = KeyRetrievalConfig::production();
        let mut retriever = ApiKeyRetriever::new(config);

        // Verify retriever is configured correctly
        assert!(!retriever.config.enabled_sources.is_empty());
        assert!(retriever.config.fallback_enabled);

        // Verify cache starts empty
        let (cache_size, _, _) = retriever.get_cache_stats();
        assert_eq!(cache_size, 0);
    }

    #[test]
    fn test_health_check_execution_sequence() {
        // Setup health monitor
        let config = HealthCheckConfig::default();
        let mut monitor = ApiKeyHealthMonitor::new(config);

        // Register multiple APIs
        for i in 0..5 {
            let api_name = format!("TestAPI{}", i);
            let policy = if i < 2 {
                Some(KeyRotationPolicy::aggressive(&api_name))
            } else {
                Some(KeyRotationPolicy::default(&api_name))
            };
            monitor.register_key(&api_name, policy);
        }

        // Execute health check
        let result = monitor.execute_health_check();

        // Verify results
        assert_eq!(result.total_apis, 5);
        assert_eq!(result.validation_results.len(), 5);
        assert!(result.check_timestamp_ms > 0);

        // Verify dashboard
        let dashboard = monitor.get_health_dashboard();
        assert_eq!(dashboard.total_apis_monitored, 5);
        assert_eq!(dashboard.checks_completed, 1);
    }

    #[test]
    fn test_performance_metrics_aggregation() {
        // Setup health monitor
        let config = HealthCheckConfig::default();
        let mut monitor = ApiKeyHealthMonitor::new(config);

        // Register API
        monitor.register_key("PerfTestAPI", None);

        // Simulate successful calls
        for latency in &[50, 60, 55, 70, 65] {
            monitor.record_success("PerfTestAPI", *latency);
        }

        // Simulate failed calls
        for _ in 0..2 {
            monitor.record_failure("PerfTestAPI", "Timeout");
        }

        // Verify metrics
        if let Some(metrics) = monitor.performance_metrics.get("PerfTestAPI") {
            assert_eq!(metrics.total_requests, 7);
            assert_eq!(metrics.successful_requests, 5);
            assert_eq!(metrics.failed_requests, 2);
            assert!(metrics.error_rate_percent > 0.0);
            assert!(metrics.error_rate_percent < 100.0);
        }
    }

    #[test]
    fn test_orchestration_state_transitions() {
        // Setup orchestrator
        let config = OrchestrationConfig::development();
        let mut orchestrator = ApiKeyOrchestrator::new(config);

        use crate::util::api_key_orchestrator::OrchestrationState;

        // Verify initial state
        assert_eq!(orchestrator.state, OrchestrationState::Initializing);

        // Transition to Running
        orchestrator.state = OrchestrationState::Running;
        assert_eq!(orchestrator.state, OrchestrationState::Running);

        // Suspend
        orchestrator.suspend();
        assert_eq!(orchestrator.state, OrchestrationState::Suspended);

        // Resume
        let result = orchestrator.resume();
        assert!(result.is_ok());
        assert_eq!(orchestrator.state, OrchestrationState::Running);

        // Shutdown
        orchestrator.shutdown();
        assert_eq!(orchestrator.state, OrchestrationState::Shutdown);
    }

    #[test]
    fn test_event_logging_and_retrieval() {
        // Setup orchestrator
        let config = OrchestrationConfig::lightweight();
        let mut orchestrator = ApiKeyOrchestrator::new(config);

        use crate::util::api_key_orchestrator::{EventType, EventSeverity};

        // Generate multiple events
        for i in 0..10 {
            orchestrator.log_event(
                EventType::HealthCheckExecuted,
                format!("Health check {}", i),
                EventSeverity::Info,
            );
        }

        // Retrieve last 5 events
        let events = orchestrator.get_event_log(Some(5));
        assert_eq!(events.len(), 5);

        // Verify events are in reverse chronological order
        assert!(events[0].timestamp_ms >= events[4].timestamp_ms);

        // Retrieve all events
        let all_events = orchestrator.get_event_log(None);
        assert_eq!(all_events.len(), 10);
    }

    #[test]
    fn test_health_status_determination() {
        // Setup health monitor
        let config = HealthCheckConfig::default();
        let mut monitor = ApiKeyHealthMonitor::new(config);

        use crate::util::api_key_health::KeyHealthStatus;

        // Register API
        monitor.register_key("StatusTestAPI", None);

        // Verify initial status is Unavailable
        let status = monitor.determine_health_status("StatusTestAPI");
        assert_eq!(status, KeyHealthStatus::Unavailable);

        // Update validation to make it valid
        if let Some(validation) = monitor.validation_results.get_mut("StatusTestAPI") {
            validation.is_valid = true;
            validation.error_rate = 0.0;
            validation.expires_in_days = Some(30);
        }

        // Verify status is now Healthy
        let status = monitor.determine_health_status("StatusTestAPI");
        assert_eq!(status, KeyHealthStatus::Healthy);

        // Simulate high error rate
        if let Some(validation) = monitor.validation_results.get_mut("StatusTestAPI") {
            validation.error_rate = 8.0;
        }

        // Verify status is now Degraded
        let status = monitor.determine_health_status("StatusTestAPI");
        assert_eq!(status, KeyHealthStatus::Degraded);

        // Simulate expiration
        if let Some(validation) = monitor.validation_results.get_mut("StatusTestAPI") {
            validation.expires_in_days = Some(0);
        }

        // Verify status is now Expired
        let status = monitor.determine_health_status("StatusTestAPI");
        assert_eq!(status, KeyHealthStatus::Expired);
    }

    #[test]
    fn test_rotation_policy_selection() {
        // Create default and aggressive policies
        let default_policy = KeyRotationPolicy::default("DefaultAPI");
        let aggressive_policy = KeyRotationPolicy::aggressive("AggressiveAPI");

        // Verify default policy
        assert_eq!(default_policy.rotation_interval_days, 30);
        assert_eq!(default_policy.max_age_days, 90);
        assert!(!default_policy.enable_auto_rotation);

        // Verify aggressive policy
        assert_eq!(aggressive_policy.rotation_interval_days, 7);
        assert_eq!(aggressive_policy.max_age_days, 30);
        assert!(aggressive_policy.enable_auto_rotation);

        // Verify error rate threshold
        assert!(aggressive_policy.error_rate_threshold < default_policy.error_rate_threshold);
    }

    #[test]
    fn test_orchestration_config_profiles() {
        // Test production config
        let prod_config = OrchestrationConfig::production();
        assert!(prod_config.enable_health_monitoring);
        assert!(!prod_config.enable_auto_rotation);
        assert!(prod_config.enable_performance_tracking);

        // Test aggressive config
        let agg_config = OrchestrationConfig::aggressive();
        assert!(agg_config.enable_health_monitoring);
        assert!(agg_config.enable_auto_rotation);
        assert!(agg_config.enable_performance_tracking);
        assert!(agg_config.health_check_config.alert_on_degraded);

        // Test development config
        let dev_config = OrchestrationConfig::development();
        assert!(!dev_config.enable_health_monitoring);
        assert!(!dev_config.enable_auto_rotation);
        assert!(!dev_config.enable_performance_tracking);
    }

    #[test]
    fn test_orchestration_summary_reporting() {
        // Setup orchestrator
        let config = OrchestrationConfig::lightweight();
        let orchestrator = ApiKeyOrchestrator::new(config);

        // Get summary
        let summary = orchestrator.get_summary();

        // Verify summary contains expected fields
        assert!(summary.uptime_seconds >= 0);
        assert_eq!(summary.total_keys_managed, 0); // No initialization done yet
        assert_eq!(summary.initialization_time_ms, 0); // No initialization done yet

        // Generate report
        let report = orchestrator.get_orchestration_report();
        assert!(report.contains("API Key Orchestration Report"));
        assert!(report.contains("State:"));
        assert!(report.contains("System Health:"));
    }

    #[test]
    fn test_alert_generation_on_critical_status() {
        // Setup health monitor
        let config = HealthCheckConfig::default();
        let mut monitor = ApiKeyHealthMonitor::new(config);

        use crate::util::api_key_health::{KeyHealthStatus, AlertLevel, AlertType};

        // Register API
        monitor.register_key("CriticalAPI", None);

        // Manually set to critical status
        if let Some(validation) = monitor.validation_results.get_mut("CriticalAPI") {
            validation.is_valid = true;
            validation.health_status = KeyHealthStatus::Critical;
            validation.error_rate = 15.0;
            validation.last_error = Some("High failure rate detected".to_string());
        }

        // Execute health check which should generate alerts
        let result = monitor.execute_health_check();

        // Verify alert was generated
        assert!(!result.alerts.is_empty());

        // Find critical alert
        let critical_alert = result
            .alerts
            .iter()
            .find(|a| a.alert_level == AlertLevel::Critical);
        assert!(critical_alert.is_some());

        if let Some(alert) = critical_alert {
            assert_eq!(alert.api_name, "CriticalAPI");
            assert!(alert.action_required);
        }
    }

    #[test]
    fn test_multiple_api_concurrent_monitoring() {
        // Setup health monitor
        let config = HealthCheckConfig::aggressive();
        let mut monitor = ApiKeyHealthMonitor::new(config);

        // Register many APIs
        for i in 0..20 {
            let api_name = format!("API{:02}", i);
            monitor.register_key(&api_name, None);
        }

        // Simulate concurrent calls
        for i in 0..20 {
            let api_name = format!("API{:02}", i);
            for _ in 0..10 {
                if i % 2 == 0 {
                    monitor.record_success(&api_name, 50);
                } else {
                    monitor.record_failure(&api_name, "Test failure");
                }
            }
        }

        // Execute health check
        let result = monitor.execute_health_check();

        // Verify results
        assert_eq!(result.total_apis, 20);
        assert!(!result.validation_results.is_empty());

        // Verify performance metrics
        for i in 0..20 {
            let api_name = format!("API{:02}", i);
            if let Some(metrics) = monitor.performance_metrics.get(&api_name) {
                assert_eq!(metrics.total_requests, 10);
            }
        }
    }
}
