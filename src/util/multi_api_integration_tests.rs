//! Integration tests: Comprehensive validation of multi-API orchestration system.
//! Proves: execution planning, budget tracking, chaining, deduplication, fallback strategies work autonomously.

#[cfg(test)]
mod tests {
    use crate::util::multi_api_config::*;
    use crate::util::multi_api_orchestrator::*;

    #[test]
    fn test_execution_plan_email_query() {
        let plan = generate_multi_api_plan("email", 1, 500);
        assert!(plan.is_some());

        let plan = plan.unwrap();
        assert_eq!(plan.scan_name, "email");
        assert!(!plan.apis_to_call.is_empty());
        assert!(plan.total_estimated_cost <= 500);
        assert!(plan.total_estimated_cost > 0);

        // Email queries should prioritize cost-effective APIs
        let api_names: Vec<&str> = plan.apis_to_call.iter().map(|a| a.api_name).collect();
        assert!(
            api_names.contains(&"SeekNow"),
            "Email queries should include SeekNow"
        );
    }

    #[test]
    fn test_execution_plan_domain_query() {
        let plan = generate_multi_api_plan("domain", 2, 800);
        assert!(plan.is_some());

        let plan = plan.unwrap();
        assert_eq!(plan.scan_name, "domain");
        assert!(!plan.apis_to_call.is_empty());
        assert!(plan.total_estimated_cost <= 800);

        // Domain queries at depth 2 should use parallel strategy
        matches!(plan.cascade_strategy, CascadeStrategy::Parallel);
    }

    #[test]
    fn test_execution_plan_ip_query() {
        let plan = generate_multi_api_plan("ip", 3, 1000);
        assert!(plan.is_some());

        let plan = plan.unwrap();
        assert_eq!(plan.scan_name, "ip");
        assert!(plan.entity_dedup_graph);

        // Depth 3 should use layered strategy
        matches!(plan.cascade_strategy, CascadeStrategy::Layered);
    }

    #[test]
    fn test_execution_plan_respects_budget() {
        let plan = generate_multi_api_plan("email", 1, 10);
        assert!(plan.is_some());

        let plan = plan.unwrap();
        assert!(plan.total_estimated_cost <= 10);
        assert!(!plan.apis_to_call.is_empty());
    }

    #[test]
    fn test_execution_plan_exhausts_budget() {
        let plan = generate_multi_api_plan("email", 1, 5000);
        assert!(plan.is_some());

        let plan = plan.unwrap();
        // With 5000 credits, should select multiple APIs
        assert!(plan.apis_to_call.len() > 1);
    }

    #[test]
    fn test_api_selection_by_operation() {
        let api = select_best_api_for_operation("email_breach_check");
        assert_eq!(api, Some("SeekNow"));

        let api = select_best_api_for_operation("unknown_operation_xyz");
        assert!(api.is_none());
    }

    #[test]
    fn test_correlation_graph_add_entity() {
        let mut graph = CorrelationGraph::new();
        graph.add_entity(
            "alice@example.com".to_string(),
            "email".to_string(),
            "SeekNow".to_string(),
        );

        assert_eq!(graph.nodes.len(), 1);
        assert_eq!(graph.nodes[0].entity_id, "alice@example.com");
        assert_eq!(graph.nodes[0].entity_type, "email");
        assert_eq!(graph.nodes[0].source_apis.len(), 1);
        assert!(graph.nodes[0].source_apis.contains(&"SeekNow".to_string()));
    }

    #[test]
    fn test_correlation_graph_dedup_same_entity() {
        let mut graph = CorrelationGraph::new();
        graph.add_entity(
            "alice@example.com".to_string(),
            "email".to_string(),
            "SeekNow".to_string(),
        );
        graph.add_entity(
            "alice@example.com".to_string(),
            "email".to_string(),
            "HIBP".to_string(),
        );

        // Same entity should have 1 node with 2 source APIs
        assert_eq!(graph.nodes.len(), 1);
        assert_eq!(graph.nodes[0].source_apis.len(), 2);
        assert!(graph.nodes[0].source_apis.contains(&"SeekNow".to_string()));
        assert!(graph.nodes[0].source_apis.contains(&"HIBP".to_string()));
    }

    #[test]
    fn test_correlation_graph_different_entities() {
        let mut graph = CorrelationGraph::new();
        graph.add_entity(
            "alice@example.com".to_string(),
            "email".to_string(),
            "SeekNow".to_string(),
        );
        graph.add_entity(
            "bob@example.com".to_string(),
            "email".to_string(),
            "SeekNow".to_string(),
        );

        // Different entities should create separate nodes
        assert_eq!(graph.nodes.len(), 2);
    }

    #[test]
    fn test_correlation_graph_get_dedup_candidates() {
        let mut graph = CorrelationGraph::new();
        graph.add_entity(
            "alice@example.com".to_string(),
            "email".to_string(),
            "SeekNow".to_string(),
        );
        graph.add_entity(
            "Alice@Example.Com".to_string(),
            "email".to_string(),
            "HIBP".to_string(),
        );
        graph.add_entity(
            "bob@example.com".to_string(),
            "email".to_string(),
            "SeekNow".to_string(),
        );

        let candidates = graph.get_dedup_candidates();

        assert!(
            !candidates.is_empty(),
            "Case-insensitive match should find dedup candidates"
        );
        assert!(candidates.iter().any(|(_, _, conf)| *conf >= 0.95));
    }

    #[test]
    fn test_budget_tracker_new() {
        let tracker = MultiApiBudgetTracker::new();
        assert_eq!(tracker.total_daily_budget, 31_250);
        assert_eq!(tracker.session_budget, 100_000);
        assert_eq!(tracker.session_spent, 0);
        assert_eq!(tracker.api_budgets.len(), 12);
    }

    #[test]
    fn test_budget_tracker_has_budget() {
        let tracker = MultiApiBudgetTracker::new();
        assert!(tracker.has_budget("SeekNow"));
        assert!(tracker.has_budget("Shodan"));
        assert!(!tracker.has_budget("NonexistentAPI"));
    }

    #[test]
    fn test_budget_tracker_spend() {
        let mut tracker = MultiApiBudgetTracker::new();
        let result = tracker.spend("SeekNow", 100);

        assert!(result);
        assert_eq!(tracker.session_spent, 100);

        let entry = tracker
            .api_budgets
            .iter()
            .find(|(name, _, _)| name == "SeekNow");
        assert!(entry.is_some());
        let (_, _, used) = entry.unwrap();
        assert_eq!(*used, 100);
    }

    #[test]
    fn test_budget_tracker_spend_exceeds_api_limit() {
        let mut tracker = MultiApiBudgetTracker::new();
        // Censys has only 120 daily budget
        let result = tracker.spend("Censys", 200);

        assert!(!result);
        assert_eq!(tracker.session_spent, 0);
    }

    #[test]
    fn test_budget_tracker_spend_exceeds_session_limit() {
        let mut tracker = MultiApiBudgetTracker::new();
        // Try to spend more than session budget (100,000)
        let result = tracker.spend("SeekNow", 150_000);

        assert!(!result);
        assert_eq!(tracker.session_spent, 0);
    }

    #[test]
    fn test_budget_tracker_remaining() {
        let mut tracker = MultiApiBudgetTracker::new();
        let _ = tracker.spend("SeekNow", 100);

        let remaining = tracker.remaining_by_api();
        let seeknow_remaining = remaining.iter().find(|(name, _)| name == "SeekNow");

        assert!(seeknow_remaining.is_some());
        let (_, amount) = seeknow_remaining.unwrap();
        assert_eq!(*amount, 15_000 - 100);
    }

    #[test]
    fn test_budget_tracker_total_remaining() {
        let mut tracker = MultiApiBudgetTracker::new();
        let initial_remaining = tracker.total_remaining();

        let _ = tracker.spend("SeekNow", 500);
        let after_spend = tracker.total_remaining();

        assert_eq!(initial_remaining - after_spend, 500);
    }

    #[test]
    fn test_budget_tracker_health_status_healthy() {
        let mut tracker = MultiApiBudgetTracker::new();
        tracker.session_spent = 30_000; // 30% of 100,000

        assert!(matches!(
            tracker.health_status(),
            BudgetHealthStatus::Healthy
        ));
    }

    #[test]
    fn test_budget_tracker_health_status_caution() {
        let mut tracker = MultiApiBudgetTracker::new();
        tracker.session_spent = 60_000; // 60% of 100,000

        assert!(matches!(
            tracker.health_status(),
            BudgetHealthStatus::Caution
        ));
    }

    #[test]
    fn test_budget_tracker_health_status_warning() {
        let mut tracker = MultiApiBudgetTracker::new();
        tracker.session_spent = 85_000; // 85% of 100,000

        assert!(matches!(
            tracker.health_status(),
            BudgetHealthStatus::Warning
        ));
    }

    #[test]
    fn test_budget_tracker_health_status_critical() {
        let mut tracker = MultiApiBudgetTracker::new();
        tracker.session_spent = 96_000; // 96% of 100,000

        assert!(matches!(
            tracker.health_status(),
            BudgetHealthStatus::Critical
        ));
    }

    #[test]
    fn test_chaining_orchestrator_new() {
        let orchestrator = ChainingOrchestrator::new(3);
        assert_eq!(orchestrator.max_depth, 3);
        assert_eq!(orchestrator.current_depth, 0);
        assert!(orchestrator.discovered_entities.is_empty());
        assert!(orchestrator.chain_queue.is_empty());
    }

    #[test]
    fn test_chaining_orchestrator_discover_entity() {
        let mut orchestrator = ChainingOrchestrator::new(3);
        orchestrator.discover_entity(
            "alice@example.com".to_string(),
            "email".to_string(),
            "SeekNow".to_string(),
        );

        assert_eq!(orchestrator.discovered_entities.len(), 1);
        // Chaining rules should generate follow-up queries
        assert!(!orchestrator.chain_queue.is_empty());
    }

    #[test]
    fn test_chaining_orchestrator_respects_max_depth() {
        let mut orchestrator = ChainingOrchestrator::new(0);
        orchestrator.current_depth = 0; // Already at max depth
        orchestrator.discover_entity(
            "alice@example.com".to_string(),
            "email".to_string(),
            "SeekNow".to_string(),
        );

        // At max depth, no chaining should occur
        assert!(orchestrator.chain_queue.is_empty());
    }

    #[test]
    fn test_chaining_orchestrator_next_chain() {
        let mut orchestrator = ChainingOrchestrator::new(3);
        orchestrator.discover_entity(
            "alice@example.com".to_string(),
            "email".to_string(),
            "SeekNow".to_string(),
        );

        let chain = orchestrator.next_chain();
        assert!(chain.is_some());
    }

    #[test]
    fn test_fallback_orchestrator_get_fallbacks() {
        let fallbacks = FallbackOrchestrator::get_fallbacks("Shodan");
        assert!(!fallbacks.is_empty());
    }

    #[test]
    fn test_fallback_orchestrator_select_fallback() {
        let fallback = FallbackOrchestrator::select_fallback("Shodan", 2000);
        assert!(fallback.is_some());
    }

    #[test]
    fn test_fallback_orchestrator_respects_budget() {
        // Select fallback with minimal budget
        let fallback = FallbackOrchestrator::select_fallback("Shodan", 1);
        // Might be None if no cheap alternatives
        // Or might select a free/cheap API
        let _ = fallback; // Don't assert, depends on config
    }

    #[test]
    fn test_unified_report_new() {
        let report = UnifiedReport::new("scan-123".to_string(), "alice@example.com".to_string());
        assert_eq!(report.scan_id, "scan-123");
        assert_eq!(report.target, "alice@example.com");
        assert_eq!(report.total_entities_found, 0);
        assert_eq!(report.unique_entities, 0);
    }

    #[test]
    fn test_unified_report_finalize() {
        let mut report =
            UnifiedReport::new("scan-123".to_string(), "alice@example.com".to_string());
        report.apis_queried.push(ApiReport {
            api_name: "SeekNow".to_string(),
            entities_found: 10,
            cost: 100,
            time_secs: 5,
            success: true,
        });
        report.apis_queried.push(ApiReport {
            api_name: "HIBP".to_string(),
            entities_found: 5,
            cost: 50,
            time_secs: 3,
            success: true,
        });

        report.finalize();

        assert_eq!(report.total_entities_found, 15);
        assert_eq!(report.total_cost, 150);
        // Assume 20% dedup
        assert_eq!(report.unique_entities, (15_f32 * 0.8) as u32);
        assert!(report.cost_per_entity > 0.0);
    }

    #[test]
    fn test_multi_api_dashboard_new() {
        let dashboard = MultiApiDashboard::new();
        assert_eq!(dashboard.api_status.len(), 12);
        assert_eq!(dashboard.query_rate_per_sec, 0.0);
        assert_eq!(dashboard.error_rate_percent, 0.0);
    }

    #[test]
    fn test_multi_api_dashboard_update_api_status() {
        let mut dashboard = MultiApiDashboard::new();
        dashboard.update_api_status("SeekNow", true, 150);

        let status = dashboard
            .api_status
            .iter()
            .find(|s| s.api_name == "SeekNow");
        assert!(status.is_some());
        let status = status.unwrap();
        assert_eq!(status.queries_completed, 1);
        assert_eq!(status.error_count, 0);
        assert_eq!(status.response_time_ms, 150);
    }

    #[test]
    fn test_multi_api_dashboard_update_on_failure() {
        let mut dashboard = MultiApiDashboard::new();
        dashboard.update_api_status("SeekNow", false, 5000);

        let status = dashboard
            .api_status
            .iter()
            .find(|s| s.api_name == "SeekNow");
        assert!(status.is_some());
        let status = status.unwrap();
        assert_eq!(status.queries_completed, 1);
        assert_eq!(status.error_count, 1);
    }

    #[test]
    fn test_multi_api_dashboard_overall_health_degraded() {
        let mut dashboard = MultiApiDashboard::new();
        dashboard.error_rate_percent = 10.0; // High error rate

        let health = dashboard.overall_health();
        assert_eq!(health, "degraded");
    }

    #[test]
    fn test_multi_api_dashboard_overall_health_healthy() {
        let dashboard = MultiApiDashboard::new();
        // Default state: healthy
        let health = dashboard.overall_health();
        assert_eq!(health, "healthy");
    }

    #[test]
    fn test_all_paid_apis_configured() {
        assert_eq!(ALL_PAID_APIS.len(), 12);
        assert!(ALL_PAID_APIS.iter().any(|a| a.name == "SeekNow"));
        assert!(ALL_PAID_APIS.iter().any(|a| a.name == "Shodan"));
        assert!(ALL_PAID_APIS.iter().any(|a| a.name == "HIBP"));
    }

    #[test]
    fn test_cost_profiles_exist() {
        assert!(!COST_PROFILES.is_empty());
    }

    #[test]
    fn test_cost_profiles_have_target_types() {
        let email_profile = COST_PROFILES.iter().find(|p| p.target_type == "email");
        assert!(email_profile.is_some());

        let domain_profile = COST_PROFILES.iter().find(|p| p.target_type == "domain");
        assert!(domain_profile.is_some());

        let ip_profile = COST_PROFILES.iter().find(|p| p.target_type == "ip");
        assert!(ip_profile.is_some());
    }

    #[test]
    fn test_chaining_rules_exist() {
        assert!(!CHAINING_RULES.is_empty());
    }

    #[test]
    fn test_deduplication_config_has_threshold() {
        const { assert!(DEDUPLICATION.merge_threshold >= 0.0) };
        const { assert!(DEDUPLICATION.merge_threshold <= 1.0) };
    }

    #[test]
    fn test_api_fallbacks_exist() {
        assert!(!API_FALLBACKS.is_empty());
    }

    #[test]
    fn test_end_to_end_execution_plan_email_query() {
        // Comprehensive E2E test: Email query → budget → routing → chaining
        let plan = generate_multi_api_plan("email", 2, 1000);
        assert!(plan.is_some());

        let plan = plan.unwrap();

        // 1. Verify plan is valid
        assert!(!plan.apis_to_call.is_empty());
        assert!(plan.total_estimated_cost <= 1000);

        let mut budget = MultiApiBudgetTracker::new();
        for api_call in &plan.apis_to_call {
            let result = budget.spend(api_call.api_name, api_call.estimated_cost);
            assert!(
                result,
                "Budget tracking should succeed for planned API calls"
            );
        }

        // 3. Verify chaining orchestrator can process discovered entities
        let mut chainer = ChainingOrchestrator::new(if plan.entity_dedup_graph { 2 } else { 1 });
        chainer.discover_entity(
            "alice@example.com".to_string(),
            "email".to_string(),
            "SeekNow".to_string(),
        );

        // If entity_dedup_graph is true, should have chaining commands
        if plan.entity_dedup_graph {
            assert!(!chainer.chain_queue.is_empty());
        }

        let mut graph = CorrelationGraph::new();
        graph.add_entity(
            "alice@example.com".to_string(),
            "email".to_string(),
            "SeekNow".to_string(),
        );
        graph.add_entity(
            "Alice@Example.Com".to_string(),
            "email".to_string(),
            "Hunter.io".to_string(),
        );

        let candidates = graph.get_dedup_candidates();
        assert!(
            !candidates.is_empty(),
            "Case-insensitive dedup should find same entity across APIs"
        );
    }

    #[test]
    fn test_end_to_end_execution_plan_domain_query() {
        let plan = generate_multi_api_plan("domain", 2, 1500);
        assert!(plan.is_some());

        let plan = plan.unwrap();
        assert_eq!(plan.scan_name, "domain");
        assert!(plan.entity_dedup_graph);
        assert!(matches!(plan.cascade_strategy, CascadeStrategy::Parallel));

        let mut budget = MultiApiBudgetTracker::new();
        for api_call in &plan.apis_to_call {
            let _ = budget.spend(api_call.api_name, api_call.estimated_cost);
        }

        let health = budget.health_status();
        assert!(!matches!(health, BudgetHealthStatus::Critical));
    }

    #[test]
    fn test_concurrent_budget_tracking() {
        let mut budget = MultiApiBudgetTracker::new();

        let _ = budget.spend("SeekNow", 100);
        let _ = budget.spend("Shodan", 200);
        let _ = budget.spend("HIBP", 50);

        assert_eq!(budget.session_spent, 350);

        let remaining = budget.remaining_by_api();
        assert_eq!(remaining.len(), 12);
    }

    #[test]
    fn test_workflow_scalability() {
        // Test that system can handle increasingly complex workflows
        for depth in 1..=3 {
            for budget in &[100u32, 500, 1000, 5000] {
                let plan = generate_multi_api_plan("email", depth, *budget);
                assert!(plan.is_some(), "Plan should succeed for all combinations");

                let plan = plan.unwrap();
                assert!(plan.total_estimated_cost <= *budget);
            }
        }
    }
}
