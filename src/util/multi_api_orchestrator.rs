/// Multi-API orchestrator: intelligent coordination of 12+ paid APIs.
/// Routes queries to optimal APIs, chains results, deduplicates entities,
/// tracks budgets, handles failures, and maximizes coverage per credit spent.

use super::multi_api_config::*;

/// Unified API execution plan (auto-generated from scan profile).
pub struct MultiApiExecutionPlan {
    pub scan_name: &'static str,
    pub apis_to_call: Vec<ApiCallSpec>,
    pub total_estimated_cost: u32,
    pub total_estimated_time_secs: u32,
    pub entity_dedup_graph: bool,  // Build correlation graph?
    pub cascade_strategy: CascadeStrategy,
}

pub struct ApiCallSpec {
    pub api_name: &'static str,
    pub priority: u32,
    pub query_type: &'static str,
    pub estimated_cost: u32,
    pub timeout_secs: u32,
    pub retry_count: u32,
}

pub enum CascadeStrategy {
    Sequential,        // Call APIs in priority order
    Parallel,          // Call all APIs concurrently
    Layered,           // Call priority 1, then use results for priority 2
}

/// Auto-generate multi-API execution plan based on target type.
pub fn generate_multi_api_plan(
    target_type: &'static str,
    depth: u32,
    budget: u32,
) -> Option<MultiApiExecutionPlan> {
    // Find cost profile for target type
    let profile = COST_PROFILES
        .iter()
        .find(|p| p.target_type == target_type)?;

    // Build API call sequence based on available budget
    let mut apis_to_call = Vec::new();
    let mut spent = 0u32;

    for (api_name, _priority) in profile.apis_in_order {
        let api = ALL_PAID_APIS.iter().find(|a| a.name == *api_name)?;

        if spent + api.per_query_cost <= budget {
            apis_to_call.push(ApiCallSpec {
                api_name,
                priority: api.priority,
                query_type: target_type,
                estimated_cost: api.per_query_cost,
                timeout_secs: api.timeout_secs,
                retry_count: 2,
            });
            spent += api.per_query_cost;
        } else {
            break;  // Budget exhausted
        }
    }

    // Sort by priority (descending)
    apis_to_call.sort_by(|a, b| b.priority.cmp(&a.priority));

    let cascade = match depth {
        1 => CascadeStrategy::Sequential,
        2 => CascadeStrategy::Parallel,
        _ => CascadeStrategy::Layered,
    };

    Some(MultiApiExecutionPlan {
        scan_name: target_type,
        apis_to_call,
        total_estimated_cost: spent,
        total_estimated_time_secs: 60,  // Placeholder
        entity_dedup_graph: depth >= 2,
        cascade_strategy: cascade,
    })
}

/// API selection strategy: pick best API for a given operation.
pub fn select_best_api_for_operation(operation: &str) -> Option<&'static str> {
    COST_OPTIMIZATIONS
        .iter()
        .find(|c| c.operation == operation)
        .map(|c| c.recommended_api)
}

/// Entity correlation graph: track which entities came from which APIs.
pub struct CorrelationGraphNode {
    pub entity_id: String,
    pub entity_type: String,
    pub source_apis: Vec<String>,
    pub correlation_score: f32,
    pub related_entities: Vec<String>,
}

pub struct CorrelationGraph {
    pub nodes: Vec<CorrelationGraphNode>,
    pub edges: Vec<(String, String, f32)>, // (entity1_id, entity2_id, confidence)
}

impl CorrelationGraph {
    pub fn new() -> Self {
        CorrelationGraph {
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    /// Add entity discovered from an API
    pub fn add_entity(&mut self, entity_id: String, entity_type: String, source_api: String) {
        // Check if entity already exists
        if let Some(node) = self.nodes.iter_mut().find(|n| n.entity_id == entity_id) {
            node.source_apis.push(source_api);
            node.correlation_score = (node.correlation_score + 0.1).min(1.0);
        } else {
            self.nodes.push(CorrelationGraphNode {
                entity_id,
                entity_type,
                source_apis: vec![source_api],
                correlation_score: 0.5,
                related_entities: Vec::new(),
            });
        }
    }

    /// Add correlation between two entities
    pub fn add_correlation(&mut self, entity1_id: String, entity2_id: String, confidence: f32) {
        self.edges.push((entity1_id, entity2_id, confidence));
    }

    /// Get deduplication candidates (same entity from multiple APIs)
    pub fn get_dedup_candidates(&self) -> Vec<(String, String, f32)> {
        let mut candidates = Vec::new();
        for i in 0..self.nodes.len() {
            for j in i + 1..self.nodes.len() {
                if self.nodes[i].entity_type == self.nodes[j].entity_type {
                    // Calculate similarity (placeholder: 0.95 if same ID, 0.8 if close match)
                    let similarity = if self.nodes[i].entity_id == self.nodes[j].entity_id {
                        0.95
                    } else {
                        0.8  // Fuzzy match
                    };
                    if similarity >= DEDUPLICATION.merge_threshold {
                        candidates.push((
                            self.nodes[i].entity_id.clone(),
                            self.nodes[j].entity_id.clone(),
                            similarity,
                        ));
                    }
                }
            }
        }
        candidates
    }
}

/// Multi-API budget tracker (across all 12 APIs).
pub struct MultiApiBudgetTracker {
    pub total_daily_budget: u32,
    pub api_budgets: Vec<(String, u32, u32)>, // (api_name, daily_limit, used_today)
    pub session_budget: u32,
    pub session_spent: u32,
}

impl MultiApiBudgetTracker {
    pub fn new() -> Self {
        MultiApiBudgetTracker {
            total_daily_budget: 31_250,
            api_budgets: ALL_PAID_APIS
                .iter()
                .map(|api| (api.name.to_string(), api.daily_budget, 0))
                .collect(),
            session_budget: 100_000,
            session_spent: 0,
        }
    }

    /// Check if API has budget remaining
    pub fn has_budget(&self, api_name: &str) -> bool {
        self.api_budgets
            .iter()
            .find(|(name, _, _)| name == api_name)
            .map(|(_, limit, used)| used < limit)
            .unwrap_or(false)
    }

    /// Spend credits from an API
    pub fn spend(&mut self, api_name: &str, cost: u32) -> bool {
        if let Some(entry) = self.api_budgets.iter_mut().find(|(name, _, _)| name == api_name) {
            if entry.2 + cost <= entry.1 && self.session_spent + cost <= self.session_budget {
                entry.2 += cost;
                self.session_spent += cost;
                return true;
            }
        }
        false
    }

    /// Get remaining budget for all APIs
    pub fn remaining_by_api(&self) -> Vec<(String, u32)> {
        self.api_budgets
            .iter()
            .map(|(name, limit, used)| (name.clone(), limit.saturating_sub(*used)))
            .collect()
    }

    /// Total remaining budget across all APIs
    pub fn total_remaining(&self) -> u32 {
        self.api_budgets
            .iter()
            .map(|(_, limit, used)| limit.saturating_sub(*used))
            .sum()
    }

    /// Health status of budget
    pub fn health_status(&self) -> BudgetHealthStatus {
        let percent_used = (self.session_spent as f32 / self.session_budget as f32) * 100.0;
        if percent_used >= 95.0 {
            BudgetHealthStatus::Critical
        } else if percent_used >= 80.0 {
            BudgetHealthStatus::Warning
        } else if percent_used >= 50.0 {
            BudgetHealthStatus::Caution
        } else {
            BudgetHealthStatus::Healthy
        }
    }
}

pub enum BudgetHealthStatus {
    Healthy,
    Caution,
    Warning,
    Critical,
}

/// Intelligent chaining orchestrator (auto-generates follow-up queries).
pub struct ChainingOrchestrator {
    pub discovered_entities: Vec<(String, String, String)>, // (entity, type, source_api)
    pub chain_queue: Vec<ChainCommand>,
    pub max_depth: u32,
    pub current_depth: u32,
}

pub struct ChainCommand {
    pub target_api: String,
    pub entity: String,
    pub entity_type: String,
    pub priority: u32,
}

impl ChainingOrchestrator {
    pub fn new(max_depth: u32) -> Self {
        ChainingOrchestrator {
            discovered_entities: Vec::new(),
            chain_queue: Vec::new(),
            max_depth,
            current_depth: 0,
        }
    }

    /// Add discovered entity and generate chaining commands
    pub fn discover_entity(&mut self, entity: String, entity_type: String, source_api: String) {
        self.discovered_entities.push((entity.clone(), entity_type.clone(), source_api.clone()));

        if self.current_depth < self.max_depth {
            // Find applicable chaining rules
            for rule in CHAINING_RULES {
                if rule.source_api == source_api && rule.entity_type_found == entity_type {
                    self.chain_queue.push(ChainCommand {
                        target_api: rule.chain_to_api.to_string(),
                        entity: entity.clone(),
                        entity_type: entity_type.clone(),
                        priority: 50,  // Lower priority than primary queries
                    });
                }
            }
        }
    }

    /// Get next chain command (priority ordered)
    pub fn next_chain(&mut self) -> Option<ChainCommand> {
        if self.chain_queue.is_empty() {
            return None;
        }
        self.chain_queue.sort_by(|a, b| b.priority.cmp(&a.priority));
        Some(self.chain_queue.remove(0))
    }

    /// Advance to next depth level
    pub fn advance_depth(&mut self) {
        self.current_depth += 1;
    }
}

/// Fallback orchestrator (when APIs fail or quota exhausted).
pub struct FallbackOrchestrator;

impl FallbackOrchestrator {
    /// Get fallback APIs for a failed API
    pub fn get_fallbacks(failed_api: &str) -> Vec<&'static str> {
        API_FALLBACKS
            .iter()
            .find(|f| f.api == failed_api)
            .map(|f| f.fallback_apis.to_vec())
            .unwrap_or_default()
    }

    /// Auto-select best fallback based on strategy
    pub fn select_fallback(failed_api: &str, available_budget: u32) -> Option<&'static str> {
        let fallback = API_FALLBACKS.iter().find(|f| f.api == failed_api)?;

        // Try each fallback in order
        for fallback_api in fallback.fallback_apis {
            let api_spec = ALL_PAID_APIS.iter().find(|a| a.name == *fallback_api)?;
            if api_spec.per_query_cost <= available_budget {
                return Some(*fallback_api);
            }
        }
        None
    }
}

/// Unified reporting (aggregate findings from all APIs).
pub struct UnifiedReport {
    pub scan_id: String,
    pub target: String,
    pub apis_queried: Vec<ApiReport>,
    pub total_entities_found: u32,
    pub unique_entities: u32,
    pub dedup_savings: u32,     // How many duplicates were merged
    pub total_cost: u32,
    pub cost_per_entity: f32,
    pub correlation_graph_nodes: u32,
    pub correlation_graph_edges: u32,
}

pub struct ApiReport {
    pub api_name: String,
    pub entities_found: u32,
    pub cost: u32,
    pub time_secs: u32,
    pub success: bool,
}

impl UnifiedReport {
    pub fn new(scan_id: String, target: String) -> Self {
        UnifiedReport {
            scan_id,
            target,
            apis_queried: Vec::new(),
            total_entities_found: 0,
            unique_entities: 0,
            dedup_savings: 0,
            total_cost: 0,
            cost_per_entity: 0.0,
            correlation_graph_nodes: 0,
            correlation_graph_edges: 0,
        }
    }

    /// Finalize report and calculate aggregates
    pub fn finalize(&mut self) {
        self.total_entities_found = self.apis_queried.iter().map(|r| r.entities_found).sum();
        self.total_cost = self.apis_queried.iter().map(|r| r.cost).sum();

        // Unique entities after deduplication (placeholder: assume 20% dedup)
        self.unique_entities = (self.total_entities_found as f32 * 0.8) as u32;
        self.dedup_savings = self.total_entities_found - self.unique_entities;

        if self.unique_entities > 0 {
            self.cost_per_entity = self.total_cost as f32 / self.unique_entities as f32;
        }
    }
}

/// Real-time multi-API monitoring dashboard.
pub struct MultiApiDashboard {
    pub api_status: Vec<ApiStatus>,
    pub query_rate_per_sec: f32,
    pub error_rate_percent: f32,
    pub budget_health: BudgetHealthStatus,
    pub last_update_secs: u32,
}

pub struct ApiStatus {
    pub api_name: String,
    pub uptime_percent: f32,
    pub response_time_ms: u32,
    pub error_count: u32,
    pub queries_completed: u32,
    pub credits_used: u32,
    pub status: &'static str,
}

impl MultiApiDashboard {
    pub fn new() -> Self {
        MultiApiDashboard {
            api_status: ALL_PAID_APIS
                .iter()
                .map(|api| ApiStatus {
                    api_name: api.name.to_string(),
                    uptime_percent: 100.0,
                    response_time_ms: 0,
                    error_count: 0,
                    queries_completed: 0,
                    credits_used: 0,
                    status: "operational",
                })
                .collect(),
            query_rate_per_sec: 0.0,
            error_rate_percent: 0.0,
            budget_health: BudgetHealthStatus::Healthy,
            last_update_secs: 0,
        }
    }

    /// Update API status
    pub fn update_api_status(&mut self, api_name: &str, success: bool, response_time_ms: u32) {
        if let Some(status) = self.api_status.iter_mut().find(|s| s.api_name == api_name) {
            status.queries_completed += 1;
            if !success {
                status.error_count += 1;
            }
            status.response_time_ms = response_time_ms;
            status.uptime_percent = ((status.queries_completed - status.error_count) as f32
                / status.queries_completed as f32)
                * 100.0;
        }
    }

    /// Get overall system health
    pub fn overall_health(&self) -> &'static str {
        let avg_uptime: f32 = self.api_status.iter().map(|s| s.uptime_percent).sum::<f32>()
            / self.api_status.len() as f32;
        let avg_error_rate = self.error_rate_percent;

        if avg_uptime < 95.0 || avg_error_rate > 5.0 {
            "degraded"
        } else if avg_uptime < 98.0 || avg_error_rate > 2.0 {
            "caution"
        } else {
            "healthy"
        }
    }
}
