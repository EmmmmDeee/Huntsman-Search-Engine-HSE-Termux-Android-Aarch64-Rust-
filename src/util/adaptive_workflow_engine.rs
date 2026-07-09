/// Adaptive Workflow Engine
///
/// Generates intelligent, cascading workflows based on:
/// - Target type and characteristics
/// - Discovered data in real-time
/// - API availability and budget
/// - Historical success patterns
/// - Adaptive routing and query expansion

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

/// Adaptive workflow definition
#[derive(Debug, Clone)]
pub struct AdaptiveWorkflow {
    pub workflow_id: String,
    pub name: String,
    pub description: String,
    pub target_type: String,
    pub stages: Vec<WorkflowStage>,
    pub total_estimated_cost: u32,
    pub expected_findings: Vec<ExpectedFinding>,
    pub success_criteria: Vec<String>,
    pub adaptive_rules: Vec<AdaptiveRule>,
}

/// Single workflow stage
#[derive(Debug, Clone)]
pub struct WorkflowStage {
    pub stage_id: u32,
    pub name: String,
    pub apis_to_call: Vec<ApiQuery>,
    pub parallel: bool,
    pub dependencies: Vec<u32>,  // stage IDs that must complete first
    pub exit_condition: Option<String>,
    pub cascade_on_findings: bool,
    pub expected_output_entities: Vec<String>,
}

/// Query to execute against an API
#[derive(Debug, Clone)]
pub struct ApiQuery {
    pub api_name: String,
    pub operation: String,  // search, lookup, scan, etc.
    pub query_params: HashMap<String, String>,
    pub data_transformers: Vec<DataTransformer>,
    pub entity_extractors: Vec<EntityExtractor>,
}

/// Data transformation function
#[derive(Debug, Clone)]
pub struct DataTransformer {
    pub input_field: String,
    pub output_field: String,
    pub transformation: String,  // "uppercase", "lowercase", "extract_domain", etc.
}

/// Entity extraction definition
#[derive(Debug, Clone)]
pub struct EntityExtractor {
    pub entity_type: String,
    pub extraction_pattern: String,
    pub confidence_threshold: f32,
    pub deduplicate: bool,
}

/// Adaptive rule: adjusts workflow based on conditions
#[derive(Debug, Clone)]
pub struct AdaptiveRule {
    pub condition: String,
    pub action: WorkflowAction,
    pub priority: u32,
}

/// Workflow action
#[derive(Debug, Clone)]
pub enum WorkflowAction {
    QueueStages(Vec<u32>),
    SkipStages(Vec<u32>),
    AdjustBudget(i32),
    EscalateToAPI(String),
    IncreaseDepth(u32),
    ParallelizeStage(u32),
}

/// Expected finding during workflow execution
#[derive(Debug, Clone)]
pub struct ExpectedFinding {
    pub entity_type: String,
    pub confidence_range: (f32, f32),
    pub probability: f32,
}

/// Workflow execution context
#[derive(Debug, Clone)]
pub struct WorkflowExecutionContext {
    pub workflow_id: String,
    pub query_value: String,
    pub query_type: String,
    pub budget_remaining: u32,
    pub depth_current: u32,
    pub depth_max: u32,
    pub discovered_entities: Vec<DiscoveredEntityData>,
    pub cascade_queue: VecDeque<CascadeQuery>,
    pub execution_history: Vec<StageExecutionRecord>,
}

/// Discovered entity with metadata
#[derive(Debug, Clone)]
pub struct DiscoveredEntityData {
    pub entity_type: String,
    pub value: String,
    pub confidence: f32,
    pub source_api: String,
    pub timestamp_ms: u64,
    pub metadata: HashMap<String, String>,
}

/// Query to cascade to next stage
#[derive(Debug, Clone)]
pub struct CascadeQuery {
    pub entity_type: String,
    pub entity_value: String,
    pub priority: u32,
    pub triggered_by_api: String,
    pub trigger_stage: u32,
}

/// Execution record for a stage
#[derive(Debug, Clone)]
pub struct StageExecutionRecord {
    pub stage_id: u32,
    pub start_time_ms: u64,
    pub end_time_ms: u64,
    pub success: bool,
    pub apis_called: Vec<String>,
    pub entities_found: u32,
    pub cost_spent: u32,
}

/// Adaptive Workflow Engine
pub struct AdaptiveWorkflowEngine {
    pub workflows: HashMap<String, AdaptiveWorkflow>,
    pub execution_contexts: HashMap<String, WorkflowExecutionContext>,
    pub api_capabilities: HashMap<String, Vec<String>>,
}

impl AdaptiveWorkflowEngine {
    pub fn new() -> Self {
        Self {
            workflows: Self::initialize_workflows(),
            execution_contexts: HashMap::new(),
            api_capabilities: Self::initialize_api_capabilities(),
        }
    }

    /// Initialize pre-built adaptive workflows
    fn initialize_workflows() -> HashMap<String, AdaptiveWorkflow> {
        let mut workflows = HashMap::new();

        // ============ WORKFLOW 1: Complete Person Dossier ============
        workflows.insert(
            "complete_person_dossier".to_string(),
            AdaptiveWorkflow {
                workflow_id: "complete_person_dossier".to_string(),
                name: "Complete Person Dossier".to_string(),
                description: "Exhaustive person investigation across all data sources".to_string(),
                target_type: "person".to_string(),
                stages: vec![
                    WorkflowStage {
                        stage_id: 1,
                        name: "Initial Breach Search".to_string(),
                        apis_to_call: vec![
                            ApiQuery {
                                api_name: "SeekNow".to_string(),
                                operation: "search".to_string(),
                                query_params: HashMap::from([("person".to_string(), "query_value".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "email".to_string(),
                                    extraction_pattern: "email_field".to_string(),
                                    confidence_threshold: 0.7,
                                    deduplicate: true,
                                }],
                            },
                            ApiQuery {
                                api_name: "OathNet Pro".to_string(),
                                operation: "search".to_string(),
                                query_params: HashMap::from([("name".to_string(), "query_value".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "breach".to_string(),
                                    extraction_pattern: "breach_database".to_string(),
                                    confidence_threshold: 0.8,
                                    deduplicate: false,
                                }],
                            },
                        ],
                        parallel: true,
                        dependencies: vec![],
                        exit_condition: None,
                        cascade_on_findings: true,
                        expected_output_entities: vec!["email".to_string(), "breach".to_string()],
                    },
                    WorkflowStage {
                        stage_id: 2,
                        name: "Person Enrichment".to_string(),
                        apis_to_call: vec![
                            ApiQuery {
                                api_name: "Pipl".to_string(),
                                operation: "search".to_string(),
                                query_params: HashMap::from([("person".to_string(), "query_value".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "address".to_string(),
                                    extraction_pattern: "address".to_string(),
                                    confidence_threshold: 0.8,
                                    deduplicate: true,
                                }],
                            },
                            ApiQuery {
                                api_name: "FullContact".to_string(),
                                operation: "lookup".to_string(),
                                query_params: HashMap::from([("email".to_string(), "discovered_email".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "social_profile".to_string(),
                                    extraction_pattern: "social_links".to_string(),
                                    confidence_threshold: 0.7,
                                    deduplicate: true,
                                }],
                            },
                        ],
                        parallel: true,
                        dependencies: vec![1],
                        exit_condition: None,
                        cascade_on_findings: true,
                        expected_output_entities: vec!["address".to_string(), "social_profile".to_string()],
                    },
                    WorkflowStage {
                        stage_id: 3,
                        name: "Social Media Investigation".to_string(),
                        apis_to_call: vec![
                            ApiQuery {
                                api_name: "Instagram OSINT".to_string(),
                                operation: "lookup".to_string(),
                                query_params: HashMap::from([("username".to_string(), "discovered_username".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "social_activity".to_string(),
                                    extraction_pattern: "posts_followers".to_string(),
                                    confidence_threshold: 0.6,
                                    deduplicate: false,
                                }],
                            },
                            ApiQuery {
                                api_name: "Twitter OSINT".to_string(),
                                operation: "lookup".to_string(),
                                query_params: HashMap::from([("username".to_string(), "discovered_username".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "twitter_activity".to_string(),
                                    extraction_pattern: "tweets".to_string(),
                                    confidence_threshold: 0.6,
                                    deduplicate: false,
                                }],
                            },
                        ],
                        parallel: true,
                        dependencies: vec![2],
                        exit_condition: None,
                        cascade_on_findings: false,
                        expected_output_entities: vec!["social_activity".to_string()],
                    },
                ],
                total_estimated_cost: 15,
                expected_findings: vec![
                    ExpectedFinding {
                        entity_type: "email".to_string(),
                        confidence_range: (0.7, 1.0),
                        probability: 0.85,
                    },
                    ExpectedFinding {
                        entity_type: "address".to_string(),
                        confidence_range: (0.6, 0.95),
                        probability: 0.70,
                    },
                    ExpectedFinding {
                        entity_type: "breach".to_string(),
                        confidence_range: (0.8, 1.0),
                        probability: 0.60,
                    },
                ],
                success_criteria: vec![
                    "found_email".to_string(),
                    "verified_person".to_string(),
                    "discovered_address".to_string(),
                ],
                adaptive_rules: vec![
                    AdaptiveRule {
                        condition: "breach_found_with_high_confidence".to_string(),
                        action: WorkflowAction::EscalateToAPI("DeHashed".to_string()),
                        priority: 1,
                    },
                    AdaptiveRule {
                        condition: "multiple_addresses_found".to_string(),
                        action: WorkflowAction::QueueStages(vec![4, 5]),
                        priority: 2,
                    },
                ],
            },
        );

        // ============ WORKFLOW 2: Domain Infrastructure Mapping ============
        workflows.insert(
            "domain_infrastructure_mapping".to_string(),
            AdaptiveWorkflow {
                workflow_id: "domain_infrastructure_mapping".to_string(),
                name: "Domain Infrastructure Mapping".to_string(),
                description: "Complete domain analysis including DNS, servers, certificates".to_string(),
                target_type: "domain".to_string(),
                stages: vec![
                    WorkflowStage {
                        stage_id: 1,
                        name: "DNS & WHOIS Resolution".to_string(),
                        apis_to_call: vec![
                            ApiQuery {
                                api_name: "WHOIS".to_string(),
                                operation: "lookup".to_string(),
                                query_params: HashMap::from([("domain".to_string(), "query_value".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "registrant".to_string(),
                                    extraction_pattern: "registrant_info".to_string(),
                                    confidence_threshold: 0.9,
                                    deduplicate: true,
                                }],
                            },
                            ApiQuery {
                                api_name: "DNS Database".to_string(),
                                operation: "lookup".to_string(),
                                query_params: HashMap::from([("domain".to_string(), "query_value".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "dns_record".to_string(),
                                    extraction_pattern: "dns_entries".to_string(),
                                    confidence_threshold: 0.95,
                                    deduplicate: true,
                                }],
                            },
                        ],
                        parallel: true,
                        dependencies: vec![],
                        exit_condition: None,
                        cascade_on_findings: true,
                        expected_output_entities: vec!["registrant".to_string(), "dns_record".to_string()],
                    },
                    WorkflowStage {
                        stage_id: 2,
                        name: "Infrastructure Scanning".to_string(),
                        apis_to_call: vec![
                            ApiQuery {
                                api_name: "SecurityTrails".to_string(),
                                operation: "scan".to_string(),
                                query_params: HashMap::from([("domain".to_string(), "query_value".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "ip_address".to_string(),
                                    extraction_pattern: "resolved_ips".to_string(),
                                    confidence_threshold: 0.95,
                                    deduplicate: true,
                                }],
                            },
                            ApiQuery {
                                api_name: "Censys".to_string(),
                                operation: "scan".to_string(),
                                query_params: HashMap::from([("domain".to_string(), "query_value".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "certificate".to_string(),
                                    extraction_pattern: "ssl_certificates".to_string(),
                                    confidence_threshold: 0.95,
                                    deduplicate: true,
                                }],
                            },
                        ],
                        parallel: true,
                        dependencies: vec![1],
                        exit_condition: None,
                        cascade_on_findings: true,
                        expected_output_entities: vec!["ip_address".to_string(), "certificate".to_string()],
                    },
                    WorkflowStage {
                        stage_id: 3,
                        name: "IP & Service Analysis".to_string(),
                        apis_to_call: vec![
                            ApiQuery {
                                api_name: "Shodan".to_string(),
                                operation: "scan".to_string(),
                                query_params: HashMap::from([("ip".to_string(), "discovered_ip".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "service".to_string(),
                                    extraction_pattern: "open_ports".to_string(),
                                    confidence_threshold: 0.9,
                                    deduplicate: false,
                                }],
                            },
                            ApiQuery {
                                api_name: "AbuseIPDB".to_string(),
                                operation: "lookup".to_string(),
                                query_params: HashMap::from([("ip".to_string(), "discovered_ip".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "abuse_report".to_string(),
                                    extraction_pattern: "abuse_history".to_string(),
                                    confidence_threshold: 0.8,
                                    deduplicate: false,
                                }],
                            },
                        ],
                        parallel: true,
                        dependencies: vec![2],
                        exit_condition: None,
                        cascade_on_findings: false,
                        expected_output_entities: vec!["service".to_string(), "abuse_report".to_string()],
                    },
                ],
                total_estimated_cost: 12,
                expected_findings: vec![
                    ExpectedFinding {
                        entity_type: "ip_address".to_string(),
                        confidence_range: (0.9, 1.0),
                        probability: 0.95,
                    },
                    ExpectedFinding {
                        entity_type: "dns_record".to_string(),
                        confidence_range: (0.95, 1.0),
                        probability: 0.98,
                    },
                ],
                success_criteria: vec![
                    "resolved_dns".to_string(),
                    "found_ip".to_string(),
                    "scanned_infrastructure".to_string(),
                ],
                adaptive_rules: vec![],
            },
        );

        // ============ WORKFLOW 3: Complete Email Investigation ============
        workflows.insert(
            "complete_email_investigation".to_string(),
            AdaptiveWorkflow {
                workflow_id: "complete_email_investigation".to_string(),
                name: "Complete Email Investigation".to_string(),
                description: "Exhaustive email analysis: breaches, verification, enrichment, person search".to_string(),
                target_type: "email".to_string(),
                stages: vec![
                    WorkflowStage {
                        stage_id: 1,
                        name: "Breach & Exposure Check".to_string(),
                        apis_to_call: vec![
                            ApiQuery {
                                api_name: "SeekNow".to_string(),
                                operation: "search".to_string(),
                                query_params: HashMap::from([("email".to_string(), "query_value".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "breach".to_string(),
                                    extraction_pattern: "breach_data".to_string(),
                                    confidence_threshold: 0.8,
                                    deduplicate: true,
                                }],
                            },
                            ApiQuery {
                                api_name: "HIBP".to_string(),
                                operation: "lookup".to_string(),
                                query_params: HashMap::from([("email".to_string(), "query_value".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "exposure".to_string(),
                                    extraction_pattern: "hibp_breaches".to_string(),
                                    confidence_threshold: 0.9,
                                    deduplicate: true,
                                }],
                            },
                            ApiQuery {
                                api_name: "Xposed-or-Not".to_string(),
                                operation: "lookup".to_string(),
                                query_params: HashMap::from([("email".to_string(), "query_value".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "exposure_summary".to_string(),
                                    extraction_pattern: "exposure_count".to_string(),
                                    confidence_threshold: 0.85,
                                    deduplicate: false,
                                }],
                            },
                        ],
                        parallel: true,
                        dependencies: vec![],
                        exit_condition: None,
                        cascade_on_findings: true,
                        expected_output_entities: vec!["breach".to_string(), "exposure".to_string()],
                    },
                    WorkflowStage {
                        stage_id: 2,
                        name: "Email Verification & Enrichment".to_string(),
                        apis_to_call: vec![
                            ApiQuery {
                                api_name: "EmailHippo".to_string(),
                                operation: "verify".to_string(),
                                query_params: HashMap::from([("email".to_string(), "query_value".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "verification".to_string(),
                                    extraction_pattern: "smtp_check".to_string(),
                                    confidence_threshold: 0.85,
                                    deduplicate: false,
                                }],
                            },
                            ApiQuery {
                                api_name: "Hunter.io".to_string(),
                                operation: "lookup".to_string(),
                                query_params: HashMap::from([("email".to_string(), "query_value".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "email_info".to_string(),
                                    extraction_pattern: "person_company".to_string(),
                                    confidence_threshold: 0.8,
                                    deduplicate: true,
                                }],
                            },
                            ApiQuery {
                                api_name: "FullContact".to_string(),
                                operation: "lookup".to_string(),
                                query_params: HashMap::from([("email".to_string(), "query_value".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "contact_data".to_string(),
                                    extraction_pattern: "social_profiles".to_string(),
                                    confidence_threshold: 0.7,
                                    deduplicate: true,
                                }],
                            },
                        ],
                        parallel: true,
                        dependencies: vec![1],
                        exit_condition: None,
                        cascade_on_findings: true,
                        expected_output_entities: vec!["verification".to_string(), "email_info".to_string(), "contact_data".to_string()],
                    },
                    WorkflowStage {
                        stage_id: 3,
                        name: "Person Association".to_string(),
                        apis_to_call: vec![
                            ApiQuery {
                                api_name: "Pipl".to_string(),
                                operation: "search".to_string(),
                                query_params: HashMap::from([("email".to_string(), "query_value".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "person".to_string(),
                                    extraction_pattern: "name_address".to_string(),
                                    confidence_threshold: 0.8,
                                    deduplicate: true,
                                }],
                            },
                        ],
                        parallel: false,
                        dependencies: vec![2],
                        exit_condition: None,
                        cascade_on_findings: true,
                        expected_output_entities: vec!["person".to_string()],
                    },
                ],
                total_estimated_cost: 18,
                expected_findings: vec![
                    ExpectedFinding {
                        entity_type: "breach".to_string(),
                        confidence_range: (0.8, 1.0),
                        probability: 0.55,
                    },
                    ExpectedFinding {
                        entity_type: "person".to_string(),
                        confidence_range: (0.7, 0.95),
                        probability: 0.70,
                    },
                ],
                success_criteria: vec![
                    "checked_exposure".to_string(),
                    "verified_email".to_string(),
                ],
                adaptive_rules: vec![
                    AdaptiveRule {
                        condition: "high_exposure_count".to_string(),
                        action: WorkflowAction::EscalateToAPI("OathNet Pro".to_string()),
                        priority: 1,
                    },
                ],
            },
        );

        // ============ WORKFLOW 4: IP Threat Analysis ============
        workflows.insert(
            "ip_threat_analysis".to_string(),
            AdaptiveWorkflow {
                workflow_id: "ip_threat_analysis".to_string(),
                name: "IP Threat Analysis".to_string(),
                description: "Complete IP investigation for security threats and abuse history".to_string(),
                target_type: "ip".to_string(),
                stages: vec![
                    WorkflowStage {
                        stage_id: 1,
                        name: "Threat Assessment".to_string(),
                        apis_to_call: vec![
                            ApiQuery {
                                api_name: "GreyNoise".to_string(),
                                operation: "lookup".to_string(),
                                query_params: HashMap::from([("ip".to_string(), "query_value".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "threat".to_string(),
                                    extraction_pattern: "classification".to_string(),
                                    confidence_threshold: 0.95,
                                    deduplicate: false,
                                }],
                            },
                            ApiQuery {
                                api_name: "AbuseIPDB".to_string(),
                                operation: "lookup".to_string(),
                                query_params: HashMap::from([("ip".to_string(), "query_value".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "abuse_report".to_string(),
                                    extraction_pattern: "reports".to_string(),
                                    confidence_threshold: 0.85,
                                    deduplicate: false,
                                }],
                            },
                        ],
                        parallel: true,
                        dependencies: vec![],
                        exit_condition: None,
                        cascade_on_findings: true,
                        expected_output_entities: vec!["threat".to_string(), "abuse_report".to_string()],
                    },
                    WorkflowStage {
                        stage_id: 2,
                        name: "Infrastructure Analysis".to_string(),
                        apis_to_call: vec![
                            ApiQuery {
                                api_name: "Shodan".to_string(),
                                operation: "scan".to_string(),
                                query_params: HashMap::from([("ip".to_string(), "query_value".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "service".to_string(),
                                    extraction_pattern: "ports".to_string(),
                                    confidence_threshold: 0.9,
                                    deduplicate: false,
                                }],
                            },
                            ApiQuery {
                                api_name: "Censys".to_string(),
                                operation: "scan".to_string(),
                                query_params: HashMap::from([("ip".to_string(), "query_value".to_string())]),
                                data_transformers: vec![],
                                entity_extractors: vec![EntityExtractor {
                                    entity_type: "certificate".to_string(),
                                    extraction_pattern: "ssl_certs".to_string(),
                                    confidence_threshold: 0.95,
                                    deduplicate: false,
                                }],
                            },
                        ],
                        parallel: true,
                        dependencies: vec![1],
                        exit_condition: None,
                        cascade_on_findings: false,
                        expected_output_entities: vec!["service".to_string(), "certificate".to_string()],
                    },
                ],
                total_estimated_cost: 9,
                expected_findings: vec![
                    ExpectedFinding {
                        entity_type: "threat".to_string(),
                        confidence_range: (0.9, 1.0),
                        probability: 0.40,
                    },
                    ExpectedFinding {
                        entity_type: "service".to_string(),
                        confidence_range: (0.85, 1.0),
                        probability: 0.75,
                    },
                ],
                success_criteria: vec![
                    "threat_assessed".to_string(),
                    "infrastructure_mapped".to_string(),
                ],
                adaptive_rules: vec![],
            },
        );

        workflows
    }

    /// Initialize API capabilities mapping
    fn initialize_api_capabilities() -> HashMap<String, Vec<String>> {
        let mut capabilities = HashMap::new();

        capabilities.insert(
            "SeekNow".to_string(),
            vec!["email", "phone", "username", "person", "breach_search"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        );

        capabilities.insert(
            "OathNet Pro".to_string(),
            vec!["email", "person", "phone", "domain", "breach_database"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        );

        capabilities.insert(
            "Hunter.io".to_string(),
            vec!["email", "domain", "person", "email_enrichment"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        );

        capabilities.insert(
            "Shodan".to_string(),
            vec!["ip", "domain", "service_discovery"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        );

        capabilities
    }

    /// Get workflow by ID
    pub fn get_workflow(&self, workflow_id: &str) -> Option<&AdaptiveWorkflow> {
        self.workflows.get(workflow_id)
    }

    /// List all available workflows
    pub fn list_workflows(&self) -> Vec<(String, String)> {
        self.workflows
            .values()
            .map(|w| (w.workflow_id.clone(), w.name.clone()))
            .collect()
    }

    /// Create execution context for workflow
    pub fn create_execution_context(
        &self,
        workflow_id: &str,
        query_value: &str,
        budget: u32,
    ) -> Option<WorkflowExecutionContext> {
        self.workflows.get(workflow_id).map(|workflow| {
            WorkflowExecutionContext {
                workflow_id: workflow_id.to_string(),
                query_value: query_value.to_string(),
                query_type: workflow.target_type.clone(),
                budget_remaining: budget.saturating_sub(workflow.total_estimated_cost),
                depth_current: 0,
                depth_max: 4,
                discovered_entities: Vec::new(),
                cascade_queue: VecDeque::new(),
                execution_history: Vec::new(),
            }
        })
    }

    /// Adaptive stage queuing based on discoveries
    pub fn queue_adaptive_stages(
        &self,
        context: &mut WorkflowExecutionContext,
        discovered_entities: &[DiscoveredEntityData],
    ) {
        for entity in discovered_entities {
            context.cascade_queue.push_back(CascadeQuery {
                entity_type: entity.entity_type.clone(),
                entity_value: entity.value.clone(),
                priority: 1,
                triggered_by_api: entity.source_api.clone(),
                trigger_stage: 1,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workflow_initialization() {
        let engine = AdaptiveWorkflowEngine::new();
        assert!(!engine.workflows.is_empty());
        assert!(engine.get_workflow("complete_person_dossier").is_some());
    }

    #[test]
    fn test_list_workflows() {
        let engine = AdaptiveWorkflowEngine::new();
        let workflows = engine.list_workflows();
        assert!(workflows.len() >= 3);
    }

    #[test]
    fn test_execution_context_creation() {
        let engine = AdaptiveWorkflowEngine::new();
        let context = engine.create_execution_context("complete_person_dossier", "test@example.com", 100);
        assert!(context.is_some());
        let ctx = context.unwrap();
        assert_eq!(ctx.query_value, "test@example.com");
    }

    #[test]
    fn test_workflow_stages_dependencies() {
        let engine = AdaptiveWorkflowEngine::new();
        let workflow = engine.get_workflow("complete_person_dossier").unwrap();
        let stage_2 = workflow.stages.iter().find(|s| s.stage_id == 2).unwrap();
        assert!(stage_2.dependencies.contains(&1));
    }

    #[test]
    fn test_cascade_queueing() {
        let engine = AdaptiveWorkflowEngine::new();
        let mut context = engine
            .create_execution_context("complete_person_dossier", "test@example.com", 100)
            .unwrap();

        let entities = vec![DiscoveredEntityData {
            entity_type: "person".to_string(),
            value: "John Doe".to_string(),
            confidence: 0.85,
            source_api: "SeekNow".to_string(),
            timestamp_ms: 1234567890,
            metadata: HashMap::new(),
        }];

        engine.queue_adaptive_stages(&mut context, &entities);
        assert!(!context.cascade_queue.is_empty());
    }
}
