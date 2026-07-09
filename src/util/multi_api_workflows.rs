/// Advanced multi-API workflows: pre-built OSINT scenarios using intelligent API chaining.
/// Each workflow optimizes across all 12 APIs for maximum coverage and minimum cost.

/// Advanced enterprise OSINT workflows (20+ scenarios).
pub struct AdvancedWorkflow {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub apis_used: &'static [&'static str],
    pub steps: &'static [WorkflowStep],
    pub estimated_cost: u32,
    pub estimated_time_secs: u32,
    pub best_for: &'static str,
}

pub struct WorkflowStep {
    pub step_num: u32,
    pub operation: &'static str,
    pub api: &'static str,
    pub depends_on_step: Option<u32>,
    pub uses_entity_from: Option<&'static str>,
}

pub const ADVANCED_WORKFLOWS: &[AdvancedWorkflow] = &[
    // ===== THREAT INTELLIGENCE WORKFLOWS =====

    // Workflow 1: Complete IP Investigation
    AdvancedWorkflow {
        id: "complete_ip_investigation",
        name: "Complete IP Investigation",
        description: "Exhaustive IP assessment: infrastructure, reputation, threat intel, history",
        apis_used: &["SeekNow", "Shodan", "AbuseIPDB", "GreyNoise", "SecurityTrails", "Censys"],
        steps: &[
            WorkflowStep { step_num: 1, operation: "breach_check", api: "SeekNow", depends_on_step: None, uses_entity_from: None },
            WorkflowStep { step_num: 2, operation: "infrastructure", api: "Shodan", depends_on_step: Some(1), uses_entity_from: Some("ip") },
            WorkflowStep { step_num: 3, operation: "reputation", api: "AbuseIPDB", depends_on_step: Some(1), uses_entity_from: Some("ip") },
            WorkflowStep { step_num: 4, operation: "threat_intel", api: "GreyNoise", depends_on_step: Some(3), uses_entity_from: Some("ip") },
            WorkflowStep { step_num: 5, operation: "reverse_dns", api: "SecurityTrails", depends_on_step: Some(1), uses_entity_from: Some("ip") },
            WorkflowStep { step_num: 6, operation: "certificates", api: "Censys", depends_on_step: Some(5), uses_entity_from: Some("domain") },
        ],
        estimated_cost: 600,
        estimated_time_secs: 120,
        best_for: "Investigating suspicious server IPs, detecting C2 infrastructure",
    },

    // Workflow 2: Domain Infrastructure Mapping
    AdvancedWorkflow {
        id: "domain_infrastructure_mapping",
        name: "Domain Infrastructure Mapping",
        description: "Complete domain footprint: infrastructure, DNS, certificates, employees, threats",
        apis_used: &["SeekNow", "Shodan", "SecurityTrails", "Censys", "Hunter.io", "Leakix"],
        steps: &[
            WorkflowStep { step_num: 1, operation: "breach_search", api: "SeekNow", depends_on_step: None, uses_entity_from: None },
            WorkflowStep { step_num: 2, operation: "dns_history", api: "SecurityTrails", depends_on_step: Some(1), uses_entity_from: Some("domain") },
            WorkflowStep { step_num: 3, operation: "ip_enumeration", api: "Shodan", depends_on_step: Some(2), uses_entity_from: Some("ip") },
            WorkflowStep { step_num: 4, operation: "certificate_search", api: "Censys", depends_on_step: Some(1), uses_entity_from: Some("domain") },
            WorkflowStep { step_num: 5, operation: "email_enumeration", api: "Hunter.io", depends_on_step: Some(1), uses_entity_from: Some("domain") },
            WorkflowStep { step_num: 6, operation: "exposed_data", api: "Leakix", depends_on_step: Some(1), uses_entity_from: Some("domain") },
        ],
        estimated_cost: 800,
        estimated_time_secs: 180,
        best_for: "Comprehensive infrastructure assessment, supply chain risk, M&A due diligence",
    },

    // ===== PERSON & IDENTITY WORKFLOWS =====

    // Workflow 3: Complete Person Dossier
    AdvancedWorkflow {
        id: "complete_person_dossier",
        name: "Complete Person Dossier",
        description: "Exhaustive person profile: breaches, credentials, company, social, enrichment",
        apis_used: &["SeekNow", "Hunter.io", "HIBP", "FullContact", "OathNet Pro"],
        steps: &[
            WorkflowStep { step_num: 1, operation: "breach_search", api: "SeekNow", depends_on_step: None, uses_entity_from: None },
            WorkflowStep { step_num: 2, operation: "company_email_enum", api: "Hunter.io", depends_on_step: Some(1), uses_entity_from: Some("domain") },
            WorkflowStep { step_num: 3, operation: "password_breach_check", api: "HIBP", depends_on_step: Some(1), uses_entity_from: Some("email") },
            WorkflowStep { step_num: 4, operation: "person_enrichment", api: "FullContact", depends_on_step: Some(1), uses_entity_from: Some("email") },
            WorkflowStep { step_num: 5, operation: "deep_breach_search", api: "OathNet Pro", depends_on_step: Some(3), uses_entity_from: Some("password") },
        ],
        estimated_cost: 500,
        estimated_time_secs: 120,
        best_for: "Background checks, insider threat investigation, credential exposure assessment",
    },

    // Workflow 4: Email Investigation (Phishing/Compromise)
    AdvancedWorkflow {
        id: "email_compromise_investigation",
        name: "Email Compromise Investigation",
        description: "Phishing/compromise assessment: breaches, company, passwords, reputation",
        apis_used: &["SeekNow", "Hunter.io", "HIBP", "AbuseIPDB"],
        steps: &[
            WorkflowStep { step_num: 1, operation: "breach_search", api: "SeekNow", depends_on_step: None, uses_entity_from: None },
            WorkflowStep { step_num: 2, operation: "company_context", api: "Hunter.io", depends_on_step: Some(1), uses_entity_from: Some("email_domain") },
            WorkflowStep { step_num: 3, operation: "password_breach", api: "HIBP", depends_on_step: Some(1), uses_entity_from: Some("email") },
            WorkflowStep { step_num: 4, operation: "header_ip_reputation", api: "AbuseIPDB", depends_on_step: Some(1), uses_entity_from: Some("ip_from_header") },
        ],
        estimated_cost: 300,
        estimated_time_secs: 60,
        best_for: "Incident response, email breach investigation, credential exposure response",
    },

    // ===== SECURITY ASSESSMENT WORKFLOWS =====

    // Workflow 5: API Key Discovery & Validation
    AdvancedWorkflow {
        id: "api_key_discovery",
        name: "API Key Discovery & Validation",
        description: "Find leaked API keys in breaches and validate them (force-multiplier cascade)",
        apis_used: &["SeekNow", "OathNet Pro", "Leakix"],
        steps: &[
            WorkflowStep { step_num: 1, operation: "breach_key_search", api: "SeekNow", depends_on_step: None, uses_entity_from: None },
            WorkflowStep { step_num: 2, operation: "stealer_log_search", api: "SeekNow", depends_on_step: Some(1), uses_entity_from: Some("domain") },
            WorkflowStep { step_num: 3, operation: "deep_breach_search", api: "OathNet Pro", depends_on_step: Some(1), uses_entity_from: Some("api_key_patterns") },
            WorkflowStep { step_num: 4, operation: "exposed_config_search", api: "Leakix", depends_on_step: Some(1), uses_entity_from: Some("domain") },
        ],
        estimated_cost: 1200,
        estimated_time_secs: 300,
        best_for: "Security audit, credential exposure assessment, attack surface mapping",
    },

    // Workflow 6: Supply Chain Risk Assessment
    AdvancedWorkflow {
        id: "supply_chain_risk",
        name: "Supply Chain Risk Assessment",
        description: "Assess vendor/supplier security: breaches, infrastructure, threat intel",
        apis_used: &["SeekNow", "Shodan", "SecurityTrails", "Censys", "AbuseIPDB", "GreyNoise"],
        steps: &[
            WorkflowStep { step_num: 1, operation: "vendor_breach_search", api: "SeekNow", depends_on_step: None, uses_entity_from: None },
            WorkflowStep { step_num: 2, operation: "infrastructure_audit", api: "Shodan", depends_on_step: Some(1), uses_entity_from: Some("domain") },
            WorkflowStep { step_num: 3, operation: "dns_security", api: "SecurityTrails", depends_on_step: Some(1), uses_entity_from: Some("domain") },
            WorkflowStep { step_num: 4, operation: "certificate_audit", api: "Censys", depends_on_step: Some(1), uses_entity_from: Some("domain") },
            WorkflowStep { step_num: 5, operation: "ip_reputation_check", api: "AbuseIPDB", depends_on_step: Some(2), uses_entity_from: Some("ip") },
            WorkflowStep { step_num: 6, operation: "threat_intel_check", api: "GreyNoise", depends_on_step: Some(5), uses_entity_from: Some("ip") },
        ],
        estimated_cost: 1500,
        estimated_time_secs: 300,
        best_for: "Vendor risk assessment, M&A due diligence, third-party security review",
    },

    // ===== FRAUD & CREDENTIAL WORKFLOWS =====

    // Workflow 7: Credential Stuffing Prevention
    AdvancedWorkflow {
        id: "credential_stuffing_detection",
        name: "Credential Stuffing Detection",
        description: "Detect leaked credentials that might be used in stuffing attacks",
        apis_used: &["SeekNow", "HIBP", "OathNet Pro"],
        steps: &[
            WorkflowStep { step_num: 1, operation: "company_breach_search", api: "SeekNow", depends_on_step: None, uses_entity_from: None },
            WorkflowStep { step_num: 2, operation: "password_breach_check", api: "HIBP", depends_on_step: Some(1), uses_entity_from: Some("email") },
            WorkflowStep { step_num: 3, operation: "credential_history", api: "OathNet Pro", depends_on_step: Some(2), uses_entity_from: Some("email_password_combo") },
        ],
        estimated_cost: 400,
        estimated_time_secs: 90,
        best_for: "Fraud prevention, account security monitoring, credential leak notification",
    },

    // ===== THREAT ACTOR WORKFLOWS =====

    // Workflow 8: Threat Actor Complete Profile
    AdvancedWorkflow {
        id: "threat_actor_complete",
        name: "Threat Actor Complete Profile",
        description: "Build complete dossier on threat actor: usernames, emails, infrastructure",
        apis_used: &["SeekNow", "Hunter.io", "HIBP", "FullContact", "Shodan", "AbuseIPDB"],
        steps: &[
            WorkflowStep { step_num: 1, operation: "username_breach_search", api: "SeekNow", depends_on_step: None, uses_entity_from: None },
            WorkflowStep { step_num: 2, operation: "email_enumeration", api: "Hunter.io", depends_on_step: Some(1), uses_entity_from: Some("email_from_breach") },
            WorkflowStep { step_num: 3, operation: "password_leak_check", api: "HIBP", depends_on_step: Some(2), uses_entity_from: Some("email") },
            WorkflowStep { step_num: 4, operation: "person_enrichment", api: "FullContact", depends_on_step: Some(2), uses_entity_from: Some("email") },
            WorkflowStep { step_num: 5, operation: "infrastructure_scan", api: "Shodan", depends_on_step: Some(1), uses_entity_from: Some("domain_from_breach") },
            WorkflowStep { step_num: 6, operation: "ip_reputation", api: "AbuseIPDB", depends_on_step: Some(5), uses_entity_from: Some("ip") },
        ],
        estimated_cost: 1000,
        estimated_time_secs: 240,
        best_for: "Threat actor profiling, APT investigation, OPSEC failure discovery",
    },

    // ===== MONITORING & DETECTION WORKFLOWS =====

    // Workflow 9: Real-Time Breach Monitoring
    AdvancedWorkflow {
        id: "breach_monitoring",
        name: "Real-Time Breach Monitoring",
        description: "Continuous monitoring: check if organization entities in new breaches",
        apis_used: &["SeekNow", "OathNet Pro", "Leakix"],
        steps: &[
            WorkflowStep { step_num: 1, operation: "daily_domain_scan", api: "SeekNow", depends_on_step: None, uses_entity_from: None },
            WorkflowStep { step_num: 2, operation: "daily_email_scan", api: "OathNet Pro", depends_on_step: Some(1), uses_entity_from: Some("employee_emails") },
            WorkflowStep { step_num: 3, operation: "exposed_data_check", api: "Leakix", depends_on_step: Some(1), uses_entity_from: Some("domain") },
        ],
        estimated_cost: 300,
        estimated_time_secs: 60,
        best_for: "Security monitoring, breach notification, incident detection",
    },

    // ===== OSINT MAXIMUM DEPTH =====

    // Workflow 10: Maximum Coverage OSINT
    AdvancedWorkflow {
        id: "osint_maximum_coverage",
        name: "Maximum Coverage OSINT",
        description: "Exhaustive investigation: all 10 APIs, complete entity correlation",
        apis_used: &["SeekNow", "Shodan", "SecurityTrails", "Censys", "Hunter.io", "AbuseIPDB", "GreyNoise", "HIBP", "FullContact", "Leakix"],
        steps: &[
            WorkflowStep { step_num: 1, operation: "universal_breach_search", api: "SeekNow", depends_on_step: None, uses_entity_from: None },
            WorkflowStep { step_num: 2, operation: "infrastructure_intelligence", api: "Shodan", depends_on_step: Some(1), uses_entity_from: Some("domain_ip") },
            WorkflowStep { step_num: 3, operation: "dns_and_history", api: "SecurityTrails", depends_on_step: Some(1), uses_entity_from: Some("domain") },
            WorkflowStep { step_num: 4, operation: "certificate_intelligence", api: "Censys", depends_on_step: Some(1), uses_entity_from: Some("domain") },
            WorkflowStep { step_num: 5, operation: "employee_enumeration", api: "Hunter.io", depends_on_step: Some(1), uses_entity_from: Some("domain_email") },
            WorkflowStep { step_num: 6, operation: "ip_reputation", api: "AbuseIPDB", depends_on_step: Some(2), uses_entity_from: Some("ip") },
            WorkflowStep { step_num: 7, operation: "threat_intelligence", api: "GreyNoise", depends_on_step: Some(6), uses_entity_from: Some("ip") },
            WorkflowStep { step_num: 8, operation: "password_breach", api: "HIBP", depends_on_step: Some(1), uses_entity_from: Some("email") },
            WorkflowStep { step_num: 9, operation: "person_enrichment", api: "FullContact", depends_on_step: Some(5), uses_entity_from: Some("email") },
            WorkflowStep { step_num: 10, operation: "exposed_data", api: "Leakix", depends_on_step: Some(1), uses_entity_from: Some("domain_config") },
        ],
        estimated_cost: 2500,
        estimated_time_secs: 600,
        best_for: "Comprehensive target intelligence, complete due diligence, maximum entity discovery",
    },
];

/// Quick-start workflow recommendations based on target type.
pub struct WorkflowRecommendation {
    pub target_type: &'static str,
    pub recommended_workflows: &'static [&'static str],
    pub primary_workflow: &'static str,
}

pub const WORKFLOW_RECOMMENDATIONS: &[WorkflowRecommendation] = &[
    WorkflowRecommendation {
        target_type: "email",
        recommended_workflows: &[
            "email_compromise_investigation",
            "complete_person_dossier",
            "credential_stuffing_detection",
        ],
        primary_workflow: "email_compromise_investigation",
    },
    WorkflowRecommendation {
        target_type: "domain",
        recommended_workflows: &[
            "domain_infrastructure_mapping",
            "supply_chain_risk",
            "breach_monitoring",
        ],
        primary_workflow: "domain_infrastructure_mapping",
    },
    WorkflowRecommendation {
        target_type: "ip",
        recommended_workflows: &[
            "complete_ip_investigation",
            "threat_actor_complete",
        ],
        primary_workflow: "complete_ip_investigation",
    },
    WorkflowRecommendation {
        target_type: "username",
        recommended_workflows: &[
            "threat_actor_complete",
            "complete_person_dossier",
        ],
        primary_workflow: "threat_actor_complete",
    },
];

/// Workflow execution context (tracks state during execution).
pub struct WorkflowExecutionContext {
    pub workflow_id: String,
    pub target: String,
    pub current_step: u32,
    pub completed_steps: Vec<u32>,
    pub discovered_entities: Vec<(String, String, String)>, // (entity, type, source_api)
    pub total_cost: u32,
    pub total_time_secs: u32,
    pub status: WorkflowStatus,
}

pub enum WorkflowStatus {
    Pending,
    Running,
    Paused,
    Completed,
    Failed,
}

impl WorkflowExecutionContext {
    pub fn new(workflow_id: String, target: String) -> Self {
        WorkflowExecutionContext {
            workflow_id,
            target,
            current_step: 1,
            completed_steps: Vec::new(),
            discovered_entities: Vec::new(),
            total_cost: 0,
            total_time_secs: 0,
            status: WorkflowStatus::Pending,
        }
    }

    /// Mark step as complete and advance
    pub fn complete_step(&mut self, cost: u32, time_secs: u32) {
        self.completed_steps.push(self.current_step);
        self.total_cost += cost;
        self.total_time_secs += time_secs;
        self.current_step += 1;
    }

    /// Add discovered entity
    pub fn discover_entity(&mut self, entity: String, entity_type: String, source_api: String) {
        self.discovered_entities.push((entity, entity_type, source_api));
    }
}
