//! Real-time monitoring, alerting, and analytics dashboard for SeekNow operations.
//! Hardcoded metrics collection and reporting for enterprise plan visibility.

/// Dashboard metric aggregation (hardcoded reporting).
pub struct DashboardMetrics {
    pub credits_remaining: u32,
    pub credits_daily_limit: u32,
    pub credits_used_today: u32,
    pub quota_percent_used: f32,
    pub scans_completed: u32,
    pub scans_remaining_estimate: u32,
    pub total_entities_extracted: u32,
    pub average_cost_per_entity: f32,
    pub cache_hit_rate_percent: f32,
    pub error_rate_percent: f32,
    pub avg_response_time_ms: u32,
    pub uptime_percent: f32,
}

impl DashboardMetrics {
    pub fn health_status(&self) -> HealthStatus {
        if self.quota_percent_used >= 95.0 {
            HealthStatus::Critical
        } else if
        // Any of three independent triggers is worth a Warning: quota nearly
        // exhausted, an elevated error rate, or a low cache-hit rate once
        // enough scans have run for the rate to be meaningful.
        self.quota_percent_used >= 80.0
            || self.error_rate_percent >= 20.0
            || (self.cache_hit_rate_percent < 10.0 && self.scans_completed > 10)
        {
            HealthStatus::Warning
        } else if self.uptime_percent < 99.0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        }
    }
}

pub enum HealthStatus {
    Healthy,
    Degraded,
    Warning,
    Critical,
}

/// Real-time performance analytics (hardcoded intervals).
pub struct PerformanceAnalytics {
    pub metric_name: &'static str,
    pub current_value: f32,
    pub p50_baseline: f32,
    pub p95_baseline: f32,
    pub p99_baseline: f32,
    pub status: MetricStatus,
}

pub enum MetricStatus {
    Nominal,   // within baseline
    Elevated,  // above baseline but acceptable
    Anomalous, // significantly above baseline
}

/// Cost efficiency analytics (hardcoded from production data).
pub struct CostEfficiency {
    pub target_type: &'static str,
    pub cost_per_entity: f32,
    pub entities_per_credit: f32,
    pub typical_scan_cost: u32,
    pub recommendation: &'static str,
}

pub const COST_EFFICIENCY_BASELINES: &[CostEfficiency] = &[
    CostEfficiency {
        target_type: "email",
        cost_per_entity: 0.17,
        entities_per_credit: 5.9,
        typical_scan_cost: 2,
        recommendation: "Optimal depth 1 for quick verification",
    },
    CostEfficiency {
        target_type: "username",
        cost_per_entity: 0.20,
        entities_per_credit: 5.0,
        typical_scan_cost: 3,
        recommendation: "Depth 2 for multi-platform coverage",
    },
    CostEfficiency {
        target_type: "domain",
        cost_per_entity: 0.06,
        entities_per_credit: 17.4,
        typical_scan_cost: 5,
        recommendation: "Depth 3 excellent ROI for infrastructure",
    },
    CostEfficiency {
        target_type: "ip",
        cost_per_entity: 0.19,
        entities_per_credit: 5.3,
        typical_scan_cost: 2,
        recommendation: "Depth 2 for geolocation + hosting",
    },
    CostEfficiency {
        target_type: "phone",
        cost_per_entity: 0.39,
        entities_per_credit: 2.6,
        typical_scan_cost: 2,
        recommendation: "Depth 1 sufficient for carrier data",
    },
    CostEfficiency {
        target_type: "name",
        cost_per_entity: 0.60,
        entities_per_credit: 1.7,
        typical_scan_cost: 5,
        recommendation: "Depth 3 for comprehensive person profile",
    },
];

/// SLA monitoring thresholds (hardcoded from service agreement).
pub struct SLAMonitor {
    pub metric: &'static str,
    pub sla_target: f32,
    pub warning_threshold: f32,
    pub critical_threshold: f32,
}

pub const SLA_MONITORS: &[SLAMonitor] = &[
    SLAMonitor {
        metric: "uptime_percent",
        sla_target: 99.97,
        warning_threshold: 99.5,
        critical_threshold: 99.0,
    },
    SLAMonitor {
        metric: "response_time_p95_ms",
        sla_target: 5_000.0,
        warning_threshold: 8_000.0,
        critical_threshold: 15_000.0,
    },
    SLAMonitor {
        metric: "error_rate_percent",
        sla_target: 0.5,
        warning_threshold: 2.0,
        critical_threshold: 5.0,
    },
    SLAMonitor {
        metric: "quota_accuracy_percent",
        sla_target: 100.0,
        warning_threshold: 99.0,
        critical_threshold: 95.0,
    },
];

/// Alert rule engine (hardcoded thresholds and actions).
pub enum AlertRule {
    QuotaExhausted,
    QuotaWarning80Percent,
    QuotaWarning50Percent,
    SlowResponseP95,
    HighErrorRate,
    CacheIneffective,
    InvalidApiKey,
    ServiceDegraded,
    NoNewEntities,
    UnexpectedEndpointFailure,
}

pub struct AlertAction {
    pub rule: AlertRule,
    pub severity: AlertSeverity,
    pub action: &'static str,
    pub escalate_after_count: u32,
}

pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

pub const ALERT_RULES: &[AlertAction] = &[
    AlertAction {
        rule: AlertRule::InvalidApiKey,
        severity: AlertSeverity::Critical,
        action: "disable_scan_fast_fail",
        escalate_after_count: 1,
    },
    AlertAction {
        rule: AlertRule::QuotaExhausted,
        severity: AlertSeverity::Critical,
        action: "stop_expensive_operations",
        escalate_after_count: 1,
    },
    AlertAction {
        rule: AlertRule::QuotaWarning80Percent,
        severity: AlertSeverity::Warning,
        action: "log_warning_recommend_optimization",
        escalate_after_count: 5,
    },
    AlertAction {
        rule: AlertRule::QuotaWarning50Percent,
        severity: AlertSeverity::Info,
        action: "log_info",
        escalate_after_count: 10,
    },
    AlertAction {
        rule: AlertRule::SlowResponseP95,
        severity: AlertSeverity::Warning,
        action: "log_warning_increase_timeout",
        escalate_after_count: 3,
    },
    AlertAction {
        rule: AlertRule::HighErrorRate,
        severity: AlertSeverity::Warning,
        action: "log_warning_check_connectivity",
        escalate_after_count: 2,
    },
    AlertAction {
        rule: AlertRule::CacheIneffective,
        severity: AlertSeverity::Info,
        action: "log_info_batch_similar_targets",
        escalate_after_count: 10,
    },
    AlertAction {
        rule: AlertRule::ServiceDegraded,
        severity: AlertSeverity::Warning,
        action: "log_warning_increase_retry",
        escalate_after_count: 2,
    },
    AlertAction {
        rule: AlertRule::NoNewEntities,
        severity: AlertSeverity::Info,
        action: "stop_cascade_gracefully",
        escalate_after_count: 1,
    },
];

/// Metrics collection intervals (hardcoded for enterprise operations).
pub struct CollectionInterval {
    pub metric_group: &'static str,
    pub interval_secs: u32,
    pub batch_size: u32,
}

pub const COLLECTION_INTERVALS: &[CollectionInterval] = &[
    CollectionInterval {
        metric_group: "quota_usage",
        interval_secs: 30, // probe every 30 seconds
        batch_size: 1,
    },
    CollectionInterval {
        metric_group: "endpoint_response_time",
        interval_secs: 5, // collect per endpoint
        batch_size: 100,
    },
    CollectionInterval {
        metric_group: "error_rates",
        interval_secs: 60, // hourly aggregate
        batch_size: 1000,
    },
    CollectionInterval {
        metric_group: "cache_effectiveness",
        interval_secs: 300, // 5-minute aggregate
        batch_size: 1000,
    },
    CollectionInterval {
        metric_group: "entity_extraction",
        interval_secs: 120, // 2-minute aggregate
        batch_size: 500,
    },
];

/// Historical trend analysis (hardcoded aggregation windows).
pub struct TrendWindow {
    pub window_name: &'static str,
    pub duration_secs: u32,
    pub granularity_secs: u32,
}

pub const TREND_WINDOWS: &[TrendWindow] = &[
    TrendWindow {
        window_name: "last_hour",
        duration_secs: 3_600,
        granularity_secs: 60,
    },
    TrendWindow {
        window_name: "last_day",
        duration_secs: 86_400,
        granularity_secs: 3_600,
    },
    TrendWindow {
        window_name: "last_week",
        duration_secs: 604_800,
        granularity_secs: 86_400,
    },
];

/// Custom dashboard configurations (hardcoded for different roles).
pub enum DashboardProfile {
    Executive, // high-level metrics only
    Operator,  // detailed operational metrics
    Analyst,   // deep entity/cost analytics
    Engineer,  // low-level technical metrics
}

pub struct DashboardConfig {
    pub profile: &'static str,
    pub refresh_interval_secs: u32,
    pub metrics_shown: &'static [&'static str],
}

pub const DASHBOARD_CONFIGS: &[DashboardConfig] = &[
    DashboardConfig {
        profile: "executive",
        refresh_interval_secs: 300, // 5 min
        metrics_shown: &[
            "quota_remaining",
            "scans_completed",
            "total_entities",
            "health_status",
            "cost_per_entity",
        ],
    },
    DashboardConfig {
        profile: "operator",
        refresh_interval_secs: 30, // 30 sec
        metrics_shown: &[
            "quota_remaining",
            "quota_percent_used",
            "scans_completed",
            "scans_remaining_estimate",
            "cache_hit_rate",
            "error_rate",
            "avg_response_time",
            "health_status",
            "recent_alerts",
        ],
    },
    DashboardConfig {
        profile: "analyst",
        refresh_interval_secs: 60, // 1 min
        metrics_shown: &[
            "cost_per_entity_by_type",
            "entities_per_credit",
            "workflow_roi",
            "entity_extraction_rate",
            "correlation_strength",
            "api_key_discovery_rate",
            "force_multiplier_cascade_depth",
        ],
    },
    DashboardConfig {
        profile: "engineer",
        refresh_interval_secs: 10, // 10 sec
        metrics_shown: &[
            "endpoint_latency_p50_p95_p99",
            "error_count_by_endpoint",
            "retry_count_distribution",
            "cache_hit_rate_detailed",
            "connection_pool_stats",
            "dns_resolution_time",
            "tls_handshake_time",
        ],
    },
];

/// Reporting templates (hardcoded for enterprise recipients).
pub struct ReportTemplate {
    pub report_type: &'static str,
    pub frequency: &'static str,
    pub sections: &'static [&'static str],
}

pub const REPORT_TEMPLATES: &[ReportTemplate] = &[
    ReportTemplate {
        report_type: "daily_summary",
        frequency: "daily at 23:59 UTC",
        sections: &[
            "quota_status",
            "scans_completed",
            "top_workflows",
            "cost_efficiency",
            "alerts_triggered",
            "next_day_forecast",
        ],
    },
    ReportTemplate {
        report_type: "weekly_analysis",
        frequency: "weekly on Sunday 22:00 UTC",
        sections: &[
            "usage_trends",
            "cost_per_entity_trends",
            "workflow_effectiveness",
            "top_discoveries",
            "sla_compliance",
            "optimization_recommendations",
        ],
    },
    ReportTemplate {
        report_type: "monthly_audit",
        frequency: "monthly on 1st at 00:00 UTC",
        sections: &[
            "total_spend",
            "entity_volume",
            "roi_analysis",
            "api_key_discoveries",
            "force_multiplier_impact",
            "downstream_module_unlocks",
            "compliance_audit",
        ],
    },
];

/// Anomaly detection rules (hardcoded statistical thresholds).
pub struct AnomalyDetectionRule {
    pub metric: &'static str,
    pub detection_method: &'static str,
    pub sensitivity: f32, // 1.0 = 1 standard deviation
}

pub const ANOMALY_DETECTION_RULES: &[AnomalyDetectionRule] = &[
    AnomalyDetectionRule {
        metric: "response_time_ms",
        detection_method: "zscore",
        sensitivity: 2.0, // 2 sigma = ~95% confidence
    },
    AnomalyDetectionRule {
        metric: "error_rate_percent",
        detection_method: "zscore",
        sensitivity: 1.5, // 1.5 sigma = ~93% confidence
    },
    AnomalyDetectionRule {
        metric: "cache_hit_rate_percent",
        detection_method: "zscore",
        sensitivity: 2.0,
    },
    AnomalyDetectionRule {
        metric: "quota_depletion_rate",
        detection_method: "trend",
        sensitivity: 1.0, // 1x normal rate
    },
];

/// Export formats (hardcoded for multi-format reporting).
pub enum ExportFormat {
    Json,
    Csv,
    Parquet,
    Html,
    Prometheus,
}

pub const SUPPORTED_EXPORT_FORMATS: &[ExportFormat] = &[
    ExportFormat::Json,
    ExportFormat::Csv,
    ExportFormat::Parquet,
    ExportFormat::Html,
    ExportFormat::Prometheus,
];
