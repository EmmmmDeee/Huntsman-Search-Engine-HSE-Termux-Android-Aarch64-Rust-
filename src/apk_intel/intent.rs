//! Android Intent Filter Analysis: Extract and assess implicit intent attack surface from manifest declarations.
//!
//! Intent filters define how Android components respond to implicit intents from other apps.
//! This module parses intent-filter declarations from the binary manifest and assesses the
//! implicit intent attack surface: component reachability, data filter exposure, and risk.

use serde::Serialize;

use super::axml::{IntentFilterDef, Manifest};

const MAX_LISTED: usize = 256;

/// Sensitive broadcast receiver actions that indicate high-risk implicit intent handling.
const SENSITIVE_BROADCAST_ACTIONS: &[&str] = &[
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.DEVICE_ADMIN_ENABLED",
    "android.intent.action.DEVICE_ADMIN_DISABLED",
    "android.intent.action.PACKAGE_ADDED",
    "android.intent.action.PACKAGE_REMOVED",
    "android.intent.action.PACKAGE_REPLACED",
    "android.intent.action.PACKAGE_CHANGED",
    "android.intent.action.PACKAGE_INSTALL",
    "android.intent.action.PACKAGE_RESTARTED",
    "android.intent.action.MY_PACKAGE_REPLACED",
    "android.intent.action.BATTERY_LOW",
    "android.intent.action.BATTERY_OKAY",
    "android.intent.action.POWER_CONNECTED",
    "android.intent.action.POWER_DISCONNECTED",
    "android.intent.action.ACTION_POWER_DISCONNECTED",
    "android.intent.action.SMS_RECEIVED",
    "android.intent.action.NEW_OUTGOING_CALL",
    "android.intent.action.PHONE_STATE",
    "android.provider.Telephony.SMS_RECEIVED",
    "android.provider.Telephony.MMS_RECEIVED",
    "android.intent.action.LOCALE_CHANGED",
    "android.intent.action.TIME_SET",
    "android.intent.action.TIMEZONE_CHANGED",
];

/// A single intent-filter declaration from the manifest, with its action/category/data constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntentFilter {
    /// The component this filter applies to (e.g., "com.example.MainActivity").
    pub component: String,
    /// Component kind: `activity`, `service`, `broadcast_receiver`, or `provider`.
    pub component_kind: String,
    /// Intent actions this component handles (e.g., "android.intent.action.VIEW").
    pub actions: Vec<String>,
    /// Intent categories this component handles (e.g., "android.intent.category.LAUNCHER").
    pub categories: Vec<String>,
    /// Whether this filter specifies data constraints (scheme, host, path).
    pub has_data_filter: bool,
    /// Data schemes this filter accepts (e.g., "http", "https", "custom").
    pub schemes: Vec<String>,
    /// Data hosts this filter accepts (e.g., "example.com", "*.example.com").
    pub hosts: Vec<String>,
    /// Declaration-based risk heuristic; not proof of external reachability.
    pub risk_level: String,
}

/// Comprehensive implicit intent risk assessment for an APK.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct IntentAnalysis {
    /// All intent filters found in the manifest.
    pub intent_filters: Vec<IntentFilter>,
    /// Intent filters omitted when list exceeds capacity.
    pub intent_filters_omitted: usize,
    /// Components declaring action-bearing filters; not proof of exported reachability.
    pub implicit_intent_components: Vec<String>,
    /// Implicit intent components omitted when list exceeds capacity.
    pub implicit_intent_omitted: usize,
    /// Legacy JSON field retained for compatibility. Empty-action filters are not
    /// implicit handlers; declarations remain visible in `intent_filters`.
    pub unguarded_action_filters: Vec<String>,
    /// Legacy JSON field retained for compatibility; always zero.
    pub unguarded_action_filters_omitted: usize,
    /// Sensitive actions (broadcast receiver intents) with implicit handlers.
    pub sensitive_intent_handlers: Vec<String>,
    /// Data-driven filters accepting multiple schemes (increased attack surface).
    pub multi_scheme_data_filters: Vec<String>,
    /// Sensitive receiver action declared; no proof of exported or unprotected access.
    pub implicit_broadcast_risk: bool,
    /// Heuristic declaration score, not a confirmed vulnerability finding.
    pub risk_score: u32,
}

/// Classify the risk level of an intent filter based on its characteristics.
fn classify_risk(component_kind: &str, filter: &IntentFilterDef) -> String {
    // In Android manifest resolution, a filter declaring no actions cannot match
    // implicit intents. Preserve the declaration without claiming exposure.
    if filter.actions.is_empty() {
        return "low".to_string();
    }

    if matches!(component_kind, "receiver" | "broadcast_receiver")
        && filter
            .actions
            .iter()
            .any(|a| SENSITIVE_BROADCAST_ACTIONS.contains(&a.as_str()))
    {
        return "high".to_string();
    }

    if !filter.schemes.is_empty() && filter.schemes.len() > 1 {
        return "high".to_string();
    }

    if !filter.actions.is_empty() && !filter.hosts.is_empty() {
        return "medium".to_string();
    }

    if !filter.actions.is_empty() {
        return "medium".to_string();
    }

    "low".to_string()
}

/// Compute intent analysis from a decoded manifest.
pub fn analyze(manifest: &Manifest) -> IntentAnalysis {
    let mut analysis = IntentAnalysis::default();
    let mut components_with_filters = std::collections::BTreeSet::new();
    let mut multi_scheme_count = 0;
    let mut sensitive_count = 0;
    let mut risk_score = 0u32;
    let mut has_broadcast_risk = false;

    // Convert manifest intent filters to IntentFilter structs and compute analysis.
    for def in &manifest.intent_filters {
        let has_data = !def.schemes.is_empty() || !def.hosts.is_empty();
        let risk_level = classify_risk(&def.component_kind, def);

        if analysis.intent_filters.len() < MAX_LISTED {
            analysis.intent_filters.push(IntentFilter {
                component: def.component.clone(),
                component_kind: def.component_kind.clone(),
                actions: def.actions.clone(),
                categories: def.categories.clone(),
                has_data_filter: has_data,
                schemes: def.schemes.clone(),
                hosts: def.hosts.clone(),
                risk_level: risk_level.clone(),
            });
        } else {
            analysis.intent_filters_omitted += 1;
        }

        // Preserve actionless declarations above, but exclude them from candidate
        // implicit handling and risk scoring; they fail the manifest action test.
        if def.actions.is_empty() {
            continue;
        }
        components_with_filters.insert(def.component.clone());

        // Multi-scheme data filters.
        if def.schemes.len() > 1 {
            if multi_scheme_count < MAX_LISTED {
                analysis.multi_scheme_data_filters.push(format!(
                    "{} ({} schemes)",
                    def.component,
                    def.schemes.len()
                ));
                multi_scheme_count += 1;
            }
            risk_score = risk_score.saturating_add(1);
        }

        // Sensitive broadcast receiver actions.
        if matches!(
            def.component_kind.as_str(),
            "receiver" | "broadcast_receiver"
        ) && def
            .actions
            .iter()
            .any(|a| SENSITIVE_BROADCAST_ACTIONS.contains(&a.as_str()))
        {
            if sensitive_count < MAX_LISTED {
                analysis.sensitive_intent_handlers.push(format!(
                    "{}: {}",
                    def.component,
                    def.actions.join(", ")
                ));
                sensitive_count += 1;
            }
            risk_score = risk_score.saturating_add(2);
            has_broadcast_risk = true;
        }

        // Risk scoring based on classification.
        match risk_level.as_str() {
            "critical" => risk_score = risk_score.saturating_add(3),
            "high" => risk_score = risk_score.saturating_add(2),
            "medium" => risk_score = risk_score.saturating_add(1),
            _ => {}
        }
    }

    analysis.implicit_broadcast_risk = has_broadcast_risk;
    analysis.risk_score = risk_score;

    // Candidate implicit handlers (filters declaring actions, not reachability proof).
    for component in components_with_filters {
        if analysis.implicit_intent_components.len() < MAX_LISTED {
            analysis.implicit_intent_components.push(component);
        } else {
            analysis.implicit_intent_omitted += 1;
        }
    }

    analysis
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_analysis_default_empty() {
        let analysis = IntentAnalysis::default();
        assert!(analysis.intent_filters.is_empty());
        assert_eq!(analysis.risk_score, 0);
        assert!(!analysis.implicit_broadcast_risk);
    }

    #[test]
    fn intent_filter_serializes() {
        let filter = IntentFilter {
            component: "com.example.MainActivity".to_string(),
            component_kind: "activity".to_string(),
            actions: vec!["android.intent.action.MAIN".to_string()],
            categories: vec!["android.intent.category.LAUNCHER".to_string()],
            has_data_filter: false,
            schemes: vec![],
            hosts: vec![],
            risk_level: "low".to_string(),
        };

        let json = serde_json::to_string(&filter);
        assert!(json.is_ok());
        assert!(json.unwrap().contains("com.example.MainActivity"));
    }

    #[test]
    fn intent_analysis_with_risk_score() {
        let analysis = IntentAnalysis {
            risk_score: 10,
            implicit_broadcast_risk: true,
            ..Default::default()
        };

        assert_eq!(analysis.risk_score, 10);
        assert!(analysis.implicit_broadcast_risk);
    }

    #[test]
    fn intent_filter_with_data_scheme() {
        let filter = IntentFilter {
            component: "com.example.DeepLinkActivity".to_string(),
            component_kind: "activity".to_string(),
            actions: vec!["android.intent.action.VIEW".to_string()],
            categories: vec!["android.intent.category.BROWSABLE".to_string()],
            has_data_filter: true,
            schemes: vec!["https".to_string()],
            hosts: vec!["example.com".to_string()],
            risk_level: "medium".to_string(),
        };

        assert!(filter.has_data_filter);
        assert!(!filter.schemes.is_empty());
        assert_eq!(filter.risk_level, "medium");
    }

    #[test]
    fn intent_filter_risk_classification() {
        let critical = IntentFilter {
            component: "com.example.Service".to_string(),
            component_kind: "service".to_string(),
            actions: vec!["com.example.SYNC".to_string()],
            categories: vec![],
            has_data_filter: false,
            schemes: vec![],
            hosts: vec![],
            risk_level: "critical".to_string(),
        };

        let low = IntentFilter {
            component: "com.example.Main".to_string(),
            component_kind: "activity".to_string(),
            actions: vec!["android.intent.action.MAIN".to_string()],
            categories: vec!["android.intent.category.LAUNCHER".to_string()],
            has_data_filter: false,
            schemes: vec![],
            hosts: vec![],
            risk_level: "low".to_string(),
        };

        assert_eq!(critical.risk_level, "critical");
        assert_eq!(low.risk_level, "low");
    }

    #[test]
    fn intent_filter_multiple_schemes_increase_surface() {
        let filter = IntentFilter {
            component: "com.example.Activity".to_string(),
            component_kind: "activity".to_string(),
            actions: vec!["android.intent.action.VIEW".to_string()],
            categories: vec!["android.intent.category.BROWSABLE".to_string()],
            has_data_filter: true,
            schemes: vec![
                "http".to_string(),
                "https".to_string(),
                "custom".to_string(),
            ],
            hosts: vec!["example.com".to_string()],
            risk_level: "high".to_string(),
        };

        assert!(filter.schemes.len() > 1);
    }

    #[test]
    fn parsed_manifest_receiver_kind_triggers_sensitive_broadcast_analysis() {
        let manifest = Manifest {
            intent_filters: vec![IntentFilterDef {
                component: ".Boot".to_string(),
                component_kind: "receiver".to_string(),
                actions: vec!["android.intent.action.BOOT_COMPLETED".to_string()],
                categories: vec![],
                schemes: vec![],
                hosts: vec![],
            }],
            ..Default::default()
        };

        let analysis = analyze(&manifest);
        assert!(analysis.implicit_broadcast_risk);
        assert_eq!(analysis.sensitive_intent_handlers.len(), 1);
        assert_eq!(analysis.intent_filters[0].risk_level, "high");
    }

    #[test]
    fn intent_filter_broadcast_receiver() {
        let filter = IntentFilter {
            component: "com.example.BootReceiver".to_string(),
            component_kind: "broadcast_receiver".to_string(),
            actions: vec!["android.intent.action.BOOT_COMPLETED".to_string()],
            categories: vec![],
            has_data_filter: false,
            schemes: vec![],
            hosts: vec![],
            risk_level: "high".to_string(),
        };

        assert_eq!(filter.component_kind, "broadcast_receiver");
        assert_eq!(filter.risk_level, "high");
    }

    #[test]
    fn intent_analysis_tracks_omitted_count() {
        let analysis = IntentAnalysis {
            intent_filters_omitted: 5,
            implicit_intent_omitted: 3,
            ..Default::default()
        };

        assert_eq!(analysis.intent_filters_omitted, 5);
        assert_eq!(analysis.implicit_intent_omitted, 3);
    }

    #[test]
    fn actionless_receivers_and_services_are_declarations_not_implicit_handlers() {
        let manifest = Manifest {
            intent_filters: vec![
                IntentFilterDef {
                    component: ".EmptyReceiver".to_string(),
                    component_kind: "receiver".to_string(),
                    actions: vec![],
                    categories: vec![],
                    schemes: vec![],
                    hosts: vec![],
                },
                IntentFilterDef {
                    component: ".EmptyService".to_string(),
                    component_kind: "service".to_string(),
                    actions: vec![],
                    categories: vec![],
                    schemes: vec![],
                    hosts: vec![],
                },
            ],
            ..Default::default()
        };

        let analysis = analyze(&manifest);
        assert_eq!(analysis.intent_filters.len(), 2);
        assert!(analysis
            .intent_filters
            .iter()
            .all(|filter| filter.risk_level == "low"));
        assert!(analysis.implicit_intent_components.is_empty());
        assert!(analysis.unguarded_action_filters.is_empty());
        assert_eq!(analysis.unguarded_action_filters_omitted, 0);
        assert!(analysis.sensitive_intent_handlers.is_empty());
        assert!(!analysis.implicit_broadcast_risk);
        assert_eq!(analysis.risk_score, 0);
    }

    #[test]
    fn sensitive_broadcast_actions_require_exact_names() {
        let manifest = Manifest {
            intent_filters: vec![IntentFilterDef {
                component: ".NotBootReceiver".to_string(),
                component_kind: "receiver".to_string(),
                actions: vec!["android.intent.action.BOOT_COMPLETED_FAKE".to_string()],
                categories: vec![],
                schemes: vec![],
                hosts: vec![],
            }],
            ..Default::default()
        };

        let analysis = analyze(&manifest);
        assert_eq!(analysis.intent_filters[0].risk_level, "medium");
        assert!(analysis.sensitive_intent_handlers.is_empty());
        assert!(!analysis.implicit_broadcast_risk);
        assert_eq!(analysis.risk_score, 1);
        assert_eq!(analysis.implicit_intent_components.len(), 1);
        assert_eq!(analysis.implicit_intent_components[0], ".NotBootReceiver");
    }

    #[test]
    fn actionless_filter_preserves_distinct_action_bearing_filter() {
        let manifest = Manifest {
            intent_filters: vec![
                IntentFilterDef {
                    component: ".Screen".to_string(),
                    component_kind: "activity".to_string(),
                    actions: vec![],
                    categories: vec![],
                    schemes: vec![],
                    hosts: vec![],
                },
                IntentFilterDef {
                    component: ".Screen".to_string(),
                    component_kind: "activity".to_string(),
                    actions: vec!["android.intent.action.VIEW".to_string()],
                    categories: vec!["android.intent.category.DEFAULT".to_string()],
                    schemes: vec!["https".to_string()],
                    hosts: vec!["example.org".to_string()],
                },
            ],
            ..Default::default()
        };

        let analysis = analyze(&manifest);
        assert_eq!(analysis.intent_filters.len(), 2);
        assert_eq!(analysis.intent_filters[0].risk_level, "low");
        assert_eq!(analysis.intent_filters[1].risk_level, "medium");
        assert_eq!(analysis.implicit_intent_components.len(), 1);
        assert_eq!(analysis.implicit_intent_components[0], ".Screen");
        assert_eq!(analysis.risk_score, 1);
        assert!(analysis.unguarded_action_filters.is_empty());
    }

}
