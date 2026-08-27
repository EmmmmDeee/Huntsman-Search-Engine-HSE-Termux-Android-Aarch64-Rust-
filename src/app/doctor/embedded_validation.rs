//! Embedded API credentials validation for the doctor diagnostic.
//!
//! Provides detailed analysis of embedded credentials:
//! - Load status and availability
//! - Format validation
//! - Coverage by API category
//! - Duplicate detection
//! - Recommendations for credential configuration

use std::collections::{HashMap, HashSet};

/// Represents the validation status of embedded credentials.
#[derive(Debug, Clone)]
pub struct EmbeddedValidation {
    /// Total embedded credentials available
    pub total_embedded: usize,
    /// Embedded credentials that are actually configured (not placeholder)
    pub configured_embedded: usize,
    /// Breakdown by category
    pub by_category: HashMap<String, CategoryStats>,
    /// Any validation issues found
    pub issues: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CategoryStats {
    pub name: String,
    pub total: usize,
    pub configured: usize,
}

/// Validate embedded credentials and produce a diagnostic report.
pub fn validate_embedded_credentials(
    loaded_keys: &HashMap<String, String>,
) -> EmbeddedValidation {
    let embedded = crate::util::keys::get_embedded_keys();
    let mut validation = EmbeddedValidation {
        total_embedded: embedded.len(),
        configured_embedded: 0,
        by_category: HashMap::new(),
        issues: Vec::new(),
    };

    // Categorize embedded credentials
    let categories = categorize_credentials(embedded.keys().copied().collect());

    for (key, category) in &categories {
        let is_configured = loaded_keys.contains_key(key);
        if is_configured {
            validation.configured_embedded += 1;
        }

        validation
            .by_category
            .entry(category.clone())
            .or_insert_with(|| CategoryStats {
                name: category.clone(),
                total: 0,
                configured: 0,
            });

        let stats = validation.by_category.get_mut(category).unwrap();
        stats.total += 1;
        if is_configured {
            stats.configured += 1;
        }
    }

    // Validate for common issues
    validate_issues(loaded_keys, &categories, &mut validation);

    validation
}

/// Format embedded credentials report for display.
pub fn format_embedded_report(validation: &EmbeddedValidation) -> String {
    let mut output = String::new();

    // Header with summary
    output.push_str(&format!(
        "Embedded credentials: {} total, {} configured\n",
        validation.total_embedded, validation.configured_embedded
    ));

    // Show categories
    if !validation.by_category.is_empty() {
        output.push_str("  Coverage by category:\n");
        let mut sorted: Vec<_> = validation.by_category.values().collect();
        sorted.sort_by_key(|s| std::cmp::Reverse(s.configured));
        for stats in sorted {
            let pct = stats
                .configured
                .checked_mul(100)
                .and_then(|v| v.checked_div(stats.total))
                .unwrap_or(0);
            output.push_str(&format!(
                "    - {:<30} {}/{} ({}%)\n",
                stats.name, stats.configured, stats.total, pct
            ));
        }
    }

    // Show any issues
    if !validation.issues.is_empty() {
        output.push_str("  Issues detected:\n");
        for issue in &validation.issues {
            output.push_str(&format!("    ⚠ {issue}\n"));
        }
    } else if validation.configured_embedded > 0 {
        output.push_str("  ✓ No validation issues detected\n");
    }

    output
}

/// Categorize credential keys by API provider type.
fn categorize_credentials(keys: Vec<&str>) -> HashMap<String, String> {
    let mut categories = HashMap::new();

    for key in keys {
        let category = match key {
            // Threat Intelligence & Malware
            k if k.contains("VIRUSTOTAL") => "Threat Intelligence",
            k if k.contains("GREYNOISE") => "Threat Intelligence",
            k if k.contains("URLSCAN") => "Threat Intelligence",
            k if k.contains("ABUSEIPDB") => "Threat Intelligence",
            k if k.contains("THREATFOX") => "Threat Intelligence",
            k if k.contains("ABUSECH") => "Threat Intelligence",

            // Breach & Intelligence
            k if k.contains("SEEKNOW") => "Breach Intelligence",
            k if k.contains("HIBP") => "Breach Intelligence",
            k if k.contains("INTELLIGENCE_X") => "Breach Intelligence",
            k if k.contains("OATHNET") => "Breach Intelligence",
            k if k.contains("STOLEN") => "Breach Intelligence",
            k if k.contains("DEHASHED") => "Breach Intelligence",

            // Infrastructure/IP/Domain
            k if k.contains("SHODAN") => "Infrastructure Intelligence",
            k if k.contains("SECURITYTRAILS") => "Infrastructure Intelligence",
            k if k.contains("LEAKIX") => "Infrastructure Intelligence",
            k if k.contains("CRIMINALIP") => "Infrastructure Intelligence",
            k if k.contains("IPQUALITYSCORE") => "Infrastructure Intelligence",
            k if k.contains("CENSYS") => "Infrastructure Intelligence",
            k if k.contains("FOFA") => "Infrastructure Intelligence",
            k if k.contains("NETLAS") => "Infrastructure Intelligence",
            k if k.contains("ONYPHE") => "Infrastructure Intelligence",
            k if k.contains("WHOISXML") => "Infrastructure Intelligence",
            k if k.contains("DOMAINSDB") => "Infrastructure Intelligence",
            k if k.contains("OSINTCAT") => "Infrastructure Intelligence",

            // Identity/Person
            k if k.contains("PROXYCURL") => "Identity Intelligence",
            k if k.contains("HUNTER") => "Identity Intelligence",
            k if k.contains("EMAILREP") => "Identity Intelligence",
            k if k.contains("GITHUB") && !k.contains("COMMITS") => "Identity Intelligence",
            k if k.contains("FULLCONTACT") => "Identity Intelligence",
            k if k.contains("SEON") => "Identity Intelligence",
            k if k.contains("TROVE") => "Identity Intelligence",

            // Telecommunications
            k if k.contains("NUMVERIFY") => "Telecommunications",
            k if k.contains("OPENCNAM") => "Telecommunications",
            k if k.contains("EPIEOS") => "Telecommunications",
            k if k.contains("NIAMONX") => "Telecommunications",
            k if k.contains("HLR") => "Telecommunications",

            // Geolocation
            k if k.contains("WIGLE") => "Geolocation",
            k if k.contains("OPENCELLID") => "Geolocation",

            // Business Intelligence
            k if k.contains("OPENCORPORATES") => "Business Intelligence",
            k if k.contains("OPENSANCTIONS") => "Business Intelligence",
            k if k.contains("BUILTWITH") => "Business Intelligence",

            // Search & AI
            k if k.contains("EXA") => "Search & AI",
            k if k.contains("ALIENVAULT") => "Search & AI",
            k if k.contains("ZOOMEYE") => "Search & AI",

            _ => "Other Services",
        };

        categories.insert(key.to_string(), category.to_string());
    }

    categories
}

/// Check for common validation issues.
fn validate_issues(
    loaded_keys: &HashMap<String, String>,
    categories: &HashMap<String, String>,
    validation: &mut EmbeddedValidation,
) {
    let embedded = crate::util::keys::get_embedded_keys();

    // Check for placeholder values (too short, contains "your-")
    for (key, value) in embedded {
        let is_placeholder = value.len() < 5 || value.contains("your-") || value.contains("xxx");
        if is_placeholder
            && let Some(category) = categories.get(&key.to_string())
        {
            validation.issues.push(format!(
                "{key} [{category}] appears to be a placeholder — configure with actual API key"
            ));
        }
    }

    // Check for keys in loaded map that don't exist in embedded (environment-only)
    let embedded_keys: HashSet<_> = embedded.keys().copied().collect();
    let configured_keys: HashSet<_> = loaded_keys.keys().map(String::as_str).collect();

    let env_only: Vec<_> = configured_keys
        .difference(&embedded_keys)
        .copied()
        .collect();

    if !env_only.is_empty() && validation.configured_embedded > 0 {
        validation.issues.push(format!(
            "{} credential(s) loaded from environment only (not in embedded set)",
            env_only.len()
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_categorization() {
        let keys = vec!["HUNTSMAN_SHODAN_KEY", "HUNTSMAN_HIBP_KEY"];
        let categories = categorize_credentials(keys);
        assert_eq!(
            categories.get("HUNTSMAN_SHODAN_KEY"),
            Some(&"Infrastructure Intelligence".to_string())
        );
        assert_eq!(
            categories.get("HUNTSMAN_HIBP_KEY"),
            Some(&"Breach Intelligence".to_string())
        );
    }

    #[test]
    fn test_categories_non_empty() {
        let keys = vec!["HUNTSMAN_SHODAN_KEY", "HUNTSMAN_VIRUSTOTAL_KEY", "HUNTSMAN_HIBP_KEY"];
        let categories = categorize_credentials(keys);
        assert!(!categories.is_empty());
        assert_eq!(categories.len(), 3);
    }
}
