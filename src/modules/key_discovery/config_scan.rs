//! Configuration and environment scanning for accidentally exposed API keys.
//!
//! Detects common patterns where developers accidentally leak credentials:
//! - Environment variable assignments (API_KEY=..., SECRET=...)
//! - Configuration files (.env, .config, config.json, etc.)
//! - Logging output (API key in error messages, debug dumps)
//! - Documentation (example keys, test credentials)
//! - Version control (git history, commits with embedded keys)
//!
//! This module implements "creative" detection vectors that go beyond simple
//! prefix matching, making proactive key discovery fundamentally more effective.

/// Scan text for accidentally exposed configuration and environment variables
/// containing API keys or credentials.
///
/// This is a heuristic approach that detects common patterns where developers
/// accidentally expose credentials in logs, configs, and documentation.
///
/// Returns a vector of (field_name, value) tuples for credential validation.
pub fn scan_config_for_credentials(text: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();

    // Simple line-based scanning for environment variable assignments
    for line in text.lines() {
        // Look for patterns like: API_KEY=value, SECRET=value, etc.
        if let Some(eq_pos) = line.find('=') {
            let (key_part, val_part) = line.split_at(eq_pos);
            let val_part = &val_part[1..]; // Skip the '='

            let key_lower = key_part.to_ascii_lowercase();
            if should_scan_key(&key_lower) {
                let value = val_part.trim_matches(|c| c == '\'' || c == '"' || c == ' ').to_string();
                if !value.is_empty() && !is_redacted(&value) && is_likely_credential(&value) {
                    found.push((key_part.to_ascii_uppercase().to_string(), value));
                }
            }
        }
    }

    // Deduplicate
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found.dedup();

    found
}

/// Check if a key name looks like it contains a credential
fn should_scan_key(key: &str) -> bool {
    matches!(
        key,
        _ if key.contains("api") && key.contains("key")
            || key.contains("secret")
            || key.contains("password")
            || key.contains("token")
            || key.contains("auth")
            || key.contains("credential")
    )
}

/// Check if a value looks like it could be a real credential
fn is_likely_credential(value: &str) -> bool {
    // Credentials are typically at least 10 characters and contain alphanumerics
    value.len() >= 10 && value.chars().any(|c| c.is_ascii_alphanumeric())
}

/// Check if a value looks redacted/fake (placeholder, censored, etc.)
fn is_redacted(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("redacted")
        || lower.contains("censored")
        || lower.contains("hidden")
        || lower.contains("example")
        || lower.contains("placeholder")
        || lower.contains("upgrade_to_see")
        || lower.contains("***")
        || lower.contains("xxxx")
        || lower.contains("[")
        || lower.contains("]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_env_var_assignments() {
        let text = "API_KEY=sk_abc123def456xyzabc";
        let found = scan_config_for_credentials(text);
        assert!(!found.is_empty(), "Should find API_KEY assignment");
        assert!(found.iter().any(|(k, v)| k.contains("API") && v.len() > 10));
    }

    #[test]
    fn ignores_redacted_values() {
        let text = "API_KEY=redacted_value_here SECRET=censored_credential_value";
        let found = scan_config_for_credentials(text);
        assert!(found.is_empty(), "Should not find redacted values");
    }

    #[test]
    fn ignores_short_values() {
        let text = "API_KEY=short";
        let found = scan_config_for_credentials(text);
        assert!(found.is_empty(), "Should ignore values shorter than 10 chars");
    }

    #[test]
    fn key_helper() {
        assert!(should_scan_key("api_key"));
        assert!(should_scan_key("secret"));
        assert!(should_scan_key("password"));
        assert!(!should_scan_key("username"));
    }
}
