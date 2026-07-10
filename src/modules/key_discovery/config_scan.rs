//! Configuration and environment scanning for accidentally exposed API keys.
//!
//! Detects common patterns where developers accidentally leak credentials:
//! - Environment variable assignments (API_KEY=..., SECRET=...)
//! - Configuration files (.env, .config, config.json, etc.)
//! - Connection strings (mongodb://, postgresql://, mysql://, etc.)
//! - Authorization headers (Bearer, Basic, AWS, etc.)
//! - Database credentials (user:pass@ patterns)
//! - Private key markers (-----BEGIN RSA PRIVATE KEY-----)
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

    // Scan for environment variable assignments and key=value patterns
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

        // Detect connection strings (mongodb://, postgresql://, mysql://, etc.)
        if let Some(cred) = extract_connection_string(line) {
            found.push(cred);
        }

        // Detect Authorization headers
        if let Some(cred) = extract_auth_header(line) {
            found.push(cred);
        }

        // Detect database URLs with embedded credentials (user:pass@host patterns)
        if let Some(cred) = extract_database_url_credentials(line) {
            found.push(cred);
        }

        // Detect AWS credentials
        if let Some(cred) = extract_aws_credentials(line) {
            found.push(cred);
        }

        // Detect private key markers
        if let Some(cred) = detect_private_key(line) {
            found.push(cred);
        }
    }

    // Deduplicate
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found.dedup();

    found
}

/// Extract credentials from connection strings
fn extract_connection_string(line: &str) -> Option<(String, String)> {
    let patterns = ["mongodb://", "postgresql://", "mysql://", "mariadb://", "redis://", "mongodb+srv://"];
    for pattern in patterns.iter() {
        if let Some(start) = line.find(pattern) {
            // Extract from the protocol to the end of word boundary
            let rest = &line[start..];
            let end = rest.find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ';')
                .unwrap_or(rest.len());
            let connection_string = &rest[..end];

            // Check if it contains credentials (has @ and : before @)
            if connection_string.contains('@') && connection_string.contains(':') {
                // Extract just the password part after the : and before the @
                if let Some(at_pos) = connection_string.find('@') {
                    let before_at = &connection_string[..at_pos];
                    if let Some(colon_pos) = before_at.rfind(':') {
                        let password = &before_at[colon_pos + 1..];
                        if !password.is_empty() && password.len() >= 8 && !is_redacted(password) {
                            return Some((format!("{}_PASSWORD", pattern.trim_end_matches("://").to_uppercase()), password.to_string()));
                        }
                    }
                }
            }
        }
    }
    None
}

/// Extract credentials from Authorization headers
fn extract_auth_header(line: &str) -> Option<(String, String)> {
    let patterns = ["Authorization:", "X-API-Key:", "X-Auth-Token:", "X-Access-Token:"];
    for pattern in patterns.iter() {
        if let Some(start) = line.find(pattern) {
            let after_pattern = &line[start + pattern.len()..];
            let rest = after_pattern.trim_start();

            // Skip Bearer, Basic, etc. prefixes
            let token_start = if rest.starts_with("Bearer ") {
                7
            } else if rest.starts_with("Basic ") {
                6
            } else {
                0
            };

            let rest = &rest[token_start..];

            // Extract the token/credential value
            let end = rest.find(|c: char| c.is_whitespace() || c == '"' || c == ';' || c == '\n')
                .unwrap_or(rest.len());
            if end >= 10 {
                let token = rest[..end].trim_matches(|c| c == '\'' || c == '"' || c == ' ');
                if !token.is_empty() && !is_redacted(token) {
                    return Some(((*pattern).trim_end_matches(':').to_uppercase().to_string(), token.to_string()));
                }
            }
        }
    }
    None
}

/// Extract credentials from database URLs (user:pass@host)
fn extract_database_url_credentials(line: &str) -> Option<(String, String)> {
    // Look for user:password@host pattern
    if let Some(at_pos) = line.find('@') {
        let before_at = &line[..at_pos];
        // Find the last colon before the @
        if let Some(colon_pos) = before_at.rfind(':') {
            let potential_pass = &before_at[colon_pos + 1..];
            if !potential_pass.is_empty() && !is_redacted(potential_pass) && is_likely_credential(potential_pass) {
                // Make sure this looks like a credentials pattern, not a timestamp or similar
                if before_at.len() > 5 {
                    return Some(("DATABASE_PASSWORD".to_string(), potential_pass.to_string()));
                }
            }
        }
    }
    None
}

/// Extract AWS access key patterns
fn extract_aws_credentials(line: &str) -> Option<(String, String)> {
    // AWS access key pattern: AKIA followed by 16 alphanumeric characters
    if let Some(start) = line.find("AKIA") {
        let rest = &line[start..];
        // Extract AKIA + alphanumeric chars (should be ~16 more after AKIA)
        let mut byte_end = 0;
        for (i, c) in rest.char_indices() {
            if !c.is_ascii_alphanumeric() {
                byte_end = i;
                break;
            }
            byte_end = i + c.len_utf8();
        }
        if byte_end >= 20 {
            let potential_key = &rest[..byte_end];
            if !is_redacted(potential_key) {
                return Some(("AWS_ACCESS_KEY_ID".to_string(), potential_key.to_string()));
            }
        }
    }

    // AWS secret key pattern: looking for SecretAccessKey= or aws_secret_access_key=
    let secret_patterns = ["SecretAccessKey=", "aws_secret_access_key="];
    for pattern in secret_patterns.iter() {
        if let Some(start) = line.find(pattern) {
            let rest = &line[start + pattern.len()..];
            let end = rest.find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .unwrap_or(rest.len());
            if end >= 20 {
                let secret = &rest[..end];
                if !is_redacted(secret) {
                    return Some(("AWS_SECRET_ACCESS_KEY".to_string(), secret.to_string()));
                }
            }
        }
    }
    None
}

/// Detect if a line contains a private key marker
fn detect_private_key(line: &str) -> Option<(String, String)> {
    let key_markers = [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN PGP PRIVATE KEY-----",
    ];
    for marker in key_markers.iter() {
        if line.contains(marker) {
            return Some(("PRIVATE_KEY".to_string(), marker.to_string()));
        }
    }
    None
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

    #[test]
    fn detects_connection_strings() {
        let text = "mongodb://user:password123@mongodb.example.com:27017/dbname";
        let found = scan_config_for_credentials(text);
        assert!(!found.is_empty(), "Should find MongoDB connection string");
        assert!(found.iter().any(|(k, _)| k.contains("MONGODB")));
    }

    #[test]
    fn detects_auth_headers() {
        let text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9Token123456789";
        let found = scan_config_for_credentials(text);
        assert!(!found.is_empty(), "Should find Authorization header");
        assert!(found.iter().any(|(k, _)| k.contains("AUTHORIZATION")));
    }

    #[test]
    fn detects_api_secret_assignments() {
        let text = "aws_secret_access_key=WJAG7ASD89fjkasdflj23kdasfljkasdflkasdjfDEADBEEF";
        let found = scan_config_for_credentials(text);
        assert!(!found.is_empty(), "Should find AWS secret via key assignment");
    }

    #[test]
    fn detects_private_key_markers() {
        let text = "-----BEGIN RSA PRIVATE KEY-----";
        let found = scan_config_for_credentials(text);
        assert!(!found.is_empty(), "Should find private key marker");
        assert!(found.iter().any(|(k, _)| k.contains("PRIVATE_KEY")));
    }

    #[test]
    fn detects_database_credentials() {
        let text = "postgresql://admin:secretpassword123@db.example.com:5432/mydb";
        let found = scan_config_for_credentials(text);
        assert!(!found.is_empty(), "Should find database credentials");
    }
}
