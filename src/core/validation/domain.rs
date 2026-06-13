use std::net::IpAddr;

use super::report::ValidationReport;

/// Validate a domain has at least one label, contains a '.', uses only
/// LDH characters (letter-digit-hyphen) per label, and is not a pure
/// IP literal. Trailing dot is stripped before validation.
pub fn validate_domain_shape(s: &str) -> ValidationReport {
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty() || s.len() > 253 {
        return ValidationReport::fail("domain.length", "1..=253 chars");
    }
    if !s.contains('.') {
        return ValidationReport::fail("domain.no_dot", "must contain '.'");
    }
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return ValidationReport::fail("domain.label_length", "label 1..=63 chars");
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return ValidationReport::fail("domain.ldh", "non-LDH char in label");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return ValidationReport::fail("domain.hyphen_edge", "leading/trailing '-' in label");
        }
    }
    if s.parse::<IpAddr>().is_ok() {
        return ValidationReport::fail("domain.is_ip", "value parses as IP literal");
    }
    ValidationReport::ok()
}
