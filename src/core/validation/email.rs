use super::report::ValidationReport;

/// True if `email`'s local-part is a generic ROLE / infrastructure mailbox
/// (`abuse@`, `dns@`, `hostmaster@`, `noreply@`, …) rather than a person's
/// address. These are registrar / DNS / CDN desks surfaced through WHOIS / RDAP /
/// SOA fields and `email_parse`; on an identity scan they are never the subject,
/// so the engine drops them at admission. The de-tagged, separator-stripped local
/// part is compared, so `no-reply` / `no_reply` also match `noreply`.
#[must_use]
pub fn is_role_mailbox(email: &str) -> bool {
    let Some((local, _)) = email.split_once('@') else {
        return false;
    };
    let base: String = local
        .split('+')
        .next()
        .unwrap_or(local)
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    const ROLE: &[&str] = &[
        "abuse",
        "admin",
        "administrator",
        "contact",
        "dns",
        "donotreply",
        "hostmaster",
        "info",
        "mailerdaemon",
        "noc",
        "noreply",
        "postmaster",
        "registrar",
        "registry",
        "root",
        "security",
        "soa",
        "ssladmin",
        "support",
        "webmaster",
    ];
    ROLE.contains(&base.as_str())
}

/// Light syntactic email check. Enforces: exactly one '@', a non-empty
/// local part shorter than 64 chars, a domain with at least one '.',
/// no consecutive dots, no leading/trailing dot in either part. Does
/// NOT verify MX or mailbox existence.
pub fn validate_email_syntax(s: &str) -> ValidationReport {
    let parts: Vec<&str> = s.split('@').collect();
    if parts.len() != 2 {
        return ValidationReport::fail("email.bad_at_count", "expected exactly one '@'");
    }
    let local = parts[0];
    let domain = parts[1];
    if local.is_empty() || local.len() > 64 {
        return ValidationReport::fail("email.local_length", "local part 1..=64 chars");
    }
    if domain.is_empty() || !domain.contains('.') {
        return ValidationReport::fail("email.domain_shape", "domain must contain '.'");
    }
    if local.starts_with('.') || local.ends_with('.') {
        return ValidationReport::fail("email.local_dot_edge", "leading/trailing '.' in local");
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return ValidationReport::fail("email.domain_dot_edge", "leading/trailing '.' in domain");
    }
    if local.contains("..") || domain.contains("..") {
        return ValidationReport::fail("email.consecutive_dots", "consecutive '.' forbidden");
    }
    ValidationReport::ok()
}
