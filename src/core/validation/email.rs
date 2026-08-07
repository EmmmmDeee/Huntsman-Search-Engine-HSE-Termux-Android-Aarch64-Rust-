use super::report::ValidationReport;

const ROLE_MAILBOXES: &[&str] = &[
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

/// Compare `input`, reduced to its lowercase ASCII-alphanumeric skeleton, against
/// an already-normalised `expected` token — streaming, so no intermediate
/// `String` is allocated per candidate. `expected` MUST already be lowercase
/// ASCII-alphanumeric (as every [`ROLE_MAILBOXES`] entry is), because it is
/// compared verbatim against the normalised `input` stream.
#[inline]
fn normalized_ascii_alnum_eq(input: &str, expected: &str) -> bool {
    input
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .eq(expected.chars())
}

/// True if `email`'s local-part is a generic ROLE / infrastructure mailbox
/// (`abuse@`, `dns@`, `hostmaster@`, `noreply@`, …) rather than a person's
/// address. These are registrar / DNS / CDN desks surfaced through WHOIS / RDAP /
/// SOA fields and `email_parse`; on an identity scan they are never the subject,
/// so the engine drops them at admission. The de-tagged, separator-stripped local
/// part is compared, so `no-reply` / `no_reply` also match `noreply`.
///
/// Allocation-free on the hot path: role matching streams the local-part through
/// the canonical ASCII normalisation ([`normalized_ascii_alnum_eq`]) instead of
/// collecting an intermediate `String` for every candidate email.
#[must_use]
pub fn is_role_mailbox(email: &str) -> bool {
    let Some((local, _)) = email.split_once('@') else {
        return false;
    };
    let base = local.split('+').next().unwrap_or(local);
    ROLE_MAILBOXES
        .iter()
        .any(|role| normalized_ascii_alnum_eq(base, role))
}

/// Light syntactic email check. Enforces: exactly one '@', a non-empty
/// local part shorter than 64 chars, a domain with at least one '.',
/// no consecutive dots, no leading/trailing dot in either part. Does
/// NOT verify MX or mailbox existence.
///
/// Uses `split_once` plus an explicit second-`@` guard rather than collecting
/// every segment into a temporary `Vec` — the exactly-one-`@` contract is
/// unchanged (`split_once` takes the first `@`, and any further `@` in the
/// remainder is rejected).
#[must_use]
pub fn validate_email_syntax(s: &str) -> ValidationReport {
    let Some((local, domain)) = s.split_once('@') else {
        return ValidationReport::fail("email.bad_at_count", "expected exactly one '@'");
    };
    if domain.contains('@') {
        return ValidationReport::fail("email.bad_at_count", "expected exactly one '@'");
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_mailbox_normalisation_is_allocation_free_semantics() {
        assert!(is_role_mailbox("No-Reply+ticket@example.com"));
        assert!(is_role_mailbox("MAILER_DAEMON@example.com"));
        assert!(!is_role_mailbox("supporter@example.com"));
        assert!(!is_role_mailbox("alice@example.com"));
    }

    #[test]
    fn email_requires_exactly_one_at_sign() {
        assert_eq!(
            validate_email_syntax("alice.example.com").reason,
            "email.bad_at_count"
        );
        assert_eq!(
            validate_email_syntax("alice@example.com@evil.invalid").reason,
            "email.bad_at_count"
        );
    }

    #[test]
    fn valid_email_shape_is_preserved() {
        assert!(validate_email_syntax("alice.smith+tag@example.com").valid);
    }
}
