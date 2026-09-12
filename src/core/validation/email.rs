use super::report::ValidationReport;

/// The local-part of an email address, i.e. everything before the first `@`
/// (or the whole string, unchanged, if there is no `@`). One definition of
/// "the bit before the `@`" so callers that fold an email down to its handle
/// for correlation/dedup purposes (breach-account keying, reuse detection,
/// identity-fingerprint folding) share the exact same split instead of each
/// re-deriving `s.split('@').next().unwrap_or(s)` inline.
///
/// Does not strip Gmail-style `+tag` suffixes — callers that need that do it
/// as an explicit second step on the returned local-part.
///
/// ```
/// use huntsman_search_engine::core::validation::email_local;
///
/// assert_eq!(email_local("erik.diegmann+news@example.com"), "erik.diegmann+news");
/// assert_eq!(email_local("no-at-sign"), "no-at-sign");
/// ```
#[must_use]
pub fn email_local(s: &str) -> &str {
    s.split('@').next().unwrap_or(s)
}

/// True if `email`'s local-part is a generic ROLE / infrastructure mailbox
/// (`abuse@`, `dns@`, `hostmaster@`, `noreply@`, …) rather than a person's
/// address. These are registrar / DNS / CDN desks surfaced through WHOIS / RDAP /
/// SOA fields and `email_parse`; on an identity scan they are never the subject,
/// so the engine drops them at admission.
///
/// Delegates to [`crate::util::domains::is_role_localpart`] — until Pass 23
/// this function carried its own, narrower 20-entry copy of the role list,
/// which diverged from that one's ~60 entries in both directions (this copy
/// alone had `noc`/`registry`/`soa`/`ssladmin`; the other alone had `sales`,
/// `billing`, `legal`, `system`, `namehost`, `whois`, … and 30-odd more, plus
/// its provider-prefixed segment match for tokens like `awsdns-hostmaster`).
/// The same `sales@acme.com` was admitted here (not a role mailbox) while
/// `email_parse` correctly skipped deriving a Username from it — an
/// inconsistency the correlator's own comments warned against but couldn't
/// prevent, since the two guards drew from different lists.
#[must_use]
pub fn is_role_mailbox(email: &str) -> bool {
    let Some((local, _)) = email.split_once('@') else {
        return false;
    };
    crate::util::domains::is_role_localpart(local)
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
