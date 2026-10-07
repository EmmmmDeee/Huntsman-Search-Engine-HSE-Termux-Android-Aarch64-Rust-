//! Pure selector classification for the `scan` command.
//!
//! Keeping routing out of `main.rs` gives the single-selector and batch paths
//! one deterministic contract and makes future recursive expansion reuse the
//! exact same classifier.

use crate::canonical::canonical_email;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanKind {
    People,
    Email,
    Username,
    Phone,
}

impl ScanKind {
    #[must_use]
    pub const fn command(self) -> &'static str {
        match self {
            Self::People => "people",
            Self::Email => "email",
            Self::Username => "username",
            Self::Phone => "phone",
        }
    }
}

/// Parse an explicit scan kind using the aliases accepted by the CLI.
///
/// # Errors
/// Returns the unknown spelling so the CLI can produce a stable usage error.
pub fn parse_kind(value: &str) -> Result<ScanKind, &str> {
    match value {
        "people" | "name" => Ok(ScanKind::People),
        "email" => Ok(ScanKind::Email),
        "username" | "handle" => Ok(ScanKind::Username),
        "phone" => Ok(ScanKind::Phone),
        other => Err(other),
    }
}

/// Infer the rebuilt lookup front-end for one selector.
///
/// Precedence is intentional: canonical email, explicit `@handle`, recognised
/// phone syntax, then a person/name fallback. This preserves the existing CLI
/// behavior while making it independently testable.
#[must_use]
pub fn infer_kind(selector: &str) -> ScanKind {
    if canonical_email(selector).is_some() {
        ScanKind::Email
    } else if selector.starts_with('@') {
        ScanKind::Username
    } else if crate::phone_intl::canonicalize(selector).is_some() {
        ScanKind::Phone
    } else {
        ScanKind::People
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_aliases_are_stable() {
        assert_eq!(parse_kind("people"), Ok(ScanKind::People));
        assert_eq!(parse_kind("name"), Ok(ScanKind::People));
        assert_eq!(parse_kind("handle"), Ok(ScanKind::Username));
        assert_eq!(parse_kind("phone"), Ok(ScanKind::Phone));
        assert_eq!(parse_kind("domain"), Err("domain"));
    }

    #[test]
    fn inference_preserves_cli_precedence() {
        assert_eq!(infer_kind("ada@example.org"), ScanKind::Email);
        assert_eq!(infer_kind("@ada"), ScanKind::Username);
        assert_eq!(infer_kind("+61412345678"), ScanKind::Phone);
        assert_eq!(infer_kind("Ada Lovelace"), ScanKind::People);
    }
}
