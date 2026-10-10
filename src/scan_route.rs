//! Pure selector classification for the `scan` command.
//!
//! Keeping routing out of `main.rs` gives the single-selector and batch paths
//! one deterministic contract and makes future recursive expansion reuse the
//! exact same classifier.

use crate::canonical::{canonical_email, canonical_handle, canonical_name, canonical_phone};

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

/// Canonical selector for a route. `None` means the route cannot run.
#[must_use]
pub fn canonical_selector(kind: ScanKind, raw: &str) -> Option<String> {
    match kind {
        ScanKind::Email => canonical_email(raw),
        ScanKind::Username => canonical_handle(raw),
        ScanKind::Phone => canonical_phone(raw),
        // The people command owns the two-token rule and its offline skip path;
        // here only an empty name is non-canonical.
        ScanKind::People => {
            let name = canonical_name(raw);
            (!name.is_empty()).then_some(name)
        }
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

/// Whether an inferred people route has a name to look up. The selector is the first
/// positional, as it was on main: a second unquoted word is a separate argument and is not
/// part of the selector. So `scan Ada Lovelace` is refused, and `scan "Ada Lovelace"` is judged
/// as one name. Judging the joined words would run people-provider lookups from unquoted input
/// that main refused. A person lookup from unquoted words stays with the explicit `-k people`.
#[must_use]
pub fn inferred_people_is_name(positionals: &[String]) -> bool {
    positionals
        .first()
        .is_some_and(|selector| crate::people_cli::is_name(selector))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn inferred_people_route_judges_the_selector_as_main_did() {
        // Quoted, two words are one selector, and that is a name.
        assert!(inferred_people_is_name(&words(&["Ada Lovelace"])));
        // Unquoted, the second word is a separate argument, so the selector is one word.
        assert!(!inferred_people_is_name(&words(&["Ada", "Lovelace"])));
        assert!(!inferred_people_is_name(&words(&["Ada"])));
        assert!(!inferred_people_is_name(&words(&[
            "Ada", "--save", "out.json"
        ])));
        assert!(!inferred_people_is_name(&[]));
    }

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

    #[test]
    fn route_selector_is_canonical() {
        assert_eq!(
            canonical_selector(ScanKind::Email, " Ada@Example.ORG "),
            Some("ada@example.org".into())
        );
        assert_eq!(
            canonical_selector(ScanKind::Username, "@Ada"),
            Some("ada".into())
        );
        assert_eq!(
            canonical_selector(ScanKind::People, " Ada   Lovelace "),
            Some("ada lovelace".into())
        );
        assert_eq!(
            canonical_selector(ScanKind::People, "Ada"),
            Some("ada".into())
        );
        assert_eq!(canonical_selector(ScanKind::People, "   "), None);
    }
}
