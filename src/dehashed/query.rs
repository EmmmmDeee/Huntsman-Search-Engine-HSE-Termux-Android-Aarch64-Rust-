//! Selector and purpose validation for `DeHashed` searches.
//!
//! A search is exactly one exact-match value on one field. Wildcards, regex,
//! lists, quotes, backslashes, whitespace and non-ASCII input are refused here,
//! before any request is built, so no caller can widen a search into a sweep by
//! construction. Input is never trimmed or rewritten: a value either validates
//! as entered or is rejected with the rule it broke.

use std::fmt;

use thiserror::Error;

pub const MAX_EMAIL_BYTES: usize = 254;
pub const MAX_DOMAIN_BYTES: usize = 253;
pub const MAX_USERNAME_BYTES: usize = 64;

/// The fields a search may target. Each maps to one `DeHashed` field name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Email,
    Username,
    Domain,
}

impl Field {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Username => "username",
            Self::Domain => "domain",
        }
    }
}

/// Why a search is being made. Every request declares one, and it is printed
/// with the results so the audit trail travels with the output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Checking the operator's own account or domain.
    OwnAccount,
    /// Work under a written authorization such as a pentest or assessment.
    AuthorizedEngagement,
    /// Responding to a confirmed incident involving the identifier.
    IncidentResponse,
    /// Security research with no targeting of a private individual.
    SecurityResearch,
}

impl Purpose {
    pub const ALL: [Self; 4] = [
        Self::OwnAccount,
        Self::AuthorizedEngagement,
        Self::IncidentResponse,
        Self::SecurityResearch,
    ];

    /// Every `--purpose` name, in [`ALL`](Self::ALL) order.
    pub const NAMES: [&'static str; 4] = {
        let mut names = [""; 4];
        let mut i = 0;
        while i < Self::ALL.len() {
            names[i] = Self::ALL[i].as_str();
            i += 1;
        }
        names
    };

    /// Parse a `--purpose` value. Unknown purposes are an error, never a default.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|purpose| purpose.as_str() == raw)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnAccount => "own-account",
            Self::AuthorizedEngagement => "authorized-engagement",
            Self::IncidentResponse => "incident-response",
            Self::SecurityResearch => "security-research",
        }
    }
}

impl fmt::Display for Purpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A validated exact-match identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector {
    field: Field,
    value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum QueryError {
    #[error("{0}")]
    Invalid(&'static str),
}

impl Selector {
    /// Validate `value` for `field`. The value is stored exactly as given.
    ///
    /// # Errors
    /// [`QueryError::Invalid`] naming the rule the value broke.
    pub fn new(field: Field, value: &str) -> Result<Self, QueryError> {
        match field {
            Field::Email => validate_email(value)?,
            Field::Username => validate_username(value)?,
            Field::Domain => validate_domain(value)?,
        }
        Ok(Self {
            field,
            value: value.to_string(),
        })
    }

    #[must_use]
    pub const fn field(&self) -> Field {
        self.field
    }

    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// The `DeHashed` field-search expression, e.g. `email:"a@example.com"`.
    /// Safe to embed: validation has already excluded quotes and backslashes.
    #[must_use]
    pub fn query(&self) -> String {
        format!("{}:\"{}\"", self.field.as_str(), self.value)
    }
}

/// Printable ASCII with no `DeHashed` syntax characters: quotes, backslashes,
/// and the wildcard characters `*` and `?`.
fn plain_ascii(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\\' | b'*' | b'?'))
}

fn validate_email(value: &str) -> Result<(), QueryError> {
    const RULE: &str = "email must be one address: at most 254 bytes, ASCII letters, digits and ._%+- in the local part (not starting or ending with '.', no '..'), and a valid domain after @; wildcards are not allowed";
    if value.len() > MAX_EMAIL_BYTES || !plain_ascii(value) {
        return Err(QueryError::Invalid(RULE));
    }
    let (local, domain) = value.split_once('@').ok_or(QueryError::Invalid(RULE))?;
    let local_ok = crate::value_syntax::email_local_error(local).is_none()
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._%+-".contains(&b));
    if !local_ok || validate_domain(domain).is_err() {
        return Err(QueryError::Invalid(RULE));
    }
    Ok(())
}

fn validate_domain(value: &str) -> Result<(), QueryError> {
    const RULE: &str = "domain must be a fully qualified name with at least one dot, at most 253 bytes, and labels of letters, digits and hyphens that neither start nor end with a hyphen; wildcards are not allowed";
    if value.len() > MAX_DOMAIN_BYTES || !value.contains('.') || !plain_ascii(value) {
        return Err(QueryError::Invalid(RULE));
    }
    if value.split('.').all(crate::value_syntax::is_domain_label) {
        Ok(())
    } else {
        Err(QueryError::Invalid(RULE))
    }
}

fn validate_username(value: &str) -> Result<(), QueryError> {
    const RULE: &str = "username must be 1 to 64 bytes of ASCII letters, digits, '.', '_' or '-'; wildcards are not allowed";
    let ok = !value.is_empty()
        && value.len() <= MAX_USERNAME_BYTES
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(QueryError::Invalid(RULE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exact_identifiers_and_renders_quoted_query() {
        let email = Selector::new(Field::Email, "a.b+tag@example.co.uk").unwrap();
        assert_eq!(email.query(), "email:\"a.b+tag@example.co.uk\"");
        let user = Selector::new(Field::Username, "ada_lovelace-1").unwrap();
        assert_eq!(user.query(), "username:\"ada_lovelace-1\"");
        let domain = Selector::new(Field::Domain, "Example.COM").unwrap();
        assert_eq!(domain.query(), "domain:\"Example.COM\"");
        assert_eq!(domain.value(), "Example.COM");
    }

    #[test]
    fn rejects_wildcards_quotes_lists_and_whitespace() {
        for bad in [
            "*@example.com",
            "a?@example.com",
            "a\"b@example.com",
            "a\\b@example.com",
            "a @example.com",
            " a@example.com",
            "a@example.com\n",
            "a@example.com,b@example.com",
            "ünïcode@example.com",
            "a@*.example.com",
            "",
        ] {
            assert!(
                Selector::new(Field::Email, bad).is_err(),
                "{bad:?} accepted"
            );
        }
        assert!(Selector::new(Field::Username, "bob*").is_err());
        assert!(Selector::new(Field::Username, "bob smith").is_err());
        assert!(Selector::new(Field::Username, "").is_err());
        assert!(Selector::new(Field::Domain, "*.example.com").is_err());
        assert!(Selector::new(Field::Domain, "localhost").is_err());
    }

    #[test]
    fn rejects_malformed_domains_and_emails() {
        for bad in [
            "a@",
            "@example.com",
            "a@@example.com",
            "a@localhost",
            "a@-x.example.com",
            "a@x-.example.com",
            "a@exa..mple.com",
            ".a@example.com",
            "a.@example.com",
            "a..b@example.com",
        ] {
            assert!(
                Selector::new(Field::Email, bad).is_err(),
                "{bad:?} accepted"
            );
        }
        let long_label = format!("{}.com", "a".repeat(64));
        assert!(Selector::new(Field::Domain, &long_label).is_err());
        let long_local = format!("{}@example.com", "a".repeat(65));
        assert!(Selector::new(Field::Email, &long_local).is_err());
        let max_label = format!("{}.com", "a".repeat(63));
        assert!(Selector::new(Field::Domain, &max_label).is_ok());
        let max_local = format!("{}@example.com", "a".repeat(64));
        assert!(Selector::new(Field::Email, &max_local).is_ok());
        assert!(Selector::new(Field::Email, "a.b%c+d@example.com").is_ok());
    }

    #[test]
    fn purpose_parses_only_declared_names() {
        assert_eq!(
            Purpose::NAMES,
            [
                "own-account",
                "authorized-engagement",
                "incident-response",
                "security-research"
            ]
        );
        for name in Purpose::NAMES {
            let parsed = Purpose::parse(name).expect(name);
            assert_eq!(parsed.as_str(), name);
        }
        assert_eq!(Purpose::parse(""), None);
        assert_eq!(Purpose::parse("curiosity"), None);
        assert_eq!(Purpose::parse("Own-Account"), None);
    }
}
