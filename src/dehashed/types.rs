//! Response shapes for `DeHashed` v2 search.
//!
//! UNVERIFIED against a live key: the field names here are taken from the
//! request contract the repository already records (`service_defs`) and from
//! third-party integrations, because the vendor's API reference could not be
//! retrieved while this module was written. They are isolated in this file so
//! a correction is a one-file change. Two rules hold regardless of schema:
//!
//! - A body with no `entries` array is a decode error, never an empty result.
//!   An empty result is only reported when the API says so.
//! - Unknown fields are ignored, so an additive vendor change does not break
//!   decoding. Missing optional fields are reported as absent, never invented.
//!
//! Passwords and hashes are deserialized only to report that they exist. They
//! are never stored in a printable form, and `Debug` is written by hand so no
//! derived output can expose them.

use std::fmt;

use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SearchResponse {
    pub entries: Vec<Entry>,
    #[serde(default)]
    pub total: Option<u64>,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct Entry {
    #[serde(default)]
    pub database_name: Option<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub email: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub username: Vec<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub hashed_password: Option<String>,
}

impl Entry {
    #[must_use]
    pub const fn has_password(&self) -> bool {
        self.password.is_some()
    }

    #[must_use]
    pub const fn has_hashed_password(&self) -> bool {
        self.hashed_password.is_some()
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("database_name", &self.database_name)
            .field("email", &self.email)
            .field("username", &self.username)
            .field("has_password", &self.has_password())
            .field("has_hashed_password", &self.has_hashed_password())
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

/// Accept `null`, a single string, or an array of strings.
fn one_or_many<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    Ok(match Option::<OneOrMany>::deserialize(deserializer)? {
        None => Vec::new(),
        Some(OneOrMany::One(value)) => vec![value],
        Some(OneOrMany::Many(values)) => values,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_string_or_array_fields_and_ignores_unknown_keys() {
        let body = r#"{
            "entries": [
                {"database_name": "ExampleBreach", "email": "a@example.com",
                 "username": ["ada", "lovelace"], "password": "hunter2",
                 "vendor_extra": {"x": 1}},
                {"email": null, "hashed_password": "$2b$12$abc"}
            ],
            "total": 2
        }"#;
        let parsed: SearchResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.total, Some(2));
        assert_eq!(parsed.entries[0].email, vec!["a@example.com"]);
        assert_eq!(parsed.entries[0].username, vec!["ada", "lovelace"]);
        assert!(parsed.entries[0].has_password());
        assert!(!parsed.entries[0].has_hashed_password());
        assert!(parsed.entries[1].email.is_empty());
        assert!(parsed.entries[1].has_hashed_password());
    }

    #[test]
    fn body_without_entries_is_an_error() {
        assert!(serde_json::from_str::<SearchResponse>(r#"{"total": 0}"#).is_err());
        assert!(serde_json::from_str::<SearchResponse>(r#"{"entries": "nope"}"#).is_err());
    }

    #[test]
    fn debug_output_never_contains_secret_values() {
        let entry: Entry = serde_json::from_str(
            r#"{"email": "a@example.com", "password": "hunter2-secret", "hashed_password": "deadbeef-hash"}"#,
        )
        .unwrap();
        let rendered = format!("{entry:?}");
        assert!(!rendered.contains("hunter2-secret"), "{rendered}");
        assert!(!rendered.contains("deadbeef-hash"), "{rendered}");
        assert!(rendered.contains("has_password: true"), "{rendered}");
    }
}
