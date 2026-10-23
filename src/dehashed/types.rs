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
//! Passwords and hashes are decoded as presence flags only (see `present_flag`):
//! the cleartext value is read only for whether it holds something and is
//! discarded during decoding, so an `Entry` can never hold or expose it. A
//! blank, empty or `false` value holds nothing and is not exposed. This makes the
//! "exposed / not exposed" redaction rule a property of the type rather than a
//! discipline every caller must keep. `Debug` is still written by hand so a
//! future field cannot leak into the derived output by accident.

use std::fmt;

use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
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
    #[serde(default, deserialize_with = "present_flag")]
    pub password: bool,
    #[serde(default, deserialize_with = "present_flag")]
    pub hashed_password: bool,
}

impl Entry {
    #[must_use]
    pub const fn has_password(&self) -> bool {
        self.password
    }

    #[must_use]
    pub const fn has_hashed_password(&self) -> bool {
        self.hashed_password
    }

    /// The record's addresses as pivots: each trimmed, a blank one dropped.
    pub fn emails(&self) -> impl Iterator<Item = &str> {
        pivots(&self.email)
    }

    /// The record's usernames as pivots: each trimmed, a blank one dropped.
    pub fn usernames(&self) -> impl Iterator<Item = &str> {
        pivots(&self.username)
    }
}

fn pivots(values: &[String]) -> impl Iterator<Item = &str> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
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

/// Decode a possibly-secret field as presence only.
///
/// The field is exposed when its value holds something: a non-blank string, a
/// number, `true`, a non-empty object, or an array with at least one element
/// that holds something by this same rule. `null`, `false`, a blank string, an
/// empty object, an array of nothing but such values, and an absent field are
/// not exposed. This is the rule `oathnet::present` applies to a breach record's
/// fields, except that each element of an array is judged on its own, since
/// `DeHashed` sends one value or a list of them (see `one_or_many`). The value
/// is read and dropped during decoding, so a cleartext password or hash is
/// never retained on an [`Entry`], and a vendor change to the field's JSON type
/// does not fail decoding.
fn present_flag<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    Ok(Option::<Presence>::deserialize(deserializer)?.is_some_and(|presence| presence.0))
}

/// Whether one decoded value holds something, by [`present_flag`]'s rule. Only
/// the answer is kept, never the value.
struct Presence(bool);

impl<'de> Deserialize<'de> for Presence {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(PresenceVisitor)
    }
}

struct PresenceVisitor;

impl<'de> Visitor<'de> for PresenceVisitor {
    type Value = Presence;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Presence, E> {
        Ok(Presence(false))
    }

    fn visit_none<E: de::Error>(self) -> Result<Presence, E> {
        Ok(Presence(false))
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Presence, D::Error> {
        Presence::deserialize(deserializer)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Presence, E> {
        Ok(Presence(value))
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Presence, E> {
        Ok(Presence(true))
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Presence, E> {
        Ok(Presence(true))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Presence, E> {
        Ok(Presence(true))
    }

    /// Borrowed, never copied: the text is only looked at.
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Presence, E> {
        Ok(Presence(!value.trim().is_empty()))
    }

    /// Every element is read, so the decoder stays in step, and judged on its own.
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Presence, A::Error> {
        let mut present = false;
        while let Some(Presence(element)) = seq.next_element()? {
            present |= element;
        }
        Ok(Presence(present))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Presence, A::Error> {
        let mut present = false;
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            present = true;
        }
        Ok(Presence(present))
    }
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

    #[test]
    fn secrets_decode_as_presence_only_and_are_never_retained() {
        // A non-blank value -> exposed.
        let present: Entry = serde_json::from_str(
            r#"{"password": "hunter2-cleartext", "hashed_password": "$2b$12$live-hash"}"#,
        )
        .unwrap();
        assert!(present.has_password());
        assert!(present.has_hashed_password());

        // null or absent -> not exposed.
        let null: Entry =
            serde_json::from_str(r#"{"password": null, "hashed_password": null}"#).unwrap();
        assert!(!null.has_password());
        assert!(!null.has_hashed_password());
        let absent: Entry = serde_json::from_str(r#"{"email": "a@example.com"}"#).unwrap();
        assert!(!absent.has_password());
        assert!(!absent.has_hashed_password());

        // The cleartext is discarded at decode time: the field is a bool, so no
        // rendering of the whole Entry can leak the value.
        let rendered = format!("{present:?}");
        assert!(!rendered.contains("hunter2-cleartext"), "{rendered}");
        assert!(!rendered.contains("live-hash"), "{rendered}");
    }

    #[test]
    fn a_blank_empty_or_false_secret_is_not_exposed() {
        for body in [
            r#"{"password": "", "hashed_password": []}"#,
            r#"{"password": "  ", "hashed_password": {}}"#,
            r#"{"password": [""], "hashed_password": false}"#,
            r#"{"password": [null, " "], "hashed_password": [[], {}]}"#,
        ] {
            let entry: Entry = serde_json::from_str(body).unwrap();
            assert!(!entry.has_password(), "{body}");
            assert!(!entry.has_hashed_password(), "{body}");
        }
        for body in [
            r#"{"password": ["x"], "hashed_password": true}"#,
            r#"{"password": ["", "x"], "hashed_password": {"bcrypt": ""}}"#,
            r#"{"password": 0, "hashed_password": [1.5]}"#,
            // Any element that holds something counts, wherever it sits in the list.
            r#"{"password": ["x", "y", ""], "hashed_password": ["h", null, []]}"#,
            // A negative number is a number too.
            r#"{"password": -1, "hashed_password": [-1]}"#,
        ] {
            let entry: Entry = serde_json::from_str(body).unwrap();
            assert!(entry.has_password(), "{body}");
            assert!(entry.has_hashed_password(), "{body}");
        }
    }

    #[test]
    fn pivot_values_are_trimmed_and_blank_free() {
        let entry: Entry = serde_json::from_str(
            r#"{"email": [" ada@example.com ", "", "  "], "username": ["ada", " "]}"#,
        )
        .unwrap();
        assert_eq!(entry.emails().collect::<Vec<_>>(), ["ada@example.com"]);
        assert_eq!(entry.usernames().collect::<Vec<_>>(), ["ada"]);
    }
}
