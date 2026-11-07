//! Response shapes for `DeHashed` v2 search.
//!
//! The shapes are those of `DeHashed`'s API documentation (v2, "Updated April 23, 2025"; its own
//! pages sit behind a bot challenge, so it was read from a published copy) and of live,
//! unauthenticated probes of `api.dehashed.com` on 2026-11-06. They are not verified against a
//! live key. The response is `{balance, entries, took, total}`. An entry carries `id`,
//! `database_name`, a `raw_record` object of flags, and arrays of strings: `email`, `ip_address`,
//! `username`, `password`, `hashed_password`, `name`, `dob`, `license_plate`, `address`, `phone`,
//! `company`, `url`, `social` and `cryptocurrency_address`. "Attributes will be omitted if they are
//! empty." Third-party clients also report `vin`, `hash_type` and `obtained_date`.
//!
//! An entry is read as the JSON object it is, so a field `DeHashed` adds is kept rather than
//! dropped:
//!
//! - **Metadata.** `id`, `database_name` and `raw_record` describe the record, not the person.
//! - **Every other field the record holds** is an exposed field, kept by name, and its values are
//!   kept as written. This is the one rule every keyed breach source follows,
//!   [`crate::breach_record::expose`], bounded by its [`MAX_FIELDS`](crate::breach_record::MAX_FIELDS),
//!   [`MAX_VALUES_PER_FIELD`](crate::breach_record::MAX_VALUES_PER_FIELD) and
//!   [`MAX_VALUE_BYTES`](crate::breach_record::MAX_VALUE_BYTES).
//! - **Credentials.** A password, a hash or a salt is the value an attacker needs for account
//!   takeover, so it is reduced to its field name and the fact that it was exposed while
//!   decoding, and an [`Entry`] can never hold or show it. That covers `password`,
//!   `hashed_password`, `hash_type` and anything else the credential rule names. Exposure is
//!   judged strictly for `password` and `hashed_password`: a blank, empty or `false` value
//!   exposes nothing (see `holds`).
//! - **No entries is an error.** A body without an `entries` array is a decode error, never an
//!   empty result: an empty result is only reported when the API says so.
//! - **Metadata types.** `balance`, `took` and `total` are read leniently: a value of an
//!   unexpected type is absent, never a reason to lose the whole answer.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

use crate::breach_record;

/// Entry keys that describe the record rather than the person it is about.
const RECORD_METADATA: [&str; 3] = ["id", "database_name", "raw_record"];
/// The two credential fields `DeHashed` documents, judged by the strict rule of `holds` so a
/// blank value exposes nothing. Their values are never kept.
const SECRET_FIELDS: [&str; 2] = ["password", "hashed_password"];
/// The longest `took` kept, in bytes: `DeHashed` writes a short duration such as `179µs`.
const MAX_TOOK_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SearchResponse {
    pub entries: Vec<Entry>,
    /// Matching records `DeHashed` holds in all, across every page.
    #[serde(default, deserialize_with = "lenient_count")]
    pub total: Option<u64>,
    /// The account's search credits left after this search ("1 search = 1 credit").
    #[serde(default, deserialize_with = "lenient_count")]
    pub balance: Option<u64>,
    /// How long `DeHashed` says the search took, as it wrote it.
    #[serde(default, deserialize_with = "lenient_took")]
    pub took: Option<String>,
}

/// One breach record, read as the object it is.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Entry {
    /// The breach database the record came from.
    pub database_name: Option<String>,
    /// The record's addresses, as written.
    pub email: Vec<String>,
    /// The record's usernames, as written.
    pub username: Vec<String>,
    /// The record's `password` field holds something. The value itself is never kept.
    pub password: bool,
    /// The record's `hashed_password` field holds something. The value itself is never kept.
    pub hashed_password: bool,
    /// Every field the record exposes, by name: credentials included, though their values are
    /// not kept.
    pub fields: BTreeSet<String>,
    /// The values each non-credential field holds, as written, within
    /// [`crate::breach_record`]'s bounds.
    pub values: BTreeMap<String, BTreeSet<String>>,
    /// A credential field other than `password` and `hashed_password` holds something (a salt, a
    /// `pwd`, ...): [`crate::breach_record`]'s rule.
    pub other_credential: bool,
    /// What `DeHashed`'s `raw_record` object says about the record.
    pub raw: RawRecord,
}

/// `DeHashed`'s `raw_record` flags: how the record was kept, not what it says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RawRecord {
    /// The record is free text `DeHashed` did not split into fields.
    pub unstructured: bool,
    /// `DeHashed` marks the record for law enforcement only.
    pub le_only: bool,
}

impl<'de> Deserialize<'de> for Entry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::from_record(&Map::deserialize(deserializer)?))
    }
}

impl Entry {
    /// The entry one record holds. The values of credential fields are read only for whether
    /// they hold something, and dropped before this returns. **Pure.**
    #[must_use]
    pub fn from_record(record: &Map<String, Value>) -> Self {
        let mut entry = Self {
            database_name: record
                .get("database_name")
                .and_then(Value::as_str)
                .map(str::to_owned),
            email: strings(record.get("email")),
            username: strings(record.get("username")),
            password: record.get("password").is_some_and(holds),
            hashed_password: record.get("hashed_password").is_some_and(holds),
            ..Self::default()
        };
        if let Some(raw) = record.get("raw_record").and_then(Value::as_object) {
            entry.raw = RawRecord {
                unstructured: raw.get("unstructured") == Some(&Value::Bool(true)),
                le_only: raw.get("le_only") == Some(&Value::Bool(true)),
            };
        }
        // DeHashed writes every field as a list of values, so each scalar in a list is one value of
        // that field, judged on its own; a list holding an object or a list stays whole.
        let named = record
            .iter()
            .filter(|(key, _)| {
                !RECORD_METADATA.contains(&key.as_str()) && !SECRET_FIELDS.contains(&key.as_str())
            })
            .flat_map(|(key, value)| match value {
                Value::Array(items) if items.iter().all(is_scalar) => {
                    items.iter().map(|item| (key, item)).collect::<Vec<_>>()
                }
                _ => vec![(key, value)],
            });
        breach_record::expose(
            named,
            &mut entry.fields,
            &mut entry.values,
            &mut entry.other_credential,
        );
        for (field, held) in [
            ("password", entry.password),
            ("hashed_password", entry.hashed_password),
        ] {
            if held {
                entry.fields.insert(field.to_owned());
            }
        }
        entry
    }

    #[must_use]
    pub const fn has_password(&self) -> bool {
        self.password
    }

    #[must_use]
    pub const fn has_hashed_password(&self) -> bool {
        self.hashed_password
    }

    /// The record exposes a password, a hash or another credential.
    #[must_use]
    pub const fn password_exposed(&self) -> bool {
        self.password || self.hashed_password || self.other_credential
    }

    /// The record's addresses as pivots: each trimmed, a blank one dropped.
    pub fn emails(&self) -> impl Iterator<Item = &str> {
        pivots(&self.email)
    }

    /// The record's usernames as pivots: each trimmed, a blank one dropped.
    pub fn usernames(&self) -> impl Iterator<Item = &str> {
        pivots(&self.username)
    }

    /// The values the record holds beyond its addresses and usernames, field by field: what a
    /// report shows besides the pivots.
    pub fn other_values(&self) -> impl Iterator<Item = (&str, &str)> {
        self.values
            .iter()
            .filter(|(field, _)| !matches!(field.as_str(), "email" | "username"))
            .flat_map(|(field, values)| {
                values
                    .iter()
                    .map(move |value| (field.as_str(), value.as_str()))
            })
    }
}

fn pivots(values: &[String]) -> impl Iterator<Item = &str> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
}

/// A JSON value with no keys inside it. **Pure.**
const fn is_scalar(value: &Value) -> bool {
    !matches!(value, Value::Array(_) | Value::Object(_))
}

/// A field `DeHashed` sends as one string or as a list of them; anything else in it is skipped.
fn strings(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(one)) => vec![one.clone()],
        Some(Value::Array(many)) => many
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

/// Whether a credential field's value holds something: a non-blank string, a number, `true`, a
/// non-empty object, or a list with at least one element that holds something by this same rule.
/// `null`, `false`, a blank string, an empty object, and a list of nothing but those hold
/// nothing. Only the answer leaves; the value is never copied. **Pure.**
fn holds(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => false,
        Value::Bool(true) | Value::Number(_) => true,
        Value::String(text) => !text.trim().is_empty(),
        Value::Array(items) => items.iter().any(holds),
        Value::Object(map) => !map.is_empty(),
    }
}

/// A count `DeHashed` sends as a number, or a whole number in a string; anything else is absent.
fn lenient_count<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Number(number)) => number.as_u64(),
        Some(Value::String(text)) => text.trim().parse().ok(),
        _ => None,
    })
}

/// `took` as `DeHashed` wrote it (`179µs`), or a number as written; anything else, blank or over
/// [`MAX_TOOK_BYTES`], is absent.
fn lenient_took<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    let text = match Option::<Value>::deserialize(deserializer)? {
        Some(Value::String(text)) => text.trim().to_owned(),
        Some(Value::Number(number)) => number.to_string(),
        _ => return Ok(None),
    };
    Ok((!text.is_empty() && text.len() <= MAX_TOOK_BYTES).then_some(text))
}

impl fmt::Debug for Entry {
    /// Written by hand so no future field can reach the output by accident. Values are counted,
    /// not shown: they are third parties' data.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("database_name", &self.database_name)
            .field("email", &self.email)
            .field("username", &self.username)
            .field("has_password", &self.has_password())
            .field("has_hashed_password", &self.has_hashed_password())
            .field("password_exposed", &self.password_exposed())
            .field("fields", &self.fields)
            .field(
                "values",
                &self.values.values().map(BTreeSet::len).sum::<usize>(),
            )
            .field("raw", &self.raw)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) mod tests {
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

    /// One record in `DeHashed`'s documented v2 shape, with every field it documents and the three
    /// third-party clients report (`vin`, `hash_type`, `obtained_date`).
    pub(crate) const V2_RECORD: &str = r#"{
        "id": "9f0e2c", "database_name": "ExampleBreach",
        "raw_record": {"le_only": false, "unstructured": true},
        "email": ["ada@example.com"], "ip_address": ["198.51.100.7"], "username": ["ada99"],
        "password": ["hunter2-cleartext"], "hashed_password": ["$2b$12$live-hash"],
        "hash_type": ["bcrypt-type"], "name": ["Ada Example"], "dob": ["1990-01-01"],
        "license_plate": ["ABC123"], "address": ["1 Example St, Brisbane QLD"],
        "phone": ["+61 7 5555 0100"], "company": ["Example Pty Ltd"],
        "url": ["https://example.com/ada"], "social": ["@ada"],
        "cryptocurrency_address": ["bc1qexampleaddress"], "vin": ["1HGCM82633A004352"],
        "obtained_date": ["2019-05-01"]
    }"#;

    /// Every value a record holds is kept as written, one per list element, except a credential:
    /// a password, a hash, or a field the credential rule names (`hash_type` holds `hash`, and the
    /// rule fails closed), which is kept by name only. The record's own metadata is no field.
    #[test]
    fn a_documented_v2_record_keeps_every_value_but_its_credentials() {
        let entry: Entry = serde_json::from_str(V2_RECORD).unwrap();
        assert_eq!(entry.database_name.as_deref(), Some("ExampleBreach"));
        assert!(entry.raw.unstructured && !entry.raw.le_only);
        assert!(entry.has_password() && entry.has_hashed_password() && entry.password_exposed());
        for (field, value) in [
            ("email", "ada@example.com"),
            ("ip_address", "198.51.100.7"),
            ("username", "ada99"),
            ("name", "Ada Example"),
            ("dob", "1990-01-01"),
            ("license_plate", "ABC123"),
            ("address", "1 Example St, Brisbane QLD"),
            ("phone", "+61 7 5555 0100"),
            ("company", "Example Pty Ltd"),
            ("url", "https://example.com/ada"),
            ("social", "@ada"),
            ("cryptocurrency_address", "bc1qexampleaddress"),
            ("vin", "1HGCM82633A004352"),
            ("obtained_date", "2019-05-01"),
        ] {
            let kept: Vec<&str> = entry.values[field].iter().map(String::as_str).collect();
            assert_eq!(kept, [value], "{field}");
            assert!(entry.fields.contains(field), "{field}");
        }
        for credential in ["password", "hashed_password", "hash_type"] {
            assert!(entry.fields.contains(credential), "{credential} not listed");
            assert!(
                !entry.values.contains_key(credential),
                "{credential}'s value kept"
            );
        }
        for metadata in ["id", "database_name", "raw_record"] {
            assert!(
                !entry.fields.contains(metadata),
                "{metadata} read as a field"
            );
        }
        // Debug counts values rather than showing them, and never holds a credential.
        let rendered = format!("{entry:?}");
        for (what, value) in [
            ("password", "hunter2-cleartext"),
            ("hash", "live-hash"),
            ("hash type", "bcrypt-type"),
            ("name", "Ada Example"),
        ] {
            assert!(!rendered.contains(value), "the {what} reached Debug");
        }
    }

    /// `balance`, `took` and `total` are metadata: a value of an unexpected type is absent, never a
    /// reason to lose the entries.
    #[test]
    fn response_metadata_is_read_leniently_and_never_voids_the_answer() {
        let read = |body: &str| -> (Option<u64>, Option<String>, Option<u64>) {
            let parsed: SearchResponse = serde_json::from_str(body).unwrap();
            (parsed.balance, parsed.took, parsed.total)
        };
        assert_eq!(
            read(r#"{"balance": 4321, "took": "179µs", "total": 3, "entries": []}"#),
            (Some(4321), Some("179µs".into()), Some(3))
        );
        assert_eq!(
            read(r#"{"balance": "17", "took": 12, "total": " 2 ", "entries": []}"#),
            (Some(17), Some("12".into()), Some(2))
        );
        assert_eq!(
            read(r#"{"balance": -1, "took": {"ms": 1}, "total": null, "entries": []}"#),
            (None, None, None)
        );
        let long = format!(
            r#"{{"took": "{}", "entries": []}}"#,
            "9".repeat(MAX_TOOK_BYTES + 1)
        );
        assert_eq!(read(&long), (None, None, None));
        assert_eq!(read(r#"{"entries": []}"#), (None, None, None));
    }

    /// One record cannot flood a report: a field keeps at most `MAX_VALUES_PER_FIELD` values, and a
    /// value over `MAX_VALUE_BYTES` is dropped whole, never cut, so a kept value is what the record
    /// held.
    #[test]
    fn values_are_bounded_per_field_and_an_oversized_value_is_dropped_whole() {
        use crate::breach_record::{MAX_VALUE_BYTES, MAX_VALUES_PER_FIELD};
        let names: Vec<String> = (0..MAX_VALUES_PER_FIELD + 5)
            .map(|i| format!("Name {i:03}"))
            .collect();
        let exact = "a".repeat(MAX_VALUE_BYTES);
        let over = "b".repeat(MAX_VALUE_BYTES + 1);
        let record = serde_json::json!({"name": names, "address": [exact, over]});
        let entry: Entry = serde_json::from_value(record).unwrap();
        assert_eq!(entry.values["name"].len(), MAX_VALUES_PER_FIELD);
        let addresses: Vec<usize> = entry.values["address"].iter().map(String::len).collect();
        assert_eq!(addresses, [MAX_VALUE_BYTES]);
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
