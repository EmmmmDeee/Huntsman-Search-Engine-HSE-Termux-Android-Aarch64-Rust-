//! The key set a `Deserialize` options struct actually defines, derived from
//! the type itself.
//!
//! An options struct whose every field is absent-tolerant — `Option<T>`,
//! `#[serde(default)]` — cannot report its own misspelling: after
//! deserialisation an unknown key and an omitted key are the same thing, and
//! omitted means the default. Where that default is the *permissive* value, a
//! one-character slip silently turns the operator's control off. These helpers
//! are how a request seam tells the two apart, for any such struct.
//!
//! The key set is derived from the type's own `Serialize` impl rather than a
//! second hand-written list, so a field added to the struct is recognised the
//! moment it exists — the `unknown_module_names`/`registry()` relationship
//! applied to option names. A field that gained `skip_serializing_if` would
//! drop out of the derived set and start being rejected as unknown, so every
//! caller pairs this with a test comparing the derived set to the struct's
//! declared fields (see `derived_key_set_matches_the_struct_fields`).
//!
//! It lives in `core` rather than `util` because its callers are
//! `core::scan`, `core::live` and the `api` request seams — and `core` does not
//! import `util` directly (`tests/architecture.rs`'s
//! `core_does_not_import_util_directly`, whose allowlist exists for pure leaves
//! that `src/modules` ALSO needs). Nothing in `modules` needs this one, so it
//! belongs on the layer its callers already share rather than in an exception
//! to that rule.
//!
//! This is deliberately NOT `#[serde(deny_unknown_fields)]`: the structs it
//! serves are also persisted (a `Scan` carries its `ScanOptions` into
//! `scans.data_json` and reads it back), and strictness there would make a
//! stored record carrying a legacy key unreadable. Operator input and stored
//! state are two contracts over one type, and only the input side wants this.

use std::collections::BTreeSet;

/// Every key `T` defines, as serde spells it on the wire.
///
/// # Panics
///
/// If `T::default()` does not serialize to a JSON object. Both conditions are
/// properties of the type, not of any input: a struct always serializes to an
/// object, and only a non-finite float in its own `Default` could fail. A
/// caller's `known_*_keys` test exercises this on every build.
#[must_use]
pub fn known_keys<T: serde::Serialize + Default>() -> BTreeSet<String> {
    let serde_json::Value::Object(map) =
        serde_json::to_value(T::default()).expect("an options struct's Default must serialize")
    else {
        panic!("an options struct must serialize to a JSON object")
    };
    map.into_iter().map(|(k, _)| k).collect()
}

/// The keys present in a supplied object that `known` does not contain,
/// sorted and deduplicated.
///
/// A non-object value yields no keys: that is a shape error, which
/// deserialisation itself reports, and claiming it here too would give the
/// operator two errors for one mistake.
#[must_use]
pub fn unknown_keys(supplied: &serde_json::Value, known: &BTreeSet<String>) -> Vec<String> {
    let serde_json::Value::Object(map) = supplied else {
        return Vec::new();
    };
    let mut unknown: Vec<String> = map
        .keys()
        .filter(|k| !known.contains(k.as_str()))
        .cloned()
        .collect();
    // Sorted explicitly rather than relying on `serde_json::Map` being a
    // `BTreeMap`: `preserve_order` is an additive feature, so any crate in the
    // graph enabling it would swap in an `IndexMap` and silently make this
    // order — which reaches the operator in an error message — input-dependent.
    unknown.sort();
    unknown
}

/// The defined key an unknown one was most likely meant to be, if any.
///
/// Matches on letters and digits alone, so the realistic transcriptions of a
/// known name — `passive-only`, `passiveOnly`, `PASSIVE_ONLY` — resolve to
/// `passive_only`. Deliberately not a fuzzy distance: a suggestion that guesses
/// is worse than none, because an operator who accepts a wrong guess lands on a
/// *different* control, which is the defect this whole module exists to stop.
#[must_use]
pub fn nearest_key(unknown: &str, known: &BTreeSet<String>) -> Option<String> {
    fn letters(s: &str) -> String {
        s.chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_lowercase())
            .collect()
    }
    let probe = letters(unknown);
    if probe.is_empty() {
        return None;
    }
    known.iter().find(|k| letters(k) == probe).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize, Default)]
    struct Probe {
        passive_only: bool,
        max_cost_usd: Option<f64>,
    }

    #[test]
    fn known_keys_are_the_types_own_field_names() {
        let k = known_keys::<Probe>();
        assert_eq!(k.len(), 2, "derived set must not be vacuous");
        assert!(k.contains("passive_only") && k.contains("max_cost_usd"));
    }

    #[test]
    fn unknown_keys_reports_only_what_the_type_does_not_define() {
        let k = known_keys::<Probe>();
        let supplied = serde_json::json!({
            "passive_only": true, "passive-only": true, "aaa": 1
        });
        // Sorted, and the correctly-spelled key is NOT flagged.
        assert_eq!(
            unknown_keys(&supplied, &k),
            vec!["aaa".to_string(), "passive-only".to_string()]
        );
    }

    #[test]
    fn a_non_object_reports_nothing() {
        let k = known_keys::<Probe>();
        for v in [
            serde_json::json!(null),
            serde_json::json!("x"),
            serde_json::json!([1]),
        ] {
            assert!(unknown_keys(&v, &k).is_empty());
        }
    }

    #[test]
    fn nearest_key_resolves_transcriptions_and_declines_to_guess() {
        let k = known_keys::<Probe>();
        for spelling in [
            "passive-only",
            "passiveOnly",
            "PASSIVE_ONLY",
            "passive only",
        ] {
            assert_eq!(nearest_key(spelling, &k).as_deref(), Some("passive_only"));
        }
        assert_eq!(
            nearest_key("stealth_mode", &k),
            None,
            "a name that transcribes to nothing known must not be guessed at"
        );
        assert_eq!(
            nearest_key("---", &k),
            None,
            "a key with no alphanumerics must not match the first known name"
        );
    }
}
