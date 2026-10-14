//! Stable JSON helpers for deterministic exports.

use serde::ser::{Serialize, SerializeMap, Serializer};
use serde_json::Value;

/// A value that serializes with every object's members in ascending key order, written as the
/// tree is walked: nothing is copied. `serde_json`'s map already iterates in key order unless its
/// `preserve_order` feature is on, which any crate in a build can switch on, so the members are
/// sorted here regardless (an ordered run sorts in one pass).
struct Canonical<'a>(&'a Value);

impl Serialize for Canonical<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Value::Object(map) => {
                let mut members = map.iter().collect::<Vec<_>>();
                members.sort_unstable_by(|left, right| left.0.cmp(right.0));
                let mut out = serializer.serialize_map(Some(members.len()))?;
                for (key, value) in members {
                    out.serialize_entry(key, &Canonical(value))?;
                }
                out.end()
            }
            Value::Array(items) => serializer.collect_seq(items.iter().map(Canonical)),
            scalar => scalar.serialize(serializer),
        }
    }
}

/// `value` as compact JSON with every object's keys in ascending order.
///
/// # Errors
/// Returns `serde_json`'s serialization failure.
pub fn to_canonical_string(value: &Value) -> serde_json::Result<String> {
    serde_json::to_string(&Canonical(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_objects_sort_by_key() {
        let value = serde_json::json!({"b":1,"a":{"z":1,"y":2}});
        assert_eq!(
            to_canonical_string(&value).unwrap(),
            r#"{"a":{"y":2,"z":1},"b":1}"#
        );
    }
}
