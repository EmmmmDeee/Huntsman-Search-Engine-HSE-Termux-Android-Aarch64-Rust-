//! Stable JSON helpers for deterministic exports.

use serde_json::{Map, Value};

#[must_use]
pub fn sorted_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys = map.keys().cloned().collect::<Vec<_>>();
            keys.sort_unstable();
            let mut sorted = Map::with_capacity(map.len());
            for key in keys {
                sorted.insert(key.clone(), sorted_value(&map[&key]));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted_value).collect()),
        other => other.clone(),
    }
}

pub fn to_canonical_string(value: &Value) -> serde_json::Result<String> {
    serde_json::to_string(&sorted_value(value))
}

pub fn from_str_sorted(raw: &str) -> serde_json::Result<Value> {
    let value: Value = serde_json::from_str(raw)?;
    Ok(sorted_value(&value))
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
