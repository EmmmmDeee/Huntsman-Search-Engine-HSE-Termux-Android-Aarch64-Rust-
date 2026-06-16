//! Shared JSON-field extraction helpers used by the breach/OSINT modules
//! (see_know, oathnet, …). Single definition so the extraction semantics
//! (treat empty strings as absent) can't drift between providers.
use serde_json::Value;

/// The value at `key` as an owned non-empty string, else `None`. An empty
/// string is treated as absent.
#[must_use]
pub fn val_str(item: &Value, key: &str) -> Option<String> {
    item.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(std::string::ToString::to_string)
}

/// The first non-empty string among several candidate `keys`, else `None`.
#[must_use]
pub fn val_str_or(item: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| val_str(item, k))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn val_str_returns_value_for_present_key() {
        let v = json!({"name": "Alice"});
        assert_eq!(val_str(&v, "name"), Some("Alice".to_string()));
    }

    #[test]
    fn val_str_treats_empty_string_as_absent() {
        let v = json!({"name": ""});
        assert!(val_str(&v, "name").is_none());
    }

    #[test]
    fn val_str_returns_none_for_missing_key() {
        let v = json!({"other": "x"});
        assert!(val_str(&v, "name").is_none());
    }

    #[test]
    fn val_str_returns_none_for_non_string_value() {
        let v = json!({"count": 42});
        assert!(val_str(&v, "count").is_none());
    }

    #[test]
    fn val_str_or_returns_first_non_empty() {
        let v = json!({"a": "", "b": "found", "c": "other"});
        assert_eq!(val_str_or(&v, &["a", "b", "c"]), Some("found".to_string()));
    }

    #[test]
    fn val_str_or_returns_none_when_all_absent() {
        let v = json!({"x": ""});
        assert!(val_str_or(&v, &["a", "b"]).is_none());
    }
}
