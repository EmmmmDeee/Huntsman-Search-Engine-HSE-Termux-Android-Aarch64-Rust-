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

/// Every non-empty string value attached to `key` in a *raw* JSON body, located
/// by textual scan of the `"key":"…"` form rather than full deserialization —
/// for endpoints whose payload is large or loosely-shaped and only one repeated
/// field is wanted (`github_user` orgs/gists, `reddit_user` listings,
/// `hacker_news` hits). A numeric `"key":123` is skipped (only the quoted form
/// matches) and the value runs to the next `"`, so an embedded escaped quote
/// truncates it — the same limitation the open-coded loops had; callers
/// length-bound the result. Order-preserving; callers dedup/filter as needed.
///
/// Single definition so the scan semantics can't drift between the four modules
/// that each hand-rolled this `find`/slice loop.
#[must_use]
pub fn scan_string_field(body: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{key}\":\"");
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(pos) = rest.find(&needle) {
        rest = &rest[pos + needle.len()..];
        let Some(end) = rest.find('"') else { break };
        let val = &rest[..end];
        if !val.is_empty() {
            out.push(val.to_string());
        }
        rest = &rest[end..];
    }
    out
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

    #[test]
    fn scan_string_field_collects_quoted_values_in_order() {
        let body = r#"[{"login":"alice"},{"login":"bob"},{"login":""}]"#;
        // Order-preserving, empties dropped (the github_user orgs case).
        assert_eq!(scan_string_field(body, "login"), vec!["alice", "bob"]);
    }

    #[test]
    fn scan_string_field_skips_numeric_and_missing() {
        // Only the quoted `"id":"…"` form matches; numeric ids are skipped,
        // exactly as github_user's gist-id scan relied on.
        let body = r#"{"id":123,"items":[{"id":"deadbeef"},{"id":456}]}"#;
        assert_eq!(scan_string_field(body, "id"), vec!["deadbeef"]);
        assert!(scan_string_field(body, "absent").is_empty());
    }
}
