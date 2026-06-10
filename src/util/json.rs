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
