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

/// Whether `s` is the SQL NULL sentinel (`\N`) that MySQL/Postgres dump exports
/// write for an ABSENT column. Breach/stealer dumps carry it literally in name,
/// city, and other fields (303 occurrences in one real SeekNow export), where it
/// is value-absence — never a real value. Extractors must treat it as missing so
/// it cannot mint a `"\N \N"` Person or a `"\N"` Address. Exact match (trimmed,
/// case-insensitive) so a legitimate value is never dropped: unlike the ambiguous
/// `null` / `nan` / `none` tokens (a real surname `Null`, the Thai province
/// `Nan`), `\N` collides with no genuine value.
#[must_use]
pub fn is_null_sentinel(s: &str) -> bool {
    s.trim().eq_ignore_ascii_case("\\N")
}

/// Like [`val_str`] but also coerces a JSON **number** to its canonical string
/// form. Breach/stealer dumps routinely encode identifiers and codes as JSON
/// numbers rather than strings — `{"discordid": 123456789012345678}` (a Discord
/// snowflake is *always* a 64-bit int), `{"phone_number": 61412345678}`,
/// `{"postal_code": 23666}` — which the string-only [`val_str`] silently drops,
/// losing the phone lead, the Discord pivot, and the postcode. `bool` / `null` /
/// array / object remain absent (a `true` is not data we want stringified), and
/// an empty string is still treated as absent.
#[must_use]
pub fn val_str_coerce(item: &Value, key: &str) -> Option<String> {
    match item.get(key) {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}

/// The first present value among `keys`, coercing numbers like [`val_str_coerce`].
#[must_use]
pub fn val_str_or_coerce(item: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| val_str_coerce(item, k))
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
    fn val_str_coerce_stringifies_numbers_but_not_bools() {
        // The data breach/stealer dumps encode as JSON numbers — `val_str` drops
        // these, `val_str_coerce` recovers them.
        let v = json!({
            "discordid": 123456789012345678_u64,
            "phone_number": 61412345678_u64,
            "postal_code": 23666,
            "verified": true,
            "blank": "",
        });
        assert_eq!(
            val_str_coerce(&v, "discordid").as_deref(),
            Some("123456789012345678")
        );
        assert_eq!(
            val_str_coerce(&v, "phone_number").as_deref(),
            Some("61412345678")
        );
        assert_eq!(val_str_coerce(&v, "postal_code").as_deref(), Some("23666"));
        // bool / empty / missing stay absent.
        assert!(val_str_coerce(&v, "verified").is_none());
        assert!(val_str_coerce(&v, "blank").is_none());
        assert!(val_str_coerce(&v, "absent").is_none());
        // String values behave exactly like `val_str`.
        let s = json!({"x": "hello"});
        assert_eq!(val_str_coerce(&s, "x").as_deref(), Some("hello"));
        assert_eq!(
            val_str_or_coerce(&v, &["absent", "postal_code"]).as_deref(),
            Some("23666")
        );
    }

    #[test]
    fn val_str_or_returns_none_when_all_absent() {
        let v = json!({"x": ""});
        assert!(val_str_or(&v, &["a", "b"]).is_none());
    }

    #[test]
    fn is_null_sentinel_matches_sql_null_not_real_values() {
        // The MySQL/Postgres `\N` (303x in a real SeekNow export) is absence.
        assert!(is_null_sentinel("\\N"));
        assert!(is_null_sentinel("  \\N  "));
        assert!(is_null_sentinel("\\n"));
        // Genuine values that merely look null-ish are NOT dropped: the surname
        // "Null", the province "Nan", or any text containing the letters.
        assert!(!is_null_sentinel("Null"));
        assert!(!is_null_sentinel("Nan"));
        assert!(!is_null_sentinel("none"));
        assert!(!is_null_sentinel("N"));
        assert!(!is_null_sentinel("Diegmann"));
        assert!(!is_null_sentinel(""));
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
