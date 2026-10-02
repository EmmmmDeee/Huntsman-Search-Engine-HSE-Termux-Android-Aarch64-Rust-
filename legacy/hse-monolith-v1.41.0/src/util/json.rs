//! Shared JSON-field extraction helpers used by the breach/OSINT modules
//! (see_know, oathnet, …). Single definition so the extraction semantics
//! (treat empty strings as absent) can't drift between providers.
use serde_json::Value;
use std::borrow::Cow;

/// A JSON **scalar** — a `string` or a `number` — rendered as text: the string
/// borrowed in place, a number in its canonical string form. Any other node
/// (`bool` / `null` / array / object) yields `None`.
///
/// This is the single definition of "accept a field that arrives as either
/// `"505"` or `505`", shared by the keyed [`val_str_coerce`] here and the
/// module-local `json_to_str` coercers (cell / radar / sunrise-sunset APIs that
/// vary the encoding between endpoints). It does **not** apply the empty-string
/// policy: a `""` yields `Some(Cow::Borrowed(""))`, leaving each caller free to
/// treat empty as absent (as `val_str_coerce` does) or as a literal empty value.
#[must_use]
pub fn scalar_str(v: &Value) -> Option<Cow<'_, str>> {
    match v {
        Value::String(s) => Some(Cow::Borrowed(s)),
        Value::Number(n) => Some(Cow::Owned(n.to_string())),
        _ => None,
    }
}

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
    item.get(key)
        .and_then(scalar_str)
        .filter(|s| !s.is_empty())
        .map(Cow::into_owned)
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
    // `memmem::Finder` (Teddy/NEON on aarch64) built once and reused across
    // every match in the loop below, instead of std `str::find`'s scalar
    // Two-Way scan repeated from scratch at each position — this can run over
    // a whole paginated API response body with many matches.
    let finder = memchr::memmem::Finder::new(needle.as_bytes());
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(pos) = finder.find(rest.as_bytes()) {
        rest = &rest[pos + needle.len()..];
        let Some(end) = memchr::memchr(b'"', rest.as_bytes()) else {
            break;
        };
        let val = &rest[..end];
        if !val.is_empty() {
            out.push(val.to_string());
        }
        rest = &rest[end..];
    }
    out
}

/// Escape `s` for embedding **inside** a JSON string literal — the caller supplies the
/// surrounding quotes, so this returns the interior only.
///
/// Delegates to `serde_json` rather than hand-rolling the escape, because hand-rolling it is a
/// mistake this crate has already made and paid for. A `replace('\\', …).replace('"', …)` chain
/// covers backslash and quote but leaves the control bytes (`\n`, `\r`, `\t`, anything `< 0x20`)
/// that are ILLEGAL raw inside a JSON string — so a value carrying a newline or tab produced an
/// invalid request body. `util::see_know` hit exactly that and fixed its copy; `modules::fullcontact`
/// carried the unfixed twin. One definition now, so a third caller cannot inherit the broken shape
/// and the two cannot drift apart again.
///
/// `Value::String(_).to_string()` yields `"…"`; the wrapping ASCII quotes are stripped to honour
/// the interior-only contract. Those quotes are always exactly one byte each, so the slice is
/// char-boundary safe for any input. Pure and total.
pub fn escape_string_interior(s: &str) -> String {
    let quoted = serde_json::Value::String(s.to_owned()).to_string();
    quoted[1..quoted.len() - 1].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn escape_string_interior_escapes_quote_and_backslash() {
        assert_eq!(escape_string_interior(r#"a"b"#), r#"a\"b"#);
        assert_eq!(escape_string_interior(r"a\b"), r"a\\b");
        assert_eq!(escape_string_interior("plain"), "plain");
        assert_eq!(escape_string_interior(""), "");
    }

    #[test]
    fn escape_string_interior_escapes_the_control_bytes_a_replace_chain_misses() {
        // The regression the hand-rolled twin carried: `\n`/`\r`/`\t` and other `< 0x20` bytes are
        // ILLEGAL raw inside a JSON string, so a `.replace('\\',…).replace('"',…)` chain emitted a
        // body no parser would accept. Each must come out as a valid escape.
        assert_eq!(escape_string_interior("a\nb"), r"a\nb");
        assert_eq!(escape_string_interior("a\rb"), r"a\rb");
        assert_eq!(escape_string_interior("a\tb"), r"a\tb");
        // Note the contrast with XML (`core::xml`), where an illegal control character is
        // DROPPED because it cannot be represented at all: JSON *can* represent every control
        // byte, as a `\u00XX` escape, so the correct handling here is to escape rather than
        // discard — the value survives intact and the body stays parseable.
        assert_eq!(escape_string_interior("a\u{1}b"), r"a\u0001b");
        assert_eq!(escape_string_interior("\u{0}"), r"\u0000");
    }

    #[test]
    fn escaped_interior_always_builds_parseable_json() {
        // The property that actually matters: whatever the value, wrapping the result in quotes
        // must yield a body `serde_json` can parse back to the original string. A hand-rolled
        // escape fails this for any control byte.
        for raw in [
            "plain",
            "quote\" and \\ backslash",
            "newline\nand\ttab",
            "\u{0}\u{1f}",
            "unicode: Ana Cañas — 東京",
            "\"}{\"injected\":\"x",
        ] {
            let body = format!(r#"{{"q":"{}"}}"#, escape_string_interior(raw));
            let parsed: serde_json::Value = serde_json::from_str(&body)
                .unwrap_or_else(|e| panic!("{raw:?} produced unparseable JSON: {e} -- {body}"));
            assert_eq!(
                parsed["q"].as_str(),
                Some(raw),
                "value must round-trip unchanged"
            );
        }
    }

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
    fn scalar_str_coerces_string_and_number_but_not_bool_or_null() {
        // String borrows in place; number renders canonically.
        assert_eq!(scalar_str(&json!("505")).as_deref(), Some("505"));
        assert!(matches!(scalar_str(&json!("505")), Some(Cow::Borrowed(_))));
        assert_eq!(scalar_str(&json!(505)).as_deref(), Some("505"));
        assert!(matches!(scalar_str(&json!(505)), Some(Cow::Owned(_))));
        // Unlike `val_str_coerce`, the empty string is NOT filtered here — the
        // empty policy belongs to the caller.
        assert_eq!(scalar_str(&json!("")).as_deref(), Some(""));
        // Everything else is absent.
        assert!(scalar_str(&json!(true)).is_none());
        assert!(scalar_str(&json!(null)).is_none());
        assert!(scalar_str(&json!([1, 2])).is_none());
        assert!(scalar_str(&json!({"k": "v"})).is_none());
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
