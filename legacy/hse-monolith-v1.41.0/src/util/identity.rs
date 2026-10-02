//! Provider-agnostic identity-demographic extraction shared by the breach
//! providers (SeekNow, OathNet). Both surface the same V2 breach schema, so
//! lifting these two helpers to one place lets their Person nodes carry the
//! same normalized `dob:`/`gender:`/`age:` tags (filterable/mergeable alike)
//! and gate their `steam:<id>` Username pivots by one identical rule — closing
//! a pure parity gap rather than reimplementing per provider.

use serde_json::Value;

use crate::util::json::val_str;

/// Normalized identity-demographic tags (`dob:` / `gender:` / `age:`) for a
/// subject node, read across the key spellings the breach providers use for the
/// same datum. Returned in a stable order; empty when the record carries no
/// demographics. Callers stamp these on the Person so the subject's headline
/// surfaces its demographics as first-class, queryable tags (`gender:M` from one
/// record merges with `gender:male` from another).
///
/// ```
/// use huntsman_search_engine::util::identity::identity_tags;
///
/// let v = serde_json::json!({ "date_birth": "1990-01-01", "gender": "female", "age": 34 });
/// assert_eq!(identity_tags(&v), ["dob:1990-01-01", "gender:F", "age:34"]);
/// assert!(identity_tags(&serde_json::json!({})).is_empty());
/// ```
#[must_use]
pub fn identity_tags(item: &Value) -> Vec<String> {
    let mut tags = Vec::new();
    // Date of birth — one canonical `dob:` tag from whichever key holds it.
    if let Some(dob) = val_str(item, "date_birth")
        .or_else(|| val_str(item, "birthdate"))
        .or_else(|| val_str(item, "date_of_birth"))
        .or_else(|| val_str(item, "dob"))
    {
        let d = dob.trim();
        if !d.is_empty() {
            tags.push(format!("dob:{d}"));
        }
    }
    // Gender — collapse the obvious spellings to a single uppercase initial so
    // `gender:M` from one record merges with `gender:male` from another.
    if let Some(g) = val_str(item, "gender") {
        let gt = g.trim();
        if !gt.is_empty() {
            let norm = match gt.to_ascii_lowercase().as_str() {
                "m" | "male" => "M",
                "f" | "female" => "F",
                _ => gt,
            };
            tags.push(format!("gender:{norm}"));
        }
    }
    // Age — a number or a numeric string; skip a placeholder/zero.
    let age = item.get("age").map(|a| {
        if a.is_number() {
            a.to_string()
        } else {
            a.as_str().unwrap_or("").trim().to_string()
        }
    });
    if let Some(a) = age
        && !a.is_empty()
        && a != "0"
    {
        tags.push(format!("age:{a}"));
    }
    tags
}

/// Strict SteamID64 heuristic: exactly 17 digits, no leading zero. Shared so
/// both breach providers gate their `steam:<id>` Username pivots identically —
/// a leaked SteamID64 is a high-value gaming-endpoint pivot, but only when it
/// actually validates as one.
///
/// ```
/// use huntsman_search_engine::util::identity::looks_like_steam_id;
///
/// assert!(looks_like_steam_id("76561198000000000")); // 17 digits, no leading zero
/// assert!(!looks_like_steam_id("7656119800000000")); // 16 digits
/// assert!(!looks_like_steam_id("07561198000000000")); // leading zero
/// assert!(!looks_like_steam_id("765611x8000000000")); // non-digit
/// ```
#[must_use]
pub fn looks_like_steam_id(s: &str) -> bool {
    s.len() == 17 && s.chars().all(|c| c.is_ascii_digit()) && !s.starts_with('0')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_tags_reads_every_dob_spelling() {
        for key in ["date_birth", "birthdate", "date_of_birth", "dob"] {
            let v = serde_json::json!({ key: "1985-06-15" });
            assert_eq!(identity_tags(&v), ["dob:1985-06-15"], "spelling {key}");
        }
    }

    #[test]
    fn identity_tags_normalises_gender_and_skips_zero_age() {
        assert_eq!(
            identity_tags(&serde_json::json!({ "gender": "MALE" })),
            ["gender:M"]
        );
        assert_eq!(
            identity_tags(&serde_json::json!({ "gender": "f" })),
            ["gender:F"]
        );
        // A non-binary/other value is preserved verbatim.
        assert_eq!(
            identity_tags(&serde_json::json!({ "gender": "nonbinary" })),
            ["gender:nonbinary"]
        );
        // A placeholder zero age is skipped; a real numeric string is kept.
        assert!(identity_tags(&serde_json::json!({ "age": 0 })).is_empty());
        assert_eq!(
            identity_tags(&serde_json::json!({ "age": "27" })),
            ["age:27"]
        );
    }

    #[test]
    fn identity_tags_order_is_dob_gender_age() {
        let v = serde_json::json!({ "dob": "1990-01-01", "gender": "M", "age": 34 });
        assert_eq!(identity_tags(&v), ["dob:1990-01-01", "gender:M", "age:34"]);
    }

    #[test]
    fn identity_tags_empty_and_blank_yield_nothing() {
        assert!(identity_tags(&serde_json::json!({})).is_empty());
        // Blank strings are treated as absent (val_str drops empties).
        assert!(identity_tags(&serde_json::json!({ "dob": "", "gender": "  " })).is_empty());
    }

    #[test]
    fn steam_id_strict_heuristic() {
        assert!(looks_like_steam_id("76561198000000000"));
        assert!(looks_like_steam_id("76561198123456789"));
        assert!(!looks_like_steam_id("7656119800000000")); // 16
        assert!(!looks_like_steam_id("765611980000000000")); // 18
        assert!(!looks_like_steam_id("07561198000000000")); // leading zero
        assert!(!looks_like_steam_id("765611x8000000000")); // non-digit
        assert!(!looks_like_steam_id(""));
    }
}
