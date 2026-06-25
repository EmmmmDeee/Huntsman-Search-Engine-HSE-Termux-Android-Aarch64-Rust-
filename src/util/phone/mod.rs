//! Shared E.164 phone-number extraction from free text.
//!
//! Both `web_crawler::crawl_util` and `search_engines::helpers::entity::extractors`
//! implement the same byte-scan loop. This module is the single canonical
//! implementation; callers choose their collection strategy.

/// Extract E.164 phone numbers from `text` and call `collect` once per
/// validated number string (e.g., `"+16502530000"`).
///
/// The byte-scan rules:
/// - Token starts with `+` followed by a digit in `1..=9` (country-code gate).
/// - Continued with ASCII digits, `-`, ` `, `(`, `)`.
/// - Final digit count must be in `10..=15` (E.164 bounds, matches [`crate::core::validation`]).
/// - Numbers that pass `crate::core::validation::validate_phone_e164` are accepted.
///
/// `cap`: maximum number of tokens to collect before stopping (use `usize::MAX`
/// for uncapped).  When `cap` is reached the function returns `true` (truncated);
/// otherwise returns `false`.
pub fn scan_phones(text: &str, cap: usize, mut collect: impl FnMut(String)) -> bool {
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut count = 0usize;

    while i < len {
        if bytes[i] == b'+' && i + 10 < len && matches!(bytes[i + 1], b'1'..=b'9') {
            let start = i;
            i += 1;
            let mut digits = 0u32;
            while i < len
                && (bytes[i].is_ascii_digit()
                    || bytes[i] == b'-'
                    || bytes[i] == b' '
                    || bytes[i] == b'('
                    || bytes[i] == b')')
            {
                if bytes[i].is_ascii_digit() {
                    digits += 1;
                }
                i += 1;
            }
            if (10..=15).contains(&digits) {
                let cleaned: String = text[start..i]
                    .chars()
                    .filter(|c| c.is_ascii_digit() || *c == '+')
                    .collect();
                if crate::core::validation::validate_phone_e164(&cleaned).valid {
                    collect(cleaned);
                    count += 1;
                    if count >= cap {
                        return true;
                    }
                }
            }
        } else {
            i += 1;
        }
    }
    false
}
