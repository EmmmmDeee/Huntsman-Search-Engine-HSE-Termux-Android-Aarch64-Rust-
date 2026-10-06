//! Deterministic username-variant derivation.
//!
//! Ports the legacy normalization-only transform: separator swaps and
//! de-decoration. It never invents numeric suffixes or other speculative names.

use std::collections::BTreeSet;

use crate::validation::{ValueKind, is_placeholder_entity};

pub const MAX_VARIANTS: usize = 12;
pub const MIN_HANDLE_LEN: usize = 4;
pub const VARIANT_CONFIDENCE: f64 = 0.42;

const SEPARATORS: [char; 3] = ['.', '_', '-'];
const VANITY_TOKENS: &[&str] = &[
    "the", "real", "official", "actual", "original", "og", "im", "iam", "its", "mr", "ms",
    "mrs", "yt", "tv", "hq",
];

fn add_variant(out: &mut BTreeSet<String>, seed: &str, candidate: String) {
    if candidate.len() >= MIN_HANDLE_LEN && candidate != seed {
        out.insert(candidate);
    }
}

fn trailing_decorator(token: &str) -> bool {
    VANITY_TOKENS.contains(&token) || token.bytes().all(|byte| byte.is_ascii_digit())
}

/// Return sorted, deduplicated, bounded normalization variants.
#[must_use]
pub fn variants(seed: &str) -> Vec<String> {
    let normalized = seed.trim().trim_start_matches('@').to_ascii_lowercase();
    let tokens: Vec<&str> = normalized
        .split(SEPARATORS)
        .filter(|token| !token.is_empty())
        .collect();
    let collapsed: String = tokens.concat();

    if collapsed.len() < MIN_HANDLE_LEN
        || is_placeholder_entity(&ValueKind::Username, &collapsed)
    {
        return Vec::new();
    }

    let mut out = BTreeSet::new();

    if tokens.len() >= 2 {
        for separator in SEPARATORS {
            add_variant(
                &mut out,
                &normalized,
                tokens.join(&separator.to_string()),
            );
        }
        add_variant(&mut out, &normalized, collapsed.clone());
    }

    let trailing_digits_removed = collapsed.trim_end_matches(char::is_numeric);
    if trailing_digits_removed != collapsed {
        add_variant(
            &mut out,
            &normalized,
            trailing_digits_removed.to_owned(),
        );
    }

    let leading_digits_removed = collapsed.trim_start_matches(char::is_numeric);
    if leading_digits_removed != collapsed && leading_digits_removed.len() >= MIN_HANDLE_LEN {
        add_variant(
            &mut out,
            &normalized,
            leading_digits_removed.to_owned(),
        );
    }

    let mut core = tokens.clone();
    while core.first().is_some_and(|token| VANITY_TOKENS.contains(token)) {
        core.remove(0);
    }
    while core.last().is_some_and(|token| trailing_decorator(token)) {
        core.pop();
    }
    if core.len() != tokens.len() && !core.is_empty() {
        let core_collapsed: String = core.concat();
        if core_collapsed.len() >= MIN_HANDLE_LEN {
            let base = core_collapsed.trim_end_matches(char::is_numeric);
            if base != core_collapsed {
                add_variant(&mut out, &normalized, base.to_owned());
            }
            add_variant(&mut out, &normalized, core_collapsed);
            if core.len() >= 2 {
                for separator in SEPARATORS {
                    add_variant(
                        &mut out,
                        &normalized,
                        core.join(&separator.to_string()),
                    );
                }
            }
        }
    }

    let mut result: Vec<String> = out.into_iter().collect();
    result.truncate(MAX_VARIANTS);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separator_swaps_match_legacy_shapes() {
        assert_eq!(
            variants("John.Doe"),
            vec!["john-doe", "john_doe", "johndoe"]
        );
    }

    #[test]
    fn strips_numeric_and_vanity_decorators() {
        let got = variants("the_real_jdoe1990");
        assert!(got.contains(&"jdoe".to_owned()));
        assert!(got.contains(&"jdoe1990".to_owned()));
    }

    #[test]
    fn plain_short_or_placeholder_handles_do_not_expand() {
        assert!(variants("jdoe").is_empty());
        assert!(variants("abc").is_empty());
        assert!(variants("username").is_empty());
    }

    #[test]
    fn result_is_bounded_and_never_contains_seed() {
        let got = variants("the_real_john_doe_official_1990");
        assert!(got.len() <= MAX_VARIANTS);
        assert!(!got.contains(&"the_real_john_doe_official_1990".to_owned()));
    }
}
