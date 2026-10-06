//! Deterministic username-variant derivation.
//!
//! This is a pure transform: it never performs I/O and never counts as an
//! independent corroborating source.

use std::collections::BTreeSet;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};

pub const SRC: &str = "username_variants";
const MAX_VARIANTS: usize = 12;
const MIN_HANDLE_LEN: usize = 4;
const VARIANT_CONF: f64 = 0.42;
const SEPARATORS: [char; 3] = ['.', '_', '-'];
const VANITY_TOKENS: &[&str] = &[
    "the", "real", "official", "actual", "original", "og", "im", "iam", "its", "mr", "ms", "mrs",
    "yt", "tv", "hq",
];

#[must_use]
pub fn variants(seed: &str) -> Vec<String> {
    let norm = seed.trim().trim_start_matches('@').to_ascii_lowercase();
    let tokens: Vec<&str> = norm.split(SEPARATORS).filter(|t| !t.is_empty()).collect();
    let collapsed: String = tokens.concat();

    if collapsed.len() < MIN_HANDLE_LEN || !collapsed.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Vec::new();
    }

    let mut out = BTreeSet::new();

    if tokens.len() >= 2 {
        for sep in SEPARATORS {
            add_variant(&mut out, &norm, tokens.join(&sep.to_string()));
        }
        add_variant(&mut out, &norm, collapsed.clone());
    }

    let trailing = collapsed.trim_end_matches(|c: char| c.is_ascii_digit());
    if trailing != collapsed {
        add_variant(&mut out, &norm, trailing.to_owned());
    }

    let leading = collapsed.trim_start_matches(|c: char| c.is_ascii_digit());
    if leading != collapsed && leading.len() >= MIN_HANDLE_LEN {
        add_variant(&mut out, &norm, leading.to_owned());
    }

    let mut core = tokens.clone();
    while core.first().is_some_and(|t| VANITY_TOKENS.contains(t)) {
        core.remove(0);
    }
    while core.last().is_some_and(|t| {
        VANITY_TOKENS.contains(t) || t.bytes().all(|b| b.is_ascii_digit())
    }) {
        core.pop();
    }
    if core.len() != tokens.len() && !core.is_empty() {
        let core_collapsed: String = core.concat();
        if core_collapsed.len() >= MIN_HANDLE_LEN {
            let base = core_collapsed.trim_end_matches(|c: char| c.is_ascii_digit());
            if base != core_collapsed {
                add_variant(&mut out, &norm, base.to_owned());
            }
            add_variant(&mut out, &norm, core_collapsed);
            if core.len() >= 2 {
                for sep in SEPARATORS {
                    add_variant(&mut out, &norm, core.join(&sep.to_string()));
                }
            }
        }
    }

    let mut variants: Vec<String> = out.into_iter().collect();
    variants.truncate(MAX_VARIANTS);
    variants
}

fn add_variant(out: &mut BTreeSet<String>, seed: &str, candidate: String) {
    if candidate.len() >= MIN_HANDLE_LEN && candidate != seed {
        out.insert(candidate);
    }
}

#[must_use]
pub fn entities(seed: &str, scan_id: &str) -> Vec<Entity> {
    variants(seed)
        .into_iter()
        .map(|variant| {
            let mut entity = Entity::new(EntityKind::Username, &variant, VARIANT_CONF, scan_id);
            entity.tag("derived");
            entity.tag("variant");
            entity.tag("candidate");
            entity.add_evidence(
                Evidence::new(
                    EvidenceProvenance::for_scan(SRC, scan_id),
                    format!("Handle variant of '{}'", seed.trim()),
                )
                .with_attr("source_username", seed.trim())
                .with_attr("derivation", "handle_variant")
                .inferred(),
            );
            entity
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separator_swaps_match_legacy_shapes() {
        assert_eq!(
            variants("john.doe"),
            vec!["john-doe", "john_doe", "johndoe"]
        );
    }

    #[test]
    fn strips_numeric_disambiguators() {
        assert!(variants("jdoe1990").contains(&"jdoe".to_owned()));
        assert!(variants("1990jdoe").contains(&"jdoe".to_owned()));
    }

    #[test]
    fn strips_separator_bounded_vanity_tokens() {
        assert!(variants("the_real_jdoe").contains(&"jdoe".to_owned()));
        assert!(variants("jdoe_official").contains(&"jdoe".to_owned()));
    }

    #[test]
    fn plain_or_short_handles_do_not_generate_noise() {
        assert!(variants("jdoe").is_empty());
        assert!(variants("abc").is_empty());
    }

    #[test]
    fn output_is_bounded_and_deterministic() {
        let first = variants("the_real_john.doe.1990_official");
        let second = variants("the_real_john.doe.1990_official");
        assert_eq!(first, second);
        assert!(first.len() <= MAX_VARIANTS);
    }
}
