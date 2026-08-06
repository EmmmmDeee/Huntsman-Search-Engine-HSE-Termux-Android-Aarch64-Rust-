//! AU-123 — Numeric-variant handle persona linkage.
//!
//! [`canonical_handle`] folds separators and case (`jordan.meyers` →
//! `jordanmeyers`) but deliberately keeps digits, so `jdiegmann` and
//! `jdiegmann92` canonicalise to DIFFERENT tokens — and the exact-match
//! cross-platform rules (AU-011 / AU-034 / AU-046 / AU-076) never join them.
//! Yet appending a number to a base handle — a birth year, a favourite number,
//! an incrementing counter — is one of the most common ways a single operator
//! reuses one identity across services (`jdiegmann` on GitHub, `jdiegmann92` on
//! Keybase, `jdiegmann_2024` on a forum). Folding the *trailing digits* reveals
//! the shared stem and ties the variants to one persona — the username-pivoting
//! tradecraft a permutation generator performs on a seed, applied here across
//! every handle the scan actually observed.
//!
//! This is weaker evidence than an exact handle reuse, so it is gated hard and
//! surfaced at **Medium** as a *lead*, not an identity merge — critical, because
//! a false link here misattributes a real stranger's account to the subject:
//!   * the stem must be distinctive — at least [`MIN_STEM_LEN`] characters, not
//!     a generic role handle ([`is_generic_handle`]), and not a common
//!     word/vanity handle ([`is_common_password`]). This last gate is the one
//!     that matters most: `dragon1`/`dragon2` or `michael1`/`michael2` are two
//!     STRANGERS who each independently picked a popular word, not one operator
//!     — the exact failure mode a dictionary-based password-strength check
//!     already screens for, reused here as a handle-distinctiveness gate;
//!   * at least two DISTINCT canonical handles must share the stem (so genuine
//!     numeric variation exists — two distinct canonicals with one stem can
//!     differ ONLY in their trailing digits);
//!   * the variants must be observed by at least two DISTINCT source modules, so
//!     the link is independently corroborated and never a single module's
//!     permutation flood (those are quarantined `candidate`s excluded upstream).
//!
//! MITRE ATT&CK: T1593.001 (Search Open Websites/Domains: Social Media) — the
//! technique this persona correlation serves, resolving one operator's accounts
//! across platforms.

use super::*;
use crate::util::hashcat::is_common_password;
use std::collections::{BTreeSet, HashSet};

/// Minimum stem length for a distinctive persona key. Stems shorter than this
/// (`dev`, `john`) are too common to link an identity on.
const MIN_STEM_LEN: usize = 5;

/// AU-123 — Numeric-variant handle persona linkage.
///
/// Entity-only: groups `Username` entities by their digit-folded stem and emits
/// one Medium correlation per distinctive stem carried by ≥2 distinct handles
/// from ≥2 distinct sources. `entity_uids` carries every variant's entity, in
/// entity order, so the SPA can render the linked persona.
pub(in crate::core::correlator) fn rule_au_123_numeric_variant_handle_persona(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    #[derive(Default)]
    struct Group {
        /// Distinct canonical handles sharing the stem (the variation count).
        canon_handles: BTreeSet<String>,
        /// Distinct source modules that observed any variant (corroboration).
        sources: BTreeSet<String>,
        /// Display forms for the finding text.
        raw_variants: BTreeSet<String>,
        /// Entity uids of every variant (order re-derived at emit time).
        uids: HashSet<String>,
    }

    // BTreeMap over the stem keeps the emitted findings deterministic regardless
    // of entity iteration order.
    let mut groups: std::collections::BTreeMap<String, Group> = std::collections::BTreeMap::new();
    for e in entities {
        if e.kind != EntityKind::Username {
            continue;
        }
        let canon = canonical_handle(e.value.trim());
        // The stem is the canonical handle with every trailing ASCII digit
        // removed — so it never ends in a digit, and two distinct canonicals
        // sharing a stem provably differ only by a numeric suffix.
        let stem: String = canon
            .trim_end_matches(|c: char| c.is_ascii_digit())
            .to_string();
        // Reject common-role handles AND common dictionary/vanity words: a
        // stem two strangers could each independently pick (a popular word,
        // not a distinctive identity) is too weak to attribute a persona on.
        if stem.len() < MIN_STEM_LEN || is_generic_handle(&stem) || is_common_password(&stem) {
            continue;
        }
        let g = groups.entry(stem).or_default();
        g.canon_handles.insert(canon);
        // Count only INDEPENDENT sources: corroborating_sources() drops the
        // non-corroborating replay/enrichment passes (recall, cross_scan_history,
        // name_intel, geo_normalize, …). Counting raw ev.source let a single
        // genuine observation replayed by `recall` manufacture a phantom 2nd
        // source, so the >= 2-source gate below — which explicitly means
        // "independently corroborated, not a permutation flood" — fired a persona
        // link on what was really one source. Mirrors identity/cluster.rs.
        for src in e.corroborating_sources() {
            g.sources.insert(src.to_string());
        }
        g.raw_variants.insert(e.value.trim().to_string());
        g.uids.insert(e.uid.clone());
    }

    let mut out = Vec::new();
    for (stem, g) in groups {
        // ≥2 distinct canonicals sharing the stem ⟹ real numeric variation;
        // ≥2 distinct sources ⟹ independently corroborated, not a permutation
        // flood. Both gates must hold.
        if g.canon_handles.len() < 2 || g.sources.len() < 2 {
            continue;
        }
        // Re-derive uids in entity order for a stable render (mirrors AU-118).
        let uids: Vec<String> = entities
            .iter()
            .filter(|e| g.uids.contains(e.uid.as_str()))
            .map(|e| e.uid.clone())
            .collect();
        let variants = join_capped(g.raw_variants.iter().map(String::as_str), 6);
        out.push(Correlation::new(
            "AU-123",
            "Numeric-variant handle persona",
            Severity::Medium,
            format!(
                "{} handles from {} sources share the stem '{}', differing only by a trailing \
                 numeric suffix ({}) — the base-handle-plus-number pattern one operator reuses \
                 across platforms, linking the variants to a single persona. Weaker than an \
                 exact handle match: treat as a lead.",
                // The count and the listed variants must agree — both counted
                // over raw display forms, never the coarser canonical count
                // (which can undercount when the same canonical has multiple
                // raw spellings, e.g. "JDiegmann92" and "jdiegmann_92").
                g.raw_variants.len(),
                g.sources.len(),
                stem,
                variants,
            ),
            uids,
            scan_id,
            ts,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::confidence;
    use crate::core::entity::Evidence;

    /// A confirmed Username entity from a named source module.
    fn handle(value: &str, source: &str) -> Entity {
        let mut e = Entity::new(EntityKind::Username, value, confidence::HIGH_PLUS, "s");
        e.add_evidence(Evidence::new(source, "found"));
        e
    }

    #[test]
    fn au123_links_numeric_variants_across_sources() {
        let a = handle("jdiegmann", "github_user");
        let b = handle("jdiegmann92", "keybase");
        let out = rule_au_123_numeric_variant_handle_persona(
            &RuleContext::new(&[a.clone(), b.clone()]),
            "s",
            0,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "AU-123");
        assert_eq!(out[0].severity, Severity::Medium);
        assert!(out[0].entity_uids.contains(&a.uid));
        assert!(out[0].entity_uids.contains(&b.uid));
    }

    #[test]
    fn au123_links_three_variants_by_shared_stem() {
        let out = rule_au_123_numeric_variant_handle_persona(
            &RuleContext::new(&[
                handle("steven", "github_user"),
                handle("steven90", "keybase"),
                handle("steven_2024", "mastodon_user"), // separator + digits fold too
            ]),
            "s",
            0,
        );
        assert_eq!(out.len(), 1, "one stem → one persona finding");
        assert_eq!(out[0].entity_uids.len(), 3);
    }

    #[test]
    fn au123_silent_without_source_diversity() {
        // Two numeric variants, but both from the SAME module — could be one
        // module's permutation output, not independent corroboration.
        let out = rule_au_123_numeric_variant_handle_persona(
            &RuleContext::new(&[
                handle("jdiegmann", "github_user"),
                handle("jdiegmann92", "github_user"),
            ]),
            "s",
            0,
        );
        assert!(out.is_empty(), "single source is not corroboration");
    }

    #[test]
    fn au123_recall_replay_does_not_manufacture_source_diversity() {
        // Both variants come from ONE genuine source (github_user); a `recall`
        // replay of that same observation must NOT count as a second independent
        // source. corroborating_sources() drops `recall`, so the >= 2-source gate
        // stays closed — the phantom-corroboration false positive the filter
        // prevents. Under the old raw-ev.source count this fired.
        let a = handle("jdiegmann", "github_user");
        let mut b = handle("jdiegmann92", "github_user");
        b.add_evidence(Evidence::new("recall", "seen in an earlier scan"));
        let out = rule_au_123_numeric_variant_handle_persona(&RuleContext::new(&[a, b]), "s", 0);
        assert!(
            out.is_empty(),
            "a recall replay must not manufacture a phantom 2nd source: {out:?}"
        );
    }

    #[test]
    fn au123_silent_without_numeric_variation() {
        // The SAME handle from two sources is exact reuse (AU-011's job), not a
        // numeric variant — one distinct canonical, so AU-123 stays silent.
        let out = rule_au_123_numeric_variant_handle_persona(
            &RuleContext::new(&[
                handle("jdiegmann", "github_user"),
                handle("jdiegmann", "keybase"),
            ]),
            "s",
            0,
        );
        assert!(out.is_empty(), "no numeric variation → not this rule");
    }

    #[test]
    fn au123_silent_on_short_or_generic_stems() {
        // Short stem ("dev", len 3) and generic role handle ("support") link
        // nothing — too common to attribute a persona.
        assert!(
            rule_au_123_numeric_variant_handle_persona(
                &RuleContext::new(&[handle("dev", "github_user"), handle("dev92", "keybase")]),
                "s",
                0
            )
            .is_empty(),
            "short stem must not link"
        );
        assert!(
            rule_au_123_numeric_variant_handle_persona(
                &RuleContext::new(&[
                    handle("support", "github_user"),
                    handle("support2", "keybase")
                ]),
                "s",
                0
            )
            .is_empty(),
            "generic role stem must not link"
        );
    }

    #[test]
    fn au123_silent_on_common_word_stems_two_strangers_could_share() {
        // `dragon1`/`dragon2` are NOT necessarily one operator — they could be
        // two different people who each independently picked a popular word.
        // A stem that is a common dictionary/vanity word must not attribute a
        // persona, the same reasoning `is_common_password` already encodes for
        // credential reuse (AU-105): shared popularity is not shared identity.
        assert!(
            rule_au_123_numeric_variant_handle_persona(
                &RuleContext::new(&[
                    handle("dragon1", "github_user"),
                    handle("dragon2", "keybase")
                ]),
                "s",
                0
            )
            .is_empty(),
            "common-word stem must not link two possible strangers"
        );
        assert!(
            rule_au_123_numeric_variant_handle_persona(
                &RuleContext::new(&[
                    handle("michael1", "github_user"),
                    handle("michael2", "keybase")
                ]),
                "s",
                0
            )
            .is_empty(),
            "common first-name-as-password stem must not link"
        );
    }

    #[test]
    fn au123_finding_text_count_matches_the_listed_variants() {
        // Regression: the reported count must equal the number of variants
        // actually listed, even when two raw spellings fold to the SAME
        // canonical handle. `Entity::new` case-folds a Username at
        // construction (so a case-only difference can never even reach this
        // rule), but it deliberately preserves separators — so
        // "jdiegmann_92" and "jdiegmann-92" survive as two DISTINCT stored
        // values that `canonical_handle` (which strips `.`/`_`/`-`) still
        // folds to one canonical "jdiegmann92". The reported count must
        // track the raw display list (3), never the coarser distinct-
        // canonical figure (2), or the finding text would understate what it
        // actually lists.
        let out = rule_au_123_numeric_variant_handle_persona(
            &RuleContext::new(&[
                handle("jdiegmann_92", "github_user"), // canonical: jdiegmann92
                handle("jdiegmann-92", "keybase"),     // canonical: jdiegmann92 (same!)
                handle("jdiegmann87", "mastodon_user"), // canonical: jdiegmann87 (distinct)
            ]),
            "s",
            0,
        );
        assert_eq!(out.len(), 1);
        let desc = &out[0].description;
        assert!(
            desc.starts_with("3 handles"),
            "count must match the 3 listed raw variants, not the 2 distinct canonicals: {desc}"
        );
        assert!(desc.contains("jdiegmann_92"));
        assert!(desc.contains("jdiegmann-92"));
        assert!(desc.contains("jdiegmann87"));
    }

    #[test]
    fn au123_ignores_non_username_entities() {
        let mut d1 = Entity::new(
            EntityKind::Domain,
            "jdiegmann.com",
            confidence::HIGH_PLUSPLUS,
            "s",
        );
        d1.add_evidence(Evidence::new("whois", "found"));
        let mut d2 = Entity::new(
            EntityKind::Domain,
            "jdiegmann92.com",
            confidence::HIGH_PLUSPLUS,
            "s",
        );
        d2.add_evidence(Evidence::new("dns_intel", "found"));
        assert!(
            rule_au_123_numeric_variant_handle_persona(&RuleContext::new(&[d1, d2]), "s", 0)
                .is_empty(),
            "AU-123 is a Username-only persona rule"
        );
    }
}
