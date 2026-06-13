//! Derive alternate-handle variants from a `Username` seed — pure offline, no
//! network. People reuse one identity across platforms with different
//! punctuation and vanity decoration; this module turns a single discovered
//! username into the handful of high-likelihood alternate handles the
//! username-search modules (`username_search`, `social_probe`, `github_user`,
//! `keybase`) should also probe at `--depth 1+`.
//!
//! It is deliberately *normalisation-only*, not speculative guessing — it only
//! ever produces variants that are demonstrably the same handle rewritten:
//!   * **separator swaps** — `john.doe` ⇒ `john_doe`, `john-doe`, `johndoe`
//!     (the one handle written for each platform's punctuation rules);
//!   * **de-decoration** — strip a trailing disambiguator (`jdoe1990` ⇒ `jdoe`)
//!     or separator-bounded vanity tokens (`the_real_jdoe` ⇒ `jdoe`,
//!     `jdoe_official` ⇒ `jdoe`).
//!
//! A plain, undecorated handle (`jdoe`) yields **nothing** — there is no
//! defensible transformation, and `username_search` already probes the exact
//! handle. Speculative additions (`jdoe1`, `jdoe_`) are intentionally *not*
//! generated: they are noise.
//!
//! Variants are emitted as low-confidence *candidates* (0.42, below the 0.50
//! expansion floor) so a plain `--depth` scan never auto-spends API budget on a
//! guessed handle. They still enrich the graph and feed the AU-034 handle-reuse
//! correlator, and a variant only crosses the expansion floor if an independent
//! source corroborates it (raising its `C_eff`). Output is hard-capped at
//! [`MAX_VARIANTS`] so one seed generates constant-bounded work on Termux.

use std::collections::BTreeSet;

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "username_variants";

/// Hard cap on emitted variants — keeps a single seed constant-bounded on
/// low-power Termux/aarch64 regardless of how decorated the handle is.
const MAX_VARIANTS: usize = 12;

/// Minimum handle length to bother with — shorter handles are too ambiguous to
/// generate useful alternates and tend to be initials / noise.
const MIN_HANDLE_LEN: usize = 4;

/// Candidate confidence — deliberately below the 0.50 expansion floor so a
/// plain `--depth` scan never auto-spends on a guessed handle. The variant
/// still enriches the graph and the AU-034 correlator, and only rises above the
/// floor if an independent source corroborates it.
const VARIANT_CONF: f64 = 0.42;

/// The handle separators people swap between across platforms.
const SEPARATORS: [char; 3] = ['.', '_', '-'];

/// Vanity / decorator tokens stripped from the ends of a separator-split handle
/// (`the_real_jdoe` → `jdoe`, `jdoe_official` → `jdoe`). Only ever removed when
/// separator-bounded, so a plain word that merely starts with one of these
/// (e.g. `theatre`, `mrkts`) is never mutilated.
const VANITY_TOKENS: &[&str] = &[
    "the", "real", "official", "actual", "original", "og", "im", "iam", "its", "mr", "ms", "mrs",
    "yt", "tv", "hq",
];

pub struct UsernameVariants;

/// Insert `c` into `out` iff it is long enough and not the seed itself.
fn add_variant(out: &mut BTreeSet<String>, seed_norm: &str, c: String) {
    if c.len() >= MIN_HANDLE_LEN && c != seed_norm {
        out.insert(c);
    }
}

/// True if `tok` is a separator-bounded vanity token or an all-digit run.
fn is_trailing_decorator(tok: &str) -> bool {
    VANITY_TOKENS.contains(&tok) || tok.bytes().all(|b| b.is_ascii_digit())
}

impl UsernameVariants {
    /// Pure variant generator — separated from `process` so it is unit-testable
    /// without a `ModuleContext`. Returns deduplicated, lexically-sorted,
    /// capped variants and never includes the (normalised) seed itself.
    fn variants(seed: &str) -> Vec<String> {
        let norm = seed.trim().to_ascii_lowercase();
        let tokens: Vec<&str> = norm.split(SEPARATORS).filter(|t| !t.is_empty()).collect();
        let collapsed: String = tokens.concat();

        // Too short, or a placeholder / role handle → nothing useful to derive.
        if collapsed.len() < MIN_HANDLE_LEN
            || crate::util::preflight::is_placeholder_username(&collapsed)
        {
            return Vec::new();
        }

        let mut out: BTreeSet<String> = BTreeSet::new();

        // 1. Separator swaps over the original tokens (john.doe → john_doe,
        //    john-doe, johndoe). Only meaningful with ≥ 2 tokens.
        if tokens.len() >= 2 {
            for sep in SEPARATORS {
                add_variant(&mut out, &norm, tokens.join(&sep.to_string()));
            }
            add_variant(&mut out, &norm, collapsed.clone());
        }

        // 2. Trailing-digit strip on the collapsed form (jdoe1990 → jdoe).
        let deburred = collapsed.trim_end_matches(|c: char| c.is_ascii_digit());
        if deburred != collapsed {
            add_variant(&mut out, &norm, deburred.to_string());
        }

        // 3. Strip separator-bounded vanity tokens (lead) and vanity-or-numeric
        //    tokens (trail), then re-emit the surviving core in every separator
        //    form (the_real_jdoe → jdoe; john.doe.1990 → john.doe / johndoe / …).
        let mut core: Vec<&str> = tokens.clone();
        while core.first().is_some_and(|t| VANITY_TOKENS.contains(t)) {
            core.remove(0);
        }
        while core.last().is_some_and(|t| is_trailing_decorator(t)) {
            core.pop();
        }
        if core.len() != tokens.len() && !core.is_empty() {
            let core_collapsed: String = core.concat();
            if core_collapsed.len() >= MIN_HANDLE_LEN {
                // Also strip a trailing numeric disambiguator from the
                // de-decorated core, so `the_real_jdoe1990` reaches the bare
                // `jdoe` (the highest-value canonical handle), not just
                // `jdoe1990`.
                let core_base = core_collapsed.trim_end_matches(|c: char| c.is_ascii_digit());
                if core_base != core_collapsed {
                    add_variant(&mut out, &norm, core_base.to_string());
                }
                add_variant(&mut out, &norm, core_collapsed);
                if core.len() >= 2 {
                    for sep in SEPARATORS {
                        add_variant(&mut out, &norm, core.join(&sep.to_string()));
                    }
                }
            }
        }

        let mut v: Vec<String> = out.into_iter().collect();
        v.truncate(MAX_VARIANTS);
        v
    }
}

#[async_trait]
impl Module for UsernameVariants {
    fn name(&self) -> &'static str {
        "username_variants"
    }

    fn description(&self) -> &'static str {
        "Derive alternate-handle variants (separator swaps, de-decoration) from a username to feed username search"
    }

    fn priority(&self) -> u8 {
        98
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Username];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let variants = Self::variants(&target.value);
        let mut result = ModuleResult::with_capacity(variants.len());
        result.extend(variants.into_iter().map(|v| {
            let mut e = Entity::new(EntityKind::Username, &v, VARIANT_CONF, &ctx.scan_id);
            e.tag("derived");
            e.tag("variant");
            e.tag("candidate");
            e.add_evidence(
                Evidence::new(SRC, format!("Handle variant of '{}'", target.value))
                    .with_attr("source_username", &target.value)
                    .with_attr("derivation", "handle_variant"),
            );
            e
        }));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn ctx() -> ModuleContext {
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        ModuleContext {
            scan_id: "t".into(),
            bus,
            http: crate::util::http::build_client(),
            keys: HashMap::default(),
            cancel: crate::core::cancel::CancelHandle::new(),
            proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
        }
    }

    #[test]
    fn separator_swaps_cover_all_forms() {
        let v = UsernameVariants::variants("john.doe");
        assert!(v.contains(&"john_doe".to_string()));
        assert!(v.contains(&"john-doe".to_string()));
        assert!(v.contains(&"johndoe".to_string()));
        // never emits the seed itself
        assert!(!v.contains(&"john.doe".to_string()));
    }

    #[test]
    fn strips_trailing_digits() {
        assert_eq!(UsernameVariants::variants("jdoe1990"), vec!["jdoe"]);
        assert_eq!(UsernameVariants::variants("jdoe123"), vec!["jdoe"]);
    }

    #[test]
    fn strips_separator_bounded_vanity_tokens() {
        assert!(UsernameVariants::variants("the_real_jdoe").contains(&"jdoe".to_string()));
        assert!(UsernameVariants::variants("jdoe_official").contains(&"jdoe".to_string()));
        // Vanity tokens AND a trailing numeric disambiguator both stripped →
        // the bare canonical handle is reached.
        assert!(UsernameVariants::variants("the_real_jdoe1990").contains(&"jdoe".to_string()));
        // leading + trailing decoration and a numeric tail all stripped
        let v = UsernameVariants::variants("the.john.doe.1990");
        assert!(v.contains(&"johndoe".to_string()));
        assert!(v.contains(&"john_doe".to_string()));
    }

    #[test]
    fn plain_handle_yields_nothing() {
        // No separator, no digits, no vanity → no defensible transformation.
        assert!(UsernameVariants::variants("jdoe").is_empty());
        assert!(UsernameVariants::variants("alice").is_empty());
    }

    #[test]
    fn rejects_short_and_placeholder_handles() {
        assert!(UsernameVariants::variants("ab").is_empty());
        assert!(UsernameVariants::variants("a.b").is_empty()); // collapses to "ab" (len 2)
        assert!(UsernameVariants::variants("admin").is_empty());
        assert!(UsernameVariants::variants("test").is_empty());
    }

    #[test]
    fn output_is_bounded_sorted_and_deduped() {
        let v = UsernameVariants::variants("a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p");
        assert!(v.len() <= MAX_VARIANTS);
        // sorted + deduped (BTreeSet invariant)
        let mut sorted = v.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(v, sorted);
    }

    #[tokio::test]
    async fn process_emits_candidate_usernames() {
        let t = Target::new(TargetKind::Username, "john.doe");
        let r = UsernameVariants.process(&t, &ctx()).await.unwrap();
        assert!(!r.entities.is_empty());
        for e in &r.entities {
            assert_eq!(e.kind, EntityKind::Username);
            assert!((e.confidence - VARIANT_CONF).abs() < 1e-9);
            assert!(e.confidence < 0.50, "must stay below the expansion floor");
            assert!(e.has_tag("variant"));
            assert!(e.has_tag("candidate"));
            assert_eq!(e.evidence[0].source, SRC);
        }
    }

    #[tokio::test]
    async fn process_emits_nothing_for_plain_handle() {
        let t = Target::new(TargetKind::Username, "jdoe");
        let r = UsernameVariants.process(&t, &ctx()).await.unwrap();
        assert!(r.entities.is_empty());
    }

    #[test]
    fn accepts_username_only() {
        assert!(UsernameVariants.accepts(&Target::new(TargetKind::Username, "x")));
        assert!(!UsernameVariants.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!UsernameVariants.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }

    #[test]
    fn is_passive_and_social() {
        assert!(UsernameVariants.is_passive());
        assert_eq!(UsernameVariants.category(), ModuleCategory::Social);
    }
}
