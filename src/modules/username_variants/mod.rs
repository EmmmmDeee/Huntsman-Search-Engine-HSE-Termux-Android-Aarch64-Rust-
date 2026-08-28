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
//! Variants are emitted as low-confidence *candidates* (0.42, below the confidence::MEDIUM
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

/// Candidate confidence — deliberately below the confidence::MEDIUM expansion floor so a
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

        // 2a. Trailing-digit strip on the collapsed form (jdoe1990 → jdoe).
        let deburred = collapsed.trim_end_matches(|c: char| c.is_ascii_digit());
        if deburred != collapsed {
            add_variant(&mut out, &norm, deburred.to_string());
        }

        // 2b. Leading-digit strip: year- or number-prefixed handles like
        //     `90jdoe`, `2001smith`, `00hbamford` — the digits mark a birth
        //     year, graduation year or numeric disambiguator. Strip the leading
        //     run of digits from the COLLAPSED form. Only fire when the
        //     remaining alpha core is ≥ MIN_HANDLE_LEN (short remainders like
        //     `90ab` are too ambiguous). Complement of the trailing-digit pass.
        let lead_stripped = collapsed.trim_start_matches(|c: char| c.is_ascii_digit());
        if lead_stripped != collapsed && lead_stripped.len() >= MIN_HANDLE_LEN {
            add_variant(&mut out, &norm, lead_stripped.to_string());
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
        "Handle-variant recon — derives alternate handles (separator swaps, de-decoration) from a username to feed username search"
    }

    fn priority(&self) -> u8 {
        98
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username | TargetKind::Email)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Generates Username variants (T1593.001 Social-media, T1589.003
        // Employee Names) and — when called on an Email seed — also covers
        // T1589.002 Email Addresses. Superset of the Social category default.
        &["T1593.001", "T1589.002", "T1589.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Username];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // For Email seeds, derive variants from the local part (text before @).
        // This surfaces separator-swap variants at depth=0 before any expansion
        // round dispatches `username_variants` on the derived Username entities.
        let (seed, source_key, source_val): (String, &'static str, String) = match target.kind {
            TargetKind::Email => {
                let local_raw = target.value.split('@').next().unwrap_or("");
                // Strip plus-addressing (e.g. `user+tag@example.com` → `user`).
                let local = local_raw
                    .split('+')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                (local, "source_email", target.value.clone())
            }
            _ => (
                target.value.clone(),
                "source_username",
                target.value.clone(),
            ),
        };

        let variants = Self::variants(&seed);
        let mut result = ModuleResult::with_capacity(variants.len());
        result.extend(variants.into_iter().map(|v| {
            let mut e = Entity::new(EntityKind::Username, &v, VARIANT_CONF, &ctx.scan_id);
            e.tag("derived");
            e.tag("variant");
            e.tag("candidate");
            e.add_evidence(
                Evidence::new(SRC, format!("Handle variant of '{seed}'"))
                    .with_attr(source_key, &source_val)
                    .with_attr("derivation", "handle_variant"),
            );
            e
        }));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
