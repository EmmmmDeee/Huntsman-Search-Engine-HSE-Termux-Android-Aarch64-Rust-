//! `name_intel` — NAMINT-style name intelligence.
//!
//! Given a `FullName` seed this module derives, with **no network calls**:
//!
//!   * plausible **usernames** (→ `username_search`, `social_probe`,
//!     `github_user`, `keybase`),
//!   * speculative **emails** across a provider set (→ the whole email pivot
//!     pipeline: `hibp`, `hunter_io`, `epieos`, `emailrep`, `disposable_check`,
//!     `email_parse`, …), each carrying its **Gravatar** avatar URL,
//!   * ready-to-click **search-query pivots** (Google/Bing/DuckDuckGo/Yandex
//!     dorks + LinkedIn/Facebook/X/Instagram/TikTok/GitHub/WhatsMyName/Epieos).
//!
//! Permutations are emitted as low-confidence *candidate* entities: they enrich
//! the graph, feed the correlator's identity-surface rules, and are expanded by
//! the comprehensive default scan (the `--min-expand-confidence` floor is 0.20, at
//! or below the permutation confidences `EMAIL_CONF`/`PIVOT_CONF`), so every
//! derived identifier gets a chance to surface unique data downstream. The
//! correlator's own strict confidence floors keep the *resolved* findings precise
//! regardless. Raise `--min-expand-confidence` for a tighter, cheaper sweep that
//! skips the guesses.
//!
//! Priority 97 so derived identifiers exist during the seed round. Pure string
//! transformation + one MD5 — no C deps, ideal for Termux/aarch64.

mod permute;

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "name_intel";

pub struct NameIntel;

#[async_trait]
impl Module for NameIntel {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "NAMINT-style name intelligence — derives usernames, emails, Gravatars, and platform search pivots from a full name (offline)"
    }
    fn priority(&self) -> u8 {
        97
    }
    fn is_passive(&self) -> bool {
        true
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName)
    }
    fn attack_techniques(&self) -> &'static [&'static str] {
        // This module never overrode the default, so it silently inherited the
        // full People-category pair (T1589.003 Employee Names + T1591.004
        // Identify Roles) — the exact over/under-claim shape already fixed for
        // `pgp`: the subject Person anchor and the derived username/email
        // permutations surface a name (T1589.003) and speculative email
        // addresses (T1589.002), but this module carries no role/organisational
        // information anywhere, so T1591.004 is over-claimed. The search-query
        // pivot URLs are unexecuted links (this module makes no network calls,
        // per its own doc comment), not a confirmed collection, so — mirroring
        // `employer_pivot`'s Url entities — they earn no separate technique.
        &["T1589.002", "T1589.003"]
    }
    fn produces(&self) -> &'static [EntityKind] {
        &[
            EntityKind::Person,
            EntityKind::Username,
            EntityKind::Email,
            EntityKind::Url,
        ]
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let sid = &ctx.scan_id;
        // Parse the name into tokens for the DERIVED identifiers below. `parse`
        // returns `None` for a single-token name (a mononym — "Madonna",
        // "Sukarno"); the subject anchor must NOT depend on it (see below).
        let parsed = permute::parse(&target.value);
        // CLEANED, canonical display name recorded in `source_name` — not the raw
        // `target.value`. A re-expansion pass can feed a quote/comma-contaminated
        // breach-derived Person value (`"Matthew Diegmann",`) back in as the
        // target; writing that verbatim made every derived entity's evidence
        // accumulate the junk on merge. `display_full()` is the quote/comma-
        // stripped reconstruction the clean seed also produces; for an unparseable
        // mononym the trimmed seed itself is already that clean form.
        let display = match &parsed {
            Some(name) => name.display_full(),
            None => target.value.trim().to_string(),
        };

        // ── Subject anchor ──────────────────────────────────────────────────
        // Emit the Person the operator named as the seed FIRST, so every derived
        // username/email/pivot has an individual to attach to (without it the
        // dossier is a pile of orphan handles, and the person-cluster correlators
        // AU-002/AU-020 have no Person to fire on). Probable-tier: it is the
        // operator's asserted subject, not a guess — but unverified externally.
        // ALWAYS emitted — before the parse gate and the handle gate — so a
        // single-token name (which `permute::parse` can't split) and a non-Latin
        // name both still get a subject node. Without this a mononym FullName seed
        // vanished from its own report (no engine fallback: `seed_anchor_entity`
        // delegates FullName here).
        if !crate::core::validation::is_placeholder_entity(&EntityKind::Person, &target.value) {
            let mut person = Entity::new(
                EntityKind::Person,
                display.clone(),
                permute::SUBJECT_CONF,
                sid,
            );
            person.tag("seed");
            person.tag("subject");
            person.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Scan subject — '{}' provided as the seed", target.value),
                )
                .with_attr("source_name", &display),
            );
            result.push(person);
        }

        // The DERIVED identifiers (username/email permutations, pivots) need a
        // parseable ≥2-token name; a mononym yields only the anchor above.
        let Some(name) = parsed else {
            return Ok(result);
        };

        // Non-Latin names ASCII-fold to empty handle tokens; skip username/email
        // permutation (which would be meaningless) but still emit search pivots
        // built from the display name.
        let has_handle = !name.first.is_empty() && !name.last.is_empty();

        // ── Usernames ───────────────────────────────────────────────────────
        if has_handle {
            for u in permute::usernames(&name) {
                let mut e = Entity::new(EntityKind::Username, &u.handle, u.weight, sid);
                e.tag("derived");
                e.tag("name-derived");
                e.add_evidence(
                    Evidence::new(SRC, format!("Username '{}' derived from name", u.handle))
                        .with_attr("source_name", &display),
                );
                result.push(e);
            }
        }

        // ── Emails (+ Gravatar) ─────────────────────────────────────────────
        let emails = if has_handle {
            permute::emails(&name, &permute::email_domains())
        } else {
            Vec::new()
        };
        for addr in &emails {
            let mut e = Entity::new(EntityKind::Email, addr, permute::EMAIL_CONF, sid);
            e.tag("derived");
            e.tag("name-derived");
            e.tag("permuted");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Speculative email '{addr}' permuted from name"),
                )
                .with_attr("source_name", &display)
                .with_attr("gravatar", permute::gravatar_url(addr)),
            );
            result.push(e);
        }

        // ── Search-query / people-search pivots ─────────────────────────────
        for piv in permute::pivots(&name, emails.first().map(String::as_str)) {
            let mut e = Entity::new(EntityKind::Url, &piv.url, permute::PIVOT_CONF, sid);
            e.tag("search-pivot");
            e.tag("name-intel");
            e.tag("passive");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("{} pivot for '{}'", piv.platform, name.display_full()),
                )
                .with_attr("platform", piv.platform)
                .with_attr("source_name", &display),
            );
            result.push(e);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
