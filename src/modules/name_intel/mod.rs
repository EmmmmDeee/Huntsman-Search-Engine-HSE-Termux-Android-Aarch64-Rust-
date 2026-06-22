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
        "NAMINT-style name intelligence: derive usernames, emails, Gravatars and \
         platform search pivots from a full name (offline)"
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
        let Some(name) = permute::parse(&target.value) else {
            return Ok(result);
        };
        let sid = &ctx.scan_id;

        // ── Subject anchor ──────────────────────────────────────────────────
        // Emit the Person the operator named as the seed FIRST, so every derived
        // username/email/pivot has an individual to attach to (without it the
        // dossier is a pile of orphan handles, and the person-cluster correlators
        // AU-002/AU-020 have no Person to fire on). Probable-tier: it is the
        // operator's asserted subject, not a guess — but unverified externally.
        // Emitted before the handle gate so non-Latin names get a subject too.
        if !crate::core::validation::is_placeholder_entity(&EntityKind::Person, &target.value) {
            let mut person = Entity::new(
                EntityKind::Person,
                name.display_full(),
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
                .with_attr("source_name", &target.value),
            );
            result.push(person);
        }

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
                        .with_attr("source_name", &target.value),
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
                .with_attr("source_name", &target.value)
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
                .with_attr("source_name", &target.value),
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
