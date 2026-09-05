//! Ahmia dark-web **exposure** — the `hse query --dark` search, wired as a scan
//! module so a normal `hse scan` checks dark-web exposure too.
//!
//! [`crate::util::ahmia`] searches Ahmia's clearnet-served index of Tor hidden
//! services for pages that MENTION a target — the same asset-exposure question
//! `intelx` and `hudsonrock` answer for breaches and stealer logs, extended to
//! onion-indexed content. Until now that search was reachable only through the
//! separate `hse query --dark` command, so a normal scan never checked the dark
//! web at all. This module makes the existing, verified search run in the scan
//! pipeline for the asset kinds worth checking, with no new API contract: it
//! calls the same [`crate::util::ahmia::search`] the CLI does.
//!
//! ## Defensive scope (inherited verbatim from `util::ahmia`)
//!
//! An **exposure sensor**, not a directory service. It reports WHERE a target is
//! mentioned and performs **no** onion fetching — the `.onion` addresses it
//! records are never resolved, probed, or health-checked, and the engine's
//! expansion loop refuses to pivot on them ([`crate::core::validation::is_onion_url`]),
//! so the no-fetch doctrine is enforced structurally rather than by convention.
//! Ahmia itself filters abuse material from its index. A "which markets are up"
//! capability is deliberately out of scope and is not implemented.
//!
//! ## Precision
//!
//! Every hit is a **full-text mention**: Ahmia matched the query term somewhere
//! on the page (a leak index, a forum thread, a paste), not verified identity —
//! the same namesake risk `austlii` and `trove_au` carry for their own
//! full-text corpora. So each onion page is emitted at a deliberately
//! conservative confidence and flagged `needs-identity-verification`, with a
//! caution recorded on its evidence. The finding is *that an exposure page
//! exists*; confirming it is the subject's is the operator's next step.

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "ahmia";

/// Upper bound on onion exposure hits surfaced per scan target. Mirrors
/// `util::ahmia`'s own `MAX_RESULTS`, so the module can never emit more onion
/// entities than the util already parsed and capped — a second, independent
/// bound at the entity-construction boundary rather than a trust that the util
/// stays capped.
const MAX_HITS: usize = 30;

/// Dark-web exposure sensor over Ahmia's clearnet-served Tor index. See the
/// module documentation for scope and precision; the behaviour lives in the
/// [`Module`] impl and the pure [`build_entities`] mapper.
pub struct Ahmia;

#[async_trait]
impl Module for Ahmia {
    fn name(&self) -> &'static str {
        "ahmia"
    }

    fn description(&self) -> &'static str {
        "Ahmia dark-web exposure — surfaces Tor hidden-service pages that mention the target, via Ahmia's clearnet index (reports exposure; never fetches an onion service)"
    }

    fn priority(&self) -> u8 {
        40
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    /// Read-only: a single clearnet GET against Ahmia's public search, no
    /// credential and no active probing of any discovered service.
    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        // The asset kinds an exposure search is meaningfully run for: an email
        // or username in a leak, a person named in a forum/paste, a brand's
        // domain or company name in a listing. Not IP/geo/infra kinds, whose
        // dark-web full-text hits are noise rather than the subject's exposure.
        matches!(
            t.kind,
            TargetKind::Email
                | TargetKind::Username
                | TargetKind::FullName
                | TargetKind::Domain
                | TargetKind::Organisation
        )
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Breach
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Url];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // `util::ahmia::search` routes through the shared curl helper (SSRF pin,
        // redirect/protocol hardening, max-filesize guard) and returns an empty
        // vec on any transport failure — it is an exposure sensor whose absence
        // of hits is never asserted as "no exposure", only "nothing indexed was
        // found", so an empty result is a clean no-op, not a false negative
        // dressed as one.
        let hits = crate::util::ahmia::search(target.value.trim(), self.max_timeout_ms()).await;
        Ok(build_entities(&hits, &ctx.scan_id))
    }
}

/// Map Ahmia hits to exposure entities. **Pure** (no network) so the mapping is
/// unit-tested against fixture results rather than the live dark web.
///
/// Each onion page that mentions the target becomes one `Url` exposure finding:
/// conservative confidence (a full-text mention, identity unverified), tagged
/// `dark-web` / `exposure` / `needs-identity-verification`, carrying the page
/// title and snippet as evidence plus a caution. The engine never pivots on a
/// `.onion` `Url` ([`crate::core::validation::is_onion_url`]), so this records
/// where the exposure is without ever fetching it. Capped at [`MAX_HITS`],
/// deterministic (input order), and deduplicated on the onion URL so a page
/// Ahmia lists twice yields one finding.
pub(crate) fn build_entities(
    hits: &[crate::util::ahmia::AhmiaResult],
    scan_id: &str,
) -> ModuleResult {
    let mut result = ModuleResult::new();
    let mut seen = std::collections::HashSet::new();
    for hit in hits.iter().take(MAX_HITS) {
        if hit.onion_url.is_empty() || !seen.insert(hit.onion_url.clone()) {
            continue;
        }
        let mut e = Entity::new(
            EntityKind::Url,
            &hit.onion_url,
            confidence::LOW_MEDIUM,
            scan_id,
        );
        e.tag("dark-web");
        e.tag("exposure");
        // A full-text onion mention is not verified as the subject's own data;
        // hold it out of the confirmed identity view until corroborated, exactly
        // as the other full-text-corpus modules do.
        e.tag("needs-identity-verification");
        let title = if hit.title.trim().is_empty() {
            "(untitled onion page)"
        } else {
            hit.title.trim()
        };
        let mut ev = Evidence::new(
            SRC,
            format!("Dark-web mention on an onion service: {title}"),
        )
        .with_attr("onion_url", &hit.onion_url)
        .with_attr("source", "ahmia.fi");
        if !hit.snippet.trim().is_empty() {
            ev = ev.with_attr("snippet", hit.snippet.trim());
        }
        ev = ev.with_attr(
            "caution",
            "Ahmia full-text match — the target term appears somewhere on this \
             onion page (a leak index, forum, paste, or listing), not necessarily \
             as the subject's own data. The page is recorded as an exposure \
             location and is never fetched; verify the identity before acting on \
             it.",
        );
        e.add_evidence(ev);
        result.push(e);
    }
    result
}
