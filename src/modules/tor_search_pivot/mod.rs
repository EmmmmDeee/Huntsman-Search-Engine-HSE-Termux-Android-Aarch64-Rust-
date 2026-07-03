//! Tor/dark-web search **pivot** generator. Free, pure, zero network I/O.
//!
//! This module does **not** search the dark web itself — it generates a
//! ready-to-open search URL against [Ahmia](https://ahmia.fi), a
//! long-established, publicly-accountable Tor hidden-service search engine
//! (operated by security researcher Juha Nurmi) whose own published policy
//! bans abuse material and maintains a blacklist of prohibited services. The
//! analyst opens the URL manually in their own Tor Browser; HSE never
//! fetches, renders, or caches anything from Tor.
//!
//! This design is deliberate, not a placeholder for a future crawler. A
//! prior design pass considered and rejected building an automated Tor
//! `.onion` crawler/search index: reliable exclusion of child-abuse material
//! would require hash-database access (NCMEC/Thorn/IWF) this project has no
//! legal path to, and a heuristic filter would be unreliable false
//! assurance. Automated scraping of Ahmia's own search results was also
//! considered and rejected: Ahmia's Terms of Service explicitly prohibit it
//! ("Attempt to reverse-engineer, scrape, or replicate the service without
//! permission"). Generating a URL and never fetching it is neither scraping
//! nor replication — it is the same act as a bookmark or a deep link, and it
//! sidesteps every risk above by construction: HSE never receives, renders,
//! or stores a single byte of Tor content.
//!
//! Every emitted [`Url`](EntityKind::Url) entity is tagged
//! [`crate::core::tags::CANDIDATE`]: this is a suggested starting point for
//! manual investigation, not a confirmed finding, so it is excluded from the
//! correlator, the exposure index, and the confirmed-footprint dossier
//! sections — the same quarantine every other speculative lead in this
//! codebase goes through.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::urlencode;

#[cfg(test)]
mod tests;

pub(super) const SRC: &str = "tor_search_pivot";

/// Ahmia's clearnet search gateway — openable in any ordinary browser (no
/// Tor required to *search*; the result links it returns are `.onion` and
/// still require Tor to *visit*).
const AHMIA_CLEARNET: &str = "https://ahmia.fi/search/?q=";

/// Ahmia's official `.onion` address (verified against `ahmia.fi`'s own
/// published About page — onion addresses are impersonation-prone, so this
/// is taken from the operator's own canonical source, not a third party).
/// Only reachable over Tor; offered as the OPSEC-preferring alternative to
/// the clearnet gateway (avoids a clearnet DNS/TLS trace of the search).
const AHMIA_ONION: &str =
    "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q=";

// `Entity::new`'s `Url` normaliser strips the trailing `/` before a query
// string, so the stored/rendered value is `.../search?q=...` (no slash), not
// `.../search/?q=...` as written above. Confirmed live this is harmless:
// `curl -w '%{http_code} %{redirect_url}' https://ahmia.fi/search?q=test`
// returns `301` to `https://ahmia.fi/search/?q=test` — any browser follows
// it transparently, so the emitted pivot link still works correctly.

pub struct TorSearchPivot;

#[async_trait]
impl Module for TorSearchPivot {
    fn name(&self) -> &'static str {
        "tor_search_pivot"
    }

    fn description(&self) -> &'static str {
        "Generates an Ahmia Tor-search pivot URL for manual follow-up (never fetched by HSE)"
    }

    fn priority(&self) -> u8 {
        90
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Email
                | TargetKind::Username
                | TargetKind::FullName
                | TargetKind::Domain
                | TargetKind::CryptoAddress
        )
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Search
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Url];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        Ok(build_pivots(target, &ctx.scan_id))
    }
}

/// **Pure** (no I/O). Builds the two pivot-URL entities for `target`, or an
/// empty result for a blank value. Separated from [`TorSearchPivot::process`]
/// so it's directly unit-testable.
fn build_pivots(target: &Target, scan_id: &str) -> ModuleResult {
    let value = target.value.trim();
    let mut result = ModuleResult::new();
    if value.is_empty() {
        return result;
    }
    let query = urlencode(value);

    for (label, base) in [("clearnet", AHMIA_CLEARNET), ("onion", AHMIA_ONION)] {
        let url = format!("{base}{query}");
        let mut e = Entity::new(EntityKind::Url, &url, 0.20, scan_id);
        e.tag(tags::CANDIDATE);
        e.tag("tor-search-pivot");
        e.tag(format!("pivot-access:{label}"));
        e.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "Ahmia Tor search pivot for '{value}' — not fetched by HSE; open manually in Tor Browser"
                ),
            )
            .with_attr("engine", "ahmia")
            .with_attr("access", label)
            .with_attr("query", value),
        );
        result.push(e);
    }
    result
}
