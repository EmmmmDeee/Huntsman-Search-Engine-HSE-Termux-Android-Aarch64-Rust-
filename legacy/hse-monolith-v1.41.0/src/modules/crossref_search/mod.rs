//! Crossref academic-literature search — keyless lookup for a **name or
//! organisation**.
//!
//! Ported from the sibling `Huntsman-` repository during consolidation. The
//! parsing judgement — prefer the work's own `URL`, fall back to the
//! canonical `doi.org` resolver built from its `DOI`, cap at 5 results, and
//! dedup case-insensitively — is the part worth carrying over verbatim; the
//! trait wrapper is rewritten against this crate's `Module` contract
//! (`accepts`/`produces`/`process`), which the source repository's simpler
//! `is_enabled`/`execute` shape has no equivalent of.
//!
//! Crossref indexes DOI metadata for the large majority of published
//! academic work; searching it by author/affiliation name is a strong,
//! verifiable pivot for a researcher or institution that a general web
//! search buries under noise. Keyless — Crossref's public API needs no key
//! (a `mailto=`-bearing User-Agent is polite-pool etiquette, not a
//! credential, and only affects Crossref's own rate-limit tier).
//!
//! Endpoint: `GET https://api.crossref.org/works?query=<q>&rows=5` →
//! `{ "message": { "items": [ { "DOI": "...", "URL": "..." }, ... ] } }`.
//!
//! What it deliberately does NOT do: a Crossref name match is a **weak**
//! pivot, not identity-confirming on its own (the same name can belong to
//! many authors, and Crossref does no disambiguation) — so every emitted
//! entity carries [`WORK_URL_CONFIDENCE`], the same numeric value
//! ([`confidence::MEDIUM_PLUS`]) the source module calibrated this at,
//! rather than anything near a "confirmed" tier.

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{RequestBuilderExt, ok_or_absent, urlencode};

const SRC: &str = "crossref_search";

/// Maximum number of work entities returned for one query. Matches the
/// `rows=5` the request itself asks Crossref for; kept as an explicit guard
/// here too (rather than trusting the upstream `rows` param to always be
/// honoured) so a differently-shaped response can never fan out unbounded.
const CAP: usize = 5;

/// Confidence for a Crossref work's URL. A name match against an academic
/// database is a strong, verifiable-looking pivot but is NOT
/// identity-confirming by itself — common names collide, and Crossref
/// performs no author disambiguation — so this is calibrated at
/// [`confidence::MEDIUM_PLUS`] (0.60) rather than anything higher, matching
/// the exact value the source module used.
const WORK_URL_CONFIDENCE: f64 = confidence::MEDIUM_PLUS;

/// Identifying User-Agent sent with every request. Crossref's "polite pool"
/// gives priority/better rate limits to callers that self-identify with a
/// contact address in the UA string; `oss@huntsman.invalid` is a
/// deliberately non-routable placeholder (the `.invalid` TLD, RFC 2606),
/// carried over unchanged from the source module rather than invented here.
const USER_AGENT: &str = "HSE/1.0 OSINT research tool (mailto:oss@huntsman.invalid)";

#[derive(Debug, Default, Deserialize)]
pub(super) struct CrossrefResp {
    #[serde(default)]
    pub(super) message: CrossrefMessage,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct CrossrefMessage {
    #[serde(default)]
    pub(super) items: Vec<CrossrefItem>,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct CrossrefItem {
    #[serde(rename = "DOI", default)]
    pub(super) doi: Option<String>,
    #[serde(rename = "URL", default)]
    pub(super) url: Option<String>,
}

/// Project a Crossref search response onto entities.
///
/// Pure, network-free, deterministic and deduplicated: prefers each item's
/// own `URL`, falling back to the canonical `doi.org` resolver built from its
/// `DOI` when `URL` is absent; an item with neither is skipped. Dedup is
/// case-insensitive on the URL (two spellings differing only in case are the
/// same resolvable resource, unlike the case-sensitive cryptocurrency-address
/// dedup elsewhere in this crate), capped at [`CAP`] entities.
pub(super) fn build_entities(resp: &CrossrefResp, query: &str, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for item in &resp.message.items {
        if out.len() >= CAP {
            // Nothing further can be emitted, so stop scanning rather than
            // walking the remaining items to discard them.
            break;
        }
        let doi = item.doi.as_deref().map(str::trim).filter(|d| !d.is_empty());
        let url = item
            .url
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .map(str::to_string)
            .or_else(|| doi.map(|d| format!("https://doi.org/{d}")));
        let Some(url) = url else {
            continue;
        };
        if !seen.insert(url.to_lowercase()) {
            continue;
        }

        let mut e = Entity::new(EntityKind::Url, &url, WORK_URL_CONFIDENCE, scan_id);
        e.tag("crossref");
        e.tag("academic");
        let mut ev = Evidence::new(SRC, format!("Crossref work matching '{query}'"))
            .with_attr("query", query);
        if let Some(d) = doi {
            ev = ev.with_attr("doi", d);
        }
        e.add_evidence(ev);
        out.push(e);
    }
    out
}

/// Crossref academic/DOI search by name or organisation — see the module
/// docs for the confidence-calibration rationale (a name match is not
/// identity-confirming).
pub struct CrossrefSearch;

#[async_trait]
impl Module for CrossrefSearch {
    fn name(&self) -> &'static str {
        "crossref_search"
    }

    fn description(&self) -> &'static str {
        "Crossref academic/DOI search (keyless) — resolves a name or organisation to indexed works, surfaced as URL pivots"
    }

    fn priority(&self) -> u8 {
        // Enrichment-tier: a weak, non-identity-confirming name-match pivot,
        // run alongside the other secondary lookups rather than the core
        // identity/breach stack.
        55
    }

    fn accepts(&self, t: &Target) -> bool {
        // The source module also matched a generic `Query`/`Person` entity
        // type, neither of which this crate's `TargetKind` has — `FullName`
        // and `Organisation` are the closest equivalents (`FullName` is what
        // `EntityKind::Person` maps back onto via
        // `TargetKind::from_entity_kind`).
        matches!(t.kind, TargetKind::FullName | TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Search
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Search default (T1593.002 Search Engines) fits: this is a
        // specialised open-database search by name, the same reconnaissance
        // shape as SERP scraping, and it produces nothing beyond a URL
        // pivot — no Email/Person/Address fields to justify widening it the
        // way `search_engines` does.
        &["T1593.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Url];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();
        if query.is_empty() {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://api.crossref.org/works?query={}&rows=5",
            urlencode(query)
        );
        let resp = ctx
            .http
            .get(&url)
            .header("User-Agent", USER_AGENT)
            .header("Accept", "application/json")
            .send_tagged(SRC)
            .await?;
        let Some(resp) = ok_or_absent(SRC, resp, &[404]).await? else {
            return Ok(ModuleResult::new());
        };
        let parsed: CrossrefResp = crate::util::http::json_decode(SRC, resp).await?;

        let mut result = ModuleResult::new();
        result.entities = build_entities(&parsed, query, &ctx.scan_id);
        Ok(result)
    }
}
