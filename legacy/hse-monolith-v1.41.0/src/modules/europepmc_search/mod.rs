//! Europe PMC module — keyless life-sciences literature search for a name or
//! organisation.
//!
//! Ported from the sibling `Huntsman-` repository during consolidation. The
//! parsing judgement — prefer a DOI resolver URL over the PubMed article
//! page, the case-insensitive URL dedup, and the result cap — is the part
//! worth carrying over verbatim; the trait wrapper is rewritten against this
//! crate's `Module` contract (`accepts`/`process`/`produces`), which the
//! source repository's simpler `is_enabled`/`execute` shape has no
//! equivalent of.
//!
//! Distinct from a PubMed-only index, not a mirror of one: Europe PMC
//! additionally covers preprints, patents, and full-text-linked results a
//! PubMed-only search does not carry, so the two genuinely turn up different
//! hits for the same name. Keyless — EBI's public REST API needs no key.
//!
//! Endpoint:
//! `https://www.ebi.ac.uk/europepmc/webservices/rest/search?query=<q>&format=json&pageSize=5`
//! → `{ "resultList": { "result": [ { "pmid": "...", "doi": "..." }, ... ] } }`.
//! A result's URL prefers its DOI resolver (works for preprints/patents that
//! carry no PMID); falls back to the PubMed article page when only a `pmid`
//! is present. A result with neither is skipped — there is nothing to link
//! to.
//!
//! What it deliberately does NOT do: rank or filter results by relevance
//! beyond the order the API itself returns them in, or fetch anything past
//! the first `pageSize` page — a name-search source is a lead generator, not
//! a literature review.

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
use crate::util::http::{RequestBuilderExt, UA_OSINT, ok_or_absent, urlencode};

const SRC: &str = "europepmc_search";

/// EBI's public search endpoint. Keyless, which is why this module is not
/// key-gated.
const API_BASE: &str = "https://www.ebi.ac.uk/europepmc/webservices/rest/search";

/// Maximum number of entities to return — matches the `pageSize` requested
/// from the API, so the cap is a formality rather than a truncation of a
/// larger page the endpoint already returned.
const CAP: usize = 5;

/// Confidence for a Europe PMC result URL from a name-search match. A
/// keyless, unauthenticated hit against a free-text name/organisation query
/// is real signal — the name appears in an indexed publication, preprint, or
/// patent — but a name match alone doesn't confirm the same person authored
/// it (common-name collisions), so this sits at a moderate, single-source
/// level rather than a directly-confirmed identity pivot.
const RESULT_URL_CONFIDENCE: f64 = confidence::MEDIUM_PLUS;

#[derive(Debug, Default, Deserialize)]
pub(super) struct SearchResp {
    #[serde(rename = "resultList", default)]
    result_list: ResultList,
}

#[derive(Debug, Default, Deserialize)]
struct ResultList {
    #[serde(default)]
    result: Vec<ResultItem>,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct ResultItem {
    #[serde(default)]
    doi: Option<String>,
    #[serde(default)]
    pmid: Option<String>,
}

/// Project the search response onto entities. Pure, network-free,
/// deterministic and deduplicated: all parsing judgement lives here so it is
/// tested directly against captured responses rather than through
/// `process`.
///
/// A result's URL prefers its DOI resolver (`https://doi.org/<doi>`), which
/// resolves for preprints and patents that carry no PMID; falls back to the
/// PubMed article page (`https://pubmed.ncbi.nlm.nih.gov/<pmid>/`) when only
/// a `pmid` is present. A result with neither is skipped entirely — there is
/// nothing to link to. Deduplicated case-insensitively on the resulting URL
/// and capped at [`CAP`], mirroring the source module's judgement exactly.
pub(super) fn build_entities(r: &SearchResp, query: &str, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for item in &r.result_list.result {
        if out.len() >= CAP {
            break;
        }

        let doi = item.doi.as_deref().map(str::trim).filter(|d| !d.is_empty());
        let pmid = item
            .pmid
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty());

        let (url, field, id_value) = match (doi, pmid) {
            (Some(doi), _) => (format!("https://doi.org/{doi}"), "doi", doi),
            (None, Some(pmid)) => (
                format!("https://pubmed.ncbi.nlm.nih.gov/{pmid}/"),
                "pmid",
                pmid,
            ),
            (None, None) => continue,
        };

        if !seen.insert(url.to_lowercase()) {
            continue;
        }

        let mut e = Entity::new(EntityKind::Url, &url, RESULT_URL_CONFIDENCE, scan_id);
        e.tag("europepmc");
        e.tag("literature");
        e.add_evidence(
            Evidence::new(SRC, format!("Europe PMC literature match for '{query}'"))
                .with_attr(field, id_value)
                .with_attr("query", query),
        );
        out.push(e);
    }

    out
}

/// Europe PMC biomedical/life-sciences literature search — see the module
/// docs for what it deliberately does (DOI-preferred URL, capped, deduped)
/// and does not (relevance ranking, pagination beyond the first page).
pub struct EuropePmcSearch;

#[async_trait]
impl Module for EuropePmcSearch {
    fn name(&self) -> &'static str {
        "europepmc_search"
    }

    fn description(&self) -> &'static str {
        "Europe PMC biomedical literature search (EBI, keyless) — matches a name or organisation against life-sciences literature, preprints, and patents"
    }

    fn priority(&self) -> u8 {
        // Enrichment-tier: a weak, non-identity-confirming name-match pivot,
        // run alongside the other secondary lookups rather than the core
        // identity/breach stack. Matches the sibling `crossref_search` port
        // (same source family, same calibration).
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
        // shape as SERP scraping, and it produces nothing beyond a URL pivot
        // — no Email/Person/Address fields to justify widening it.
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
            "{API_BASE}?query={}&format=json&pageSize={CAP}",
            urlencode(query)
        );
        let resp = ctx
            .http
            .get(&url)
            .header("User-Agent", UA_OSINT)
            .header("Accept", "application/json")
            .send_tagged(SRC)
            .await?;
        let Some(resp) = ok_or_absent(SRC, resp, &[404]).await? else {
            return Ok(ModuleResult::new());
        };
        let parsed: SearchResp = crate::util::http::json_decode(SRC, resp).await?;

        let mut result = ModuleResult::new();
        result.entities = build_entities(&parsed, query, &ctx.scan_id);
        Ok(result)
    }
}
