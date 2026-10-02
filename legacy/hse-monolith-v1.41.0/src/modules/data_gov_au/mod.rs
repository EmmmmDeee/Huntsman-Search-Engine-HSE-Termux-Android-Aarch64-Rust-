//! data.gov.au — the Australian Government's open-data catalog (CKAN), keyless full-text search.
//!
//! Ported from the sibling `Huntsman-` repository during consolidation. The parsing judgement —
//! filtering matches by the dataset's OWNING ORGANISATION rather than accepting any full-text hit,
//! and the resulting confidence split between a confirmed organisation and its (weaker) dataset
//! pivot — is the part worth carrying over verbatim; the trait wrapper is rewritten against this
//! crate's `Module` contract (`accepts`/`process`/`produces`), which the source repository's
//! simpler `is_enabled`/`execute` shape has no equivalent of.
//!
//! Given an `Organisation` name, this searches the catalog's `package_search` action and surfaces
//! the *owning agency* of any matching dataset whose organisation title plausibly relates to the
//! query, plus that dataset's public page. This confirms/discovers the Australian government
//! agency behind an organisation name — e.g. "Australian Taxation Office" → the ATO's own
//! open-data organisation entry and its published datasets.
//!
//! Endpoint (verified live by the source repository): `GET
//! https://data.gov.au/data/api/3/action/package_search?q=...` (note the `/data/` path segment —
//! the bare `/api/3/action/...` path used by older CKAN docs 404s on this deployment). Response
//! shape: `{"success":bool,"result":{"count":N,"results":[{"name":...,"title":...,
//! "organization":{"title":...}}]}}`.
//!
//! What it deliberately does NOT do: accept a dataset purely because CKAN's full-text search
//! matched something in its title/notes/tags. That search matches broadly, so filtering on the
//! dataset's OWNING ORGANISATION specifically — via a case-insensitive, either-direction substring
//! match, [`fuzzy_contains`] — is what keeps this from flooding the graph with tangentially-related
//! agencies. Below [`MIN_QUERY_LEN`] characters the query is too generic for that filter to mean
//! anything, so the request is skipped entirely rather than risk exactly that flood. A
//! rejected/malformed query (CKAN answers with a 2xx status and `success:false`) is a genuine
//! API-level failure, distinct from a legitimate zero-match search (`success:true, count:0`), and
//! surfaces as `Err` (fail-closed) rather than being folded into "no results".
//!
//! Keyless — data.gov.au's CKAN API is a free public service with no authentication, so this
//! module is not key-gated.

use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json_or_404;

const SRC: &str = "data_gov_au";

/// Bound the search page so one query can't pull an unbounded catalog response.
const ROWS: usize = 10;

/// Below this length a query is too generic for full-text search to return a meaningful,
/// specific match — skip the request rather than risk flooding the graph with loosely-related
/// government agencies.
const MIN_QUERY_LEN: usize = 3;

#[derive(Debug, Deserialize, Default)]
pub(super) struct PackageSearchResponse {
    #[serde(default)]
    pub(super) success: bool,
    #[serde(default)]
    pub(super) result: Option<SearchResult>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct SearchResult {
    #[serde(default)]
    pub(super) results: Vec<Dataset>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct Dataset {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) organization: Option<Organization>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct Organization {
    #[serde(default)]
    pub(super) title: Option<String>,
}

/// Case-insensitive substring match, either direction — tolerates a query that's a fuller name
/// than the catalog's own short title, or vice versa. An abbreviation like "ATO" against
/// "Australian Taxation Office" will NOT match this: neither string contains the other, so that
/// needs an exact or fuller name.
fn fuzzy_contains(haystack: &str, needle: &str) -> bool {
    let h = haystack.to_lowercase();
    let n = needle.to_lowercase();
    !n.is_empty() && (h.contains(&n) || n.contains(&h))
}

/// Pure projection of a `package_search` response into engine entities. Only datasets whose
/// OWNING ORGANISATION plausibly relates to the query are kept — see the module docs for why.
/// Network-free and deterministic; deduplicates by exact value so a query returning the same
/// organisation or dataset URL across several matching rows emits it once. Unit-testable with no
/// network.
pub(super) fn build_entities(
    resp: &PackageSearchResponse,
    query: &str,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    let Some(result) = &resp.result else {
        return out;
    };
    let mut seen_orgs: HashSet<String> = HashSet::new();
    let mut seen_urls: HashSet<String> = HashSet::new();

    for ds in &result.results {
        let Some(org_title) = ds.organization.as_ref().and_then(|o| o.title.as_deref()) else {
            continue;
        };
        if !fuzzy_contains(org_title, query) {
            continue;
        }

        // The dataset's owning agency — a search-matched organisation is a real signal but not
        // an authoritative identity confirmation (HIGH, not AUTHORITATIVE/VERY_HIGH_PLUS).
        if seen_orgs.insert(org_title.to_string()) {
            let mut org = Entity::new(
                EntityKind::Organisation,
                org_title,
                confidence::HIGH,
                scan_id,
            );
            org.tag("data_gov_au");
            org.tag("au-government");
            org.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Organisation matched data.gov.au dataset search for '{query}'"),
                )
                .with_attr("query", query)
                .with_attr("organisation", org_title),
            );
            out.push(org);
        }

        // The dataset's public page — a supporting pivot, one step further removed than the
        // organisation match itself, so it carries a lower confidence (MEDIUM_HIGH).
        if let Some(name) = ds.name.as_deref() {
            let url = format!("https://data.gov.au/data/dataset/{name}");
            if seen_urls.insert(url.clone()) {
                let mut u = Entity::new(EntityKind::Url, &url, confidence::MEDIUM_HIGH, scan_id);
                u.tag("data_gov_au");
                u.tag("dataset");
                u.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("Dataset '{name}' owned by organisation '{org_title}'"),
                    )
                    .with_attr("dataset_name", name)
                    .with_attr("organisation", org_title),
                );
                out.push(u);
            }
        }
    }
    out
}

/// data.gov.au CKAN dataset search — see the module docs for the organisation-match filter that
/// keeps this from flooding the graph with tangentially-related agencies.
pub struct DataGovAu;

#[async_trait]
impl Module for DataGovAu {
    fn name(&self) -> &'static str {
        "data_gov_au"
    }

    fn description(&self) -> &'static str {
        "data.gov.au CKAN dataset search (keyless) — confirms the Australian government agency behind an organisation name via its open-data catalog entries"
    }

    fn priority(&self) -> u8 {
        // A fuzzy full-text search, not an authoritative registry lookup — deliberately low.
        42
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // T1596 Search Open Technical Databases — a literal full-text search against a
        // government open-data catalog API.
        &["T1596"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Organisation, EntityKind::Url];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // A single keyless CKAN GET — same budget as the other one-shot
        // keyless lookups (opencorporates, hackertarget).
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();
        if query.len() < MIN_QUERY_LEN {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://data.gov.au/data/api/3/action/package_search?q={}&rows={ROWS}",
            crate::util::http::urlencode(query)
        );

        let data: Option<PackageSearchResponse> = fetch_json_or_404(&ctx.http, SRC, &url).await?;
        let Some(data) = data else {
            return Ok(ModuleResult::new());
        };

        // CKAN answers a rejected/malformed query with a 2xx status and success=false — a
        // genuine API-level failure, distinct from a legitimate zero-match search
        // (success=true, count=0) — so it must surface as Err (fail-closed), not be treated the
        // same as "no results".
        if !data.success {
            return Err(Error::module(
                SRC,
                "data.gov.au: search request rejected (success=false)",
            ));
        }

        let mut result = ModuleResult::new();
        result.entities = build_entities(&data, query, &ctx.scan_id);
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
