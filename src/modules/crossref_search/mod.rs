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
    /// The work's title(s) — Crossref models `title` as a list.
    #[serde(default)]
    pub(super) title: Vec<String>,
    /// The work's authors — what ties a work to the subject.
    #[serde(default)]
    pub(super) author: Vec<CrossrefAuthor>,
}

/// One author of a work (`author[]`): the `given` / `family` name parts and
/// the affiliation names the publisher deposited. Live shape 2026-09-15:
/// `{"given":"Ada","family":"Lovelace","affiliation":[{"name":"…"}]}`.
#[derive(Debug, Default, Deserialize)]
pub(super) struct CrossrefAuthor {
    #[serde(default)]
    pub(super) given: Option<String>,
    #[serde(default)]
    pub(super) family: Option<String>,
    #[serde(default)]
    pub(super) affiliation: Vec<CrossrefAffiliation>,
}

/// An author's affiliation (`author[].affiliation[]`).
#[derive(Debug, Default, Deserialize)]
pub(super) struct CrossrefAffiliation {
    #[serde(default)]
    pub(super) name: Option<String>,
}

/// The Crossref query for a target: an author-scoped `query.author=` for a
/// name, an affiliation-scoped `query.affiliation=` for an organisation. The
/// generic `query=` searches every field (title, abstract, references,
/// funder), so it returned works ABOUT a person as if they were the person's
/// (backlog #14; observed live 2026-09-15: `query=Ada Lovelace` → "Introduction
/// to the Ada Lovelace Symposium" by Alexander Wolf and "Ada Lovelace lives
/// forever" by Betty Toole; `query.author=Ada Lovelace` → works whose author
/// is Ada Lovelace). `select=` limits the payload to the fields read. **Pure.**
fn build_query(kind: TargetKind, value: &str) -> Option<String> {
    let field = match kind {
        TargetKind::FullName => "query.author",
        TargetKind::Organisation => "query.affiliation",
        _ => return None,
    };
    Some(format!(
        "https://api.crossref.org/works?{field}={}&rows={CAP}&select=DOI,URL,title,author",
        urlencode(value)
    ))
}

/// Why a work is attributable to the seed: the author whose name matches a
/// FullName seed, or the affiliation naming an Organisation seed. `None` when
/// nothing in the work's author list ties it to the subject — a work that
/// merely mentions the name, or one Crossref's fuzzy author match admitted on
/// a different person. **Pure.**
pub(super) fn attribution(kind: TargetKind, seed: &str, item: &CrossrefItem) -> Option<String> {
    match kind {
        TargetKind::FullName => item.author.iter().find_map(|a| {
            let family = a.family.as_deref()?.trim();
            let given = a.given.as_deref().unwrap_or("").trim();
            author_matches(seed, given, family)
                .then(|| format!("{given} {family}").trim().to_string())
        }),
        TargetKind::Organisation => item
            .author
            .iter()
            .flat_map(|a| a.affiliation.iter())
            .filter_map(|af| af.name.as_deref())
            .map(str::trim)
            .find(|name| affiliation_matches(seed, name))
            .map(str::to_string),
        _ => None,
    }
}

/// A seed name matches an author when the author's family name is the seed's
/// trailing token(s) (Western order) or its leading token(s) (family-first
/// order — Vietnamese, Hungarian, East Asian names), and, when both sides
/// carry a given name, the seed's given token is the author's given name or
/// its initial (`J.` for `Jordan`, either way round). ASCII case- and
/// diacritic-folded. A bare family-name seed matches on the family name alone.
///
/// `pub(crate)` because `europepmc_search` gates its author list through this
/// same matcher: two literature sources must not disagree on whether a byline
/// names the subject.
pub(crate) fn author_matches(seed: &str, given: &str, family: &str) -> bool {
    let fold = |t: &str| crate::util::str_util::fold_ascii_lower(t.trim_end_matches('.'));
    let tokens: Vec<String> = seed.split_whitespace().map(fold).collect();
    let fam: Vec<String> = family.split_whitespace().map(fold).collect();
    if fam.is_empty() || tokens.len() < fam.len() {
        return false;
    }
    let given_first = given.split_whitespace().next().map(fold);
    let given_ok = |rest: &[String]| match (rest.first(), given_first.as_deref()) {
        // Nothing to compare on one side: the family name decides.
        (None, _) | (_, None) => true,
        (Some(s), Some(g)) => {
            s == g
                || (s.chars().count() == 1 && g.starts_with(s.as_str()))
                || (g.chars().count() == 1 && s.starts_with(g))
        }
    };
    if tokens.ends_with(&fam) && given_ok(&tokens[..tokens.len() - fam.len()]) {
        return true;
    }
    tokens.len() > fam.len() && tokens.starts_with(&fam) && given_ok(&tokens[fam.len()..])
}

/// An affiliation names the organisation when every token of the seed appears
/// in it (folded, punctuation-split), so `University of Wollongong` matches
/// `University of Wollongong , Wollongong , Australia` and not `The Wollongong
/// Hospital`. Shared with `europepmc_search` for the same reason as
/// [`author_matches`].
pub(crate) fn affiliation_matches(seed: &str, affiliation: &str) -> bool {
    let tokens = |s: &str| -> Vec<String> {
        s.split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty())
            .map(crate::util::str_util::fold_ascii_lower)
            .collect()
    };
    let hay = tokens(affiliation);
    let needles = tokens(seed);
    !needles.is_empty() && needles.iter().all(|n| hay.contains(n))
}

/// Project a Crossref search response onto entities.
///
/// Only a work [`attribution`] ties to the seed — by author for a name, by
/// affiliation for an organisation — is emitted; the rest of a page is works
/// that mention the name or fuzzy-matched someone else. Pure, network-free,
/// deterministic and deduplicated: prefers each item's
/// own `URL`, falling back to the canonical `doi.org` resolver built from its
/// `DOI` when `URL` is absent; an item with neither is skipped. Dedup is
/// case-insensitive on the URL (two spellings differing only in case are the
/// same resolvable resource, unlike the case-sensitive cryptocurrency-address
/// dedup elsewhere in this crate), capped at [`CAP`] entities.
pub(super) fn build_entities(
    resp: &CrossrefResp,
    kind: TargetKind,
    query: &str,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for item in &resp.message.items {
        if out.len() >= CAP {
            // Nothing further can be emitted, so stop scanning rather than
            // walking the remaining items to discard them.
            break;
        }
        let Some(matched) = attribution(kind, query, item) else {
            continue;
        };
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
        // The summary names the WORK — its DOI, or its URL when it has none —
        // not only the author: an evidence record's identity is `(source,
        // summary)`, which `absorb` de-duplicates on and the GEXF
        // co-occurrence edge keys on. One summary per author made every work
        // by that author look like one shared record naming them all (18
        // false Crossref edges in scan 7258fc07's graph).
        let work = doi.map_or_else(|| url.clone(), |d| format!("doi {d}"));
        let (summary, matched_key) = match kind {
            TargetKind::Organisation => (
                format!("Crossref work affiliated with '{matched}': {work}"),
                "matched_affiliation",
            ),
            _ => (
                format!("Crossref work by '{matched}': {work}"),
                "matched_author",
            ),
        };
        let mut ev = Evidence::new(SRC, summary)
            .with_attr("query", query)
            .with_attr(matched_key, &matched);
        if let Some(t) = item.title.iter().map(|t| t.trim()).find(|t| !t.is_empty()) {
            ev = ev.with_attr("title", t);
        }
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

        let Some(url) = build_query(target.kind, query) else {
            return Ok(ModuleResult::new());
        };
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
        result.entities = build_entities(&parsed, target.kind, query, &ctx.scan_id);
        Ok(result)
    }
}
