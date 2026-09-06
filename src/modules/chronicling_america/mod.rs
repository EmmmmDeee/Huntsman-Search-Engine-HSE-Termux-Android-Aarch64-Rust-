//! Library of Congress — Chronicling America (digitised US newspapers,
//! 1756–1963) full-text search through the loc.gov JSON API.
//!
//! Endpoint: `GET https://www.loc.gov/collections/chronicling-america/?q=%22{query}%22&fo=json&c=10&at=results,pagination`
//! Keyless. The pre-2024 `chroniclingamerica.loc.gov/search/pages/results/?format=json`
//! endpoint answers 404 (live-confirmed 2026-09-06): the collection's search
//! lives under loc.gov's own API now, and `at=results,pagination` trims the
//! ~1.9 MB facet payload to the ~14 KB this module reads.
//!
//! Wire shape (live 2026-09-06): `{"pagination":{"of":202007,"total":67336,
//! "perpage":3,…},"results":[{"id":"http://www.loc.gov/resource/sn87090149/1844-06-20/ed-1/?sp=1",
//! "title":"Image 1 of Port-Gibson herald (Port Gibson, Miss.), June 20, 1844",
//! "date":"1844-06-20","url":"https://www.loc.gov/resource/sn87090149/1844-06-20/ed-1/?sp=1&q=%22john+smith%22",
//! "description":["<the page's OCR text>"],"location":["port gibson","claiborne county",…],
//! "number_lccn":["sn87090149"],"partof":[…],"type":["segment"]},…]}`.
//! `pagination.of` is the number of matching pages (`total` is the page
//! count of the result set).
//!
//! What it yields: the seed's own headline entity (a `Person` for a name, an
//! `Organisation` for an org) carrying the match count, and one `Url` source
//! per newspaper page — a dated, placed, OCR-searchable page the operator can
//! open at the highlighted hit — tagged as a document to read rather than a
//! page to mine. The archive ends in 1963, so a hit is genealogical or
//! historical context by construction: every entity carries
//! `needs-identity-verification` and a sub-medium confidence.
//!
//! MITRE ATT&CK: T1593.002 — a full-text search over an open archive, the
//! same shape as `trove_au`.

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "chronicling_america";
/// Pages requested per search: each result carries its page's OCR text, so
/// ten keeps the read well inside the body cap while giving a reviewable set.
const ROWS: usize = 10;

/// Chronicling America newspaper-archive collector — see the module docs for
/// the loc.gov wire format and the confidence policy.
pub struct ChroniclingAmerica;

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct LocResp {
    pagination: Option<LocPagination>,
    results: Vec<LocResult>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct LocPagination {
    /// Matching pages across the whole collection.
    of: Option<u64>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub(super) struct LocResult {
    pub(super) id: Option<String>,
    pub(super) title: Option<String>,
    pub(super) date: Option<String>,
    pub(super) url: Option<String>,
    /// The page's OCR text (one element per segment).
    pub(super) description: Vec<String>,
    pub(super) location: Vec<String>,
    pub(super) number_lccn: Vec<String>,
}

#[async_trait]
impl Module for ChroniclingAmerica {
    fn name(&self) -> &'static str {
        "chronicling_america"
    }

    fn description(&self) -> &'static str {
        "Library of Congress Chronicling America — full-text search of digitised US newspapers (1756–1963) for a name or organisation"
    }

    fn priority(&self) -> u8 {
        42
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName | TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Search
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // An open-archive full-text search, not a people-register lookup —
        // the same technique `trove_au` declares for the same shape.
        &["T1593.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::Url,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn cache_ttl_secs(&self) -> u64 {
        // A closed (1756–1963) archive: results only change when the Library
        // digitises more pages, never at scan cadence.
        86_400
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let seed = target.value.trim();
        if seed.is_empty() {
            return Ok(ModuleResult::new());
        }
        // Quoted so the phrase is matched as a whole, not as two common words.
        let url = format!(
            "https://www.loc.gov/collections/chronicling-america/?q={}&fo=json&c={ROWS}&at=results,pagination",
            crate::util::http::urlencode(&format!("\"{seed}\""))
        );
        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send_tagged(SRC)
            .await?;
        let Some(resp) = crate::util::http::ok_or_absent(SRC, resp, &[404]).await? else {
            return Ok(ModuleResult::new());
        };
        let body: LocResp = crate::util::http::json_decode(SRC, resp).await?;
        let matching = body.pagination.and_then(|p| p.of).unwrap_or(0);
        Ok(build_entities(
            target.kind,
            seed,
            matching,
            &body.results,
            &ctx.scan_id,
        ))
    }
}

/// The seed's headline entity plus one `Url` source per newspaper page. Pure
/// (no I/O) so the extraction is unit-tested directly; empty when nothing
/// matched.
pub(super) fn build_entities(
    kind: TargetKind,
    seed: &str,
    matching: u64,
    results: &[LocResult],
    scan_id: &str,
) -> ModuleResult {
    let mut result = ModuleResult::new();
    if results.is_empty() {
        return result;
    }
    // `pagination.of` is optional: if it is ever absent/renamed, the returned
    // pages are still valid and must not be dropped. Fall back to the count
    // actually returned.
    let matching = if matching > 0 {
        matching
    } else {
        results.len() as u64
    };
    let headline_kind = match kind {
        TargetKind::Organisation => EntityKind::Organisation,
        _ => EntityKind::Person,
    };
    let mut headline = Entity::new(headline_kind, seed, confidence::LOW_MEDIUM, scan_id);
    headline.tag(SRC);
    headline.tag("newspaper-archive");
    headline.tag("historic");
    headline.tag("needs-identity-verification");
    let mut ev = Evidence::new(
        SRC,
        format!("Chronicling America: {matching} digitised US newspaper pages (1756–1963) match \"{seed}\""),
    )
    .with_attr("matching_pages", matching.to_string())
    .with_attr(
        "caution",
        "The archive closes in 1963: a match is genealogical or historical context, \
         not a record of a living subject, until corroborated.",
    );
    for r in results.iter().take(5) {
        if let (Some(t), Some(d)) = (&r.title, &r.date) {
            ev = ev.with_attr("page", format!("{d}: {t}"));
        }
    }
    headline.add_evidence(ev);
    result.push(headline);

    let mut seen_urls = std::collections::HashSet::new();
    for r in results.iter().take(ROWS) {
        let Some(u) = r.url.as_deref() else {
            continue;
        };
        if !(u.starts_with("http://") || u.starts_with("https://"))
            || !seen_urls.insert(u.to_string())
        {
            continue;
        }
        // The page's own OCR text naming the seed confirms the hit landed on
        // this page (the API's phrase search already requires it, so a miss
        // here means noisy OCR, not a wrong page — graded, never dropped).
        let ocr_names_seed = r
            .description
            .iter()
            .any(|d| crate::util::str_util::shares_whole_word_token(d, seed));
        let conf = if ocr_names_seed {
            confidence::MEDIUM_LIGHT
        } else {
            confidence::LOW_MEDIUM
        };
        let mut url_e = Entity::new(EntityKind::Url, u, conf, scan_id);
        url_e.tag(SRC);
        url_e.tag("newspaper-archive");
        url_e.tag("historic");
        url_e.tag(crate::core::tags::SOURCE_DOCUMENT);
        url_e.tag("needs-identity-verification");
        let mut uev = Evidence::new(
            SRC,
            "Chronicling America newspaper page matching the seed (open at the highlighted hit)",
        );
        if let Some(t) = &r.title {
            uev = uev.with_attr("title", t);
        }
        if let Some(d) = &r.date {
            uev = uev.with_attr("date", d);
        }
        if !r.location.is_empty() {
            uev = uev.with_attr("place", r.location.join(", "));
        }
        if let Some(l) = r.number_lccn.first() {
            uev = uev.with_attr("lccn", l);
        }
        if let Some(id) = &r.id {
            uev = uev.with_attr("page_id", id);
        }
        if !ocr_names_seed {
            uev = uev.with_attr("caution", "The page's OCR text does not name the seed as whole words — noisy OCR; open the page to confirm.");
        }
        url_e.add_evidence(uev);
        result.push(url_e);
    }
    result
}
