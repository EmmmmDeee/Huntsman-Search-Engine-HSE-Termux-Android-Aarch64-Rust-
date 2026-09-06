//! Europeana — the European Union's aggregated cultural-heritage index (~50 M
//! records from archives, libraries and museums: civil and parish registers,
//! newspapers, photographs, war records), through its Search API.
//! Key-gated; requires HUNTSMAN_EUROPEANA_KEY (a free `wskey`).
//!
//! Endpoint: `GET https://api.europeana.eu/record/v2/search.json?wskey={key}&query=%22{query}%22&rows=10`
//! Auth: `wskey` query parameter.
//!
//! Wire shape (live 2026-09-06, with Europeana's published demo key):
//! `{"apikey":"…","success":true,"itemsCount":2,"totalResults":1238,"items":[
//! {"id":"/…","guid":"https://www.europeana.eu/item/…","link":"https://api.europeana.eu/record/….json?wskey=…",
//! "title":["…"],"year":["1922"],"dataProvider":["…"],"provider":["…"],
//! "country":["Ireland"],"type":"TEXT","edmIsShownAt":["https://…"],"dcCreator":[…],…}]}`.
//! `link` embeds the caller's key and is never surfaced; the item page is
//! `edmIsShownAt` (the holding institution) or `guid` (Europeana's own).
//!
//! What it yields: the seed's own headline entity carrying the match count,
//! and one `Url` source per record — titled, dated, attributed to its holding
//! institution and country — tagged as a document to read rather than a page
//! to mine. Heritage records are overwhelmingly historical, so every entity
//! carries `needs-identity-verification` and a sub-medium confidence.
//!
//! MITRE ATT&CK: T1593.002 — a full-text search over an open archive, the
//! same shape as `trove_au` and `chronicling_america`.

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "europeana";
const KEY_ENV: &str = "HUNTSMAN_EUROPEANA_KEY";
/// Records requested per search.
const ROWS: usize = 10;

/// Europeana cultural-heritage collector — see the module docs for the Search
/// API wire format and the confidence policy.
pub struct Europeana;

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct EuResp {
    success: bool,
    error: Option<String>,
    #[serde(rename = "totalResults")]
    total_results: Option<u64>,
    items: Vec<EuItem>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub(super) struct EuItem {
    pub(super) id: Option<String>,
    pub(super) guid: Option<String>,
    pub(super) title: Vec<String>,
    pub(super) year: Vec<String>,
    #[serde(rename = "dataProvider")]
    pub(super) data_provider: Vec<String>,
    pub(super) country: Vec<String>,
    #[serde(rename = "type")]
    pub(super) kind: Option<String>,
    #[serde(rename = "edmIsShownAt")]
    pub(super) shown_at: Vec<String>,
    #[serde(rename = "dcCreator")]
    pub(super) creator: Vec<String>,
}

#[async_trait]
impl Module for Europeana {
    fn name(&self) -> &'static str {
        "europeana"
    }

    fn description(&self) -> &'static str {
        "Europeana cultural-heritage search — registers, newspapers, photographs and war records across European archives for a name or organisation"
    }

    fn priority(&self) -> u8 {
        41
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName | TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
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
        // Heritage aggregations grow by institutional harvest, not at scan
        // cadence; a day's cache spares the free key allowance.
        86_400
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = ctx.key(KEY_ENV)?;
        let seed = target.value.trim();
        if seed.is_empty() {
            return Ok(ModuleResult::new());
        }
        let url = format!(
            "https://api.europeana.eu/record/v2/search.json?wskey={}&query={}&rows={ROWS}",
            crate::util::http::urlencode(key),
            crate::util::http::urlencode(&format!("\"{seed}\""))
        );
        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send_tagged(SRC)
            .await?;
        // 401/403/429 → note_keyed_error + Err; 404 → clean miss; other non-2xx → Err.
        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
            return Ok(ModuleResult::new());
        };
        let body: EuResp = crate::util::http::json_decode(SRC, resp).await?;
        if !body.success {
            // The API reports its own refusals (bad key, malformed query) as a
            // 200 with `success:false` — an error, never an empty answer.
            return Err(Error::module(
                SRC,
                format!(
                    "Europeana refused the query: {}",
                    body.error.as_deref().unwrap_or("no reason given")
                ),
            ));
        }
        Ok(build_entities(
            target.kind,
            seed,
            body.total_results.unwrap_or(0),
            &body.items,
            &ctx.scan_id,
        ))
    }
}

/// The seed's headline entity plus one `Url` source per record. Pure (no
/// I/O) so the extraction is unit-tested directly; empty when nothing matched.
pub(super) fn build_entities(
    kind: TargetKind,
    seed: &str,
    total: u64,
    items: &[EuItem],
    scan_id: &str,
) -> ModuleResult {
    let mut result = ModuleResult::new();
    if total == 0 || items.is_empty() {
        return result;
    }
    let headline_kind = match kind {
        TargetKind::Organisation => EntityKind::Organisation,
        _ => EntityKind::Person,
    };
    let mut headline = Entity::new(headline_kind, seed, confidence::LOW_MEDIUM, scan_id);
    headline.tag(SRC);
    headline.tag("heritage-archive");
    headline.tag("historic");
    headline.tag("needs-identity-verification");
    let mut ev = Evidence::new(
        SRC,
        format!("Europeana: {total} cultural-heritage records match \"{seed}\""),
    )
    .with_attr("matching_records", total.to_string())
    .with_attr(
        "caution",
        "Heritage records are overwhelmingly historical: a match is genealogical or \
         historical context, not a record of a living subject, until corroborated.",
    );
    for it in items.iter().take(5) {
        if let Some(t) = it.title.first() {
            let year = it
                .year
                .first()
                .map(|y| format!("{y}: "))
                .unwrap_or_default();
            ev = ev.with_attr("record", format!("{year}{t}"));
        }
    }
    headline.add_evidence(ev);
    result.push(headline);

    let mut seen_urls = std::collections::HashSet::new();
    for it in items.iter().take(ROWS) {
        // The holding institution's own page first; Europeana's item page
        // otherwise. Never `link`: it carries the caller's key.
        let Some(u) = it
            .shown_at
            .iter()
            .chain(it.guid.iter())
            .map(String::as_str)
            .find(|u| u.starts_with("http://") || u.starts_with("https://"))
        else {
            continue;
        };
        if !seen_urls.insert(u.to_string()) {
            continue;
        }
        let names_seed = it
            .title
            .iter()
            .chain(it.creator.iter())
            .any(|t| crate::util::str_util::shares_whole_word_token(t, seed));
        let conf = if names_seed {
            confidence::MEDIUM_LIGHT
        } else {
            confidence::LOW_MEDIUM
        };
        let mut url_e = Entity::new(EntityKind::Url, u, conf, scan_id);
        url_e.tag(SRC);
        url_e.tag("heritage-archive");
        url_e.tag("historic");
        url_e.tag(crate::core::tags::SOURCE_DOCUMENT);
        url_e.tag("needs-identity-verification");
        let mut uev = Evidence::new(SRC, "Europeana heritage record matching the seed");
        if let Some(t) = it.title.first() {
            uev = uev.with_attr("title", t);
        }
        if let Some(y) = it.year.first() {
            uev = uev.with_attr("year", y);
        }
        if let Some(p) = it.data_provider.first() {
            uev = uev.with_attr("holding_institution", p);
        }
        if let Some(c) = it.country.first() {
            uev = uev.with_attr("country", c);
        }
        if let Some(k) = &it.kind {
            uev = uev.with_attr("media_type", k);
        }
        if let Some(c) = it.creator.first() {
            uev = uev.with_attr("creator", c);
        }
        if let Some(id) = &it.id {
            uev = uev.with_attr("record_id", id);
        }
        if let Some(g) = &it.guid {
            uev = uev.with_attr("europeana_url", g);
        }
        if !names_seed {
            uev = uev.with_attr(
                "caution",
                "Neither the record's title nor its creator names the seed as whole words — \
                 the match is in the full text or metadata; open the record to confirm.",
            );
        }
        url_e.add_evidence(uev);
        result.push(url_e);
    }
    result
}
