//! National Library of Australia — Trove newspaper archive search.
//! Key-gated; requires HUNTSMAN_TROVE_KEY.
//!
//! Endpoint: `GET https://api.trove.nla.gov.au/v3/result?q={query}&zone=newspaper&encoding=json`
//! Auth: X-API-KEY header.

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "trove_au";
const KEY_ENV: &str = "HUNTSMAN_TROVE_KEY";

pub struct TroveAu;

#[derive(Deserialize, Default)]
#[serde(default)]
struct TroveResp {
    response: Option<TroveResponse>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TroveResponse {
    zone: Option<Vec<TroveZone>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TroveZone {
    records: Option<TroveRecords>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TroveRecords {
    total: Option<u64>,
    article: Option<Vec<TroveArticle>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TroveArticle {
    id: Option<String>,
    title: Option<String>,
    date: Option<String>,
    #[serde(rename = "titleId")]
    title_id: Option<String>,
    snippet: Option<String>,
    url: Option<String>,
}

#[async_trait]
impl Module for TroveAu {
    fn name(&self) -> &'static str {
        "trove_au"
    }

    fn description(&self) -> &'static str {
        "National Library of Australia Trove: newspaper archive mentions for organisations and ABNs"
    }

    fn priority(&self) -> u8 {
        57
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Organisation | TargetKind::AbnAcn)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn produces(&self) -> &'static [EntityKind] {
        // The org headline, plus each newspaper article as a pivotable Url source
        // (deserialized all along, previously dropped).
        const KINDS: &[EntityKind] = &[EntityKind::Organisation, EntityKind::Url];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };

        let query = crate::util::http::urlencode(target.value.trim());
        let url = format!(
            "https://api.trove.nla.gov.au/v3/result?q={query}&zone=newspaper&encoding=json&n=20&reclevel=brief"
        );

        let resp = ctx
            .http
            .get(&url)
            .header("X-API-KEY", key)
            .header("Accept", "application/json")
            .send_tagged(SRC)
            .await?;

        // 401/403/429 → note_keyed_error + Err; 404 → clean miss; other non-2xx → Err.
        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
            return Ok(ModuleResult::new());
        };

        let body: TroveResp = crate::util::http::json_decode(SRC, resp).await?;

        let zones = match body.response.and_then(|r| r.zone) {
            Some(z) => z,
            None => return Ok(ModuleResult::new()),
        };

        let mut total_hits: u64 = 0;
        let mut articles: Vec<TroveArticle> = Vec::new();
        for zone in zones {
            if let Some(records) = zone.records {
                if let Some(t) = records.total {
                    total_hits += t;
                }
                if let Some(arts) = records.article {
                    articles.extend(arts);
                }
            }
        }

        Ok(build_entities(
            target.value.trim(),
            total_hits,
            &articles,
            &ctx.scan_id,
        ))
    }
}

/// Build the org headline plus a pivotable `Url` SOURCE per newspaper article.
/// Pure (no I/O) so the extraction is unit-tested directly. Returns empty when
/// the archive reported no hits.
fn build_entities(
    target_value: &str,
    total_hits: u64,
    articles: &[TroveArticle],
    scan_id: &str,
) -> ModuleResult {
    let mut result = ModuleResult::new();
    if total_hits == 0 {
        return result;
    }

    let mut org = Entity::new(EntityKind::Organisation, target_value, 0.65, scan_id);
    org.tag("trove");
    org.tag("newspaper-archive");
    let mut ev = Evidence::new(
        SRC,
        format!("Trove newspaper archive: {total_hits} mentions of '{target_value}'"),
    )
    .with_attr("total_hits", total_hits.to_string());
    for article in articles.iter().take(5) {
        if let Some(title) = &article.title
            && let Some(date) = &article.date
        {
            ev = ev.with_attr("article", format!("{date}: {title}"));
        }
    }
    org.add_evidence(ev);
    result.push(org);

    // Surface each article as a pivotable `Url` SOURCE — a dated Australian
    // newspaper mention of the subject the operator can open and read. The
    // url / id / title / snippet were deserialized into `TroveArticle` all along
    // but never emitted; only the headline+date were folded into the org evidence
    // above. Capped, http-only, deduped, deterministic (input order).
    let mut seen_urls = std::collections::HashSet::new();
    for article in articles.iter().take(10) {
        let Some(u) = article.url.as_deref() else {
            continue;
        };
        if !(u.starts_with("http://") || u.starts_with("https://"))
            || !seen_urls.insert(u.to_string())
        {
            continue;
        }
        let mut url_e = Entity::new(EntityKind::Url, u, 0.55, scan_id);
        url_e.tag("trove");
        url_e.tag("newspaper-archive");
        url_e.tag("source-document");
        let mut uev = Evidence::new(SRC, "Trove newspaper article mentioning the subject");
        if let Some(t) = &article.title {
            uev = uev.with_attr("title", t);
        }
        if let Some(d) = &article.date {
            uev = uev.with_attr("date", d);
        }
        if let Some(s) = &article.snippet {
            uev = uev.with_attr("snippet", s);
        }
        if let Some(id) = &article.id {
            uev = uev.with_attr("article_id", id);
        }
        url_e.add_evidence(uev);
        result.push(url_e);
    }
    result
}
