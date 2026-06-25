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

    fn cache_ttl_secs(&self) -> u64 {
        604_800
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Organisation | TargetKind::AbnAcn)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Organisation];
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

        let status = resp.status();
        if !status.is_success() {
            crate::util::http::note_keyed_error(status.as_u16(), SRC, key, ctx);
            return Ok(ModuleResult::new());
        }

        let body: TroveResp = crate::util::http::json_decode(SRC, resp).await?;
        let mut result = ModuleResult::new();

        let zones = match body.response.and_then(|r| r.zone) {
            Some(z) => z,
            None => return Ok(result),
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

        if total_hits == 0 {
            return Ok(result);
        }

        let mut org = Entity::new(
            EntityKind::Organisation,
            target.value.trim(),
            0.65,
            &ctx.scan_id,
        );
        org.tag("trove");
        org.tag("newspaper-archive");

        let mut ev = Evidence::new(
            SRC,
            format!(
                "Trove newspaper archive: {total_hits} mentions of '{}'",
                target.value.trim()
            ),
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

        Ok(result)
    }
}
