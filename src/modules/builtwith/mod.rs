//! BuiltWith technology-profile lookup — domain → tech stack + owner contacts.
//!
//! BuiltWith indexes the technologies a website runs (analytics, CMS, ad
//! networks, frameworks, hosting) and, in its Domain API `Meta` block, the
//! registrant-facing contacts it has observed (company name, emails, phone
//! numbers, social handles). For a Domain target this module surfaces the
//! observed technologies as evidence on the domain and pivots the Meta block
//! into Organisation / Email / Phone entities.
//!
//! Endpoint: `GET https://api.builtwith.com/v21/api.json?KEY={key}&LOOKUP={domain}`
//! Auth: `KEY` query parameter.
//!
//! Output: a technology-annotated Domain plus the owning Organisation and any
//! contact emails/phones — an infrastructure→identity bridge.

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

const SRC: &str = "builtwith";
const KEY_ENV: &str = "HUNTSMAN_BUILTWITH_KEY";

pub struct BuiltWith;

#[derive(Deserialize, Default)]
#[serde(default)]
struct BwResp {
    #[serde(rename = "Results")]
    results: Vec<BwResult>,
    #[serde(rename = "Errors")]
    errors: Option<Vec<BwError>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BwError {
    #[serde(rename = "Message")]
    message: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BwResult {
    #[serde(rename = "Result")]
    result: Option<BwResultInner>,
    #[serde(rename = "Meta")]
    meta: Option<BwMeta>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BwResultInner {
    #[serde(rename = "Paths")]
    paths: Vec<BwPath>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BwPath {
    #[serde(rename = "Technologies")]
    technologies: Vec<BwTech>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BwTech {
    #[serde(rename = "Name")]
    name: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BwMeta {
    #[serde(rename = "CompanyName")]
    company_name: Option<String>,
    #[serde(rename = "Emails")]
    emails: Option<Vec<String>>,
    #[serde(rename = "Telephones")]
    telephones: Option<Vec<String>>,
    #[serde(rename = "Names")]
    names: Option<Vec<BwName>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BwName {
    #[serde(rename = "Name")]
    name: Option<String>,
}

#[async_trait]
impl Module for BuiltWith {
    fn name(&self) -> &'static str {
        "builtwith"
    }

    fn description(&self) -> &'static str {
        "BuiltWith technology profile: site tech stack + owning company, emails, phones"
    }

    fn priority(&self) -> u8 {
        74
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Domain,
            EntityKind::Organisation,
            EntityKind::Email,
            EntityKind::Phone,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn cache_ttl_secs(&self) -> u64 {
        // Tech stacks and registrant contacts change slowly: cache 7 days to
        // stretch the BuiltWith quota (billed per lookup).
        604_800
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };

        let domain = target.value.trim();
        if domain.is_empty() {
            return Ok(ModuleResult::new());
        }
        let lookup = crate::util::http::urlencode(domain);
        let url = format!("https://api.builtwith.com/v21/api.json?KEY={key}&LOOKUP={lookup}");

        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send_tagged(SRC)
            .await?;

        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
            return Ok(ModuleResult::new());
        };

        let body: BwResp = crate::util::http::json_decode(SRC, resp).await?;

        if let Some(errors) = &body.errors
            && let Some(first) = errors.iter().find_map(|e| e.message.as_deref())
        {
            tracing::warn!(target: "module.builtwith", "BuiltWith error: {}", first);
            return Ok(ModuleResult::new());
        }

        Ok(build_entities(&body, domain, &ctx.scan_id))
    }
}

/// Map a decoded BuiltWith response to entities. **Pure** (no network/IO).
/// Emits a technology-annotated Domain plus the owning Organisation and any
/// observed contact Emails / Phones from the `Meta` block.
fn build_entities(body: &BwResp, domain: &str, scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();

    // Collect a deterministic, deduplicated technology list across every path.
    let mut techs: Vec<String> = Vec::new();
    for res in &body.results {
        if let Some(inner) = &res.result {
            for path in &inner.paths {
                for tech in &path.technologies {
                    if let Some(name) = tech
                        .name
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        techs.push(name.to_string());
                    }
                }
            }
        }
    }
    techs.sort();
    techs.dedup();

    if !techs.is_empty() {
        let mut dom = Entity::new(EntityKind::Domain, domain, 0.70, scan_id);
        dom.tag("builtwith");
        dom.tag("tech-profile");
        dom.add_evidence(
            Evidence::new(SRC, format!("BuiltWith technology profile for {domain}"))
                .with_attr("technology_count", techs.len().to_string())
                .with_attr(
                    "technologies",
                    techs.iter().take(30).cloned().collect::<Vec<_>>().join(","),
                ),
        );
        result.push(dom);
    }

    // Meta block → Organisation / Email / Phone.
    for res in &body.results {
        let Some(meta) = &res.meta else { continue };

        // Company name (or the first observed registrant Name) → Organisation.
        let org_name = meta
            .company_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| {
                meta.names.as_ref().and_then(|names| {
                    names
                        .iter()
                        .find_map(|n| n.name.as_deref().map(str::trim).filter(|s| !s.is_empty()))
                        .map(str::to_string)
                })
            });
        if let Some(org) = org_name.filter(|s| s.len() >= 3) {
            let mut oe = Entity::new(EntityKind::Organisation, &org, 0.65, scan_id);
            oe.tag("builtwith");
            oe.add_evidence(
                Evidence::new(
                    SRC,
                    format!("BuiltWith registrant company for {domain}: {org}"),
                )
                .with_attr("domain", domain),
            );
            result.push(oe);
        }

        if let Some(emails) = &meta.emails {
            let mut seen: Vec<String> = emails
                .iter()
                .map(|e| e.trim().to_ascii_lowercase())
                .filter(|e| e.len() >= 5 && e.contains('@'))
                .collect();
            seen.sort();
            seen.dedup();
            for email in &seen {
                let mut e = Entity::new(EntityKind::Email, email, 0.60, scan_id);
                e.tag("builtwith");
                e.add_evidence(Evidence::new(
                    SRC,
                    format!("Contact email observed by BuiltWith for {domain}"),
                ));
                result.push(e);
            }
        }

        if let Some(phones) = &meta.telephones {
            let mut seen: Vec<String> = phones
                .iter()
                .map(|p| p.trim().to_string())
                .filter(|p| p.chars().filter(char::is_ascii_digit).count() >= 7)
                .collect();
            seen.sort();
            seen.dedup();
            for phone in &seen {
                let mut e = Entity::new(EntityKind::Phone, phone, 0.55, scan_id);
                e.tag("builtwith");
                e.add_evidence(Evidence::new(
                    SRC,
                    format!("Contact phone observed by BuiltWith for {domain}"),
                ));
                result.push(e);
            }
        }
    }

    result
}
