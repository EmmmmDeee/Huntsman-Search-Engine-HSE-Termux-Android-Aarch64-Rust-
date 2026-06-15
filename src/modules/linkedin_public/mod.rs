//! LinkedIn public profile discovery — zero API key, passive HTTP scraping.
//!
//! Accepts `FullName` and `Organisation` targets. For each target it
//! constructs several candidate LinkedIn slug forms and probes the
//! public profile endpoint (`/in/<slug>` or `/company/<slug>`) to see
//! whether a public page is returned. A 200 with recognisable LinkedIn
//! profile HTML is treated as a hit; a 404 / redirect-to-login is a miss.
//!
//! This module deliberately limits scope to what is publicly visible
//! without logging in. It never uses credentials and never bypasses
//! LinkedIn's access controls. For paid deep extraction see `proxycurl`.
//!
//! Entities produced:
//!   - `Url` → the confirmed public profile URL
//!   - `Username` → the resolved LinkedIn slug (handle)
//!
//! MITRE ATT&CK:
//!   - T1591.002 — Gather Victim Org Information: Business Relationships
//!   - T1589.003 — Gather Victim Identity Information: Employee Names

mod slug;

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use futures::future::join_all;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "linkedin_public";

pub struct LinkedinPublic;

#[async_trait]
impl Module for LinkedinPublic {
    fn name(&self) -> &'static str {
        "linkedin_public"
    }

    fn description(&self) -> &'static str {
        "LinkedIn public profile discovery — slug probing for FullName / Organisation"
    }

    fn priority(&self) -> u8 {
        52
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName | TargetKind::Organisation)
    }

    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.002", "T1589.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Url, EntityKind::Username];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let is_org = matches!(target.kind, TargetKind::Organisation);
        let slugs = slug::generate_slugs(&target.value, is_org);
        if slugs.is_empty() {
            return Ok(ModuleResult::new());
        }

        let http = &ctx.http;
        let scan_id = &ctx.scan_id;

        let profile_type = if is_org { "company" } else { "in" };

        let futures = slugs.iter().map(|s| {
            let url = format!("https://www.linkedin.com/{profile_type}/{s}");
            async move {
                let resp = http
                    .get(&url)
                    .header("Accept", "text/html")
                    .header("Accept-Language", "en-AU,en;q=0.9")
                    .send_tagged(SRC)
                    .await;
                match resp {
                    Ok(r) if r.status().is_success() => {
                        let body = r.text().await.unwrap_or_default();
                        if is_linkedin_profile(&body) {
                            Some((url, s.clone()))
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            }
        });

        let results: Vec<_> = join_all(futures)
            .await
            .into_iter()
            .flatten()
            .take(3)
            .collect();

        let mut result = ModuleResult::with_capacity(results.len() * 2);
        for (url, found_slug) in results {
            let mut url_ent = Entity::new(EntityKind::Url, &url, 0.72, scan_id);
            url_ent.tag("linkedin");
            url_ent.tag(if is_org {
                "company-profile"
            } else {
                "person-profile"
            });
            url_ent.add_evidence(
                Evidence::new(SRC, format!("LinkedIn public profile: {url}"))
                    .with_attr("slug", &found_slug)
                    .with_attr("profile_type", profile_type)
                    .with_attr("source", "linkedin.com"),
            );
            result.push(url_ent);

            let mut uname = Entity::new(EntityKind::Username, &found_slug, 0.68, scan_id);
            uname.tag("linkedin");
            uname.add_evidence(
                Evidence::new(SRC, format!("LinkedIn slug for: {}", target.value))
                    .with_attr("platform", "linkedin")
                    .with_attr("profile_url", &url),
            );
            result.push(uname);
        }

        Ok(result)
    }
}

/// Heuristic: a real LinkedIn profile page contains at least one of these
/// markers. A login-wall redirect shows a different pattern.
fn is_linkedin_profile(html: &str) -> bool {
    html.contains("linkedin.com/in/")
        || html.contains("linkedin.com/company/")
        || html.contains("og:type\" content=\"profile")
        || html.contains("\"@type\":\"Person\"")
        || html.contains("\"@type\":\"Organization\"")
}
