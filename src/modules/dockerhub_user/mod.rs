//! Docker Hub user profile lookup. Free, no API key required.
//!
//! Endpoint: `GET https://hub.docker.com/v2/users/{username}/`
//!
//! Docker Hub is the world's largest container image registry — used by
//! tens of millions of DevOps engineers, cloud architects, and software
//! teams. The public user profile exposes full name, company, location,
//! personal website URL, and optionally a Gravatar email. As an independent
//! `infra`-family source it provides a distinct corroboration pathway from
//! code-hosting (GitHub/GitLab) and social-media platforms.

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use super::profile_kit;
use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json_or_404, urlencode};

const SRC: &str = "dockerhub_user";

#[derive(Deserialize)]
pub(super) struct DhUser {
    #[serde(default)]
    pub(super) username: String,
    #[serde(default)]
    pub(super) full_name: Option<String>,
    #[serde(default)]
    pub(super) company: Option<String>,
    #[serde(default)]
    pub(super) location: Option<String>,
    #[serde(default)]
    pub(super) profile_url: Option<String>,
    /// Gravatar email — populated when the user links a Gravatar account.
    #[serde(default)]
    pub(super) gravatar_email: Option<String>,
}

pub(super) fn build_entities(user: DhUser, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let handle = user.username.trim();
    if handle.is_empty() {
        return out;
    }
    let profile_url = format!("https://hub.docker.com/u/{handle}");
    let ev = || {
        Evidence::new(SRC, format!("Docker Hub profile of '{handle}'"))
            .with_attr("profile_url", &profile_url)
    };

    // Confirmed username.
    let mut e = Entity::new(EntityKind::Username, handle, 0.85, scan_id);
    e.tag("dockerhub");
    e.tag("public-profile");
    e.add_evidence(ev());
    out.push(e);

    // Profile URL.
    let mut u = Entity::new(EntityKind::Url, &profile_url, 0.80, scan_id);
    u.tag("dockerhub");
    u.add_evidence(ev());
    out.push(u);

    // Full name → Person (multi-word only).
    if let Some(name) = user.full_name.as_deref()
        && let Some(mut p) = profile_kit::person_from_name(name, 0.70, scan_id)
    {
        p.tag("dockerhub");
        p.add_evidence(ev().with_attr("source_field", "full_name"));
        out.push(p);
    }

    // Company → Organisation (self-asserted).
    if let Some(company) = user.company.as_deref()
        && !company.trim().is_empty()
    {
        let mut o = Entity::new(EntityKind::Organisation, company.trim(), 0.58, scan_id);
        o.tag("dockerhub");
        o.tag("self-asserted");
        o.add_evidence(ev().with_attr("source_field", "company"));
        out.push(o);
    }

    // Location → Address (self-asserted, low confidence).
    if let Some(loc) = user.location.as_deref()
        && let Some(mut a) = profile_kit::location_address(loc, 0.35, scan_id)
    {
        a.tag("dockerhub");
        a.tag("self-asserted");
        a.add_evidence(ev().with_attr("source_field", "location"));
        out.push(a);
    }

    // Personal website from profile_url (distinct from the canonical hub.docker.com URL).
    if let Some(site) = user.profile_url.as_deref() {
        for mut e in profile_kit::website_url_and_domain(site, 0.68, 0.62, scan_id) {
            e.tag("dockerhub");
            if e.kind == EntityKind::Domain {
                e.tag("derived");
            }
            e.add_evidence(ev().with_attr("source_field", "profile_url"));
            out.push(e);
        }
    }

    // Gravatar email — surfaces direct email pivot when the user links Gravatar.
    if let Some(email) = user.gravatar_email.as_deref()
        && email.contains('@')
    {
        let mut em = Entity::new(EntityKind::Email, email.trim(), 0.72, scan_id);
        em.tag("dockerhub");
        em.tag("gravatar");
        em.add_evidence(ev().with_attr("source_field", "gravatar_email"));
        out.push(em);
    }

    out
}

pub struct DockerhubUser;

#[async_trait]
impl Module for DockerhubUser {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "Docker Hub profile: fullname, company, location, website, gravatar email (free)"
    }
    fn priority(&self) -> u8 {
        50
    }
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }
    fn attack_techniques(&self) -> &'static [&'static str] {
        // Container registry profile lookup — Code Repositories (T1593.003).
        &["T1593.003"]
    }
    fn produces(&self) -> &'static [EntityKind] {
        const K: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Url,
            EntityKind::Domain,
            EntityKind::Organisation,
            EntityKind::Address,
        ];
        K
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        let url = format!("https://hub.docker.com/v2/users/{}/", urlencode(handle));
        let user: DhUser = match fetch_json_or_404(&ctx.http, SRC, &url).await {
            Ok(Some(u)) => u,
            Ok(None) | Err(_) => return Ok(ModuleResult::new()),
        };
        if !user.username.eq_ignore_ascii_case(handle) {
            return Ok(ModuleResult::new());
        }
        let mut result = ModuleResult::new();
        result.entities = build_entities(user, &ctx.scan_id);
        Ok(result)
    }
}
