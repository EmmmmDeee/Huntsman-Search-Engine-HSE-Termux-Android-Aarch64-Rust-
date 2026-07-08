//! Hugging Face user profile lookup. Free, no API key required.
//!
//! Endpoint: `GET https://huggingface.co/api/users/{username}`
//!
//! Hugging Face is the leading platform for sharing ML models, datasets,
//! and Spaces — tens of millions of practitioners, researchers, and teams.
//! The public profile exposes full name, optional email (if made public),
//! website, Twitter handle, and org memberships, all via an unauthenticated
//! JSON API. As an independent `code`-family source it provides a distinct
//! corroboration pathway from GitHub/GitLab (models/datasets vs source code)
//! and from social-media platforms.

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

const SRC: &str = "huggingface_user";

#[derive(Deserialize)]
pub(super) struct HfUser {
    #[serde(default)]
    pub(super) username: String,
    #[serde(default)]
    pub(super) fullname: Option<String>,
    #[serde(default)]
    pub(super) email: Option<String>,
    #[serde(default)]
    pub(super) website: Option<String>,
    #[serde(default)]
    pub(super) twitter: Option<String>,
    #[serde(default)]
    pub(super) orgs: Vec<HfOrg>,
}

#[derive(Deserialize)]
pub(super) struct HfOrg {
    #[serde(default)]
    pub(super) name: String,
    #[serde(default)]
    pub(super) fullname: Option<String>,
}

pub(super) fn build_entities(user: HfUser, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let handle = user.username.trim();
    if handle.is_empty() {
        return out;
    }
    let profile_url = format!("https://huggingface.co/{handle}");
    let ev = || {
        Evidence::new(SRC, format!("Hugging Face profile of '{handle}'"))
            .with_attr("profile_url", &profile_url)
    };

    // Confirmed username entity.
    let mut e = Entity::new(EntityKind::Username, handle, 0.88, scan_id);
    e.tag("huggingface");
    e.tag("public-profile");
    e.add_evidence(ev());
    out.push(e);

    // Profile URL.
    let mut u = Entity::new(EntityKind::Url, &profile_url, 0.82, scan_id);
    u.tag("huggingface");
    u.add_evidence(ev());
    out.push(u);

    // Full name → Person (require at least two tokens to avoid single-word handles).
    if let Some(name) = user.fullname.as_deref()
        && let Some(mut p) = profile_kit::person_from_name(name, 0.72, scan_id)
    {
        p.tag("huggingface");
        p.add_evidence(ev().with_attr("source_field", "fullname"));
        out.push(p);
    }

    // Email — present only when the user has it set to public.
    if let Some(email) = user.email.as_deref()
        && email.contains('@')
    {
        let mut em = Entity::new(EntityKind::Email, email.trim(), 0.82, scan_id);
        em.tag("huggingface");
        em.add_evidence(ev().with_attr("source_field", "email"));
        out.push(em);
    }

    // Website URL and derived domain.
    if let Some(site) = user.website.as_deref() {
        for mut e in profile_kit::website_url_and_domain(site, 0.72, 0.65, scan_id) {
            e.tag("huggingface");
            if e.kind == EntityKind::Domain {
                e.tag("derived");
            }
            e.add_evidence(ev().with_attr("source_field", "website"));
            out.push(e);
        }
    }

    // Twitter / X handle.
    if let Some(tw_raw) = user.twitter.as_deref() {
        let tw = tw_raw.trim().trim_start_matches('@');
        if !tw.is_empty() {
            let mut t = Entity::new(EntityKind::Username, tw, 0.62, scan_id);
            t.tag("twitter");
            t.add_evidence(ev().with_attr("source_field", "twitter_handle"));
            out.push(t);
        }
    }

    // Organisation memberships.
    for org in &user.orgs {
        let display = org.fullname.as_deref().unwrap_or(&org.name);
        if display.trim().is_empty() {
            continue;
        }
        let mut o = Entity::new(EntityKind::Organisation, display.trim(), 0.55, scan_id);
        o.tag("huggingface");
        o.tag("org-member");
        o.add_evidence(ev().with_attr("org_handle", &org.name));
        out.push(o);
    }

    out
}

pub struct HuggingfaceUser;

#[async_trait]
impl Module for HuggingfaceUser {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "Hugging Face profile: fullname, email, website, Twitter handle, orgs (free)"
    }
    fn priority(&self) -> u8 {
        52
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
        // Model/dataset registry profile lookup — T1593.003 for the
        // Username itself, not the Social-Media default (T1593.001) its
        // category implies. This REPLACED the whole default array instead
        // of substituting just that one technique — the same gap already
        // fixed for the sibling "profile lookup" modules
        // (github_user/dockerhub_user/codewars_user/mastodon_user/
        // sourceforge_user/bitbucket_user/rubygems_user/gitlab_user/
        // cpan_user/gitea_user/codeberg_user). `build_entities` also
        // constructs a Person (`fullname`), an Email (`email`, when made
        // public), and an Organisation (`orgs[]` membership) — each needs
        // its own technique so the `attack:<ID>` provenance tag
        // core::engine::dispatch stamps on every admitted entity actually
        // matches what collected it. No `location` field exists on
        // `HfUser`, so T1591.001 does not apply.
        &[
            "T1589.002", // Email Addresses — Email from the public `email` field
            "T1589.003", // Employee Names — Person from the real `fullname` field
            "T1591.002", // Business Relationships — Organisation from `orgs[]` membership
            "T1593.003", // Code Repositories — Username via the Hugging Face profile itself
        ]
    }
    fn produces(&self) -> &'static [EntityKind] {
        const K: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Url,
            EntityKind::Domain,
            EntityKind::Organisation,
        ];
        K
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        let url = format!("https://huggingface.co/api/users/{}", urlencode(handle));
        let user: HfUser = match fetch_json_or_404(&ctx.http, SRC, &url).await {
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
