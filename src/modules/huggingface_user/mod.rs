//! Hugging Face user profile lookup. Free, no API key required.
//!
//! Endpoint: `GET https://huggingface.co/api/users/{handle}/overview`
//!
//! Hugging Face is the leading platform for sharing ML models, datasets,
//! and Spaces — tens of millions of practitioners, researchers, and teams.
//! The public profile confirms the handle and exposes the full name, the
//! account-creation date, and org memberships via an unauthenticated JSON
//! API. As an independent `code`-family source it provides a distinct
//! corroboration pathway from GitHub/GitLab (models/datasets vs source code)
//! and from social-media platforms.
//!
//! **Endpoint migration (2026):** the pre-2026 `GET /api/users/{handle}`
//! endpoint now returns `404 {"error":"Sorry, we can't find the page you are
//! looking for."}` for *every* real user (live-confirmed against
//! `julien-c`/`osanseviero`/`clem`), so the module was silently emitting
//! nothing on every scan — `fetch_json_or_404` mapped the 404 to `Ok(None)`
//! and `process` returned empty, indistinguishable from "no such user." The
//! live endpoint is `…/{handle}/overview`, whose JSON carries the handle in a
//! top-level `user` string (the old shape called it `username`), plus
//! `fullname`, `createdAt`, and `orgs[]`. That endpoint no longer exposes the
//! public email / website / Twitter fields the pre-2026 API did, so those are
//! no longer extracted here (they simply aren't in the response).

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
    /// The account handle. In the `/overview` response this is the top-level
    /// `user` string. (The pre-2026 `/api/users/{h}` endpoint called this
    /// field `username`; that endpoint now 404s for every real user.)
    #[serde(default)]
    pub(super) user: String,
    #[serde(default)]
    pub(super) fullname: Option<String>,
    /// ISO-8601 account-creation timestamp (`createdAt` in the overview
    /// response) — a first-seen date for the handle, surfaced as evidence.
    #[serde(default, rename = "createdAt")]
    pub(super) created_at: Option<String>,
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
    let handle = user.user.trim();
    if handle.is_empty() {
        return out;
    }
    let profile_url = format!("https://huggingface.co/{handle}");
    let created = user
        .created_at
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let ev = || {
        let mut e = Evidence::new(SRC, format!("Hugging Face profile of '{handle}'"))
            .with_attr("profile_url", &profile_url);
        // `createdAt` is a genuine first-seen date for the handle — attach it
        // to every derived record so the account age travels with the finding.
        if let Some(c) = created {
            e = e.with_attr("account_created", c);
        }
        e
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
        "Hugging Face profile: handle, fullname, account-created date, orgs (free)"
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
        // Model/dataset registry profile lookup — Code Repositories (T1593.003).
        &["T1593.003"]
    }
    fn produces(&self) -> &'static [EntityKind] {
        const K: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Url,
            EntityKind::Organisation,
        ];
        K
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        let url = format!(
            "https://huggingface.co/api/users/{}/overview",
            urlencode(handle)
        );
        // 404 (`Ok(None)`) = genuine "no such user" clean miss; every other
        // failure (429/5xx/transport) propagates via `?` instead of a fake 404
        // (T2.117 — `fetch_json_or_404`'s split is pinned in `util::http::tests`).
        let Some(user) = fetch_json_or_404::<HfUser>(&ctx.http, SRC, &url).await? else {
            return Ok(ModuleResult::new());
        };
        // Identity guard: the overview response echoes the requested handle in
        // its top-level `user` field; confirm it matches so a redirect or a
        // fuzzy match can't attribute someone else's profile to this handle.
        if !user.user.eq_ignore_ascii_case(handle) {
            return Ok(ModuleResult::new());
        }
        let mut result = ModuleResult::new();
        result.entities = build_entities(user, &ctx.scan_id);
        Ok(result)
    }
}
