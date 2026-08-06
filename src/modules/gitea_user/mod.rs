//! Gitea.com user profile lookup. Free, no API key required.
//!
//! Endpoint: `GET https://gitea.com/api/v1/users/{username}`
//!
//! Gitea.com is the official hosted instance of the Gitea open-source Git
//! service — a self-hostable GitHub alternative popular with privacy-conscious
//! developers, self-hosting communities, and small teams. The public REST API
//! (Swagger v1) returns the user's login, full name, public email, website,
//! location, and biography. As an independent `code`-family source it covers
//! a population that prefers decentralised or self-hosted alternatives to the
//! major platforms, complementary to Codeberg (Forgejo) and GitHub/GitLab.

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use super::profile_kit;
use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json_or_404, urlencode};

const SRC: &str = "gitea_user";

#[derive(Deserialize)]
pub(super) struct GtUser {
    /// Login name.
    #[serde(default)]
    pub(super) login: String,
    /// Full display name.
    #[serde(default)]
    pub(super) full_name: Option<String>,
    /// Public email (empty string when not set).
    #[serde(default)]
    pub(super) email: Option<String>,
    /// Self-reported personal website.
    #[serde(default)]
    pub(super) website: Option<String>,
    /// Self-reported location.
    #[serde(default)]
    pub(super) location: Option<String>,
    /// Profile biography — may contain additional contact info.
    #[serde(default)]
    pub(super) description: Option<String>,
    /// Canonical HTML profile URL.
    #[serde(default)]
    pub(super) html_url: Option<String>,
    /// Account creation timestamp (ISO-8601).
    #[serde(default)]
    pub(super) created: Option<String>,
}

pub(super) fn build_entities(user: GtUser, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let handle = user.login.trim();
    if handle.is_empty() {
        return out;
    }
    let profile_url = profile_kit::profile_url(user.html_url.as_deref(), || {
        format!("https://gitea.com/{handle}")
    });

    let mut ev_base = Evidence::new(SRC, format!("Gitea.com profile of '{handle}'"))
        .with_attr("profile_url", &profile_url);
    if let Some(ref ts) = user.created {
        ev_base = ev_base.with_attr("created_at", ts);
    }
    let ev = || ev_base.clone();

    // Confirmed username on Gitea.com.
    let mut e = Entity::new(
        EntityKind::Username,
        handle,
        confidence::HIGH_PLUSPLUS_PLUS,
        scan_id,
    );
    e.tag("gitea");
    e.tag("public-profile");
    e.add_evidence(ev());
    out.push(e);

    // Profile URL.
    let mut u = Entity::new(EntityKind::Url, &profile_url, confidence::STRONG, scan_id);
    u.tag("gitea");
    u.add_evidence(ev());
    out.push(u);

    // Real name → Person (multi-word, ≥2 tokens).
    if let Some(name) = user.full_name.as_deref()
        && let Some(mut p) = profile_kit::person_from_name(name, confidence::HIGH_PLUS, scan_id)
    {
        p.tag("gitea");
        p.tag("derived");
        p.add_evidence(
            Evidence::new(SRC, format!("Real name from Gitea.com account '{handle}'"))
                .with_attr("source_field", "full_name"),
        );
        out.push(p);
    }

    // Public email. Skip forge no-reply masking addresses
    // (`user@noreply.gitea.io` / `…@users.noreply.…`) — privacy placeholders,
    // not a real contact pivot — so this agrees with the sibling codeberg_user
    // on the identical Forgejo API.
    if let Some(ref email) = user.email
        && email.contains('@')
        && !crate::util::domains::is_noreply_email_domain(email)
    {
        let mut em = Entity::new(
            EntityKind::Email,
            email.trim(),
            confidence::VERY_HIGH,
            scan_id,
        );
        em.tag("gitea");
        em.add_evidence(
            Evidence::new(
                SRC,
                format!("Public email from Gitea.com profile of '{handle}'"),
            )
            .with_attr("source_field", "email"),
        );
        out.push(em);
    }

    // Personal website URL + Domain.
    if let Some(site) = user.website.as_deref() {
        for mut e in profile_kit::website_url_and_domain(
            site,
            confidence::HIGH_PLUS,
            confidence::NOTABLE,
            scan_id,
        ) {
            e.tag("gitea");
            if e.kind == EntityKind::Domain {
                e.tag("derived");
            }
            e.add_evidence(ev().with_attr("source_field", "website"));
            out.push(e);
        }
    }

    // Location → Address (self-asserted, low confidence).
    if let Some(loc) = user.location.as_deref()
        && let Some(mut a) = profile_kit::location_address(loc, 0.36, scan_id)
    {
        a.tag("gitea");
        a.tag("self-asserted");
        a.add_evidence(ev().with_attr("source_field", "location"));
        out.push(a);
        if let Some(mut c) = profile_kit::location_coordinates(loc, 0.26, scan_id) {
            c.tag("gitea");
            c.add_evidence(ev().with_attr("source_field", "location"));
            out.push(c);
        }
    }

    // Bio/description — extract email addresses.
    if let Some(bio) = user.description.as_deref() {
        for mut em in profile_kit::bio_emails(bio, 0.68, scan_id) {
            em.tag("gitea");
            em.tag("public-profile");
            em.add_evidence(
                Evidence::new(SRC, format!("Email in Gitea.com bio of '{handle}'"))
                    .with_attr("source_field", "description"),
            );
            out.push(em);
        }
    }

    out
}

pub struct GiteaUser;

#[async_trait]
impl Module for GiteaUser {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "Gitea.com profile recon (free) — harvests name, email, website, and location via Gitea API v1"
    }
    fn priority(&self) -> u8 {
        98
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
        // Code-repository profile — T1593.003; real name/email — T1589.002.
        &["T1589.002", "T1593.003"]
    }
    fn produces(&self) -> &'static [EntityKind] {
        const K: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Url,
            EntityKind::Domain,
            EntityKind::Address,
            EntityKind::Coordinates,
        ];
        K
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        if handle.is_empty() || handle.len() > 40 {
            return Ok(ModuleResult::new());
        }
        let url = format!("https://gitea.com/api/v1/users/{}", urlencode(handle));
        // 404 (`Ok(None)`) = genuine "no such user" clean miss; every other
        // failure (429/5xx/transport) propagates via `?` instead of a fake 404
        // (T2.117 — `fetch_json_or_404`'s split is pinned in `util::http::tests`).
        let Some(user) = fetch_json_or_404::<GtUser>(&ctx.http, SRC, &url).await? else {
            return Ok(ModuleResult::new());
        };
        if !user.login.eq_ignore_ascii_case(handle) {
            return Ok(ModuleResult::new());
        }
        let mut result = ModuleResult::new();
        result.entities = build_entities(user, &ctx.scan_id);
        Ok(result)
    }
}
