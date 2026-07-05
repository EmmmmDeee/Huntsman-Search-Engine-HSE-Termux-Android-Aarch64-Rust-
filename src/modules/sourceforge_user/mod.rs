//! SourceForge user profile lookup. Free, no API key required.
//!
//! Endpoint: `GET https://sourceforge.net/api/user/username={username}/json`
//!
//! SourceForge is one of the oldest and largest open-source project hosting
//! platforms, home to tens of thousands of legacy OSS projects in C, Java,
//! Python, and other languages that predate GitHub by over a decade. Many
//! projects never migrated and continue to use it for releases and issue
//! tracking. The public REST API returns the user's login, display name,
//! profile URL, biography, and location — all without authentication. As a
//! `code`-family source it independently corroborates developer identities
//! from a population largely invisible to GitHub/GitLab/Bitbucket searches.

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

const SRC: &str = "sourceforge_user";

#[derive(Deserialize)]
pub(super) struct SfUser {
    /// Login / API name.
    #[serde(default)]
    pub(super) name: String,
    /// Human-readable display name.
    #[serde(default)]
    pub(super) display_name: Option<String>,
    /// Canonical profile URL (e.g. `"https://sourceforge.net/u/johndoe/"`).
    #[serde(default)]
    pub(super) url: Option<String>,
    /// Free-text biography — may contain email addresses and links.
    #[serde(default)]
    pub(super) about: Option<String>,
    /// Self-reported location string.
    #[serde(default)]
    pub(super) location: Option<String>,
}

pub(super) fn build_entities(user: SfUser, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let handle = user.name.trim();
    if handle.is_empty() {
        return out;
    }

    let profile_url = profile_kit::profile_url(user.url.as_deref(), || {
        format!("https://sourceforge.net/u/{handle}")
    });

    let ev = || {
        Evidence::new(SRC, format!("SourceForge profile of '{handle}'"))
            .with_attr("profile_url", &profile_url)
    };

    // Confirmed username on SourceForge.
    let mut e = Entity::new(EntityKind::Username, handle, 0.86, scan_id);
    e.tag("sourceforge");
    e.tag("public-profile");
    e.add_evidence(ev());
    out.push(e);

    // Profile URL.
    let mut u = Entity::new(EntityKind::Url, &profile_url, 0.79, scan_id);
    u.tag("sourceforge");
    u.add_evidence(ev());
    out.push(u);

    // Display name → Person (multi-word only).
    if let Some(name) = user.display_name.as_deref()
        && let Some(mut p) = profile_kit::person_from_name(name, 0.70, scan_id)
    {
        p.tag("sourceforge");
        p.tag("derived");
        p.add_evidence(
            Evidence::new(
                SRC,
                format!("Real name from SourceForge account '{handle}'"),
            )
            .with_attr("source_field", "display_name"),
        );
        out.push(p);
    }

    // Location → Address (self-asserted, low confidence).
    if let Some(loc) = user.location.as_deref()
        && let Some(mut a) = profile_kit::location_address(loc, 0.35, scan_id)
    {
        a.tag("sourceforge");
        a.tag("self-asserted");
        a.add_evidence(ev().with_attr("source_field", "location"));
        out.push(a);
        if let Some(mut c) = profile_kit::location_coordinates(loc, 0.25, scan_id) {
            c.tag("sourceforge");
            c.add_evidence(ev().with_attr("source_field", "location"));
            out.push(c);
        }
    }

    // Bio — extract email addresses.
    if let Some(bio) = user.about.as_deref() {
        for mut em in profile_kit::bio_emails(bio, 0.68, scan_id) {
            em.tag("sourceforge");
            em.tag("public-profile");
            em.add_evidence(
                Evidence::new(SRC, format!("Email in SourceForge bio of '{handle}'"))
                    .with_attr("source_field", "about"),
            );
            out.push(em);
        }
    }

    out
}

pub struct SourceforgeUser;

#[async_trait]
impl Module for SourceforgeUser {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "SourceForge profile: display name, location, bio via SF REST API (free)"
    }
    fn priority(&self) -> u8 {
        94
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
        // Code-repository profile — T1593.003; bio may surface real name/email — T1589.002.
        &["T1589.002", "T1593.003"]
    }
    fn produces(&self) -> &'static [EntityKind] {
        const K: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Url,
            EntityKind::Address,
            EntityKind::Coordinates,
        ];
        K
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        // SourceForge usernames: 3–20 chars, alphanumeric + hyphen/underscore.
        if handle.is_empty() || handle.len() > 20 {
            return Ok(ModuleResult::new());
        }
        let url = format!(
            "https://sourceforge.net/api/user/username={}/json",
            urlencode(handle)
        );
        let user: SfUser = match fetch_json_or_404(&ctx.http, SRC, &url).await {
            Ok(Some(u)) => u,
            Ok(None) | Err(_) => return Ok(ModuleResult::new()),
        };
        if !user.name.eq_ignore_ascii_case(handle) {
            return Ok(ModuleResult::new());
        }
        let mut result = ModuleResult::new();
        result.entities = build_entities(user, &ctx.scan_id);
        Ok(result)
    }
}
