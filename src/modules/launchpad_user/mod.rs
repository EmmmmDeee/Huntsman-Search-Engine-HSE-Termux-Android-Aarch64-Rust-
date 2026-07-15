//! Launchpad user profile lookup. Free, no API key required.
//!
//! Endpoint: `GET https://api.launchpad.net/1.0/~{username}`
//!
//! Launchpad (launchpad.net) is Canonical's open-source platform for Ubuntu and
//! Debian development — home to package maintainers, PPAs, bug tracking,
//! translations, and Bazaar/Git hosting. The public REST API returns a user's
//! display name, time zone, and biography. As an independent `code`-family
//! source it covers a population (Ubuntu/Debian contributors, Canonical staff)
//! that is almost entirely absent from GitHub/GitLab/Bitbucket — many Debian
//! maintainers develop exclusively within the Launchpad ecosystem, making this
//! a unique cross-platform corroboration pathway. The API is unauthenticated
//! for public data and explicitly documented as stable.

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

const SRC: &str = "launchpad_user";

#[derive(Deserialize)]
pub(super) struct LpPerson {
    /// Login / API name (the `~{name}` slug).
    #[serde(default)]
    pub(super) name: String,
    /// Human-readable full display name — often a real name.
    #[serde(default)]
    pub(super) display_name: Option<String>,
    /// Canonical web profile URL (e.g. `"https://launchpad.net/~alice"`).
    #[serde(default)]
    pub(super) web_link: Option<String>,
    /// Free-text biography — may contain email addresses. `homepage_content`
    /// (the field this used to read) is obsolete and `null` on essentially
    /// every modern account; `description` is the field Launchpad's own web
    /// UI ("Personal standing" / profile page) actually populates and keeps
    /// in sync.
    #[serde(default)]
    pub(super) description: Option<String>,
    /// `false` when the account is deactivated or suspended.
    #[serde(default = "default_true")]
    pub(super) is_valid: bool,
}

fn default_true() -> bool {
    true
}

pub(super) fn build_entities(person: LpPerson, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let handle = person.name.trim();
    if handle.is_empty() || !person.is_valid {
        return out;
    }
    let profile_url = profile_kit::profile_url(person.web_link.as_deref(), || {
        format!("https://launchpad.net/~{handle}")
    });

    let ev = || {
        Evidence::new(SRC, format!("Launchpad profile of '{handle}'"))
            .with_attr("profile_url", &profile_url)
    };

    // Confirmed username on Launchpad.
    let mut e = Entity::new(EntityKind::Username, handle, 0.85, scan_id);
    e.tag("launchpad");
    e.tag("public-profile");
    e.add_evidence(ev());
    out.push(e);

    // Profile URL.
    let mut u = Entity::new(EntityKind::Url, &profile_url, 0.78, scan_id);
    u.tag("launchpad");
    u.add_evidence(ev());
    out.push(u);

    // Display name → Person (multi-word only).
    if let Some(name) = person.display_name.as_deref()
        && let Some(mut p) = profile_kit::person_from_name(name, 0.72, scan_id)
    {
        p.tag("launchpad");
        p.add_evidence(ev().with_attr("source_field", "display_name"));
        out.push(p);
    }

    // Bio — extract email addresses mentioned in the free-text field.
    if let Some(bio) = person.description.as_deref() {
        for mut em in profile_kit::bio_emails(bio, 0.68, scan_id) {
            em.tag("launchpad");
            em.tag("public-profile");
            em.add_evidence(
                Evidence::new(SRC, format!("Email in Launchpad bio of '{handle}'"))
                    .with_attr("source_field", "description"),
            );
            out.push(em);
        }
    }

    out
}

pub struct LaunchpadUser;

#[async_trait]
impl Module for LaunchpadUser {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "Launchpad profile: display name, bio, email (Ubuntu/Debian ecosystem, free)"
    }
    fn priority(&self) -> u8 {
        53
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
        // Code/package-hosting profile — T1593.003; bio may surface email — T1589.002.
        &["T1589.002", "T1593.003"]
    }
    fn produces(&self) -> &'static [EntityKind] {
        const K: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Url,
        ];
        K
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        if handle.is_empty() {
            return Ok(ModuleResult::new());
        }
        // Launchpad uses a tilde prefix in the API path to denote a person.
        let url = format!("https://api.launchpad.net/1.0/~{}", urlencode(handle));
        // A genuine 404 (`Ok(None)`) is a real "no such Launchpad person" clean
        // miss; every other failure (429/5xx/transport) propagates via `?` as a
        // real `Error::module` instead of masquerading as that clean miss
        // (T2.117). `fetch_json_or_404`'s 404→`None`/non-2xx→`Err` split is the
        // contract this relies on (hermetically pinned in `util::http::tests`).
        let Some(person) = fetch_json_or_404::<LpPerson>(&ctx.http, SRC, &url).await? else {
            return Ok(ModuleResult::new());
        };
        if !person.name.eq_ignore_ascii_case(handle) {
            return Ok(ModuleResult::new());
        }
        let mut result = ModuleResult::new();
        result.entities = build_entities(person, &ctx.scan_id);
        Ok(result)
    }
}
