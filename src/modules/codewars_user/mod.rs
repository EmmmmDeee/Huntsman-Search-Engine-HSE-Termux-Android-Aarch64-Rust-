//! Codewars user profile lookup. Free, no API key required.
//!
//! Endpoint: `GET https://www.codewars.com/api/v1/users/{username}`
//!
//! Codewars is a developer training platform with millions of members
//! ("warriors") who solve programming challenges ("kata") in dozens of
//! languages. Its public REST API exposes the user's display name, honour
//! score, programming language ranks, and optionally a real name and clan
//! (team / organisation) membership. As an independent `code`-family source it
//! serves a population that is meaningfully distinct from pure code-hosting
//! (GitHub/GitLab) — competitive programmers, learners, and hobbyists who may
//! not maintain public repositories but are identifiable by their kata ranking.

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

const SRC: &str = "codewars_user";

#[derive(Deserialize)]
pub(super) struct CwUser {
    #[serde(default)]
    pub(super) username: String,
    /// Optional display / real name set by the user.
    #[serde(default)]
    pub(super) name: Option<String>,
    /// Clan (team / organisation) — user-defined, free-text.
    #[serde(default)]
    pub(super) clan: Option<String>,
    /// Self-reported city — present but often null.
    #[serde(default)]
    pub(super) city: Option<String>,
}

pub(super) fn build_entities(user: CwUser, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let handle = user.username.trim();
    if handle.is_empty() {
        return out;
    }
    let profile_url = format!("https://www.codewars.com/users/{handle}");
    let ev = || {
        Evidence::new(SRC, format!("Codewars profile of '{handle}'"))
            .with_attr("profile_url", &profile_url)
    };

    // Confirmed username on Codewars.
    let mut e = Entity::new(EntityKind::Username, handle, 0.84, scan_id);
    e.tag("codewars");
    e.tag("public-profile");
    e.add_evidence(ev());
    out.push(e);

    // Profile URL.
    let mut u = Entity::new(EntityKind::Url, &profile_url, confidence::STRONG, scan_id);
    u.tag("codewars");
    u.add_evidence(ev());
    out.push(u);

    // Real name → Person (multi-word only; single-token names are likely
    // pseudonyms or first-name-only entries).
    if let Some(name) = user.name.as_deref()
        && let Some(mut p) = profile_kit::person_from_name(name, 0.68, scan_id)
    {
        p.tag("codewars");
        p.add_evidence(ev().with_attr("source_field", "name"));
        out.push(p);
    }

    // Clan → Organisation (self-asserted; low confidence).
    if let Some(clan) = user.clan.as_deref()
        && !clan.trim().is_empty()
    {
        let mut o = Entity::new(EntityKind::Organisation, clan.trim(), 0.48, scan_id);
        o.tag("codewars");
        o.tag("self-asserted");
        o.add_evidence(ev().with_attr("source_field", "clan"));
        out.push(o);
    }

    // City → Address (self-asserted, very low confidence).
    if let Some(city) = user.city.as_deref()
        && let Some(mut a) = profile_kit::location_address(city, 0.32, scan_id)
    {
        a.tag("codewars");
        a.tag("self-asserted");
        a.add_evidence(ev().with_attr("source_field", "city"));
        out.push(a);
        if let Some(mut c) = profile_kit::location_coordinates(city, 0.22, scan_id) {
            c.tag("codewars");
            c.add_evidence(ev().with_attr("source_field", "city"));
            out.push(c);
        }
    }

    out
}

pub struct CodewarsUser;

#[async_trait]
impl Module for CodewarsUser {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "Codewars profile recon — surfaces real name, clan/org, and city via the public kata-platform API (free)"
    }
    fn priority(&self) -> u8 {
        49
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
        // A coding-platform profile — ATT&CK Code Repositories (T1593.003)
        // for the Username itself. `build_entities` also constructs a Person
        // (real `name`), an Organisation (`clan`), and an Address/
        // Coordinates (`city`) — each needs its own technique so the
        // `attack:<ID>` provenance tag core::engine::dispatch stamps on
        // every admitted entity actually matches what collected it (the
        // same gap fixed for `github_user`/`dockerhub_user`). No Email field
        // exists on this API, so T1589.002 does not apply.
        &[
            "T1589.003", // Employee Names — Person from the real `name` field
            "T1591.001", // Determine Physical Locations — Address/Coordinates from `city`
            "T1591.002", // Business Relationships — Organisation from `clan`
            "T1593.003", // Code Repositories — Username via the Codewars profile itself
        ]
    }
    fn produces(&self) -> &'static [EntityKind] {
        const K: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Url,
            EntityKind::Organisation,
            EntityKind::Address,
            EntityKind::Coordinates,
        ];
        K
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        let url = format!(
            "https://www.codewars.com/api/v1/users/{}",
            urlencode(handle)
        );
        // 404 (`Ok(None)`) = genuine "no such user" clean miss; every other
        // failure (429/5xx/transport) propagates via `?` instead of a fake 404
        // (T2.117 — `fetch_json_or_404`'s split is pinned in `util::http::tests`).
        let Some(user) = fetch_json_or_404::<CwUser>(&ctx.http, SRC, &url).await? else {
            return Ok(ModuleResult::new());
        };
        if !user.username.eq_ignore_ascii_case(handle) {
            return Ok(ModuleResult::new());
        }
        let mut result = ModuleResult::new();
        result.entities = build_entities(user, &ctx.scan_id);
        Ok(result)
    }
}
