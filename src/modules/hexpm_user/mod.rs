//! hex.pm user profile lookup. Free, no API key required.
//!
//! Endpoint: `GET https://hex.pm/api/users/{username}`
//!
//! hex.pm is the official package registry for the Erlang/Elixir ecosystem —
//! home to tens of thousands of library authors, framework maintainers, and
//! BEAM developers worldwide. The public user profile exposes full name and a
//! `handles` map that links the hex.pm identity to GitHub and Twitter accounts,
//! providing direct cross-platform pivots at zero cost. As an independent
//! `code`-family source it adds genuine corroboration diversity from a community
//! that is largely non-overlapping with the mainstream GitHub/GitLab population.

#[cfg(test)]
mod tests;

use std::collections::HashMap;

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

const SRC: &str = "hexpm_user";

#[derive(Deserialize)]
pub(super) struct HexUser {
    #[serde(default)]
    pub(super) username: String,
    /// Display name — hex.pm uses "full_name"; accept "name" as alias.
    #[serde(alias = "name", default)]
    pub(super) full_name: Option<String>,
    /// Platform handle map: "github" → handle, "twitter" → handle, etc.
    #[serde(default)]
    pub(super) handles: HashMap<String, String>,
}

pub(super) fn build_entities(user: HexUser, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let handle = user.username.trim();
    if handle.is_empty() {
        return out;
    }
    let profile_url = format!("https://hex.pm/users/{handle}");
    let ev = || {
        Evidence::new(SRC, format!("hex.pm profile of '{handle}'"))
            .with_attr("profile_url", &profile_url)
    };

    // Confirmed username on hex.pm.
    let mut e = Entity::new(EntityKind::Username, handle, 0.87, scan_id);
    e.tag("hexpm");
    e.tag("public-profile");
    e.add_evidence(ev());
    out.push(e);

    // Profile URL.
    let mut u = Entity::new(EntityKind::Url, &profile_url, 0.80, scan_id);
    u.tag("hexpm");
    u.add_evidence(ev());
    out.push(u);

    // Full name → Person (multi-word only).
    if let Some(name) = user.full_name.as_deref()
        && let Some(mut p) = profile_kit::person_from_name(name, 0.72, scan_id)
    {
        p.tag("hexpm");
        p.add_evidence(ev().with_attr("source_field", "full_name"));
        out.push(p);
    }

    // Cross-platform handle pivots: GitHub and Twitter are the two common ones.
    for (platform, linked_handle) in &user.handles {
        let linked = linked_handle.trim().trim_start_matches('@');
        if linked.is_empty() {
            continue;
        }
        let (tag, confidence): (&str, f64) = match platform.as_str() {
            "github" => ("github", 0.72),
            "twitter" => ("twitter", 0.62),
            _ => continue,
        };
        let mut t = Entity::new(EntityKind::Username, linked, confidence, scan_id);
        t.tag("hexpm");
        t.tag(tag);
        t.add_evidence(ev().with_attr("source_field", format!("handles.{platform}")));
        out.push(t);
    }

    out
}

pub struct HexpmUser;

#[async_trait]
impl Module for HexpmUser {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "hex.pm profile: fullname, GitHub/Twitter handles via Elixir/Erlang package registry (free)"
    }
    fn priority(&self) -> u8 {
        51
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
        // Package registry profile lookup — Code Repositories (T1593.003).
        &["T1593.003"]
    }
    fn produces(&self) -> &'static [EntityKind] {
        const K: &[EntityKind] = &[EntityKind::Username, EntityKind::Person, EntityKind::Url];
        K
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        let url = format!("https://hex.pm/api/users/{}", urlencode(handle));
        let user: HexUser = match fetch_json_or_404(&ctx.http, SRC, &url).await {
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
