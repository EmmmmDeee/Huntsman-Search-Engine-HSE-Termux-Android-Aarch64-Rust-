//! hex.pm user profile lookup. Free, no API key required.
//!
//! Endpoint: `GET https://hex.pm/api/users/{username}`
//!
//! hex.pm is the official package registry for the Erlang/Elixir ecosystem —
//! home to tens of thousands of library authors, framework maintainers, and
//! BEAM developers worldwide. The public user profile exposes a real personal
//! `email`, the full name, the account-creation date, and a `handles` map that
//! links the hex.pm identity to GitHub and X/Twitter accounts — direct
//! cross-platform pivots at zero cost. As an independent `code`-family source
//! it adds genuine corroboration diversity from a community largely
//! non-overlapping with the mainstream GitHub/GitLab population.
//!
//! **Live-shape correction:** the `handles` map is keyed by human display
//! names (`"GitHub"`, `"X.com"`, `"Elixir Forum"`, …), NOT lowercase platform
//! ids, and its values are full profile **URLs** (`"https://github.com/…"`),
//! not bare handles — so the pre-fix `match "github"`/`"twitter"` on the raw
//! key never fired and every cross-platform pivot was silently dropped.
//! Separately the top-level `email` (a real personal address, the single
//! highest-value field the endpoint returns) was never deserialised. Both are
//! now handled (live-confirmed against `wojtekmach`/`josevalim`).

#[cfg(test)]
mod tests;

use std::collections::HashMap;

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

const SRC: &str = "hexpm_user";

#[derive(Deserialize)]
pub(super) struct HexUser {
    #[serde(default)]
    pub(super) username: String,
    /// Display name — hex.pm uses "full_name"; accept "name" as alias.
    #[serde(alias = "name", default)]
    pub(super) full_name: Option<String>,
    /// Real personal email the author chose to publish (e.g.
    /// `"jose.valim@gmail.com"`) — the highest-value field the endpoint returns.
    #[serde(default)]
    pub(super) email: Option<String>,
    /// ISO-8601 account-creation timestamp (`inserted_at`) — a first-seen date.
    #[serde(default)]
    pub(super) inserted_at: Option<String>,
    /// Linked-account map. Keyed by DISPLAY NAME (`"GitHub"`, `"X.com"`,
    /// `"Elixir Forum"`, `"Slack"`, `"Libera"`, …), with full profile **URLs**
    /// as values (`"https://github.com/wojtekmach"`).
    #[serde(default)]
    pub(super) handles: HashMap<String, String>,
}

/// Extract a bare account handle from a hex.pm `handles` value. Values are full
/// profile URLs (`"https://github.com/wojtekmach"` → `"wojtekmach"`); a rare
/// bare handle is returned as-is. Returns `None` for a host-only URL (no
/// profile path segment) so we never mistake a host for a handle.
fn handle_from_link(value: &str) -> Option<String> {
    let v = value.trim().trim_end_matches('/');
    if v.is_empty() {
        return None;
    }
    // Bare handle (no path) — use verbatim.
    if !v.contains('/') {
        let h = v.trim_start_matches('@').trim();
        return (!h.is_empty()).then(|| h.to_string());
    }
    // URL — the profile handle is the last path segment.
    let seg = v.rsplit('/').next().unwrap_or_default().trim();
    // A host-only URL (`https://github.com`) leaves the host as the segment;
    // a real handle has no dot/colon, so reject those.
    if seg.is_empty() || seg.contains('.') || seg.contains(':') {
        return None;
    }
    Some(seg.trim_start_matches('@').to_string())
}

pub(super) fn build_entities(user: HexUser, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let handle = user.username.trim();
    if handle.is_empty() {
        return out;
    }
    let profile_url = format!("https://hex.pm/users/{handle}");
    let created = user
        .inserted_at
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let ev = || {
        let mut e = Evidence::new(SRC, format!("hex.pm profile of '{handle}'"))
            .with_attr("profile_url", &profile_url);
        if let Some(c) = created {
            e = e.with_attr("account_created", c);
        }
        e
    };

    // Confirmed username on hex.pm.
    let mut e = Entity::new(EntityKind::Username, handle, 0.87, scan_id);
    e.tag("hexpm");
    e.tag("public-profile");
    e.add_evidence(ev());
    out.push(e);

    // Profile URL.
    let mut u = Entity::new(
        EntityKind::Url,
        &profile_url,
        confidence::HIGH_PLUSPLUS,
        scan_id,
    );
    u.tag("hexpm");
    u.add_evidence(ev());
    out.push(u);

    // Real personal email the author published — the endpoint's top-level
    // `email` field (previously never deserialised, so silently dropped).
    if let Some(email) = user.email.as_deref() {
        let email = email.trim();
        if email.contains('@') {
            let mut em = Entity::new(EntityKind::Email, email, 0.82, scan_id);
            em.tag("hexpm");
            em.tag("public-profile");
            em.add_evidence(ev().with_attr("source_field", "email"));
            out.push(em);
        }
    }

    // Full name → Person (multi-word only).
    if let Some(name) = user.full_name.as_deref()
        && let Some(mut p) = profile_kit::person_from_name(name, 0.72, scan_id)
    {
        p.tag("hexpm");
        p.add_evidence(ev().with_attr("source_field", "full_name"));
        out.push(p);
    }

    // Cross-platform handle pivots: GitHub and X/Twitter. The `handles` map is
    // keyed by DISPLAY NAME (`"GitHub"`, `"X.com"`) with full URL values, so
    // match on the lowercased key and extract the handle from the URL. Sorted
    // by key first so the HashMap's iteration order never leaks into output.
    let mut linked: Vec<(&String, &String)> = user.handles.iter().collect();
    linked.sort_by(|a, b| a.0.cmp(b.0));
    for (platform, link) in linked {
        let (tag, confidence): (&str, f64) = match platform.to_ascii_lowercase().as_str() {
            "github" => ("github", 0.72),
            "x.com" | "x" | "twitter" => ("twitter", 0.62),
            _ => continue,
        };
        let Some(pivot) = handle_from_link(link) else {
            continue;
        };
        let mut t = Entity::new(EntityKind::Username, &pivot, confidence, scan_id);
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
        "hex.pm profile recon (free) — surfaces email, fullname, account age, and GitHub/X handles from the Elixir/Erlang registry"
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
        // Package registry profile lookup — Code Repositories (T1593.003); the
        // published `email` is Email Addresses (T1589.002); the GitHub/X handle
        // pivots are Social Media (T1593.001).
        &["T1589.002", "T1593.001", "T1593.003"]
    }
    fn produces(&self) -> &'static [EntityKind] {
        const K: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Url,
            EntityKind::Email,
        ];
        K
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        let url = format!("https://hex.pm/api/users/{}", urlencode(handle));
        // 404 (`Ok(None)`) = genuine "no such user" clean miss; every other
        // failure (429/5xx/transport) propagates via `?` instead of a fake 404
        // (T2.117 — `fetch_json_or_404`'s split is pinned in `util::http::tests`).
        let Some(user) = fetch_json_or_404::<HexUser>(&ctx.http, SRC, &url).await? else {
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
