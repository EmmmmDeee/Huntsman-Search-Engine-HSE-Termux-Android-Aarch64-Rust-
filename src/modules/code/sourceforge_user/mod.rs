//! SourceForge user profile lookup. Free, no API key required.
//!
//! Endpoint: `GET https://sourceforge.net/rest/u/{handle}`
//!
//! SourceForge is one of the oldest and largest open-source project hosting
//! platforms, home to tens of thousands of legacy OSS projects in C, Java,
//! Python, and other languages that predate GitHub by over a decade. Many
//! projects never migrated and continue to use it for releases and issue
//! tracking. The public Allura REST API returns the user's login, display
//! name (via the matching `developers[]` record), profile URL, account age,
//! personal homepage, and linked social accounts — all without
//! authentication. As a `code`-family source it independently corroborates
//! developer identities from a population largely invisible to
//! GitHub/GitLab/Bitbucket searches.
//!
//! **Endpoint migration:** the legacy `GET /api/user/username={h}/json`
//! endpoint was removed — it now returns SourceForge's HTML `404` page for
//! every real user (live-confirmed against `jonelo`), which the module read
//! as a clean "no such user" and so emitted nothing on every scan. The live
//! Allura endpoint is `GET /rest/u/{handle}`, whose JSON keys the handle as
//! `name`, carries `creation_date`, `external_homepage`, `socialnetworks[]`,
//! and a `developers[]` array (the record whose `username` matches the handle
//! holds the account's real/display name). It no longer exposes the free-text
//! bio or self-reported location the legacy endpoint did, so those (and the
//! Email/Address/Coordinates they produced) are no longer extracted.

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use crate::modules::profile_kit;
use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json_or_404, urlencode};

const SRC: &str = "sourceforge_user";

#[derive(Deserialize)]
pub(super) struct SfUser {
    /// Login / API name — the handle. `/rest/u/{h}` echoes it here.
    #[serde(default)]
    pub(super) name: String,
    /// Canonical profile URL (e.g. `"https://sourceforge.net/u/johndoe/"`).
    #[serde(default)]
    pub(super) url: Option<String>,
    /// ISO date the account was created (`creation_date`) — a first-seen
    /// date for the handle, surfaced as evidence.
    #[serde(default)]
    pub(super) creation_date: Option<String>,
    /// Self-reported personal / homepage URL.
    #[serde(default)]
    pub(super) external_homepage: Option<String>,
    /// Linked social-network accounts (each a `{socialnetwork, accounturl}`);
    /// most entries are blank placeholders, so only non-empty URLs are used.
    #[serde(default)]
    pub(super) socialnetworks: Vec<SfSocial>,
    /// Developer records for the account; the one whose `username` matches the
    /// handle carries the account's real / display name (the legacy endpoint's
    /// `display_name`, relocated here in the Allura REST shape).
    #[serde(default)]
    pub(super) developers: Vec<SfDeveloper>,
}

#[derive(Deserialize)]
pub(super) struct SfSocial {
    #[serde(default)]
    pub(super) accounturl: String,
    #[serde(default)]
    pub(super) socialnetwork: String,
}

#[derive(Deserialize)]
pub(super) struct SfDeveloper {
    #[serde(default)]
    pub(super) username: String,
    #[serde(default)]
    pub(super) name: String,
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
    let created = user
        .creation_date
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let ev = || {
        let mut e = Evidence::new(SRC, format!("SourceForge profile of '{handle}'"))
            .with_attr("profile_url", &profile_url);
        if let Some(c) = created {
            e = e.with_attr("account_created", c);
        }
        e
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

    // Real / display name → Person (multi-word only). In the Allura shape this
    // lives on the `developers[]` record whose `username` matches the handle.
    if let Some(name) = user
        .developers
        .iter()
        .find(|d| d.username.eq_ignore_ascii_case(handle))
        .map(|d| d.name.as_str())
        && let Some(mut p) = profile_kit::person_from_name(name, confidence::HIGH_PLUS, scan_id)
    {
        p.tag("sourceforge");
        p.tag("derived");
        p.add_evidence(
            Evidence::new(
                SRC,
                format!("Real name from SourceForge account '{handle}'"),
            )
            .with_attr("source_field", "developers.name"),
        );
        out.push(p);
    }

    // Personal homepage → URL + derived domain (cross-platform pivot).
    if let Some(site) = user.external_homepage.as_deref()
        && !site.trim().is_empty()
    {
        for mut e in profile_kit::website_url_and_domain(site, confidence::HIGH_PLUS, 0.63, scan_id)
        {
            e.tag("sourceforge");
            if e.kind == EntityKind::Domain {
                e.tag("derived");
            }
            e.add_evidence(ev().with_attr("source_field", "external_homepage"));
            out.push(e);
        }
    }

    // Linked social accounts → URL entities (most placeholders are blank).
    for social in &user.socialnetworks {
        let account = social.accounturl.trim();
        if account.is_empty() || !account.starts_with("http") {
            continue;
        }
        let mut s = Entity::new(EntityKind::Url, account, 0.62, scan_id);
        s.tag("sourceforge");
        s.tag("social-link");
        let network = social.socialnetwork.trim();
        s.add_evidence(ev().with_attr("source_field", "socialnetworks").with_attr(
            "social_network",
            if network.is_empty() {
                "unknown"
            } else {
                network
            },
        ));
        out.push(s);
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
        "SourceForge profile recon — harvests real name, homepage, social links, and account age via SF REST API (free)"
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
        // Code-repository profile — T1593.003 (the SourceForge profile/handle
        // itself). `build_entities` also constructs a Person from the matching
        // `developers[].name` (T1589.003) and, from `external_homepage` /
        // `socialnetworks[]`, personal-website + social-account URLs
        // (T1593.001 Social Media). The legacy `about`/`location` fields —
        // and the Email/Address/Coordinates they produced (T1589.002/
        // T1591.001) — are gone from the Allura REST shape, so those
        // techniques no longer apply here.
        &[
            "T1589.003", // Employee Names — Person from developers[].name
            "T1593.001", // Social Media — homepage + linked social-account URLs
            "T1593.003", // Code Repositories — Username via the SourceForge profile itself
        ]
    }
    fn produces(&self) -> &'static [EntityKind] {
        const K: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Url,
            EntityKind::Domain,
        ];
        K
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        // SourceForge usernames: 3–20 chars, alphanumeric + hyphen/underscore.
        if handle.is_empty() || handle.len() > 20 {
            return Ok(ModuleResult::new());
        }
        let url = format!("https://sourceforge.net/rest/u/{}", urlencode(handle));
        // 404 (`Ok(None)`) = genuine "no such user" clean miss; every other
        // failure (429/5xx/transport) propagates via `?` instead of a fake 404
        // (T2.117 — `fetch_json_or_404`'s split is pinned in `util::http::tests`).
        let Some(user) = fetch_json_or_404::<SfUser>(&ctx.http, SRC, &url).await? else {
            return Ok(ModuleResult::new());
        };
        // Identity guard: the Allura response echoes the requested handle in
        // its `name` field; confirm it matches before attributing the profile.
        if !user.name.eq_ignore_ascii_case(handle) {
            return Ok(ModuleResult::new());
        }
        let mut result = ModuleResult::new();
        result.entities = build_entities(user, &ctx.scan_id);
        Ok(result)
    }
}
