//! Bitbucket Cloud workspace lookup for a handle. Free, no API key required.
//!
//! Endpoints: `GET https://api.bitbucket.org/2.0/workspaces/{slug}` and, for a
//! resolved workspace, `GET https://api.bitbucket.org/2.0/repositories/{slug}`
//! (its public repositories, newest activity first, one page).
//!
//! Bitbucket removed the username-addressable user resource with its 2019
//! username deprecation: `GET /2.0/users/{username}` — the endpoint this
//! module shipped against — answers `404 {"type": "error", "error":
//! {"message": "<handle>"}}` for every handle (observed 2026-09-15 for
//! `atlassian`, `torvalds`, `zzzeek` and a team UUID), so every account,
//! existing or not, read as the clean negative "no such user" (28 of 28
//! live-drift sweeps: `empty`). A handle is a **workspace** now: every account
//! holds one under its former username (`zzzeek` → "Mike Bayer", `jespern` →
//! "Jesper Noehr"; resolved case-insensitively to the canonical slug), and a
//! handle nobody holds answers `404 … "No workspace with identifier '…'."`.
//! The profile fields the old resource published (`location`, `website`)
//! exist on no public Bitbucket resource any more; what a workspace publishes
//! is its display name, creation date, visibility and public repositories
//! (names, languages, last activity, project websites).
//!
//! A workspace may be a person's or a team's. Bitbucket marks only personal
//! workspaces created under the workspace model (`is_personal: true`); the
//! accounts it migrated on 2018-11-29 read `false` whether they are people or
//! teams. A multi-word display name is therefore minted as a `Person` at the
//! account-holder rung only when Bitbucket says the workspace is personal,
//! and one rung lower, tagged `workspace-name`, when it does not say.
//!
//! Bitbucket Cloud (Atlassian) is one of the three largest code-hosting
//! platforms, with especially deep penetration in enterprise teams using the
//! Atlassian toolchain; as an independent `code`-family source it
//! corroborates GitHub / GitLab / Codeberg across a complementary population.

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

const SRC: &str = "bitbucket_user";

/// The workspace resource — the one public resource a handle resolves to.
pub(super) const WORKSPACES_BASE: &str = "https://api.bitbucket.org/2.0/workspaces";
/// The public-repository listing of a workspace.
pub(super) const REPOSITORIES_BASE: &str = "https://api.bitbucket.org/2.0/repositories";
/// Public repositories read per lookup (newest activity first).
const REPO_PAGE: usize = 10;
/// Bitbucket's partial-response selector: every field [`BbRepoPage`] decodes
/// must be named here, or the API omits it and the decoder reads an absence.
pub(super) const REPO_FIELDS: &str = "size,values.full_name,values.language,values.updated_on,values.website,values.parent.full_name";

#[derive(Deserialize, Default)]
pub(super) struct BbLink {
    #[serde(default)]
    pub(super) href: Option<String>,
}

#[derive(Deserialize, Default)]
pub(super) struct BbLinks {
    #[serde(default)]
    pub(super) html: Option<BbLink>,
}

/// A workspace as `GET /2.0/workspaces/{slug}` answers it.
#[derive(Deserialize, Default)]
pub(super) struct BbWorkspace {
    /// Canonical handle (lower-case; the lookup is case-insensitive).
    #[serde(default)]
    pub(super) slug: String,
    /// Display name — a person's or a team's.
    #[serde(default)]
    pub(super) name: Option<String>,
    /// `true` only for a personal workspace created under Bitbucket's 2019
    /// workspace model; the accounts migrated on 2018-11-29 read `false`.
    #[serde(default)]
    pub(super) is_personal: bool,
    /// Whether the workspace's profile is private to its members. Its public
    /// repositories stay public: `atlassian` reads `true` with 407 of them.
    #[serde(default)]
    pub(super) is_private: bool,
    /// Creation timestamp (the migration date, 2018-11-29, for older accounts).
    #[serde(default)]
    pub(super) created_on: Option<String>,
    /// Nested link object containing `html.href` (canonical profile URL).
    #[serde(default)]
    pub(super) links: Option<BbLinks>,
}

/// One page of `GET /2.0/repositories/{slug}` — the workspace's public
/// repositories.
#[derive(Deserialize, Default)]
pub(super) struct BbRepoPage {
    /// Total public repositories (the page holds at most [`REPO_PAGE`]).
    #[serde(default)]
    pub(super) size: Option<u64>,
    #[serde(default)]
    pub(super) values: Vec<BbRepo>,
}

/// The upstream of a fork.
#[derive(Deserialize, Default)]
pub(super) struct BbRepoParent {
    #[serde(default)]
    pub(super) full_name: Option<String>,
}

/// One public repository.
#[derive(Deserialize, Default)]
pub(super) struct BbRepo {
    #[serde(default)]
    pub(super) full_name: Option<String>,
    #[serde(default)]
    pub(super) language: Option<String>,
    #[serde(default)]
    pub(super) updated_on: Option<String>,
    /// The project's website — the upstream project's for a fork.
    #[serde(default)]
    pub(super) website: Option<String>,
    /// Present for a fork.
    #[serde(default)]
    pub(super) parent: Option<BbRepoParent>,
}

/// What the public-repository listing yielded. The workspace's answer never
/// depends on it: a listing that could not be read is written into the
/// evidence as such — never dropped, never read as "no repositories".
pub(super) enum RepoReading {
    Read(BbRepoPage),
    NotRead(String),
}

/// `GET {workspaces_base}/{handle}` — `None` for Bitbucket's 404 (no workspace
/// holds the handle), the typed error for anything else (a 429 is
/// `RateLimited`, a wall `BotChallenge`, an outage `Module`).
pub(super) async fn fetch_workspace(
    client: &reqwest::Client,
    workspaces_base: &str,
    handle: &str,
) -> Result<Option<BbWorkspace>> {
    let url = format!("{workspaces_base}/{}", urlencode(handle));
    fetch_json_or_404::<BbWorkspace>(client, SRC, &url).await
}

/// `GET {repositories_base}/{slug}?…` — the newest page of the workspace's
/// public repositories, or why it was not read.
pub(super) async fn fetch_public_repositories(
    client: &reqwest::Client,
    repositories_base: &str,
    slug: &str,
) -> RepoReading {
    let url = format!(
        "{repositories_base}/{}?pagelen={REPO_PAGE}&sort=-updated_on&fields={REPO_FIELDS}",
        urlencode(slug)
    );
    match fetch_json_or_404::<BbRepoPage>(client, SRC, &url).await {
        Ok(Some(page)) => RepoReading::Read(page),
        Ok(None) => RepoReading::NotRead("HTTP 404 on the repository listing".to_string()),
        Err(e) => RepoReading::NotRead(e.to_string()),
    }
}

/// The lookup behind [`Module::process`]: the handle's workspace — `None` when
/// no workspace holds it, or when the slug Bitbucket resolved is not the
/// handle — and its public-repository reading.
pub(super) async fn lookup(
    client: &reqwest::Client,
    workspaces_base: &str,
    repositories_base: &str,
    handle: &str,
) -> Result<Option<(BbWorkspace, RepoReading)>> {
    let Some(workspace) = fetch_workspace(client, workspaces_base, handle).await? else {
        return Ok(None);
    };
    if !workspace.slug.eq_ignore_ascii_case(handle) {
        return Ok(None);
    }
    let repositories = fetch_public_repositories(client, repositories_base, &workspace.slug).await;
    Ok(Some((workspace, repositories)))
}

/// The evidence attributes every entity carries: what the workspace
/// publishes, and what its repository listing yielded — or why it was not
/// read.
fn evidence_attrs(
    workspace: &BbWorkspace,
    profile_url: &str,
    repositories: &RepoReading,
) -> Vec<(&'static str, String)> {
    let mut attrs = vec![
        ("profile_url", profile_url.to_string()),
        (
            "workspace_kind",
            if workspace.is_personal {
                "personal"
            } else {
                "unmarked"
            }
            .to_string(),
        ),
        ("is_private", workspace.is_private.to_string()),
    ];
    if let Some(name) = workspace
        .name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
    {
        attrs.push(("workspace_name", name.to_string()));
    }
    if let Some(created) = workspace.created_on.as_deref() {
        attrs.push(("created_on", created.to_string()));
    }
    match repositories {
        RepoReading::Read(page) => {
            let count = page.size.unwrap_or(page.values.len() as u64);
            attrs.push(("public_repositories", count.to_string()));
            let mut languages: Vec<&str> = page
                .values
                .iter()
                .filter_map(|r| r.language.as_deref())
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect();
            languages.sort_unstable();
            languages.dedup();
            if !languages.is_empty() {
                attrs.push(("languages", languages.join(", ")));
            }
            if let Some(latest) = page
                .values
                .iter()
                .filter_map(|r| r.updated_on.as_deref())
                .max()
            {
                attrs.push(("last_public_activity", latest.to_string()));
            }
            let names: Vec<&str> = page
                .values
                .iter()
                .filter_map(|r| r.full_name.as_deref())
                .take(5)
                .collect();
            if !names.is_empty() {
                attrs.push(("repositories", names.join(", ")));
            }
            // A fork's website is the upstream project's, not this
            // workspace's; the workspace's own projects' sites, newest first.
            let mut sites: Vec<&str> = Vec::new();
            for site in page
                .values
                .iter()
                .filter(|r| r.parent.is_none())
                .filter_map(|r| r.website.as_deref())
                .map(str::trim)
            {
                if crate::util::url_util::is_absolute_http_url(site)
                    && !sites.contains(&site)
                    && sites.len() < 3
                {
                    sites.push(site);
                }
            }
            if !sites.is_empty() {
                attrs.push(("project_websites", sites.join(", ")));
            }
            // What the workspace forks says what it works on; the upstream
            // is named so a fork is never read as the workspace's own project.
            let forks: Vec<String> = page
                .values
                .iter()
                .filter_map(|r| {
                    let upstream = r.parent.as_ref()?.full_name.as_deref()?;
                    Some(format!("{} (fork of {upstream})", r.full_name.as_deref()?))
                })
                .take(3)
                .collect();
            if !forks.is_empty() {
                attrs.push(("forks", forks.join(", ")));
            }
        }
        RepoReading::NotRead(why) => {
            attrs.push(("public_repositories", format!("not read: {why}")));
        }
    }
    attrs
}

pub(super) fn build_entities(
    workspace: BbWorkspace,
    repositories: RepoReading,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    let handle = workspace.slug.trim();
    if handle.is_empty() {
        return out;
    }
    // Resolve the canonical profile URL from the nested `links.html.href`
    // (trailing slash trimmed for dedup), falling back to the constructed form.
    let profile_url = profile_kit::profile_url(
        workspace
            .links
            .as_ref()
            .and_then(|l| l.html.as_ref())
            .and_then(|h| h.href.as_deref()),
        || format!("https://bitbucket.org/{handle}"),
    );
    let attrs = evidence_attrs(&workspace, &profile_url, &repositories);
    let ev = || {
        let mut ev = Evidence::new(SRC, format!("Bitbucket Cloud workspace '{handle}'"));
        for (key, value) in &attrs {
            ev = ev.with_attr(*key, value.as_str());
        }
        ev
    };

    // Confirmed handle on Bitbucket Cloud — a single-source, keyless
    // account-existence lookup, graded at the cohort canon HIGH_PLUSPLUS_PLUS
    // (0.85; OD-19, matching gitea_user/gitlab_user).
    let mut e = Entity::new(
        EntityKind::Username,
        handle,
        confidence::HIGH_PLUSPLUS_PLUS,
        scan_id,
    );
    e.tag("bitbucket");
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
    u.tag("bitbucket");
    u.add_evidence(ev());
    out.push(u);

    // Display name → Person (multi-word only; a single token is a handle). The
    // account-holder rung only when Bitbucket marks the workspace personal; a
    // workspace it does not mark may be a team's, so its name sits one rung
    // lower and carries the `workspace-name` tag.
    if let Some(name) = workspace.name.as_deref() {
        let rung = if workspace.is_personal {
            confidence::HIGH_PLUS
        } else {
            confidence::NOTABLE
        };
        if let Some(mut p) = profile_kit::person_from_name(name, rung, scan_id) {
            p.tag("bitbucket");
            if !workspace.is_personal {
                p.tag("workspace-name");
            }
            p.add_evidence(ev().with_attr("source_field", "name"));
            out.push(p);
        }
    }

    out
}

pub struct BitbucketUser;

#[async_trait]
impl Module for BitbucketUser {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "Bitbucket Cloud workspace recon — confirms a handle's workspace, display name, creation date and public repositories via public API v2 (free)"
    }
    fn priority(&self) -> u8 {
        97
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
        // Code-repository profile — T1593.003; display name → real identity — T1589.002.
        &["T1589.002", "T1593.003"]
    }
    fn produces(&self) -> &'static [EntityKind] {
        const K: &[EntityKind] = &[EntityKind::Username, EntityKind::Person, EntityKind::Url];
        K
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        if handle.is_empty() || handle.len() > 64 {
            return Ok(ModuleResult::new());
        }
        // `None` = no workspace holds the handle (Bitbucket's 404), the one
        // clean negative; every other failure propagates typed.
        let Some((workspace, repositories)) =
            lookup(&ctx.http, WORKSPACES_BASE, REPOSITORIES_BASE, handle).await?
        else {
            return Ok(ModuleResult::new());
        };
        let mut result = ModuleResult::new();
        result.entities = build_entities(workspace, repositories, &ctx.scan_id);
        Ok(result)
    }
}
