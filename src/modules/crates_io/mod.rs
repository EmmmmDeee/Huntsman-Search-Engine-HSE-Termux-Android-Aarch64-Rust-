//! crates.io user lookup. Free, no key — the official public registry API.
//!
//! Endpoint: `GET https://crates.io/api/v1/users/{login}`
//! (documented at <https://crates.io/data-access>; a descriptive User-Agent is
//! required by their crawler policy, which the shared client supplies). Returns
//! the registry account:
//!
//! ```json
//! {"user":{"id":1,"login":"alice","name":"Alice Smith",
//!          "avatar":"https://avatars.githubusercontent.com/u/1",
//!          "url":"https://github.com/alice",
//!          "created_at":"2012-07-09T03:55:40Z"}}
//! ```
//!
//! Why it earns a place in the keyless-API set: it confirms the handle on a
//! code-registry platform (the `code` family), exposes the maintainer's REAL
//! NAME (a handle→identity link feeding AU-046), and — because crates.io
//! authenticates via GitHub — its `url` field ties the handle to the owner's
//! GitHub profile, a cross-platform confirmation. Official, keyless, exact-match.
//!
//! With the account `id` in hand it goes one step further, listing the
//! maintainer's published crates (`GET /api/v1/crates?user_id={id}`) and
//! surfacing each crate's source-repository / homepage / documentation URL —
//! the direct route from a confirmed handle to the owner's repos and personal
//! domains, plus a GitHub-owner `Username` pivot per source repository.

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
use crate::util::http::fetch_json_or_404;

const SRC: &str = "crates_io";

pub struct CratesIo;

#[derive(Deserialize)]
struct UserResp {
    #[serde(default)]
    user: Option<CrateUser>,
}

#[derive(Deserialize)]
struct CrateUser {
    login: String,
    /// Stable numeric account id — the key for the `/crates?user_id=` listing
    /// that turns this handle-confirmer into a code-family expander.
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    url: Option<String>,
    /// GitHub-hosted avatar, e.g. `https://avatars.githubusercontent.com/u/1`.
    /// Surfaced as the `avatar_url` evidence attr: it embeds the maintainer's
    /// stable numeric GitHub user id (survives handle renames) — an attribution
    /// pivot the response carried but the module previously discarded.
    #[serde(default)]
    avatar: Option<String>,
    /// Account-creation timestamp (ISO-8601, e.g. `2012-07-09T03:55:40Z`). The
    /// live `/api/v1/users/{login}` response carries this on every real account
    /// (confirmed against `dtolnay`/`alexcrichton`), but the module previously
    /// dropped it — surfaced as the `created_at` evidence attr, matching the
    /// account-age signal the sibling `code`-registry modules (`gitea_user`,
    /// `codeberg_user`, `hexpm_user`) already record.
    #[serde(default)]
    created_at: Option<String>,
}

/// Map a decoded crates.io user record to its entities. **Pure** (no network),
/// so the account→identity→linked-profile mapping is unit-testable off JSON.
///
/// | source                              | output                                 |
/// |-------------------------------------|----------------------------------------|
/// | `user.login`                        | `Username` (+ `crates-io`/`code` tags) |
/// | `user.name` (non-blank, ≥ 2 words)  | `Person` pivot + `name` attr           |
/// | `user.url` (`http(s)://…`)          | `Url` linked-profile pivot             |
///
/// Empty when the response carries no `user` (the caller maps a 404 to the same
/// no-user shape). A blank `name` adds neither the evidence attr nor the Person
/// pivot; a placeholder name (per [`crate::core::validation::is_placeholder_entity`])
/// is likewise not promoted.
fn build_entities(body: &UserResp, scan_id: &str) -> Vec<Entity> {
    let Some(user) = body.user.as_ref() else {
        return Vec::new();
    };

    let mut result = Vec::new();

    // The confirmed-on-crates.io username.
    let mut u = Entity::new(
        EntityKind::Username,
        &user.login,
        confidence::EXPERT,
        scan_id,
    );
    u.tag("crates-io");
    u.tag("code");
    let mut ev = Evidence::new(SRC, format!("crates.io registry account '{}'", user.login))
        .with_attr(
            "profile_url",
            format!("https://crates.io/users/{}", user.login),
        );
    if let Some(n) = user.name.as_deref().filter(|n| !n.is_empty()) {
        ev = ev.with_attr("name", n);
    }
    if let Some(av) = user
        .avatar
        .as_deref()
        .filter(|a| a.starts_with("http://") || a.starts_with("https://"))
    {
        ev = ev.with_attr("avatar_url", av);
    }
    if let Some(ts) = user.created_at.as_deref().filter(|t| !t.is_empty()) {
        ev = ev.with_attr("created_at", ts);
    }
    u.add_evidence(ev);
    result.push(u);

    // Real name → Person (handle→identity).
    if let Some(name) = user.name.as_deref()
        && let Some(mut p) = profile_kit::person_from_name(name, confidence::HIGH_PLUS, scan_id)
    {
        p.tag("crates-io");
        p.tag("derived");
        p.add_evidence(
            Evidence::new(
                SRC,
                format!("Real name from crates.io account '{}'", user.login),
            )
            .with_attr("crates_login", &user.login),
        );
        result.push(p);
    }

    // The linked profile URL (crates.io auths via GitHub, so this is usually
    // the owner's GitHub profile — a cross-platform confirmation).
    if let Some(link) = user.url.as_deref()
        && (link.starts_with("http://") || link.starts_with("https://"))
    {
        let mut url_e = Entity::new(EntityKind::Url, link, 0.74, scan_id);
        url_e.tag("crates-io");
        url_e.tag("linked-profile");
        url_e.add_evidence(
            Evidence::new(
                SRC,
                format!("Linked profile of crates.io user '{}'", user.login),
            )
            .with_attr("source", "crates_io_profile"),
        );
        result.push(url_e);

        // Direct GitHub username extraction — crates.io authenticates via GitHub
        // so the url field is nearly always `https://github.com/{handle}`.
        // Emitting the Username directly saves one expansion round-trip.
        if let Some(gh_user) = github_username_from_url(link) {
            let mut g = Entity::new(
                EntityKind::Username,
                gh_user,
                confidence::HIGH_PLUSPLUS,
                scan_id,
            );
            g.tag("github");
            g.tag("crates-io-pivot");
            g.add_evidence(
                Evidence::new(
                    SRC,
                    format!("GitHub username from crates.io profile of '{}'", user.login),
                )
                .with_attr("source_url", link)
                .with_attr("crates_login", &user.login),
            );
            result.push(g);
        }
    }

    result
}

/// Extract the GitHub username from a URL of the form
/// `https://github.com/{username}` (path depth exactly 1, no trailing slash).
/// Returns `None` for any other URL shape.
fn github_username_from_url(url: &str) -> Option<&str> {
    let path = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("http://github.com/"))?;
    let path = path.trim_end_matches('/');
    // Must be a bare username — no slashes (would be a repo/path), no query.
    if path.is_empty() || path.contains('/') || path.contains('?') || path.contains('#') {
        return None;
    }
    Some(path)
}

/// Extract the GitHub OWNER (first path segment) from a repository URL of the
/// form `https://github.com/{owner}/{repo}` — the maintainer's or org's handle.
/// Returns `None` for a non-GitHub URL or one with no owner segment. Unlike
/// [`github_username_from_url`] (which requires a bare depth-1 profile), this
/// takes the leading segment of a deeper repo path.
fn github_owner_from_url(url: &str) -> Option<&str> {
    let path = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("http://github.com/"))?;
    let owner = path
        .split(['/', '?', '#'])
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())?;
    // GitHub handles are alphanumeric + hyphen; reject reserved/asset hosts.
    if owner.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        Some(owner)
    } else {
        None
    }
}

/// crates.io `/api/v1/crates?user_id={id}` listing — the maintainer's published
/// crates, each carrying the source-repository / homepage / documentation URLs.
#[derive(Deserialize)]
struct CratesResp {
    #[serde(default)]
    crates: Vec<CrateInfo>,
}

#[derive(Deserialize)]
struct CrateInfo {
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    homepage: Option<String>,
    #[serde(default)]
    documentation: Option<String>,
}

/// Cap on distinct crate URLs surfaced — a prolific maintainer can publish
/// dozens of crates, but the salient repo/homepage set is small after dedup.
const MAX_CRATE_URLS: usize = 60;

/// Map a maintainer's crate listing to its repo/homepage/documentation `Url`
/// pivots plus a GitHub-owner `Username` for each distinct source repo.
/// **Pure** (no network) so the http(s) filter, dedup, deterministic ordering,
/// and owner extraction are unit-tested off JSON. URLs are deduped and sorted
/// (BTreeSet) so the output never leaks the API's array ordering, then capped.
fn crate_url_entities(resp: &CratesResp, scan_id: &str) -> Vec<Entity> {
    let is_http = |u: &&str| u.starts_with("http://") || u.starts_with("https://");

    // Distinct http(s) URLs across every crate's repo/homepage/doc fields.
    let mut urls: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    // Distinct GitHub owners drawn from the source-repository URLs.
    let mut owners: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for c in &resp.crates {
        for field in [
            c.repository.as_deref(),
            c.homepage.as_deref(),
            c.documentation.as_deref(),
        ] {
            if let Some(u) = field.map(str::trim).filter(is_http) {
                urls.insert(u);
            }
        }
        if let Some(owner) = c.repository.as_deref().map(str::trim).and_then(|r| {
            if is_http(&r) {
                github_owner_from_url(r)
            } else {
                None
            }
        }) {
            owners.insert(owner);
        }
    }

    let mut out = Vec::new();
    for url in urls.into_iter().take(MAX_CRATE_URLS) {
        let mut e = Entity::new(EntityKind::Url, url, confidence::NOTABLE, scan_id);
        e.tag("crates-io");
        e.tag("code");
        e.add_evidence(Evidence::new(
            SRC,
            "URL from a crate published by this user",
        ));
        out.push(e);
    }
    for owner in owners {
        let mut g = Entity::new(EntityKind::Username, owner, 0.66, scan_id);
        g.tag("github");
        g.tag("crates-io-pivot");
        g.add_evidence(Evidence::new(
            SRC,
            format!("GitHub owner of a crate's source repository ({owner})"),
        ));
        out.push(g);
    }
    out
}

#[async_trait]
impl Module for CratesIo {
    fn name(&self) -> &'static str {
        "crates_io"
    }

    fn description(&self) -> &'static str {
        "crates.io registry recon — resolves a user to real name and linked GitHub via the official API"
    }

    fn priority(&self) -> u8 {
        103
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // crates.io author packages — ATT&CK Code Repositories (T1593.003).
        &["T1593.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Username, EntityKind::Person, EntityKind::Url];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        6_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        // crates.io logins mirror GitHub logins: alphanumeric + hyphen, ≤39 chars.
        if handle.is_empty()
            || handle.len() > 39
            || !handle
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Ok(ModuleResult::new());
        }

        let url = format!("https://crates.io/api/v1/users/{handle}");
        let Some(body): Option<UserResp> = fetch_json_or_404(&ctx.http, SRC, &url).await? else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.entities = build_entities(&body, &ctx.scan_id);

        // Expand the maintainer's published crates into their source repos and
        // homepages — the direct route from a confirmed handle to the owner's
        // repositories and personal domains (official, keyless).
        if let Some(id) = body.user.as_ref().and_then(|u| u.id) {
            let crates_url =
                format!("https://crates.io/api/v1/crates?user_id={id}&per_page=100&sort=downloads");
            if let Some(listing) =
                fetch_json_or_404::<CratesResp>(&ctx.http, SRC, &crates_url).await?
            {
                result
                    .entities
                    .extend(crate_url_entities(&listing, &ctx.scan_id));
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
