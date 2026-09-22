//! Email → identity via GitHub commit authorship. Free, no key required (an
//! optional `HUNTSMAN_GITHUB_TOKEN` only raises the rate limit).
//!
//! Endpoint: `GET https://api.github.com/search/commits?q=author-email:<email>`.
//!
//! Git records the author's name and email in every commit, and GitHub indexes
//! them. So an email resolves to:
//!   * the **real name** the owner configured in `git` (`commit.author.name`) —
//!     a high-value email → person link; and
//!   * the **GitHub account** GitHub itself associated with that email (the
//!     top-level `author.login`) — a verified email ↔ account mapping.
//!
//! This is the email-side complement of [`crate::modules::github_user`]
//! (username → profile) and is distinct from
//! [`crate::modules::github_code_search`] (which searches code *content*, not
//! commit authorship). It broadens the email → digital-footprint surface — the
//! SEON-style primitive — with a real, keyless public source. No mock.

use std::collections::HashSet;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::extract::looks_like_email;
use crate::util::http::{RequestBuilderExt, UA_OSINT, urlencode};

const SRC: &str = "github_commits";

/// GitHub's REST root — the commit search lives under `/search/commits`.
const API_BASE: &str = "https://api.github.com";

/// Commits scanned per email. The author identity repeats across commits, so a
/// small page is plenty to recover it without paying for deep pagination.
const PER_PAGE: u32 = 20;

pub struct GithubCommits;

#[derive(Deserialize, Default)]
#[serde(default)]
struct CommitSearchResp {
    items: Vec<CommitItem>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct CommitItem {
    /// Git-recorded author (name/email set in the committer's `git` config).
    commit: CommitDetail,
    /// The GitHub account GitHub matched the commit to — `null` when the email
    /// is not associated with any account.
    author: Option<GhUser>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct CommitDetail {
    author: Option<GitAuthor>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct GitAuthor {
    name: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct GhUser {
    login: Option<String>,
    html_url: Option<String>,
}

#[async_trait]
impl Module for GithubCommits {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "GitHub commit-author search (free, no key) — pivots an email to a real name and GitHub account"
    }

    fn priority(&self) -> u8 {
        106
    }

    fn accepts(&self, t: &Target) -> bool {
        // Kind-only so the dispatch index (built from `consumes()`) stays
        // consistent with `accepts()`; the `looks_like_email` gate is applied in
        // `process()`.
        matches!(t.kind, TargetKind::Email)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // A code-hosting source, like github_user: ATT&CK Code Repositories.
        &["T1593.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Person, EntityKind::Username, EntityKind::Url];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let email = target.value.trim();
        if !looks_like_email(email) {
            return Ok(ModuleResult::new());
        }

        let parsed = search_commits(ctx, API_BASE, email).await?;

        Ok(ModuleResult {
            entities: extract(&parsed.items, email, &ctx.scan_id),
            truncation: None,
            sightings: Vec::new(),
            link: None,
        })
    }
}

/// One commit-author search. A non-2xx is never "no commits by this author":
/// GitHub signals an empty search as a `200` with `total_count: 0`. A throttle
/// (`429`, or a `403` that names the rate limit — `github_api::throttled`) is
/// the typed [`crate::core::error::Error::RateLimited`], so the breaker backs the module off and
/// the scan records a throttled provider; any other non-2xx (a `401` on a
/// revoked token, a `422` on a query GitHub cannot index, a 5xx) is the
/// module's error. A configured token is reported to the key pool on every
/// rejection so a dead or exhausted token can be rotated. Before this every
/// non-2xx collapsed into an empty result — a clean negative about the named
/// email (`docs/PROVIDER_SWEEP_BACKLOG.md` #23).
async fn search_commits(
    ctx: &ModuleContext,
    api_base: &str,
    email: &str,
) -> Result<CommitSearchResp> {
    let url = format!(
        "{api_base}/search/commits?q={}&per_page={PER_PAGE}",
        urlencode(&format!("author-email:{email}"))
    );
    // Optional token only raises the unauthenticated search rate limit
    // (10/min → 30/min); the module is fully functional without it.
    let token = ctx.key_opt("HUNTSMAN_GITHUB_TOKEN");
    let mut req = ctx
        .http
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header(
            "X-GitHub-Api-Version",
            crate::modules::github_api::API_VERSION,
        )
        .header("User-Agent", UA_OSINT);
    if let Some(token) = token {
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    let resp = req.send_tagged(SRC).await?;
    let status = resp.status();
    if !status.is_success() {
        // The key pool must learn a 401/403/429 happened, or a dead/throttled
        // token silently degrades every future scan with no operator-visible
        // signal and no chance to rotate.
        if let Some(token) = token {
            crate::util::http::note_keyed_error(status.as_u16(), "github", token, ctx);
        }
        // One judgement for every GitHub caller: a throttle is the typed
        // RateLimited, anything else the module's error.
        return Err(crate::modules::github_api::status_error(SRC, resp).await);
    }
    // json_scanned: commit messages are free-form text that can carry leaked
    // API keys — route the body through the key scanner.
    crate::util::http::json_scanned(resp, SRC).await
}

/// Pure entity extraction from the commit-search items — unit-tested against a
/// fixture so the network shell in `process` stays a thin adapter.
fn extract(items: &[CommitItem], email: &str, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let mut seen_login: HashSet<String> = HashSet::new();
    let mut seen_name: HashSet<String> = HashSet::new();

    for item in items {
        // The GitHub account GitHub itself tied to this email — a verified
        // email ↔ account mapping, the stronger of the two signals. Every
        // DISTINCT login is emitted (deduped by `seen_login`): a shared/role
        // email can front several real accounts, and dropping the extras hides
        // genuine identities.
        if let Some(gh) = &item.author
            && let Some(login) = gh
                .login
                .as_deref()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.to_ascii_lowercase().ends_with("[bot]"))
            && seen_login.insert(login.to_ascii_lowercase())
        {
            let mut u = Entity::new(EntityKind::Username, login, confidence::STRONG, scan_id);
            u.tag("github");
            u.tag("github-commit");
            u.add_evidence(
                Evidence::new(
                    SRC,
                    format!("GitHub account `{login}` authored commits as {email}"),
                )
                .with_attr("email", email)
                .with_attr("source", "github-commit-search"),
            );
            out.push(u);

            if let Some(profile) = gh.html_url.as_deref().filter(|u| u.starts_with("http")) {
                let mut url_e = Entity::new(EntityKind::Url, profile, confidence::STRONG, scan_id);
                url_e.tag("github");
                url_e.tag("github-commit");
                url_e.add_evidence(
                    Evidence::new(SRC, format!("GitHub profile for commit author {email}"))
                        .with_attr("email", email),
                );
                out.push(url_e);
            }
        }

        // The git author name — a self-asserted real name behind the email.
        // Multi-word + non-placeholder only, so a handle or the `git` default
        // ("Your Name") never becomes a Person. Every DISTINCT real name is
        // emitted (deduped by `seen_name`): a shared/role email can front several
        // genuine contributors, and dropping the 4th+ hides real identities.
        if let Some(name) = item.commit.author.as_ref().and_then(|a| a.name.as_deref()) {
            let name = name.trim();
            if crate::modules::github_api::is_real_name(name)
                && seen_name.insert(name.to_ascii_lowercase())
            {
                let mut p = Entity::new(EntityKind::Person, name, confidence::NOTABLE, scan_id);
                p.tag("derived");
                p.tag("github-commit");
                p.add_evidence(
                    Evidence::new(SRC, format!("git author name for {email}"))
                        .with_attr("email", email)
                        .with_attr("source", "github-commit-search"),
                );
                out.push(p);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
