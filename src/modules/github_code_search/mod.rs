//! GitHub code search — mine public repositories for email/username seeds.
//!
//! Endpoint: `GET https://api.github.com/search/code?q={seed}&per_page=10`
//! Auth:     Optional GitHub Personal Access Token (`github` key in key pool).
//!           Without a key: 10 req/min unauthenticated. With a key: 30 req/min.
//!
//! MITRE ATT&CK: T1593.003 — Search: Code Repositories.
//!
//! For an Email or Username seed, searches GitHub code for literal occurrences
//! and fans out from each matching repository:
//!
//!   * Repository owner → `Username` (confirms the account hosts content
//!     matching the seed — a strong cross-correlation pivot).
//!   * Repository URL → `Url` tagged `code-repo` (for `social_location` +
//!     `exif_geo` downstream).
//!   * Commit author emails from the repo's recent commits → `Email` entities
//!     (T1589.002 — low confidence since repos can have many contributors).
//!
//! Precision gate: only repositories whose `full_name` or `description` contain
//! the search term as a substring, OR whose owner login matches a username seed
//! exactly, are fanned out at PROBABLE tier; the rest are surfaced as
//! low-confidence candidates. This avoids false-positives from incidental
//! string matches in large codebases.

use async_trait::async_trait;

use crate::core::{
    entity::EntityKind,
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

mod types;
use types::{CodeItem, CommitItem, CommitsResp, SearchResp};

mod build;
use build::{build_commit_emails, build_repo_entities};

#[cfg(test)]
mod tests;

pub(super) const SRC: &str = "github_code_search";
const API: &str = "https://api.github.com";

pub struct GithubCodeSearch;

#[async_trait]
impl Module for GithubCodeSearch {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "GitHub code search — find repositories containing the seed email/username and pivot to owner accounts and commit emails"
    }

    fn priority(&self) -> u8 {
        85
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email | TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1593.003", "T1589.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Url, EntityKind::Username, EntityKind::Email];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let seed = target.value.trim();
        if seed.is_empty() {
            return Ok(ModuleResult::new());
        }

        let token = ctx.key_opt("GITHUB_TOKEN");
        let url = format!(
            "{API}/search/code?q={}&per_page=10",
            crate::util::http::urlencode(seed),
        );

        let mut req = ctx
            .http
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "huntsman-search-engine/1.4");
        if let Some(tok) = token {
            req = req.header("Authorization", format!("Bearer {tok}"));
        }

        let resp = req.send_tagged(SRC).await?;
        let status = resp.status();
        if status.as_u16() == 403 || status.as_u16() == 429 {
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
            return Ok(ModuleResult::new());
        }

        let body: SearchResp = match crate::util::http::json_scanned(resp, SRC).await {
            Ok(b) => b,
            Err(_) => return Ok(ModuleResult::new()),
        };

        if body.items.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        let mut seen_repos: std::collections::HashSet<String> = std::collections::HashSet::new();

        for item in &body.items {
            let full_name = item
                .repository
                .as_ref()
                .and_then(|r| r.full_name.as_deref())
                .unwrap_or("");
            if full_name.is_empty() || !seen_repos.insert(full_name.to_string()) {
                continue;
            }

            result.extend(build_repo_entities(item, seed, target.kind, &ctx.scan_id));

            // Fetch recent commits for the repo to harvest author emails.
            // Best-effort: skip on any error (rate limit, private repo).
            let commits_url = format!("{API}/repos/{full_name}/commits?per_page=5");
            let mut creq = ctx
                .http
                .get(&commits_url)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .header("User-Agent", "huntsman-search-engine/1.4");
            if let Some(tok) = token {
                creq = creq.header("Authorization", format!("Bearer {tok}"));
            }
            if let Ok(cr) = creq.send_tagged(SRC).await
                && cr.status().is_success()
                && let Ok(raw) = cr.bytes().await
                && let Ok(arr) = serde_json::from_slice::<Vec<CommitItem>>(&raw)
            {
                let wrapped = CommitsResp { commits: arr };
                result.extend(build_commit_emails(&wrapped, full_name, &ctx.scan_id));
            }
        }

        Ok(result)
    }
}
