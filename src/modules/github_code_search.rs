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
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use crate::util::str_util::nonempty;

const SRC: &str = "github_code_search";
const API: &str = "https://api.github.com";

pub struct GithubCodeSearch;

#[derive(Deserialize)]
struct SearchResp {
    #[serde(default)]
    items: Vec<CodeItem>,
}

#[derive(Deserialize)]
struct CodeItem {
    #[serde(default)]
    repository: Option<Repo>,
}

#[derive(Deserialize)]
struct Repo {
    #[serde(default)]
    full_name: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    owner: Option<Owner>,
}

#[derive(Deserialize)]
struct Owner {
    #[serde(default)]
    login: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
}

#[derive(Deserialize)]
struct CommitsResp {
    #[serde(default)]
    commits: Vec<CommitItem>,
}

#[derive(Deserialize)]
struct CommitItem {
    #[serde(default)]
    commit: Option<CommitDetail>,
}

#[derive(Deserialize)]
struct CommitDetail {
    #[serde(default)]
    author: Option<CommitAuthor>,
}

#[derive(Deserialize)]
struct CommitAuthor {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

/// Build entities from a single search result item. Pure.
fn build_repo_entities(
    item: &CodeItem,
    seed: &str,
    seed_kind: TargetKind,
    scan_id: &str,
) -> Vec<Entity> {
    let Some(repo) = &item.repository else {
        return vec![];
    };
    let mut out = Vec::new();

    let full_name = repo.full_name.as_deref().unwrap_or("");
    let description = repo.description.as_deref().unwrap_or("");
    let html_url = match nonempty(&repo.html_url) {
        Some(u) => u,
        None => return vec![],
    };

    // Confidence: higher if owner login matches username seed exactly,
    // or if the repo name/description contain the seed string.
    let owner_login = repo
        .owner
        .as_ref()
        .and_then(|o| o.login.as_deref())
        .unwrap_or("");
    let exact_owner = seed_kind == TargetKind::Username && owner_login.eq_ignore_ascii_case(seed);
    let seed_in_repo = full_name.to_lowercase().contains(&seed.to_lowercase())
        || description.to_lowercase().contains(&seed.to_lowercase());
    let conf = if exact_owner || seed_in_repo {
        0.58
    } else {
        0.38
    };

    // Repo URL entity.
    let mut url_e = Entity::new(EntityKind::Url, html_url, conf, scan_id);
    url_e.tag(SRC);
    url_e.tag("code-repo");
    url_e.tag("github");
    let mut ev = Evidence::new(SRC, format!("GitHub code search hit: {full_name}"))
        .with_attr("repo", full_name)
        .with_attr("seed", seed);
    if let Some(d) = nonempty(&repo.description) {
        ev = ev.with_attr("description", d);
    }
    url_e.add_evidence(ev.clone());
    out.push(url_e);

    // Repo owner → Username pivot.
    if !owner_login.is_empty() {
        let login = owner_login;
        let owner_conf = if exact_owner { 0.65 } else { conf };
        let mut u = Entity::new(EntityKind::Username, login, owner_conf, scan_id);
        u.tag(SRC);
        u.tag("github");
        u.tag("repo-owner");
        let mut uev = Evidence::new(SRC, format!("GitHub repo owner: {login} ({full_name})"))
            .with_attr("repo", full_name)
            .with_attr("owner", login);
        if let Some(profile_url) = repo.owner.as_ref().and_then(|o| nonempty(&o.html_url)) {
            uev = uev.with_attr("profile_url", profile_url);
        }
        u.add_evidence(uev);
        out.push(u);
    }

    out
}

/// Build Email entities from a repository's recent commits. Pure.
fn build_commit_emails(commits: &CommitsResp, repo_name: &str, scan_id: &str) -> Vec<Entity> {
    let mut seen = std::collections::HashSet::new();
    commits
        .commits
        .iter()
        .filter_map(|item| {
            let author = item.commit.as_ref()?.author.as_ref()?;
            let email = nonempty(&author.email)?;
            // Skip noreply GitHub emails — not real contact addresses.
            if email.contains("noreply.github.com") || email.contains("users.noreply") {
                return None;
            }
            let email_lc = email.to_lowercase();
            if !seen.insert(email_lc.clone()) {
                return None;
            }

            let mut e = Entity::new(EntityKind::Email, &email_lc, 0.35, scan_id);
            e.tag(SRC);
            e.tag("github");
            e.tag("commit-author");
            let mut ev = Evidence::new(SRC, format!("Commit author email from {repo_name}"))
                .with_attr("repo", repo_name)
                .with_attr("email", &email_lc);
            if let Some(name) = author.name.as_deref().filter(|s| !s.is_empty()) {
                ev = ev.with_attr("commit_author_name", name);
            }
            e.add_evidence(ev);
            Some(e)
        })
        .collect()
}

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
                .unwrap_or("")
                .to_string();
            if full_name.is_empty() || !seen_repos.insert(full_name.clone()) {
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
                result.extend(build_commit_emails(&wrapped, &full_name, &ctx.scan_id));
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item_from_json(json: &str) -> CodeItem {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn accepts_email_and_username_only() {
        let m = GithubCodeSearch;
        assert!(m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(m.accepts(&Target::new(TargetKind::Username, "haigen")));
        assert!(!m.accepts(&Target::new(TargetKind::FullName, "Haigen Bamford")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    }

    #[test]
    fn module_metadata() {
        let m = GithubCodeSearch;
        assert_eq!(m.name(), "github_code_search");
        assert_eq!(m.cost(), ModuleCost::Free);
        assert!(m.attack_techniques().contains(&"T1593.003"));
        assert!(m.attack_techniques().contains(&"T1589.002"));
    }

    #[test]
    fn build_repo_entities_exact_owner_match() {
        let item = item_from_json(
            r#"{"repository":{"full_name":"haigen/dotfiles","html_url":"https://github.com/haigen/dotfiles",
                "description":"my configs","owner":{"login":"haigen","html_url":"https://github.com/haigen"}}}"#,
        );
        let ents = build_repo_entities(&item, "haigen", TargetKind::Username, "s");
        let url_e = ents.iter().find(|e| e.kind == EntityKind::Url).unwrap();
        assert!(url_e.confidence >= 0.58);
        assert!(url_e.has_tag("code-repo") && url_e.has_tag("github"));

        let user_e = ents
            .iter()
            .find(|e| e.kind == EntityKind::Username)
            .unwrap();
        assert_eq!(user_e.value, "haigen");
        assert!(user_e.confidence >= 0.65);
        assert!(user_e.has_tag("repo-owner"));
    }

    #[test]
    fn build_repo_entities_low_conf_unrelated() {
        // A repo that doesn't mention the seed at all → low-confidence candidate.
        let item = item_from_json(
            r#"{"repository":{"full_name":"other/project","html_url":"https://github.com/other/project",
                "description":"unrelated","owner":{"login":"other","html_url":"https://github.com/other"}}}"#,
        );
        let ents = build_repo_entities(&item, "haigen@example.com", TargetKind::Email, "s");
        let url_e = ents.iter().find(|e| e.kind == EntityKind::Url).unwrap();
        assert!(
            url_e.confidence < 0.50,
            "unrelated repo should be sub-floor"
        );
    }

    #[test]
    fn build_commit_emails_filters_noreply() {
        let commits = CommitsResp {
            commits: vec![
                CommitItem {
                    commit: Some(CommitDetail {
                        author: Some(CommitAuthor {
                            name: Some("Alice".into()),
                            email: Some("alice@example.com".into()),
                        }),
                    }),
                },
                CommitItem {
                    commit: Some(CommitDetail {
                        author: Some(CommitAuthor {
                            name: Some("Bot".into()),
                            email: Some("123+bot@users.noreply.github.com".into()),
                        }),
                    }),
                },
            ],
        };
        let ents = build_commit_emails(&commits, "test/repo", "s");
        assert_eq!(ents.len(), 1);
        assert_eq!(ents[0].value, "alice@example.com");
        assert!(ents[0].has_tag("commit-author"));
    }

    #[test]
    fn build_commit_emails_deduplicates() {
        let commits = CommitsResp {
            commits: vec![
                CommitItem {
                    commit: Some(CommitDetail {
                        author: Some(CommitAuthor {
                            name: Some("Alice".into()),
                            email: Some("Alice@Example.COM".into()),
                        }),
                    }),
                },
                CommitItem {
                    commit: Some(CommitDetail {
                        author: Some(CommitAuthor {
                            name: Some("Alice again".into()),
                            email: Some("alice@example.com".into()),
                        }),
                    }),
                },
            ],
        };
        let ents = build_commit_emails(&commits, "test/repo", "s");
        assert_eq!(
            ents.len(),
            1,
            "duplicate lowercased email should be deduped"
        );
    }
}
