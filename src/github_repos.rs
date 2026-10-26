//! Passive, keyless public GitHub repository footprint for a username.
//!
//! One bounded read against the official public GitHub API. This does not crawl
//! repositories, examine source code or infer the account holder's real-world identity.
//! A repository homepage is a self-declared claim, not proof of domain ownership.

use serde::Deserialize;

use crate::canonical::canonical_url;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::github_user::{self, TOKEN_SLOT};
use crate::http::{Request, Transport};
use crate::keys::Keys;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SRC: &str = "github_repos";
const MAX_REPOS: usize = 30;
const MAX_TEXT_CHARS: usize = 240;

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug, Deserialize)]
struct Owner {
    login: String,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct Repository {
    id: u64,
    name: String,
    full_name: String,
    owner: Owner,
    #[serde(default)]
    private: bool,
    #[serde(default)]
    fork: bool,
    #[serde(default)]
    archived: bool,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    homepage: Option<String>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    default_branch: Option<String>,
    #[serde(default)]
    pushed_at: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    stargazers_count: Option<u64>,
    #[serde(default)]
    forks_count: Option<u64>,
    #[serde(default)]
    open_issues_count: Option<u64>,
    #[serde(default)]
    topics: Vec<String>,
    #[serde(default)]
    license: Option<License>,
}

#[derive(Debug, Deserialize)]
struct License {
    #[serde(default)]
    spdx_id: Option<String>,
}

/// Read at most 30 recently updated, publicly visible repositories for this
/// account. Reuses the origin-locked GitHub credential, if configured.
/// A page of 30 is NOT an exhaustive inventory.
///
/// # Errors
/// The shared guarded HTTP layer may refuse the request before it is sent.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    username: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let username = username.trim().trim_start_matches('@');
    if !github_user::valid_login(username) {
        return Ok(empty(SourceExecutionOutcome::inconclusive(
            SRC,
            now_unix,
            "selector is not a valid GitHub account login",
        )));
    }
    let credential = keys
        .get(TOKEN_SLOT)
        .map(|value| github_user::token_credential(value, now_unix))
        .transpose()?;
    let url = format!(
        "https://api.github.com/users/{username}/repos?type=owner&sort=updated&per_page={MAX_REPOS}"
    );
    let fetched = fetch(
        transport,
        Request::get(&url)
            .header("accept", "application/vnd.github+json")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
        credential.as_ref(),
        &FetchOptions::no_redirects(),
        SRC,
        now_unix,
    )?;
    Ok(interpret(&fetched, username, scan_id, now_unix).unwrap_or_else(empty))
}

fn empty(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

fn interpret(
    fetched: &Fetched,
    username: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, SourceExecutionOutcome> {
    if let Some(response) = &fetched.response {
        if response.status == 404 && fetched.outcome.kind == SourceOutcomeKind::Upstream4xx {
            return Err(
                SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(response.status)
            );
        }
        if response.status == 403
            && response
                .header_value("x-ratelimit-remaining")
                .is_some_and(|value| value.trim() == "0")
        {
            let mut outcome = fetched.outcome.clone();
            outcome.kind = SourceOutcomeKind::RateLimited;
            outcome.found = None;
            outcome.detail = Some("GitHub API rate limit exhausted".into());
            return Err(outcome);
        }
    }
    let response = whole_response(fetched, "GitHub")?;
    answer(fetched, "GitHub")?;
    let repositories: Vec<Repository> = decode_json(response, SRC, now_unix, "GitHub")?;
    if repositories.is_empty() {
        return Err(
            SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(response.status)
        );
    }
    let mut entities = Vec::new();
    let mut accepted = 0;
    for repo in repositories.into_iter().take(MAX_REPOS) {
        if repo.private
            || repo.id == 0
            || repo.owner.id == 0
            || !repo.owner.login.eq_ignore_ascii_case(username)
            || !valid_repo_name(&repo.name)
            || !repo
                .full_name
                .eq_ignore_ascii_case(&format!("{}/{}", repo.owner.login, repo.name))
        {
            continue;
        }
        accepted += 1;
        let url = format!("https://github.com/{}/{}", repo.owner.login, repo.name);
        let mut evidence = Evidence::new(
            EvidenceProvenance::for_scan(SRC, scan_id),
            format!(
                "Public GitHub repository {}/{}",
                repo.owner.login, repo.name
            ),
        )
        .with_attr("dataset", "GitHub public repositories")
        .with_attr(
            "source_url",
            format!(
                "https://api.github.com/repos/{}/{}",
                repo.owner.login, repo.name
            ),
        )
        .with_attr("repo_id", repo.id.to_string())
        .with_attr("account_id", repo.owner.id.to_string())
        .with_attr("account_login", &repo.owner.login)
        .with_attr("repository", &repo.full_name)
        .with_attr("fork", repo.fork.to_string())
        .with_attr("archived", repo.archived.to_string())
        .with_attr(
            "observation_limit",
            format!("latest {MAX_REPOS}; nonexhaustive"),
        );
        for (key, field) in [
            ("description", repo.description.as_deref()),
            ("language", repo.language.as_deref()),
            ("default_branch", repo.default_branch.as_deref()),
            ("created_at", repo.created_at.as_deref()),
            ("updated_at", repo.updated_at.as_deref()),
            ("pushed_at", repo.pushed_at.as_deref()),
            (
                "license_spdx",
                repo.license.as_ref().and_then(|v| v.spdx_id.as_deref()),
            ),
        ] {
            if let Some(value) = field.map(str::trim).filter(|v| !v.is_empty()) {
                evidence = evidence.with_attr(key, bounded(value));
            }
        }
        if let Some(homepage) = repo
            .homepage
            .as_deref()
            .filter(|v| canonical_url(v).is_some())
        {
            evidence = evidence
                .with_attr("self_declared_homepage", bounded(homepage))
                .with_attr("homepage_verification", "unverified");
        }
        for (key, value) in [
            ("stars", repo.stargazers_count),
            ("forks", repo.forks_count),
            ("open_issues_including_prs", repo.open_issues_count),
        ] {
            if let Some(value) = value {
                evidence = evidence.with_attr(key, value.to_string());
            }
        }
        let topics: Vec<_> = repo
            .topics
            .iter()
            .filter(|v| v.len() <= 40)
            .take(8)
            .map(String::as_str)
            .collect();
        if !topics.is_empty() {
            evidence = evidence.with_attr("topics", topics.join(", "));
        }
        push_entity(
            &mut entities,
            EntityKind::Url,
            &url,
            0.90,
            scan_id,
            evidence,
            &["github", "public-repository"],
        );
    }
    if accepted == 0 {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "GitHub API rows did not match requested account",
        ));
    }
    Ok(Report {
        entities,
        outcome: SourceExecutionOutcome::success(SRC, now_unix, accepted)
            .with_http_status(response.status),
    })
}

fn bounded(value: &str) -> String {
    value.chars().take(MAX_TEXT_CHARS).collect()
}

fn valid_repo_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::OneResponse;

    const REPO: &str = r#"[{
        "id":123,"name":"project","full_name":"Octocat/project",
        "owner":{"login":"Octocat","id":7},
        "private":false,"fork":true,"archived":false,
        "description":"Public research","homepage":"https://example.org/",
        "language":"Rust","default_branch":"main","pushed_at":"2026-10-20T00:00:00Z",
        "stargazers_count":19,"topics":["osint","rust"],"license":{"spdx_id":"MIT"}
    }]"#;

    #[test]
    fn maps_public_repository_and_preserves_claim_boundaries() {
        let transport = OneResponse::json(200, REPO);
        let got = lookup(&transport, &Keys::default(), "octocat", "scan", 1).unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(got.entities.len(), 1);
        let e = &got.entities[0];
        assert_eq!(e.kind, EntityKind::Url);
        assert_eq!(e.value, "https://github.com/Octocat/project");
        assert_eq!(
            e.evidence[0].attributes.get("fork").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            e.evidence[0]
                .attributes
                .get("homepage_verification")
                .map(String::as_str),
            Some("unverified")
        );
        assert!(!got.entities.iter().any(|e| e.kind == EntityKind::Domain));
    }

    #[test]
    fn refuses_attribution_from_a_different_account_or_private_repo() {
        for body in [
            REPO.replace("Octocat", "someone-else"),
            REPO.replace("\"private\":false", "\"private\":true"),
            REPO.replace(
                "\"full_name\":\"Octocat/project\"",
                "\"full_name\":\"Octocat/other\"",
            ),
        ] {
            let got = lookup(
                &OneResponse::json(200, &body),
                &Keys::default(),
                "octocat",
                "scan",
                1,
            )
            .unwrap();
            assert_eq!(got.outcome.kind, SourceOutcomeKind::SchemaDrift);
            assert!(got.entities.is_empty());
        }
    }

    #[test]
    fn distinguishes_zero_rows_from_rate_limits_and_malformed_json() {
        let zero = lookup(
            &OneResponse::json(200, "[]"),
            &Keys::default(),
            "octocat",
            "scan",
            1,
        )
        .unwrap();
        assert_eq!(zero.outcome.kind, SourceOutcomeKind::ValidZero);
        let rate = lookup(
            &OneResponse::with_headers(403, &[("x-ratelimit-remaining", "0")], "{}"),
            &Keys::default(),
            "octocat",
            "scan",
            1,
        )
        .unwrap();
        assert_eq!(rate.outcome.kind, SourceOutcomeKind::RateLimited);
        let wrong = lookup(
            &OneResponse::json(200, "{}"),
            &Keys::default(),
            "octocat",
            "scan",
            1,
        )
        .unwrap();
        assert_eq!(wrong.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn does_not_request_invalid_logins() {
        let got = lookup(
            &crate::test_support::Refusing,
            &Keys::default(),
            "../x",
            "scan",
            1,
        )
        .unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::Inconclusive);
    }

    #[test]
    fn fails_closed_on_bad_repository_name() {
        assert!(!valid_repo_name("../x"));
        assert!(!valid_repo_name(""));
        assert!(!valid_repo_name("a/b"));
        assert!(valid_repo_name("name.rs"));
    }
}
