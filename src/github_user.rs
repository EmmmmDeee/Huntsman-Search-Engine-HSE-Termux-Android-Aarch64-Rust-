//! Public GitHub user lookup for username enrichment.

use serde::Deserialize;

use crate::canonical::canonical_email;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::error::Error;
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Transport};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};

pub const SRC: &str = "github_user";

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug, Deserialize)]
struct GithubProfile {
    login: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    company: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    blog: Option<String>,
    #[serde(default)]
    bio: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    twitter_username: Option<String>,
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    created_at: Option<String>,
}

#[must_use]
pub fn valid_login(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 39
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
}

/// Query GitHub's unauthenticated public user endpoint.
///
/// # Errors
/// Invalid input or a request rejected by the shared transport.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let username = username.trim();
    if !valid_login(username) {
        return Ok(Report {
            entities: Vec::new(),
            outcome: SourceExecutionOutcome::valid_zero(SRC, now_unix),
        });
    }

    let url = format!("https://api.github.com/users/{username}");
    let fetched = fetch(
        transport,
        Request::get(&url)
            .header("accept", "application/vnd.github+json")
            .header("x-github-api-version", "2022-11-28"),
        None,
        &FetchOptions::no_redirects(),
        SRC,
        now_unix,
    )?;

    let Some(response) = fetched.response else {
        return Ok(Report {
            entities: Vec::new(),
            outcome: fetched.outcome,
        });
    };

    if response.status == 404 {
        return Ok(Report {
            entities: Vec::new(),
            outcome: SourceExecutionOutcome::valid_zero(SRC, now_unix)
                .with_http_status(response.status),
        });
    }
    if response.truncated {
        return Ok(Report {
            entities: Vec::new(),
            outcome: failed(
                now_unix,
                SourceOutcomeKind::ParserDrift,
                Some(response.status),
                "truncated GitHub response",
            ),
        });
    }

    let body = response.text();
    let classified = classify_fetch(response.status, &body);
    if classified != SourceOutcomeKind::Inconclusive {
        return Ok(Report {
            entities: Vec::new(),
            outcome: failed(
                now_unix,
                classified,
                Some(response.status),
                "GitHub response was not a profile document",
            ),
        });
    }

    let profile: GithubProfile = match serde_json::from_slice(&response.body) {
        Ok(profile) => profile,
        Err(err) => {
            return Ok(Report {
                entities: Vec::new(),
                outcome: failed(
                    now_unix,
                    SourceOutcomeKind::ParserDrift,
                    Some(response.status),
                    &format!("GitHub JSON: {err}"),
                ),
            });
        }
    };

    let entities = build_entities(&profile, scan_id);
    Ok(Report {
        entities,
        outcome: SourceExecutionOutcome::success(SRC, now_unix, 1)
            .with_http_status(response.status),
    })
}

fn failed(
    now_unix: u64,
    kind: SourceOutcomeKind,
    status: Option<u16>,
    detail: &str,
) -> SourceExecutionOutcome {
    let mut outcome = SourceExecutionOutcome::success(SRC, now_unix, 0);
    outcome.kind = kind;
    outcome.found = None;
    outcome.http_status = status;
    outcome.detail = Some(detail.to_owned());
    outcome
}

fn evidence(profile: &GithubProfile, scan_id: &str) -> Evidence {
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!("GitHub public profile @{}", profile.login),
    )
    .with_attr("dataset", "GitHub public user profiles")
    .with_attr(
        "profile_url",
        profile
            .html_url
            .as_deref()
            .unwrap_or("https://github.com/"),
    );
    if let Some(id) = profile.id {
        evidence = evidence.with_attr("github_id", id.to_string());
    }
    if let Some(created) = profile.created_at.as_deref() {
        evidence = evidence.with_attr("created_at", created);
    }
    if let Some(bio) = profile.bio.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        evidence = evidence.with_attr("bio", bio);
    }
    evidence
}

fn add(
    entities: &mut Vec<Entity>,
    kind: EntityKind,
    value: &str,
    confidence: f64,
    scan_id: &str,
    evidence: Evidence,
    tag: &str,
) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    let mut entity = Entity::new(kind, value, confidence, scan_id);
    entity.tag("github");
    entity.tag(tag);
    entity.add_evidence(evidence);
    entities.push(entity);
}

fn build_entities(profile: &GithubProfile, scan_id: &str) -> Vec<Entity> {
    let base = evidence(profile, scan_id);
    let mut entities = Vec::new();

    add(
        &mut entities,
        EntityKind::Username,
        &profile.login,
        0.85,
        scan_id,
        base.clone(),
        "confirmed-profile",
    );

    if let Some(name) = profile.name.as_deref().filter(|v| v.split_whitespace().count() >= 2) {
        add(
            &mut entities,
            EntityKind::Person,
            name,
            0.80,
            scan_id,
            base.clone(),
            "public-profile",
        );
    }

    if let Some(email) = profile.email.as_deref().and_then(canonical_email) {
        add(
            &mut entities,
            EntityKind::Email,
            &email,
            0.85,
            scan_id,
            base.clone(),
            "public-profile",
        );
    }

    if let Some(company) = profile.company.as_deref() {
        let company = company.trim().trim_start_matches('@');
        if company.len() >= 2 {
            add(
                &mut entities,
                EntityKind::Organisation,
                company,
                0.72,
                scan_id,
                base.clone(),
                "public-profile",
            );
        }
    }

    if let Some(location) = profile.location.as_deref().filter(|v| v.trim().len() >= 3) {
        add(
            &mut entities,
            EntityKind::Address,
            location,
            0.62,
            scan_id,
            base.clone(),
            "self-reported",
        );
    }

    if let Some(blog) = profile
        .blog
        .as_deref()
        .map(str::trim)
        .filter(|v| v.starts_with("https://") || v.starts_with("http://"))
    {
        add(
            &mut entities,
            EntityKind::Url,
            blog,
            0.72,
            scan_id,
            base.clone(),
            "public-profile",
        );
    }

    let profile_url = profile
        .html_url
        .clone()
        .unwrap_or_else(|| format!("https://github.com/{}", profile.login));
    add(
        &mut entities,
        EntityKind::Url,
        &profile_url,
        0.85,
        scan_id,
        base.clone(),
        "profile-url",
    );

    if let Some(twitter) = profile
        .twitter_username
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        add(
            &mut entities,
            EntityKind::Username,
            twitter.trim_start_matches('@'),
            0.70,
            scan_id,
            base.with_attr("platform", "twitter"),
            "cross-platform",
        );
    }

    entities
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    use crate::http::{Response, TransportFailure};

    struct Fake {
        response: RefCell<Option<Result<Response, TransportFailure>>>,
    }

    impl Fake {
        fn response(status: u16, body: &str) -> Self {
            Self {
                response: RefCell::new(Some(Ok(Response {
                    status,
                    headers: Vec::new(),
                    body: body.as_bytes().to_vec(),
                    truncated: false,
                }))),
            }
        }
    }

    impl Transport for Fake {
        fn send(&self, _request: &Request) -> Result<Response, TransportFailure> {
            self.response
                .borrow_mut()
                .take()
                .expect("one request expected")
        }
    }

    #[test]
    fn login_validation_matches_github_shape() {
        assert!(valid_login("octocat"));
        assert!(valid_login("foo-bar"));
        assert!(!valid_login("_foo"));
        assert!(!valid_login("-foo"));
        assert!(!valid_login("foo--bar"));
    }

    #[test]
    fn missing_user_is_valid_zero() {
        let report = lookup(&Fake::response(404, ""), "nobody", "scan", 1).unwrap();
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn profile_emits_public_fields() {
        let body = r#"{
          "login":"janedoe",
          "id":123,
          "name":"Jane Doe",
          "email":"jane@example.com",
          "company":"@Example",
          "location":"Brisbane",
          "blog":"https://example.com",
          "html_url":"https://github.com/janedoe",
          "twitter_username":"jane_social",
          "created_at":"2020-01-01T00:00:00Z"
        }"#;
        let report = lookup(&Fake::response(200, body), "janedoe", "scan", 1).unwrap();
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        for kind in [
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Organisation,
            EntityKind::Address,
            EntityKind::Url,
        ] {
            assert!(report.entities.iter().any(|entity| entity.kind == kind));
        }
    }
}
