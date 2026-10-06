//! Keyless GitHub public-profile lookup for a username selector.

use serde::Deserialize;

use crate::canonical::{canonical_email, canonical_url};
use crate::domains::host_only;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::error::Error;
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Transport};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};

pub const SRC: &str = "github_user";

const USERNAME_CONF: f64 = 0.85;
const PERSON_CONF: f64 = 0.75;
const EMAIL_CONF: f64 = 0.78;
const SOCIAL_CONF: f64 = 0.70;
const ORG_CONF: f64 = 0.65;
const ADDRESS_CONF: f64 = 0.55;
const URL_CONF: f64 = 0.70;
const DOMAIN_CONF: f64 = 0.65;

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug, Deserialize)]
struct GhUser {
    login: String,
    id: u64,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    company: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    blog: Option<String>,
    #[serde(default)]
    bio: Option<String>,
    #[serde(default)]
    twitter_username: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    public_repos: Option<u64>,
    #[serde(default)]
    public_gists: Option<u64>,
    #[serde(default)]
    followers: Option<u64>,
    #[serde(default)]
    following: Option<u64>,
    #[serde(default)]
    created_at: Option<String>,
}

#[must_use]
pub fn valid_login(value: &str) -> bool {
    let login = value.trim().trim_start_matches('@');
    !login.is_empty()
        && login.len() <= 39
        && !login.starts_with('-')
        && !login.ends_with('-')
        && !login.contains("--")
        && login
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// Query one public GitHub user profile.
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses a URL.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let username = username.trim().trim_start_matches('@');
    if !valid_login(username) {
        return Ok(Report {
            entities: Vec::new(),
            outcome: inconclusive(now_unix, "selector is not a valid GitHub login"),
        });
    }

    let url = format!("https://api.github.com/users/{username}");
    let fetched = fetch(
        transport,
        Request::get(&url)
            .header("accept", "application/vnd.github+json")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
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

    if response.status == 403
        && response
            .header_value("x-ratelimit-remaining")
            .is_some_and(|value| value.trim() == "0")
    {
        let mut outcome = fetched.outcome;
        outcome.kind = SourceOutcomeKind::RateLimited;
        outcome.found = None;
        outcome.detail = Some("GitHub unauthenticated rate limit exhausted".into());
        return Ok(Report {
            entities: Vec::new(),
            outcome,
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

    let user: GhUser = match serde_json::from_slice(&response.body) {
        Ok(user) => user,
        Err(error) => {
            return Ok(Report {
                entities: Vec::new(),
                outcome: failed(
                    now_unix,
                    SourceOutcomeKind::ParserDrift,
                    Some(response.status),
                    &format!("GitHub JSON: {error}"),
                ),
            });
        }
    };
    if user.login.trim().is_empty() {
        return Ok(Report {
            entities: Vec::new(),
            outcome: failed(
                now_unix,
                SourceOutcomeKind::SchemaDrift,
                Some(response.status),
                "GitHub profile has no login",
            ),
        });
    }

    let mut entities = build_entities(&user, scan_id);
    merge_by_uid(&mut entities);
    Ok(Report {
        outcome: SourceExecutionOutcome::success(SRC, now_unix, 1)
            .with_http_status(response.status),
        entities,
    })
}

fn inconclusive(now_unix: u64, detail: &str) -> SourceExecutionOutcome {
    SourceExecutionOutcome {
        module: SRC.into(),
        kind: SourceOutcomeKind::Inconclusive,
        observed_at_unix: now_unix,
        http_status: None,
        found: None,
        retry_after_secs: None,
        detail: Some(detail.into()),
    }
}

fn failed(
    now_unix: u64,
    kind: SourceOutcomeKind,
    status: Option<u16>,
    detail: &str,
) -> SourceExecutionOutcome {
    SourceExecutionOutcome {
        module: SRC.into(),
        kind,
        observed_at_unix: now_unix,
        http_status: status,
        found: None,
        retry_after_secs: None,
        detail: Some(detail.into()),
    }
}

fn evidence(user: &GhUser, profile_url: &str, scan_id: &str) -> Evidence {
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!("GitHub public profile @{}", user.login),
    )
    .with_attr("dataset", "GitHub public profiles")
    .with_attr("github_id", user.id.to_string())
    .with_attr("profile_url", profile_url);

    for (key, value) in [
        ("name", user.name.as_deref()),
        ("company", user.company.as_deref()),
        ("location", user.location.as_deref()),
        ("blog", user.blog.as_deref()),
        ("bio", user.bio.as_deref()),
        ("twitter", user.twitter_username.as_deref()),
        ("email", user.email.as_deref()),
        ("created_at", user.created_at.as_deref()),
    ] {
        if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
            evidence = evidence.with_attr(key, value);
        }
    }
    for (key, value) in [
        ("public_repos", user.public_repos),
        ("public_gists", user.public_gists),
        ("followers", user.followers),
        ("following", user.following),
    ] {
        if let Some(value) = value {
            evidence = evidence.with_attr(key, value.to_string());
        }
    }
    evidence
}

fn build_entities(user: &GhUser, scan_id: &str) -> Vec<Entity> {
    let profile_url = user
        .html_url
        .as_deref()
        .filter(|value| canonical_url(value).is_some())
        .map_or_else(
            || format!("https://github.com/{}", user.login),
            str::to_owned,
        );
    let base = evidence(user, &profile_url, scan_id);
    let mut entities = Vec::new();

    add(
        &mut entities,
        EntityKind::Username,
        &user.login,
        USERNAME_CONF,
        scan_id,
        base.clone(),
        &["github", "public-profile"],
    );
    add(
        &mut entities,
        EntityKind::Url,
        &profile_url,
        URL_CONF,
        scan_id,
        base.clone(),
        &["github", "public-profile"],
    );

    if let Some(name) = user
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| name.split_whitespace().count() >= 2)
    {
        add(
            &mut entities,
            EntityKind::Person,
            name,
            PERSON_CONF,
            scan_id,
            base.clone(),
            &["github", "public-profile"],
        );
    }

    if let Some(email) = user
        .email
        .as_deref()
        .map(str::trim)
        .filter(|email| canonical_email(email).is_some())
    {
        add(
            &mut entities,
            EntityKind::Email,
            email,
            EMAIL_CONF,
            scan_id,
            base.clone(),
            &["github", "public-profile"],
        );
    }

    if let Some(company) = user
        .company
        .as_deref()
        .map(str::trim)
        .map(|company| company.trim_start_matches('@'))
        .filter(|company| company.len() >= 2)
    {
        add(
            &mut entities,
            EntityKind::Organisation,
            company,
            ORG_CONF,
            scan_id,
            base.clone(),
            &["github", "self-reported"],
        );
    }

    if let Some(location) = user
        .location
        .as_deref()
        .map(str::trim)
        .filter(|location| location.len() >= 3)
    {
        add(
            &mut entities,
            EntityKind::Address,
            location,
            ADDRESS_CONF,
            scan_id,
            base.clone(),
            &["github", "self-reported"],
        );
    }

    if let Some(twitter) = user
        .twitter_username
        .as_deref()
        .map(str::trim)
        .map(|value| value.trim_start_matches('@'))
        .filter(|value| !value.is_empty())
    {
        add(
            &mut entities,
            EntityKind::Username,
            twitter,
            SOCIAL_CONF,
            scan_id,
            base.clone().with_attr("platform", "twitter"),
            &["twitter", "social-profile"],
        );
    }

    if let Some(blog) = user
        .blog
        .as_deref()
        .map(str::trim)
        .filter(|blog| canonical_url(blog).is_some())
    {
        add(
            &mut entities,
            EntityKind::Url,
            blog,
            URL_CONF,
            scan_id,
            base.clone(),
            &["personal-site", "github"],
        );
        let host = host_only(blog).to_ascii_lowercase();
        if host.contains('.') && !matches!(host.as_str(), "github.com" | "github.io") {
            add(
                &mut entities,
                EntityKind::Domain,
                &host,
                DOMAIN_CONF,
                scan_id,
                base.clone().with_attr("blog_url", blog),
                &["personal-site", "derived"],
            );
        }
    }

    entities
}

fn add(
    entities: &mut Vec<Entity>,
    kind: EntityKind,
    value: &str,
    confidence: f64,
    scan_id: &str,
    evidence: Evidence,
    tags: &[&str],
) {
    let mut entity = Entity::new(kind, value, confidence, scan_id);
    for tag in tags {
        entity.tag(*tag);
    }
    entity.add_evidence(evidence);
    entities.push(entity);
}

fn merge_by_uid(entities: &mut Vec<Entity>) {
    let mut merged: Vec<Entity> = Vec::new();
    for entity in entities.drain(..) {
        if let Some(existing) = merged.iter_mut().find(|seen| seen.uid == entity.uid) {
            existing.absorb(entity);
        } else {
            merged.push(entity);
        }
    }
    *entities = merged;
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
        fn response(status: u16, headers: &[(&str, &str)], body: &str) -> Self {
            Self {
                response: RefCell::new(Some(Ok(Response {
                    status,
                    headers: headers
                        .iter()
                        .map(|(name, value)| ((*name).into(), (*value).into()))
                        .collect(),
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
    fn login_validation_blocks_path_shaped_input() {
        assert!(valid_login("octocat"));
        assert!(valid_login("foo-bar"));
        assert!(!valid_login("../admin"));
        assert!(!valid_login("foo--bar"));
        assert!(!valid_login("-foo"));
    }

    #[test]
    fn missing_profile_is_valid_zero() {
        let got = lookup(&Fake::response(404, &[], ""), "nobody", "scan", 1).unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::ValidZero);
        assert!(got.entities.is_empty());
    }

    #[test]
    fn rate_limit_is_not_a_missing_profile() {
        let got = lookup(
            &Fake::response(403, &[("x-ratelimit-remaining", "0")], "{}"),
            "octocat",
            "scan",
            1,
        )
        .unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::RateLimited);
    }

    #[test]
    fn profile_emits_high_value_public_pivots() {
        let body = r#"{
          "login":"octocat",
          "id":1,
          "html_url":"https://github.com/octocat",
          "name":"The Octocat",
          "company":"GitHub",
          "location":"San Francisco",
          "blog":"https://example.org/",
          "twitter_username":"octocat",
          "email":"octocat@example.org",
          "public_repos":8,
          "followers":100,
          "created_at":"2011-01-25T18:44:36Z"
        }"#;
        let got = lookup(
            &Fake::response(200, &[("content-type", "application/json")], body),
            "octocat",
            "scan",
            1,
        )
        .unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::Success);
        for kind in [
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Organisation,
            EntityKind::Address,
            EntityKind::Url,
            EntityKind::Domain,
        ] {
            assert!(
                got.entities.iter().any(|entity| entity.kind == kind),
                "missing {kind}"
            );
        }
    }

    #[test]
    fn malformed_json_is_parser_drift() {
        let got = lookup(
            &Fake::response(200, &[("content-type", "application/json")], "{"),
            "octocat",
            "scan",
            1,
        )
        .unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::ParserDrift);
    }
}
