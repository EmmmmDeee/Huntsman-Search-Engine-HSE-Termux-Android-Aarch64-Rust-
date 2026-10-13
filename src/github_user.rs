//! GitHub public-profile lookup for a username selector. Keyless by default; when the operator
//! configures `HUNTSMAN_GITHUB_TOKEN` the token is sent as a Bearer credential pinned to the API
//! origin, which raises the rate limit without changing what is read.

use serde::Deserialize;

use crate::canonical::{canonical_email, canonical_url};
use crate::credential_origin::{AuthenticationAuthority, OperatorCredentialRef};
use crate::domains::host_only;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{AuthStyle, Credential, FetchOptions, fetch};
use crate::http::{Request, Response, Transport};
use crate::keys::Keys;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};

pub const SRC: &str = "github_user";
/// The credential slot holding an optional GitHub token.
pub const TOKEN_SLOT: &str = crate::environment::GITHUB_TOKEN_ENV;
/// The only origin the token is ever sent to.
const API_ORIGIN: &str = "https://api.github.com:443";

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
    keys: &Keys,
    username: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let username = username.trim().trim_start_matches('@');
    if !valid_login(username) {
        return Ok(Report {
            entities: Vec::new(),
            outcome: SourceExecutionOutcome::inconclusive(
                SRC,
                now_unix,
                "selector is not a valid GitHub login",
            ),
        });
    }

    let credential = keys
        .get(TOKEN_SLOT)
        .map(|secret| token_credential(secret, now_unix))
        .transpose()?;
    let url = format!("https://api.github.com/users/{username}");
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

    let Some(response) = fetched.response else {
        return Ok(Report {
            entities: Vec::new(),
            outcome: fetched.outcome,
        });
    };
    Ok(parse_response(
        &response,
        fetched.outcome,
        credential.is_some(),
        scan_id,
        now_unix,
    ))
}

fn token_credential(secret: crate::keys::Secret, now_unix: u64) -> Result<Credential, Error> {
    let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
        provider_id: "github".into(),
        credential_slot: TOKEN_SLOT.into(),
        approved_at_unix: now_unix,
        approval_provenance: format!("operator configured {TOKEN_SLOT}"),
    })
    .map_err(|e| Error::Invalid(e.to_string()))?;
    Ok(Credential::new(authority, secret, AuthStyle::Bearer)?.only_for_origin(API_ORIGIN))
}

fn parse_response(
    response: &Response,
    fallback: SourceExecutionOutcome,
    authenticated: bool,
    scan_id: &str,
    now_unix: u64,
) -> Report {
    if response.status == 404 {
        return Report {
            entities: Vec::new(),
            outcome: SourceExecutionOutcome::valid_zero(SRC, now_unix)
                .with_http_status(response.status),
        };
    }
    if response.status == 403
        && response
            .header_value("x-ratelimit-remaining")
            .is_some_and(|value| value.trim() == "0")
    {
        let mut outcome = fallback;
        outcome.kind = SourceOutcomeKind::RateLimited;
        outcome.found = None;
        outcome.detail = Some(if authenticated {
            "GitHub token rate limit exhausted".into()
        } else {
            format!("GitHub unauthenticated rate limit exhausted; set {TOKEN_SLOT} to raise it")
        });
        return Report {
            entities: Vec::new(),
            outcome,
        };
    }
    if response.truncated {
        return Report {
            entities: Vec::new(),
            outcome: SourceExecutionOutcome::failed(
                SRC,
                now_unix,
                SourceOutcomeKind::ParserDrift,
                Some(response.status),
                "truncated GitHub response",
            ),
        };
    }

    let body = response.text();
    let classified = classify_fetch(response.status, &body);
    if classified != SourceOutcomeKind::Inconclusive {
        return Report {
            entities: Vec::new(),
            outcome: SourceExecutionOutcome::failed(
                SRC,
                now_unix,
                classified,
                Some(response.status),
                "GitHub response was not a profile document",
            ),
        };
    }

    let user: GhUser = match serde_json::from_slice(&response.body) {
        Ok(user) => user,
        Err(error) => {
            return Report {
                entities: Vec::new(),
                outcome: SourceExecutionOutcome::failed(
                    SRC,
                    now_unix,
                    SourceOutcomeKind::ParserDrift,
                    Some(response.status),
                    format!("GitHub JSON: {error}"),
                ),
            };
        }
    };
    if user.login.trim().is_empty() {
        return Report {
            entities: Vec::new(),
            outcome: SourceExecutionOutcome::failed(
                SRC,
                now_unix,
                SourceOutcomeKind::SchemaDrift,
                Some(response.status),
                "GitHub profile has no login",
            ),
        };
    }

    let mut entities = build_entities(&user, scan_id);
    merge_by_uid(&mut entities);
    Report {
        outcome: SourceExecutionOutcome::success(SRC, now_unix, 1)
            .with_http_status(response.status),
        entities,
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
    let profile_evidence = evidence(user, &profile_url, scan_id);
    let mut entities = Vec::new();

    push_entity(
        &mut entities,
        EntityKind::Username,
        &user.login,
        USERNAME_CONF,
        scan_id,
        profile_evidence.clone(),
        &["github", "public-profile"],
    );
    push_entity(
        &mut entities,
        EntityKind::Url,
        &profile_url,
        URL_CONF,
        scan_id,
        profile_evidence.clone(),
        &["github", "public-profile"],
    );
    add_identity_fields(user, scan_id, &profile_evidence, &mut entities);
    add_social_fields(user, scan_id, &profile_evidence, &mut entities);
    add_blog(user, scan_id, &profile_evidence, &mut entities);
    entities
}

fn add_identity_fields(
    user: &GhUser,
    scan_id: &str,
    profile_evidence: &Evidence,
    entities: &mut Vec<Entity>,
) {
    if let Some(name) = user
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| name.split_whitespace().count() >= 2)
    {
        push_entity(
            entities,
            EntityKind::Person,
            name,
            PERSON_CONF,
            scan_id,
            profile_evidence.clone(),
            &["github", "public-profile"],
        );
    }
    if let Some(email) = user
        .email
        .as_deref()
        .map(str::trim)
        .filter(|email| canonical_email(email).is_some())
    {
        push_entity(
            entities,
            EntityKind::Email,
            email,
            EMAIL_CONF,
            scan_id,
            profile_evidence.clone(),
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
        push_entity(
            entities,
            EntityKind::Organisation,
            company,
            ORG_CONF,
            scan_id,
            profile_evidence.clone(),
            &["github", "self-reported"],
        );
    }
    if let Some(location) = user
        .location
        .as_deref()
        .map(str::trim)
        .filter(|location| location.len() >= 3)
    {
        push_entity(
            entities,
            EntityKind::Address,
            location,
            ADDRESS_CONF,
            scan_id,
            profile_evidence.clone(),
            &["github", "self-reported"],
        );
    }
}

fn add_social_fields(
    user: &GhUser,
    scan_id: &str,
    profile_evidence: &Evidence,
    entities: &mut Vec<Entity>,
) {
    let Some(twitter) = user
        .twitter_username
        .as_deref()
        .map(str::trim)
        .map(|value| value.trim_start_matches('@'))
        .filter(|value| !value.is_empty())
    else {
        return;
    };
    push_entity(
        entities,
        EntityKind::Username,
        twitter,
        SOCIAL_CONF,
        scan_id,
        profile_evidence.clone().with_attr("platform", "twitter"),
        &["twitter", "social-profile"],
    );
}

fn add_blog(user: &GhUser, scan_id: &str, profile_evidence: &Evidence, entities: &mut Vec<Entity>) {
    let Some(blog) = user
        .blog
        .as_deref()
        .map(str::trim)
        .filter(|blog| canonical_url(blog).is_some())
    else {
        return;
    };
    push_entity(
        entities,
        EntityKind::Url,
        blog,
        URL_CONF,
        scan_id,
        profile_evidence.clone(),
        &["personal-site", "github"],
    );
    let host = host_only(blog).to_ascii_lowercase();
    if host.contains('.') && !matches!(host.as_str(), "github.com" | "github.io") {
        push_entity(
            entities,
            EntityKind::Domain,
            &host,
            DOMAIN_CONF,
            scan_id,
            profile_evidence.clone().with_attr("blog_url", blog),
            &["personal-site", "derived"],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::OneResponse;

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
        let got = lookup(
            &OneResponse::with_headers(404, &[], ""),
            &Keys::default(),
            "nobody",
            "scan",
            1,
        )
        .unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::ValidZero);
        assert!(got.entities.is_empty());
    }

    const TOKEN: &str = "ghp_h7K2mQ9xR4vL8nT3pW6zY1bC5dF0gJ2sA9eU";

    fn sent_authorization(keys: &Keys) -> (Option<String>, Report) {
        let transport = crate::test_support::ScriptedTransport::new(vec![Ok(Response {
            status: 403,
            headers: vec![("x-ratelimit-remaining".into(), "0".into())],
            body: b"{}".to_vec(),
            truncated: false,
        })]);
        let report = lookup(&transport, keys, "octocat", "scan", 1).unwrap();
        let seen = transport.seen.borrow();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].url, "https://api.github.com/users/octocat");
        let authorization = seen[0]
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.clone());
        (authorization, report)
    }

    #[test]
    fn a_configured_token_is_sent_as_bearer_and_named_in_the_rate_limit() {
        let keys = Keys::parse(&format!("{TOKEN_SLOT}={TOKEN}")).unwrap();
        let (authorization, report) = sent_authorization(&keys);
        assert_eq!(authorization, Some(format!("Bearer {TOKEN}")));
        assert_eq!(report.outcome.kind, SourceOutcomeKind::RateLimited);
        assert_eq!(
            report.outcome.detail.as_deref(),
            Some("GitHub token rate limit exhausted")
        );
    }

    #[test]
    fn without_a_token_no_credential_is_sent_and_the_slot_is_named() {
        let (authorization, report) = sent_authorization(&Keys::default());
        assert_eq!(authorization, None);
        let detail = report.outcome.detail.unwrap();
        assert!(detail.contains("unauthenticated"), "{detail}");
        assert!(detail.contains(TOKEN_SLOT), "{detail}");
    }

    #[test]
    fn rate_limit_is_not_a_missing_profile() {
        let got = lookup(
            &OneResponse::with_headers(403, &[("x-ratelimit-remaining", "0")], "{}"),
            &Keys::default(),
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
            &OneResponse::with_headers(200, &[("content-type", "application/json")], body),
            &Keys::default(),
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
            &OneResponse::with_headers(200, &[("content-type", "application/json")], "{"),
            &Keys::default(),
            "octocat",
            "scan",
            1,
        )
        .unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::ParserDrift);
    }
}
