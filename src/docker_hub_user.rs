//! Docker Hub account lookup for a username selector. Keyless -- the public Docker Hub registry API
//! (`GET /v2/users/{handle}/`, with `GET /v2/orgs/{handle}/` for an organisation, then
//! `GET /v2/repositories/{handle}/` for the account's published image repositories).
//!
//! Docker Hub is a major developer-identity platform: a handle resolves to a public account --
//! confirmed only when the returned `username` (a user) or `orgname` (an organisation) is exactly the
//! queried handle, never a near-match -- its self-declared display name, website, location and
//! company, and the number of image repositories it publishes. The account is a candidate
//! [`EntityKind::Username`] lead; its display name is a [`EntityKind::Person`] (a user with a
//! person-shaped name) or the account is an [`EntityKind::Organisation`] (`type` is `Organization`);
//! its self-declared website is a [`EntityKind::Url`] and its non-forge host a [`EntityKind::Domain`]
//! pivot. A published name or website is a lead to review, never proof of who controls the account.
//!
//! The user endpoint is an exact lookup and the account is the single fail-closed gate: a 404 is a
//! clean negative, a returned handle that is not the queried one is semantic drift, and a response
//! that carries neither a `username` nor an `orgname` is schema drift. Docker Hub serves an
//! organisation on `/v2/orgs/`; the `/v2/users/` path may redirect there, so a 3xx is followed to the
//! organisation endpoint this client builds (same host), never by chasing an arbitrary `Location`.
//! `gravatar_email` is published blank, so no email is ever minted. Every field is kept verbatim;
//! nothing is redacted.

use serde::Deserialize;

use crate::canonical::canonical_url;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{DEFAULT_USER_AGENT, Request, Transport, percent_encode_unreserved};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SRC: &str = "docker_hub_user";
const PUBLIC_BASE: &str = "https://hub.docker.com";

/// Largest repository page requested; the account's repository count is read from the page envelope,
/// so this only bounds how many repository names ride as evidence.
const MAX_REPOS: usize = 100;

/// Confirmed-on-Docker-Hub handle: a single-source, keyless account-existence lead.
const USERNAME_CONF: f64 = 0.80;
/// The account's self-declared display name, when it reads as a person's.
const PERSON_CONF: f64 = 0.62;
/// An organisation account (`type` is `Organization`).
const ORG_CONF: f64 = 0.62;
/// The account's self-declared website.
const URL_CONF: f64 = 0.58;
/// The host of the account's website, as a pivot.
const DOMAIN_CONF: f64 = 0.56;

/// Code forges whose bare host is noise as a `Domain` pivot: the link is already a `Url`.
const CODE_FORGES: &[&str] = &[
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "codeberg.org",
    "sr.ht",
];

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

/// A Docker Hub account: a user (keyed by `username`) or an organisation (keyed by `orgname`), with
/// the self-declared profile fields shared by both shapes.
#[derive(Debug, Deserialize)]
struct Account {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    orgname: Option<String>,
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    full_name: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    company: Option<String>,
    #[serde(default)]
    profile_url: Option<String>,
    #[serde(default)]
    date_joined: Option<String>,
    #[serde(default)]
    gravatar_url: Option<String>,
    #[serde(default)]
    badge: Option<String>,
}

impl Account {
    /// The handle Docker Hub keys this account on: a user's `username` or an organisation's `orgname`.
    fn handle(&self) -> Option<&str> {
        self.username
            .as_deref()
            .or(self.orgname.as_deref())
            .map(str::trim)
            .filter(|handle| !handle.is_empty())
    }

    /// Whether this account is an organisation. Fail-closed: a handle sourced from `orgname` (no
    /// `username`) is an organisation even if `type` is absent or renamed, so a field drift can never
    /// mint an organisation as a `Person`; `type` only corroborates.
    fn is_org(&self) -> bool {
        let username = self
            .username
            .as_deref()
            .map(str::trim)
            .filter(|handle| !handle.is_empty());
        let orgname = self
            .orgname
            .as_deref()
            .map(str::trim)
            .filter(|handle| !handle.is_empty());
        (username.is_none() && orgname.is_some())
            || self
                .kind
                .as_deref()
                .is_some_and(|kind| kind.eq_ignore_ascii_case("Organization"))
    }
}

/// The repository-listing envelope: its `count` is the account's total published repositories.
#[derive(Debug, Deserialize)]
struct ReposResp {
    #[serde(default)]
    count: Option<u64>,
}

/// Whether `handle` is a shape Docker Hub keys an account on: non-empty, at most 255 bytes, ASCII
/// alphanumeric after case-folding (Docker Hub handles are lowercase letters and digits). **Pure.**
#[must_use]
pub fn valid_handle(handle: &str) -> bool {
    !handle.is_empty()
        && handle.len() <= 255
        && handle.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

/// The `/v2/users/{handle}/` URL. **Pure.**
#[must_use]
pub fn user_url(handle: &str) -> String {
    format!(
        "{PUBLIC_BASE}/v2/users/{}/",
        percent_encode_unreserved(handle)
    )
}

/// The `/v2/orgs/{handle}/` URL. **Pure.**
#[must_use]
pub fn org_url(handle: &str) -> String {
    format!(
        "{PUBLIC_BASE}/v2/orgs/{}/",
        percent_encode_unreserved(handle)
    )
}

/// The `/v2/repositories/{handle}/` URL for the account's published repositories. **Pure.**
#[must_use]
pub fn repos_url(handle: &str) -> String {
    format!(
        "{PUBLIC_BASE}/v2/repositories/{}/?page_size={MAX_REPOS}",
        percent_encode_unreserved(handle)
    )
}

fn request(url: String) -> Request {
    Request::get(url)
        .header("accept", "application/json")
        .header("user-agent", DEFAULT_USER_AGENT)
}

fn options() -> FetchOptions {
    FetchOptions::no_redirects().paced()
}

/// Look up one Docker Hub account and its repository count, keyless.
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses the account URL.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let handle = username.trim().trim_start_matches('@').to_ascii_lowercase();
    if !valid_handle(&handle) {
        return Ok(miss(SourceExecutionOutcome::inconclusive(
            SRC,
            now_unix,
            "selector is not a valid Docker Hub handle",
        )));
    }
    let fetched = fetch(
        transport,
        request(user_url(&handle)),
        None,
        &options(),
        SRC,
        now_unix,
    )?;
    // Docker Hub serves organisations on `/v2/orgs/`; the `/v2/users/` path may redirect there. Follow
    // it to an endpoint this client builds (same host), never by chasing the response's `Location`.
    let fetched = if is_redirect(&fetched) {
        fetch(
            transport,
            request(org_url(&handle)),
            None,
            &options(),
            SRC,
            now_unix,
        )?
    } else {
        fetched
    };
    let (account, status) = match interpret_account(&fetched, &handle, now_unix) {
        Ok(found) => found,
        Err(outcome) => return Ok(miss(outcome)),
    };

    // The account is confirmed; its repository count is enrichment, so a listing that is refused or
    // unreadable loses only that attribute, never the account.
    let repo_count = match fetch(
        transport,
        request(repos_url(&handle)),
        None,
        &options(),
        SRC,
        now_unix,
    ) {
        Ok(fetched) => interpret_repos(&fetched),
        Err(_) => None,
    };

    let mut entities = build_entities(&account, &handle, repo_count, scan_id);
    merge_by_uid(&mut entities);
    Ok(Report {
        outcome: SourceExecutionOutcome::success(SRC, now_unix, entities.len())
            .with_http_status(status),
        entities,
    })
}

/// A report that found nothing, carrying only its outcome. **Pure.**
fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

/// Whether the fetch returned an unfollowed redirect (a 3xx under [`FetchOptions::no_redirects`]).
/// **Pure.**
fn is_redirect(fetched: &Fetched) -> bool {
    fetched
        .response
        .as_ref()
        .is_some_and(|response| matches!(response.status, 301 | 302 | 307 | 308))
}

/// The confirmed account with the response status; `Err` is the outcome of a response that named no
/// such account or a different one. A 404 is a clean negative; a 200 whose handle is not the queried
/// one is semantic drift; a response with neither a `username` nor an `orgname` is schema drift.
/// **Pure.**
fn interpret_account(
    fetched: &Fetched,
    handle: &str,
    now_unix: u64,
) -> Result<(Account, u16), SourceExecutionOutcome> {
    if let Some(response) = &fetched.response {
        if response.status == 404 && fetched.outcome.kind == SourceOutcomeKind::Upstream4xx {
            return Err(
                SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(response.status)
            );
        }
    }
    let response = whole_response(fetched, "Docker Hub account")?;
    answer(fetched, "Docker Hub account")?;
    let account: Account = decode_json(response, SRC, now_unix, "Docker Hub account")?;
    let Some(resolved) = account.handle() else {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "Docker Hub response carried no username or orgname",
        ));
    };
    if !resolved.eq_ignore_ascii_case(handle) {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SemanticDrift,
            Some(response.status),
            "Docker Hub returned a different account than the queried handle",
        ));
    }
    Ok((account, response.status))
}

/// The account's published-repository total, or `None` when the listing is unreadable -- the account
/// itself is already confirmed, so a missing listing drops only the count. **Pure.**
fn interpret_repos(fetched: &Fetched) -> Option<u64> {
    let response = whole_response(fetched, "Docker Hub repositories").ok()?;
    answer(fetched, "Docker Hub repositories").ok()?;
    decode_json::<ReposResp>(response, SRC, 0, "Docker Hub repositories")
        .ok()
        .and_then(|resp| resp.count)
}

/// Build the report entities from the confirmed account. **Pure** -- unit-testable off JSON fixtures.
fn build_entities(
    account: &Account,
    handle: &str,
    repo_count: Option<u64>,
    scan_id: &str,
) -> Vec<Entity> {
    let is_org = account.is_org();
    let name = account
        .full_name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty());
    let website = account
        .profile_url
        .as_deref()
        .map(str::trim)
        .filter(|url| canonical_url(url).is_some());

    let evidence = account_evidence(account, handle, is_org, name, website, repo_count, scan_id);

    let mut entities = Vec::new();
    push_entity(
        &mut entities,
        EntityKind::Username,
        handle,
        USERNAME_CONF,
        scan_id,
        evidence.clone(),
        &["docker-hub", "code"],
    );

    if is_org {
        // An organisation account: its display name, or the handle when it has none.
        push_entity(
            &mut entities,
            EntityKind::Organisation,
            name.unwrap_or(handle),
            ORG_CONF,
            scan_id,
            evidence.clone(),
            &["docker-hub", "self-reported"],
        );
    } else if let Some(name) = name.filter(|name| name.split_whitespace().count() >= 2) {
        // A display name of two or more words reads as a person's; a single token is kept as
        // evidence only, never asserted to be a person.
        push_entity(
            &mut entities,
            EntityKind::Person,
            name,
            PERSON_CONF,
            scan_id,
            evidence.clone(),
            &["docker-hub", "self-reported"],
        );
    }

    if let Some(website) = website {
        push_entity(
            &mut entities,
            EntityKind::Url,
            website,
            URL_CONF,
            scan_id,
            evidence.clone(),
            &["docker-hub"],
        );
        if let Some((kind, host)) = crate::entity::link_host(website) {
            if !CODE_FORGES.contains(&host.as_str()) {
                push_entity(
                    &mut entities,
                    kind,
                    &host,
                    DOMAIN_CONF,
                    scan_id,
                    evidence,
                    &["docker-hub", crate::tags::DERIVED],
                );
            }
        }
    }
    entities
}

/// The shared evidence for the account's entities: its type, self-declared fields and repository
/// count, kept verbatim. **Pure.**
fn account_evidence(
    account: &Account,
    handle: &str,
    is_org: bool,
    name: Option<&str>,
    website: Option<&str>,
    repo_count: Option<u64>,
    scan_id: &str,
) -> Evidence {
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!(
            "Docker Hub {} @{handle}: a public registry account, a candidate to review, not a confirmed identity",
            if is_org { "organisation" } else { "account" }
        ),
    )
    .with_attr("dataset", "Docker Hub")
    .with_attr("account_type", if is_org { "Organization" } else { "User" })
    .with_attr("hub_profile", format!("{PUBLIC_BASE}/u/{handle}"))
    .with_optional_attrs([
        ("display_name", name),
        ("website", website),
        (
            "location",
            account
                .location
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty()),
        ),
        (
            "company",
            account
                .company
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty()),
        ),
        (
            "date_joined",
            account
                .date_joined
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty()),
        ),
        (
            "gravatar_url",
            account
                .gravatar_url
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty()),
        ),
        (
            "badge",
            account
                .badge
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty()),
        ),
    ]);
    if let Some(count) = repo_count {
        evidence = evidence.with_attr("repository_count", count.to_string());
    }
    evidence
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{ScriptedTransport, json_ok};

    const USER: &str = r#"{"id":"34956c7c74c011e4bea40242ac11001b","username":"jpetazzo","full_name":"Jérôme Petazzoni","location":"California","company":"","profile_url":"http://jpetazzo.github.io/","date_joined":"2013-05-01T07:14:57Z","gravatar_url":"https://www.gravatar.com/avatar/b1b977516f227cd30b912417d3f1916f","gravatar_email":"","type":"User"}"#;
    const ORG: &str = r#"{"id":"57b4593474c011e4bea40242ac11001b","orgname":"docker","full_name":"Docker, Inc.","location":"San Francisco, CA, USA","company":"Docker, Inc.","profile_url":"https://www.docker.com","date_joined":"2014-05-27T21:11:00Z","gravatar_url":"https://www.gravatar.com/avatar/0fb5734bc033c43c456a233739d1eb05","gravatar_email":"","type":"Organization","badge":"verified_publisher","is_active":true}"#;
    const REPOS: &str = r#"{"count":102,"next":null,"previous":null,"results":[{"name":"pgsql","namespace":"jpetazzo","pull_count":2072,"star_count":0,"source":null}]}"#;

    fn redirect() -> crate::http::Response {
        crate::http::Response {
            status: 301,
            headers: vec![(
                "location".into(),
                "https://hub.docker.com/v2/orgs/docker/".into(),
            )],
            body: Vec::new(),
            truncated: false,
        }
    }

    fn has(report: &Report, kind: &EntityKind, value: &str) -> bool {
        report
            .entities
            .iter()
            .any(|entity| entity.kind == *kind && entity.raw_value == value)
    }

    fn account_attr<'a>(report: &'a Report, key: &str) -> Option<&'a str> {
        report
            .entities
            .iter()
            .find(|entity| entity.kind == EntityKind::Username)
            .and_then(|entity| entity.evidence.first())
            .and_then(|evidence| evidence.attributes.get(key))
            .map(String::as_str)
    }

    #[test]
    fn valid_handle_accepts_docker_shaped_handles_only() {
        assert!(valid_handle("jpetazzo"));
        assert!(valid_handle("docker"));
        assert!(!valid_handle(""));
        assert!(!valid_handle("has-hyphen"));
        assert!(!valid_handle("has_underscore"));
        assert!(!valid_handle("../etc"));
        assert!(!valid_handle(&"x".repeat(256)));
    }

    #[test]
    fn the_urls_carry_the_handle() {
        assert_eq!(
            user_url("jpetazzo"),
            "https://hub.docker.com/v2/users/jpetazzo/"
        );
        assert_eq!(org_url("docker"), "https://hub.docker.com/v2/orgs/docker/");
        assert_eq!(
            repos_url("jpetazzo"),
            "https://hub.docker.com/v2/repositories/jpetazzo/?page_size=100"
        );
    }

    #[test]
    fn a_confirmed_user_emits_username_person_website_and_domain() {
        let transport = ScriptedTransport::new(vec![Ok(json_ok(USER)), Ok(json_ok(REPOS))]);
        let report = lookup(&transport, "jpetazzo", "scan-docker", 1).expect("runs");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(has(&report, &EntityKind::Username, "jpetazzo"));
        assert!(has(&report, &EntityKind::Person, "Jérôme Petazzoni"));
        assert!(has(&report, &EntityKind::Url, "http://jpetazzo.github.io/"));
        assert!(has(&report, &EntityKind::Domain, "jpetazzo.github.io"));
        // A user is never minted as an organisation.
        assert!(
            !report
                .entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Organisation)
        );
        assert_eq!(account_attr(&report, "repository_count"), Some("102"));
        assert_eq!(account_attr(&report, "account_type"), Some("User"));
    }

    #[test]
    fn an_organisation_resolves_through_the_orgs_redirect() {
        // /v2/users/docker/ 3xx-redirects; the client follows to /v2/orgs/docker/ which it builds.
        let transport =
            ScriptedTransport::new(vec![Ok(redirect()), Ok(json_ok(ORG)), Ok(json_ok(REPOS))]);
        let report = lookup(&transport, "docker", "scan-docker", 1).expect("runs");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(has(&report, &EntityKind::Username, "docker"));
        assert!(has(&report, &EntityKind::Organisation, "Docker, Inc."));
        // An organisation is never minted as a person.
        assert!(
            !report
                .entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Person)
        );
        assert_eq!(account_attr(&report, "account_type"), Some("Organization"));
        assert_eq!(account_attr(&report, "badge"), Some("verified_publisher"));
        // The org website is a Domain pivot.
        assert!(has(&report, &EntityKind::Domain, "www.docker.com"));
    }

    #[test]
    fn an_organisation_served_directly_on_the_users_path_is_handled() {
        // Docker Hub also serves an organisation object on /v2/users/ with a 200; no redirect hop.
        let transport = ScriptedTransport::new(vec![Ok(json_ok(ORG)), Ok(json_ok(REPOS))]);
        let report = lookup(&transport, "docker", "scan-docker", 1).expect("runs");
        assert!(has(&report, &EntityKind::Organisation, "Docker, Inc."));
    }

    #[test]
    fn an_unknown_account_is_a_clean_negative() {
        let transport = ScriptedTransport::new(vec![Ok(crate::http::Response {
            status: 404,
            headers: Vec::new(),
            body: b"{\"message\":\"object not found\"}".to_vec(),
            truncated: false,
        })]);
        let report = lookup(&transport, "nobodyxyz", "scan", 1).expect("runs");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn a_response_for_a_different_account_is_semantic_drift() {
        let other = r#"{"username":"someoneelse","full_name":"X","type":"User"}"#;
        let transport = ScriptedTransport::new(vec![Ok(json_ok(other))]);
        let report = lookup(&transport, "jpetazzo", "scan", 1).expect("runs");
        assert!(report.entities.is_empty(), "{:#?}", report.entities);
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SemanticDrift);
    }

    #[test]
    fn a_response_with_no_handle_is_schema_drift() {
        let report = {
            let transport =
                ScriptedTransport::new(vec![Ok(json_ok(r#"{"full_name":"X","type":"User"}"#))]);
            lookup(&transport, "jpetazzo", "scan", 1).expect("runs")
        };
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn the_account_survives_an_unreadable_repo_listing() {
        let transport = ScriptedTransport::new(vec![Ok(json_ok(USER)), Ok(json_ok("not json"))]);
        let report = lookup(&transport, "jpetazzo", "scan", 1).expect("runs");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(has(&report, &EntityKind::Username, "jpetazzo"));
        assert_eq!(account_attr(&report, "repository_count"), None);
    }

    #[test]
    fn an_org_missing_its_type_field_is_not_minted_as_a_person() {
        // Fail-closed: an account keyed by `orgname` (no `username`) is an organisation even if its
        // `type` is absent or renamed, so its multi-word name is never asserted as a Person.
        let org_no_type = r#"{"orgname":"acmecorp","full_name":"Acme Corporation Ltd"}"#;
        let transport = ScriptedTransport::new(vec![Ok(json_ok(org_no_type)), Ok(json_ok(REPOS))]);
        let report = lookup(&transport, "acmecorp", "scan", 1).expect("runs");
        assert!(has(
            &report,
            &EntityKind::Organisation,
            "Acme Corporation Ltd"
        ));
        assert!(
            !report.entities.iter().any(|e| e.kind == EntityKind::Person),
            "an org without a type field must not be minted as a Person: {:#?}",
            report.entities
        );
    }

    #[test]
    fn a_single_word_display_name_is_not_asserted_to_be_a_person() {
        let solo = r#"{"username":"mobydock","full_name":"Moby","type":"User"}"#;
        let transport = ScriptedTransport::new(vec![Ok(json_ok(solo)), Ok(json_ok(REPOS))]);
        let report = lookup(&transport, "mobydock", "scan", 1).expect("runs");
        assert!(has(&report, &EntityKind::Username, "mobydock"));
        assert!(
            !report.entities.iter().any(|e| e.kind == EntityKind::Person),
            "{:#?}",
            report.entities
        );
    }

    #[test]
    fn the_handle_is_case_folded_before_the_request() {
        let transport = ScriptedTransport::new(vec![Ok(json_ok(USER)), Ok(json_ok(REPOS))]);
        let report = lookup(&transport, "JPetazzo", "scan", 1).expect("runs");
        // The returned lowercase username confirms the folded query.
        assert!(has(&report, &EntityKind::Username, "jpetazzo"));
    }
}
