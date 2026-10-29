//! crates.io author lookup for a username selector. Keyless -- the official public registry API
//! (`GET /api/v1/users/{login}`, then `GET /api/v1/crates?user_id={id}`).
//!
//! crates.io authenticates through GitHub, so an account's `login` is its GitHub handle and the
//! `url` field ties the handle to the owner's GitHub profile. One handle resolves to the crates.io
//! account -- confirmed only when the returned `login` is exactly the queried handle, never a
//! near-match -- the owner's self-declared real name and GitHub profile, and the published crates'
//! source-repository, homepage and documentation URLs. Each crate URL is a [`EntityKind::Url`], its
//! non-forge host a [`EntityKind::Domain`], and a `github.com` repository's owner a
//! [`EntityKind::Username`] pivot (a cross-platform lead, never confirmed identity).
//!
//! The user endpoint is an exact lookup and the crate listing is filtered by the resolved numeric
//! `user_id`, so -- unlike a fuzzy maintainer search -- every crate returned genuinely belongs to
//! the confirmed account; the account is the single fail-closed gate. A published name or repo link
//! is a lead to review, not proof of who controls the account.

use serde::Deserialize;

use crate::canonical::canonical_url;
use crate::domains::host_only;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{DEFAULT_USER_AGENT, Request, Transport, percent_encode_unreserved};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SRC: &str = "crates_io";
const PUBLIC_BASE: &str = "https://crates.io";

/// Largest crate page requested (crates.io caps `per_page` at 100). Every crate the page returns is
/// surfaced; an author with more than 100 crates would need cursor pagination (a follow-up).
const MAX_CRATES: usize = 100;

/// Confirmed-on-crates.io handle: a single-source, keyless account-existence lead.
const USERNAME_CONF: f64 = 0.85;
/// The account's self-declared display name, when it reads as a person's.
const PERSON_CONF: f64 = 0.70;
/// The GitHub profile the account authenticates through.
const GITHUB_URL_CONF: f64 = 0.74;
/// A GitHub owner drawn from a crate's source repository: a cross-platform lead.
const OWNER_USERNAME_CONF: f64 = 0.70;
/// A crate's declared source-repository, homepage or documentation URL.
const CRATE_URL_CONF: f64 = 0.62;
/// The host of a crate URL, as a pivot.
const DOMAIN_CONF: f64 = 0.60;

/// Code forges whose host is noise as a `Domain` pivot: the link is already a `Url`.
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

#[derive(Debug, Deserialize)]
struct UserResp {
    #[serde(default)]
    user: Option<CrateUser>,
}

#[derive(Debug, Deserialize)]
struct CrateUser {
    #[serde(default)]
    id: u64,
    #[serde(default)]
    login: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CratesResp {
    crates: Vec<CrateInfo>,
}

#[derive(Debug, Deserialize)]
struct CrateInfo {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    homepage: Option<String>,
    #[serde(default)]
    documentation: Option<String>,
}

/// Whether `handle` is a shape crates.io (a GitHub login) would key an account on: non-empty, at
/// most 39 bytes, ASCII letters/digits/hyphen, no leading, trailing or doubled hyphen. **Pure.**
#[must_use]
pub fn valid_handle(handle: &str) -> bool {
    !handle.is_empty()
        && handle.len() <= 39
        && !handle.starts_with('-')
        && !handle.ends_with('-')
        && !handle.contains("--")
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// The `/api/v1/users/{login}` URL. **Pure.**
#[must_use]
pub fn user_url(handle: &str) -> String {
    format!(
        "{PUBLIC_BASE}/api/v1/users/{}",
        percent_encode_unreserved(handle)
    )
}

/// The `/api/v1/crates?user_id={id}` URL for the account's published crates. **Pure.**
#[must_use]
pub fn crates_url(user_id: u64) -> String {
    format!("{PUBLIC_BASE}/api/v1/crates?user_id={user_id}&per_page={MAX_CRATES}&sort=alpha")
}

/// The public profile page a human reads for a handle. **Pure.**
fn profile_url(handle: &str) -> String {
    format!("{PUBLIC_BASE}/users/{handle}")
}

fn request(url: String) -> Request {
    Request::get(url)
        .header("accept", "application/json")
        .header("user-agent", DEFAULT_USER_AGENT)
}

/// Look up one crates.io account and its published crates, keyless.
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
            "selector is not a valid crates.io handle",
        )));
    }
    let fetched = fetch(
        transport,
        request(user_url(&handle)),
        None,
        &FetchOptions::no_redirects().paced(),
        SRC,
        now_unix,
    )?;
    let (user, status) = match interpret_user(&fetched, &handle, now_unix) {
        Ok(found) => found,
        Err(outcome) => return Ok(miss(outcome)),
    };

    // The account is confirmed; its crates are enrichment filtered by the resolved numeric id, so a
    // crates fetch that is refused or unreadable loses only the crate pivots, never the account.
    let crates = match fetch(
        transport,
        request(crates_url(user.id)),
        None,
        &FetchOptions::no_redirects().paced(),
        SRC,
        now_unix,
    ) {
        Ok(fetched) => interpret_crates(&fetched),
        Err(_) => None,
    };

    let mut entities = build_entities(
        &user,
        crates.as_deref().unwrap_or(&[]),
        &handle,
        scan_id,
        crates.as_ref().map(Vec::len),
    );
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

/// The confirmed account, with the response status; `Err` is the outcome of a response that named
/// no such account or named a different one. A 404 is a clean negative; a 200 whose `login` is not
/// the queried handle is semantic drift, never attributed to the query. **Pure.**
fn interpret_user(
    fetched: &Fetched,
    handle: &str,
    now_unix: u64,
) -> Result<(CrateUser, u16), SourceExecutionOutcome> {
    if let Some(response) = &fetched.response {
        if response.status == 404 && fetched.outcome.kind == SourceOutcomeKind::Upstream4xx {
            return Err(
                SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(response.status)
            );
        }
    }
    let response = whole_response(fetched, "crates.io user")?;
    answer(fetched, "crates.io user")?;
    let resp: UserResp = decode_json(response, SRC, now_unix, "crates.io user")?;
    let Some(user) = resp.user else {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "crates.io response carried no user object",
        ));
    };
    if user.id == 0 || user.login.trim().is_empty() {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "crates.io user has no id or login",
        ));
    }
    if !user.login.eq_ignore_ascii_case(handle) {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SemanticDrift,
            Some(response.status),
            "crates.io returned a different account than the queried handle",
        ));
    }
    Ok((user, response.status))
}

/// The published crates of a confirmed account, or an empty list when the listing is unreadable --
/// the account itself is already confirmed, so a missing listing drops only crate pivots. **Pure.**
fn interpret_crates(fetched: &Fetched) -> Option<Vec<CrateInfo>> {
    let response = whole_response(fetched, "crates.io crates").ok()?;
    answer(fetched, "crates.io crates").ok()?;
    decode_json::<CratesResp>(response, SRC, 0, "crates.io crates")
        .ok()
        .map(|resp| resp.crates)
}

/// Only a matching HTTPS GitHub profile can be labelled as this registry account's authenticated
/// profile. An arbitrary self-declared URL is not proof of account linkage. **Pure.**
fn is_confirmed_github_profile(url: &str, login: &str) -> bool {
    let Some(path) = url.strip_prefix("https://github.com/") else {
        return false;
    };
    let username = path.strip_suffix('/').unwrap_or(path);
    valid_handle(username) && username.eq_ignore_ascii_case(login)
}

/// The GitHub owner (first path segment) of a `github.com/{owner}/{repo}` URL, lower-cased and
/// validated as a login, or `None` for any other URL. **Pure.**
fn github_owner(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://github.com/")?;
    let (owner, repository) = rest.split_once('/')?;
    if valid_handle(owner)
        && !repository.is_empty()
        && !repository.starts_with(['/', '?', '#'])
        && !matches!(repository.split('/').next(), Some(".") | Some(".."))
    {
        Some(owner.to_ascii_lowercase())
    } else {
        None
    }
}

/// Build the report entities from the confirmed account and its crates. **Pure** (no network/IO),
/// so the account/crate -> entity mapping is unit-testable off JSON fixtures.
fn build_entities(
    user: &CrateUser,
    crates: &[CrateInfo],
    handle: &str,
    scan_id: &str,
    crate_count: Option<usize>,
) -> Vec<Entity> {
    let mut entities = Vec::new();
    add_account(user, crate_count, scan_id, &mut entities);
    add_crate_links(crates, handle, scan_id, &mut entities);
    entities
}

/// The confirmed account: its `Username`, the owner's display name as a `Person` when it reads as
/// one, and the GitHub profile `Url` the account authenticates through. **Pure.**
fn add_account(user: &CrateUser, crate_count: Option<usize>, scan_id: &str, entities: &mut Vec<Entity>) {
    let login = user.login.to_ascii_lowercase();
    let name = user
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty());
    let github = user
        .url
        .as_deref()
        .map(str::trim)
        .filter(|url| is_confirmed_github_profile(url, &login));

    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!(
            "crates.io account @{login}: a public registry account, a candidate to review, not a confirmed identity"
        ),
    )
    .with_attr("dataset", "crates.io")
    .with_attr("crates_io_id", user.id.to_string())
    .with_attr("profile_url", profile_url(&login))
    .with_attr(
        "crate_listing",
        if crate_count.is_some() {
            "observed_page"
        } else {
            "unavailable"
        },
    )
    .with_optional_attrs([("display_name", name), ("github_url", github)]);
    if let Some(count) = crate_count {
        evidence = evidence.with_attr("crate_page_count", count.to_string());
        // A full page may be truncated; do not claim it is the complete account total.
        if count < MAX_CRATES {
            evidence = evidence.with_attr("crate_count", count.to_string());
        }
    }
    if let Some(name) = name {
        evidence = evidence.with_attr("owner", name);
    }
    push_entity(
        entities,
        EntityKind::Username,
        &login,
        USERNAME_CONF,
        scan_id,
        evidence.clone(),
        &["crates-io", "code"],
    );

    // A display name of two or more words reads as a person's; a single token is kept as evidence
    // only, never asserted to be a person.
    if let Some(name) = name.filter(|name| name.split_whitespace().count() >= 2) {
        push_entity(
            entities,
            EntityKind::Person,
            name,
            PERSON_CONF,
            scan_id,
            evidence.clone(),
            &["crates-io", "self-reported"],
        );
    }
    if let Some(github) = github {
        push_entity(
            entities,
            EntityKind::Url,
            github,
            GITHUB_URL_CONF,
            scan_id,
            evidence,
            &["crates-io", "code"],
        );
    }
}

/// Each crate's source-repository, homepage and documentation URL as a `Url`, its non-forge host a
/// `Domain`, and a `github.com` repository's owner a `Username` pivot (skipping the account's own
/// handle, already emitted). URLs, domains and owners are de-duplicated. **Pure.**
fn add_crate_links(crates: &[CrateInfo], handle: &str, scan_id: &str, entities: &mut Vec<Entity>) {
    let mut seen_urls: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut seen_domains: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut seen_owners: std::collections::HashSet<String> = std::collections::HashSet::new();

    for info in crates {
        let crate_name = info.name.as_deref().unwrap_or("").trim();
        for link in [
            info.repository.as_deref(),
            info.homepage.as_deref(),
            info.documentation.as_deref(),
        ]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|link| canonical_url(link).is_some())
        {
            add_one_link(
                link,
                crate_name,
                scan_id,
                entities,
                &mut seen_urls,
                &mut seen_domains,
            );
            add_repo_owner(
                link,
                handle,
                crate_name,
                scan_id,
                entities,
                &mut seen_owners,
            );
        }
    }
}

/// One crate link as a `Url`, and its non-forge host as a `Domain`, each once. **Pure.**
fn add_one_link(
    link: &str,
    crate_name: &str,
    scan_id: &str,
    entities: &mut Vec<Entity>,
    seen_urls: &mut std::collections::HashSet<String>,
    seen_domains: &mut std::collections::HashSet<String>,
) {
    if seen_urls.insert(link.to_owned()) {
        push_entity(
            entities,
            EntityKind::Url,
            link,
            CRATE_URL_CONF,
            scan_id,
            crate_evidence(scan_id, "crates.io crate link", crate_name),
            &["crates-io", "code"],
        );
    }
    let host = host_only(link).to_ascii_lowercase();
    if host.contains('.')
        && !CODE_FORGES.contains(&host.as_str())
        && seen_domains.insert(host.clone())
    {
        push_entity(
            entities,
            EntityKind::Domain,
            &host,
            DOMAIN_CONF,
            scan_id,
            crate_evidence(scan_id, "crates.io crate link domain", crate_name),
            &["crates-io", crate::tags::DERIVED],
        );
    }
}

/// A `github.com` repository's owner as a `Username` lead, once, when it is not the account's own
/// handle (already emitted) -- a cross-platform maintainer or organisation. **Pure.**
fn add_repo_owner(
    link: &str,
    handle: &str,
    crate_name: &str,
    scan_id: &str,
    entities: &mut Vec<Entity>,
    seen_owners: &mut std::collections::HashSet<String>,
) {
    let Some(owner) = github_owner(link) else {
        return;
    };
    if owner.eq_ignore_ascii_case(handle) || !seen_owners.insert(owner.clone()) {
        return;
    }
    push_entity(
        entities,
        EntityKind::Username,
        &owner,
        OWNER_USERNAME_CONF,
        scan_id,
        crate_evidence(scan_id, "crates.io crate repository owner", crate_name),
        &["github", "code"],
    );
}

/// Evidence naming the crate a value came from, omitting the attribute when the name is blank
/// (dead-field hygiene). **Pure.**
fn crate_evidence(scan_id: &str, summary: &str, crate_name: &str) -> Evidence {
    let base = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        summary.to_owned(),
    );
    if crate_name.is_empty() {
        base
    } else {
        base.with_attr("crate", crate_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{ScriptedTransport, json_ok};

    const USER: &str = r#"{"user":{"id":3618,"login":"dtolnay","name":"David Tolnay","url":"https://github.com/dtolnay"}}"#;
    const CRATES: &str = r#"{"crates":[
        {"name":"anyhow","repository":"https://github.com/dtolnay/anyhow","documentation":"https://docs.rs/anyhow"},
        {"name":"cxx","repository":"https://github.com/dtolnay/cxx","homepage":"https://cxx.rs/"},
        {"name":"shared","repository":"https://github.com/rust-lang/shared-thing"}
    ]}"#;

    fn report_of(user: &str, crates: &str, handle: &str) -> Report {
        let transport = ScriptedTransport::new(vec![Ok(json_ok(user)), Ok(json_ok(crates))]);
        lookup(&transport, handle, "scan-crates", 1).expect("lookup runs")
    }

    fn has(report: &Report, kind: &EntityKind, value: &str) -> bool {
        report
            .entities
            .iter()
            .any(|entity| entity.kind == *kind && entity.raw_value == value)
    }

    #[test]
    fn valid_handle_accepts_github_shaped_logins_only() {
        assert!(valid_handle("dtolnay"));
        assert!(valid_handle("rust-lang"));
        assert!(!valid_handle(""));
        assert!(!valid_handle("-foo"));
        assert!(!valid_handle("foo--bar"));
        assert!(!valid_handle("../etc"));
        assert!(!valid_handle(&"x".repeat(40)));
    }

    #[test]
    fn the_urls_carry_the_handle_and_id() {
        assert_eq!(
            user_url("dtolnay"),
            "https://crates.io/api/v1/users/dtolnay"
        );
        assert_eq!(
            crates_url(3618),
            "https://crates.io/api/v1/crates?user_id=3618&per_page=100&sort=alpha"
        );
    }

    #[test]
    fn a_confirmed_account_emits_its_username_name_github_and_crate_pivots() {
        let report = report_of(USER, CRATES, "dtolnay");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(has(&report, &EntityKind::Username, "dtolnay"));
        assert!(has(&report, &EntityKind::Person, "David Tolnay"));
        assert!(has(&report, &EntityKind::Url, "https://github.com/dtolnay"));
        // crate links and a personal domain
        assert!(has(&report, &EntityKind::Url, "https://docs.rs/anyhow"));
        assert!(has(&report, &EntityKind::Domain, "docs.rs"));
        assert!(has(&report, &EntityKind::Domain, "cxx.rs"));
        // a github.com host is a Url but never a Domain pivot (noise)
        assert!(!has(&report, &EntityKind::Domain, "github.com"));
        // a crate whose repo belongs to another owner surfaces that owner as a lead...
        assert!(has(&report, &EntityKind::Username, "rust-lang"));
        // ...but the account's own handle is not re-emitted as a repo-owner lead.
        let dtolnay_usernames = report
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Username && e.raw_value == "dtolnay")
            .count();
        assert_eq!(dtolnay_usernames, 1, "{:#?}", report.entities);
        // crate_count is the verified listing size.
        let account = report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.raw_value == "dtolnay")
            .expect("account");
        assert_eq!(
            account.evidence[0]
                .attributes
                .get("crate_count")
                .map(String::as_str),
            Some("3")
        );
    }

    #[test]
    fn an_unknown_account_is_a_clean_negative() {
        let transport = ScriptedTransport::new(vec![Ok(crate::http::Response {
            status: 404,
            headers: Vec::new(),
            body: b"{}".to_vec(),
            truncated: false,
        })]);
        let report = lookup(&transport, "nobody-xyz", "scan", 1).expect("runs");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn a_response_for_a_different_account_is_semantic_drift_not_a_confirmation() {
        let other = r#"{"user":{"id":1,"login":"someone-else","name":"X","url":"https://github.com/someone-else"}}"#;
        let transport = ScriptedTransport::new(vec![Ok(json_ok(other))]);
        let report = lookup(&transport, "dtolnay", "scan", 1).expect("runs");
        assert!(report.entities.is_empty(), "{:#?}", report.entities);
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SemanticDrift);
    }

    #[test]
    fn a_response_without_a_user_object_is_schema_drift() {
        let report = report_of(r#"{"errors":[{"detail":"Not Found"}]}"#, CRATES, "dtolnay");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn the_account_survives_an_unreadable_crate_listing() {
        // The user resolves; the crates call answers with a refusal body, so only crate pivots are
        // lost -- the confirmed account is still emitted.
        let transport = ScriptedTransport::new(vec![Ok(json_ok(USER)), Ok(json_ok("not json"))]);
        let report = lookup(&transport, "dtolnay", "scan", 1).expect("runs");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(has(&report, &EntityKind::Username, "dtolnay"));
        assert!(!has(&report, &EntityKind::Url, "https://docs.rs/anyhow"));
    }

    #[test]
    fn mismatched_github_profile_is_not_asserted_as_an_authenticated_link() {
        let spoof = r#"{"user":{"id":3618,"login":"dtolnay","name":"David Tolnay","url":"https://github.com/someone-else"}}"#;
        let report = report_of(spoof, r#"{"crates":[]}"#, "dtolnay");
        assert!(has(&report, &EntityKind::Username, "dtolnay"));
        assert!(!has(&report, &EntityKind::Url, "https://github.com/someone-else"));
        let account = report.entities.iter().find(|e| e.kind == EntityKind::Username).expect("account");
        assert!(!account.evidence[0].attributes.contains_key("github_url"));
        assert!(!is_confirmed_github_profile("https://example.org/dtolnay", "dtolnay"));
        assert!(!is_confirmed_github_profile("https://github.com/dtolnay.evil.org", "dtolnay"));
        assert!(is_confirmed_github_profile("https://github.com/dtolnay", "dtolnay"));
    }

    #[test]
    fn missing_or_invalid_crate_listing_is_not_evidence_of_zero_crates() {
        for body in ["not json", r#"{}"#] {
            let report = report_of(USER, body, "dtolnay");
            assert!(has(&report, &EntityKind::Username, "dtolnay"));
            let account = report.entities.iter().find(|e| e.kind == EntityKind::Username).expect("account");
            let attrs = &account.evidence[0].attributes;
            assert_eq!(attrs.get("crate_listing").map(String::as_str), Some("unavailable"));
            assert!(!attrs.contains_key("crate_count"));
            assert!(!attrs.contains_key("crate_page_count"));
        }
        assert!(github_owner("https://github.com/rust-lang").is_none());
        assert_eq!(github_owner("https://github.com/rust-lang/rust"), Some("rust-lang".to_owned()));
    }

    #[test]
    fn a_single_word_display_name_is_not_asserted_to_be_a_person() {
        let org = r#"{"user":{"id":7,"login":"tokio-rs","name":"Tokio","url":"https://github.com/tokio-rs"}}"#;
        let report = report_of(org, r#"{"crates":[]}"#, "tokio-rs");
        assert!(has(&report, &EntityKind::Username, "tokio-rs"));
        assert!(
            !report.entities.iter().any(|e| e.kind == EntityKind::Person),
            "{:#?}",
            report.entities
        );
    }
}
