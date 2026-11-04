//! Codeberg account lookup for a username selector. Keyless -- the public Forgejo user API Codeberg
//! serves at `https://codeberg.org/api/v1/users/{username}`.
//!
//! One handle resolves to the Codeberg account. Forgejo logins are case-insensitive and the API
//! answers any case with the canonical `login`, so the account is confirmed only when that `login`
//! is the queried handle ignoring ASCII case, never a near-match. A `404` read as a plain upstream
//! 4xx is the clean "no such account" answer; a challenge page at that status is a wall, not a
//! zero; a body that is not the account document is schema or semantic drift.
//!
//! The account keeps its public profile `Url`, its follower, following and starred counts, join
//! date, location and self-written description as verbatim evidence. Its self-declared full name
//! (two or more words) is a `Person` candidate, its website a `Url` and its non-forge host a
//! `Domain` pivot, and a public e-mail address (never Forgejo's `@noreply.codeberg.org`
//! placeholder) an `Email` candidate. Each is self-reported: a lead to review, never proof of who
//! controls the account.

use serde::Deserialize;

use crate::canonical::{canonical_email, canonical_url};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport, percent_encode_unreserved};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::textnorm::nonblank;

pub const SRC: &str = "codeberg_user";
const API_BASE: &str = "https://codeberg.org";
/// The placeholder domain Forgejo shows in place of an address the user keeps private.
const NOREPLY_SUFFIX: &str = "@noreply.codeberg.org";

/// Forgejo logins are 1-40 characters: an ASCII letter, digit, hyphen, underscore or dot.
const MAX_HANDLE_LEN: usize = 40;

/// Confirmed-on-Codeberg handle: a single-source, keyless account-existence lead.
const USERNAME_CONF: f64 = 0.80;
/// The public profile page.
const PROFILE_URL_CONF: f64 = 0.74;
/// A self-declared name, website or address: a candidate lead.
const SELF_REPORTED_CONF: f64 = 0.55;
/// The host of the self-declared website, as a pivot.
const DOMAIN_CONF: f64 = 0.50;

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug, Deserialize)]
struct Account {
    #[serde(default)]
    login: String,
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    full_name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    created: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    website: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    followers_count: Option<u64>,
    #[serde(default)]
    following_count: Option<u64>,
    #[serde(default)]
    starred_repos_count: Option<u64>,
}

/// Whether `handle` is a shape Forgejo keys an account on. **Pure.**
#[must_use]
pub fn valid_handle(handle: &str) -> bool {
    !handle.is_empty()
        && handle.len() <= MAX_HANDLE_LEN
        && !handle.starts_with('.')
        && !handle.contains("..")
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// The user API URL. **Pure.**
#[must_use]
pub fn user_url(handle: &str) -> String {
    format!(
        "{API_BASE}/api/v1/users/{}",
        percent_encode_unreserved(handle)
    )
}

/// The public profile page a human reads for a handle. **Pure.**
fn profile_url(handle: &str) -> String {
    format!("{API_BASE}/{}", percent_encode_unreserved(handle))
}

/// Look up one Codeberg account, keyless.
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses the account URL.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let handle = username.trim().trim_start_matches('@');
    if !valid_handle(handle) {
        return Ok(miss(SourceExecutionOutcome::inconclusive(
            SRC,
            now_unix,
            "selector is not a valid Codeberg handle",
        )));
    }
    let fetched = fetch(
        transport,
        Request::get_json(user_url(handle)),
        None,
        &FetchOptions::no_redirects().paced(),
        SRC,
        now_unix,
    )?;
    let (account, status) = match interpret_account(&fetched, handle, now_unix) {
        Ok(found) => found,
        Err(outcome) => return Ok(miss(outcome)),
    };
    let mut entities = build_entities(&account, scan_id);
    merge_by_uid(&mut entities);
    Ok(Report {
        outcome: SourceExecutionOutcome::success(SRC, now_unix, entities.len())
            .with_http_status(status),
        entities,
    })
}

fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

/// The confirmed account and response status; `Err` is the outcome of a response that named no
/// such account or a different one. **Pure.**
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
    let response = whole_response(fetched, "Codeberg user")?;
    answer(fetched, "Codeberg user")?;
    let account: Account = decode_json(response, SRC, now_unix, "Codeberg user")?;
    if account.login.trim().is_empty() {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "Codeberg payload carried no login",
        ));
    }
    if !account.login.trim().eq_ignore_ascii_case(handle) {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SemanticDrift,
            Some(response.status),
            "Codeberg returned a different account than the queried handle",
        ));
    }
    Ok((account, response.status))
}

/// A public address the account shows; Forgejo's private-address placeholder is dropped. **Pure.**
fn public_email(account: &Account) -> Option<String> {
    let email = nonblank(account.email.as_deref())?;
    if email.to_ascii_lowercase().ends_with(NOREPLY_SUFFIX) {
        return None;
    }
    canonical_email(email)
}

fn account_evidence(account: &Account, scan_id: &str) -> Evidence {
    let login = account.login.trim();
    let id = account.id.map(|id| id.to_string());
    let followers = account.followers_count.map(|n| n.to_string());
    let following = account.following_count.map(|n| n.to_string());
    let starred = account.starred_repos_count.map(|n| n.to_string());
    Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!(
            "Codeberg account {login}: a public code-forge account, a candidate to review, not a confirmed identity"
        ),
    )
    .with_attr("dataset", "Codeberg")
    .with_attr("profile_url", profile_url(login))
    .with_optional_attrs([
        ("account_id", id.as_deref()),
        ("created", nonblank(account.created.as_deref())),
        ("followers_count", followers.as_deref()),
        ("following_count", following.as_deref()),
        ("starred_repos_count", starred.as_deref()),
        ("full_name", nonblank(account.full_name.as_deref())),
        ("location", nonblank(account.location.as_deref())),
        ("website", nonblank(account.website.as_deref())),
        ("description", nonblank(account.description.as_deref())),
    ])
}

/// Build the report entities from the confirmed account. **Pure.**
fn build_entities(account: &Account, scan_id: &str) -> Vec<Entity> {
    let login = account.login.trim();
    let evidence = account_evidence(account, scan_id);
    let mut entities = Vec::new();
    push_entity(
        &mut entities,
        EntityKind::Username,
        login,
        USERNAME_CONF,
        scan_id,
        evidence.clone(),
        &["codeberg", "code"],
    );
    push_entity(
        &mut entities,
        EntityKind::Url,
        &profile_url(login),
        PROFILE_URL_CONF,
        scan_id,
        evidence.clone(),
        &["codeberg", "code"],
    );
    // A display name of two or more words reads as a person's; a single token stays evidence.
    if let Some(name) =
        nonblank(account.full_name.as_deref()).filter(|n| n.split_whitespace().count() >= 2)
    {
        push_entity(
            &mut entities,
            EntityKind::Person,
            name,
            SELF_REPORTED_CONF,
            scan_id,
            evidence.clone(),
            &["codeberg", "self-reported"],
        );
    }
    if let Some(email) = public_email(account) {
        push_entity(
            &mut entities,
            EntityKind::Email,
            &email,
            SELF_REPORTED_CONF,
            scan_id,
            evidence.clone(),
            &["codeberg", "self-reported"],
        );
    }
    if let Some(website) =
        nonblank(account.website.as_deref()).filter(|url| canonical_url(url).is_some())
    {
        push_entity(
            &mut entities,
            EntityKind::Url,
            website,
            SELF_REPORTED_CONF,
            scan_id,
            evidence.clone(),
            &["codeberg", "self-reported"],
        );
        if let Some((kind, host)) = crate::entity::link_host(website) {
            if !crate::domains::is_code_forge_host(&host) {
                push_entity(
                    &mut entities,
                    kind,
                    &host,
                    DOMAIN_CONF,
                    scan_id,
                    evidence,
                    &["codeberg", crate::tags::DERIVED],
                );
            }
        }
    }
    entities
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{OneResponse, ScriptedTransport, json_ok};

    /// Captured from `codeberg.org/api/v1/users/forgejo` on 2026-11-04.
    const FORGEJO: &str = r#"{"id":70422,"login":"forgejo","login_name":"","source_id":0,"full_name":"Forgejo","email":"forgejo@noreply.codeberg.org","avatar_url":"https://codeberg.org/avatars/dae8ab126a96f6fbd6942cf08ab92382","html_url":"https://codeberg.org/forgejo","language":"","is_admin":false,"last_login":"0001-01-01T00:00:00Z","created":"2022-11-06T07:18:11+01:00","restricted":false,"active":false,"prohibit_login":false,"location":"","pronouns":"","website":"https://forgejo.org","description":"Beyond coding. We forge.","visibility":"public","followers_count":641,"following_count":0,"starred_repos_count":0,"username":"forgejo"}"#;

    fn report_of(body: &str, handle: &str) -> Report {
        let transport = ScriptedTransport::new(vec![Ok(json_ok(body))]);
        lookup(&transport, handle, "scan-cb", 1).expect("lookup runs")
    }

    fn has(report: &Report, kind: &EntityKind, value: &str) -> bool {
        report
            .entities
            .iter()
            .any(|entity| entity.kind == *kind && entity.raw_value == value)
    }

    fn attr<'a>(report: &'a Report, key: &str) -> Option<&'a str> {
        report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Username)
            .and_then(|e| e.evidence.first())
            .and_then(|ev| ev.attributes.get(key))
            .map(String::as_str)
    }

    #[test]
    fn valid_handle_accepts_forgejo_logins_only() {
        assert!(valid_handle("forgejo"));
        assert!(valid_handle("ada.lovelace_1-x"));
        assert!(!valid_handle(""));
        assert!(!valid_handle(".hidden"));
        assert!(!valid_handle("a..b"));
        assert!(!valid_handle("has space"));
        assert!(!valid_handle("../etc"));
        assert!(!valid_handle(&"x".repeat(41)));
    }

    #[test]
    fn the_urls_carry_the_handle() {
        assert_eq!(
            user_url("forgejo"),
            "https://codeberg.org/api/v1/users/forgejo"
        );
        assert_eq!(profile_url("forgejo"), "https://codeberg.org/forgejo");
    }

    #[test]
    fn a_confirmed_account_emits_username_profile_website_and_domain() {
        let report = report_of(FORGEJO, "forgejo");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(has(&report, &EntityKind::Username, "forgejo"));
        assert!(has(
            &report,
            &EntityKind::Url,
            "https://codeberg.org/forgejo"
        ));
        assert!(has(&report, &EntityKind::Url, "https://forgejo.org"));
        assert!(has(&report, &EntityKind::Domain, "forgejo.org"));
        // A single-token display name is evidence, never a Person.
        assert!(!report.entities.iter().any(|e| e.kind == EntityKind::Person));
        // The noreply placeholder is never an e-mail lead.
        assert!(!report.entities.iter().any(|e| e.kind == EntityKind::Email));
        assert_eq!(attr(&report, "followers_count"), Some("641"));
        assert_eq!(attr(&report, "created"), Some("2022-11-06T07:18:11+01:00"));
        assert_eq!(
            attr(&report, "description"),
            Some("Beyond coding. We forge.")
        );
        assert_eq!(attr(&report, "location"), None);
    }

    #[test]
    fn a_public_address_and_full_name_are_self_reported_leads() {
        let body = r#"{"login":"Ada","full_name":"Ada Lovelace","email":"ada@example.org","website":"https://codeberg.org/ada"}"#;
        let report = report_of(body, "ada");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(report.entities.iter().any(|e| e.kind == EntityKind::Person
            && e.raw_value == "Ada Lovelace"
            && e.has_tag("self-reported")));
        assert!(report.entities.iter().any(|e| e.kind == EntityKind::Email
            && e.raw_value == "ada@example.org"
            && e.has_tag("self-reported")));
        // A website on the forge itself is a Url, but its host is no Domain pivot.
        assert!(!report.entities.iter().any(|e| e.kind == EntityKind::Domain));
    }

    #[test]
    fn an_unknown_account_is_a_clean_negative() {
        let transport =
            OneResponse::with_headers(404, &[], r#"{"message":"user redirect does not exist"}"#);
        let report = lookup(&transport, "zz-nobody", "scan-cb", 1).expect("lookup runs");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn a_payload_for_a_different_account_is_semantic_drift() {
        let report = report_of(r#"{"login":"someone_else"}"#, "forgejo");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SemanticDrift);
    }

    #[test]
    fn a_payload_without_a_login_is_schema_drift() {
        let report = report_of(r#"{"id":5}"#, "forgejo");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn an_invalid_handle_never_reaches_the_network() {
        let transport = ScriptedTransport::new(vec![]);
        let report = lookup(&transport, "bad handle", "scan-cb", 1).expect("lookup runs");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Inconclusive);
    }
}
