//! DEV Community account lookup for a username selector. Keyless -- the public Forem user API
//! dev.to serves at `https://dev.to/api/users/by_username?url={username}`.
//!
//! One handle resolves to the DEV account. DEV usernames are lower-case and the API matches them
//! case-sensitively (a capitalised handle is a `404`), so the handle is lower-cased before the
//! request, and the account is confirmed only when the returned `username` is that handle. A
//! `404` read as a plain upstream 4xx is the clean "no such account" answer; a challenge page at
//! that status is a wall, not a zero; a body that is not the account document is schema or
//! semantic drift.
//!
//! The account keeps its public profile `Url`, join date, location and self-written summary as
//! verbatim evidence. Its self-declared name (two or more words) is a `Person` candidate, its
//! website a `Url` and that host a `Domain` pivot, and the GitHub and X/Twitter handles it links
//! are cross-platform `Username` leads, the linked-account extraction Maigret performs. Each is
//! self-reported: a candidate to review, never a confirmed link or identity.

use serde::Deserialize;

use crate::canonical::canonical_url;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::github_user::valid_login_shape as valid_github_handle;
use crate::http::{Request, Transport, percent_encode_unreserved};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SRC: &str = "devto_user";
const API_BASE: &str = "https://dev.to";

/// DEV usernames are 1-30 characters: a lower-case ASCII letter, digit or underscore.
const MAX_HANDLE_LEN: usize = 30;
/// X/Twitter handles are 1-15 characters: an ASCII letter, digit or underscore.
const MAX_TWITTER_LEN: usize = 15;

/// Confirmed-on-DEV handle: a single-source, keyless account-existence lead.
const USERNAME_CONF: f64 = 0.80;
/// The public profile page.
const PROFILE_URL_CONF: f64 = 0.74;
/// A self-declared name, website or linked account: a candidate lead.
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
    username: String,
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    website_url: Option<String>,
    #[serde(default)]
    joined_at: Option<String>,
    #[serde(default)]
    github_username: Option<String>,
    #[serde(default)]
    twitter_username: Option<String>,
}

/// Whether `handle` is a shape DEV keys an account on. **Pure.**
#[must_use]
pub fn valid_handle(handle: &str) -> bool {
    !handle.is_empty()
        && handle.len() <= MAX_HANDLE_LEN
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Whether `handle` is a shape X/Twitter keys an account on. **Pure.**
fn valid_twitter_handle(handle: &str) -> bool {
    !handle.is_empty()
        && handle.len() <= MAX_TWITTER_LEN
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// The user API URL. **Pure.**
#[must_use]
pub fn user_url(handle: &str) -> String {
    format!(
        "{API_BASE}/api/users/by_username?url={}",
        percent_encode_unreserved(handle)
    )
}

/// The public profile page a human reads for a handle. **Pure.**
fn profile_url(handle: &str) -> String {
    format!("{API_BASE}/{}", percent_encode_unreserved(handle))
}

/// Look up one DEV Community account, keyless.
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
            "selector is not a valid DEV Community handle",
        )));
    }
    let fetched = fetch(
        transport,
        Request::get_json(user_url(&handle)),
        None,
        &FetchOptions::no_redirects().paced(),
        SRC,
        now_unix,
    )?;
    let (account, status) = match interpret_account(&fetched, &handle, now_unix) {
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
    let response = whole_response(fetched, "DEV user")?;
    answer(fetched, "DEV user")?;
    let account: Account = decode_json(response, SRC, now_unix, "DEV user")?;
    if account.username.trim().is_empty() {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "DEV payload carried no username",
        ));
    }
    if account.username.trim() != handle {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SemanticDrift,
            Some(response.status),
            "DEV returned a different account than the queried handle",
        ));
    }
    Ok((account, response.status))
}

fn nonblank(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

/// A linked handle without its leading `@`. **Pure.**
fn clean(value: Option<&str>) -> Option<&str> {
    nonblank(value).map(|handle| handle.trim_start_matches('@'))
}

fn account_evidence(account: &Account, scan_id: &str) -> Evidence {
    let login = account.username.trim();
    let id = account.id.map(|id| id.to_string());
    Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!(
            "DEV Community account {login}: a public developer-forum account, a candidate to review, not a confirmed identity"
        ),
    )
    .with_attr("dataset", "DEV Community")
    .with_attr("profile_url", profile_url(login))
    .with_optional_attrs([
        ("account_id", id.as_deref()),
        ("joined_at", nonblank(account.joined_at.as_deref())),
        ("name", nonblank(account.name.as_deref())),
        ("location", nonblank(account.location.as_deref())),
        ("website", nonblank(account.website_url.as_deref())),
        ("summary", nonblank(account.summary.as_deref())),
        ("github_username", nonblank(account.github_username.as_deref())),
        ("twitter_username", nonblank(account.twitter_username.as_deref())),
    ])
}

/// Build the report entities from the confirmed account. **Pure.**
fn build_entities(account: &Account, scan_id: &str) -> Vec<Entity> {
    let login = account.username.trim();
    let evidence = account_evidence(account, scan_id);
    let mut entities = Vec::new();
    push_entity(
        &mut entities,
        EntityKind::Username,
        login,
        USERNAME_CONF,
        scan_id,
        evidence.clone(),
        &["devto", "forum"],
    );
    push_entity(
        &mut entities,
        EntityKind::Url,
        &profile_url(login),
        PROFILE_URL_CONF,
        scan_id,
        evidence.clone(),
        &["devto", "forum"],
    );
    if let Some(name) =
        nonblank(account.name.as_deref()).filter(|n| n.split_whitespace().count() >= 2)
    {
        push_entity(
            &mut entities,
            EntityKind::Person,
            name,
            SELF_REPORTED_CONF,
            scan_id,
            evidence.clone(),
            &["devto", "self-reported"],
        );
    }
    add_linked_accounts(account, scan_id, &evidence, &mut entities);
    if let Some(website) =
        nonblank(account.website_url.as_deref()).filter(|url| canonical_url(url).is_some())
    {
        push_entity(
            &mut entities,
            EntityKind::Url,
            website,
            SELF_REPORTED_CONF,
            scan_id,
            evidence.clone(),
            &["devto", "self-reported"],
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
                    &["devto", crate::tags::DERIVED],
                );
            }
        }
    }
    entities
}

/// The GitHub and X/Twitter handles the account links, as cross-platform `Username` leads tagged
/// with the platform and `self-reported`; a malformed handle is kept as evidence only. **Pure.**
fn add_linked_accounts(
    account: &Account,
    scan_id: &str,
    evidence: &Evidence,
    entities: &mut Vec<Entity>,
) {
    if let Some(github) =
        clean(account.github_username.as_deref()).filter(|h| valid_github_handle(h))
    {
        push_entity(
            entities,
            EntityKind::Username,
            github,
            SELF_REPORTED_CONF,
            scan_id,
            evidence.clone(),
            &["github", "self-reported", "linked-account"],
        );
    }
    if let Some(twitter) =
        clean(account.twitter_username.as_deref()).filter(|h| valid_twitter_handle(h))
    {
        push_entity(
            entities,
            EntityKind::Username,
            twitter,
            SELF_REPORTED_CONF,
            scan_id,
            evidence.clone(),
            &["twitter", "self-reported", "linked-account"],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{OneResponse, ScriptedTransport, json_ok};

    /// Captured from `dev.to/api/users/by_username?url=ben` on 2026-11-04.
    const BEN: &str = r#"{"type_of":"user","id":1,"username":"ben","name":"Ben Halpern","twitter_username":"bendhalpern","github_username":"benhalpern","summary":"A Canadian software developer who thinks he’s funny.","location":"NY","website_url":"http://benhalpern.com","joined_at":"Dec 27, 2015","profile_image":"https://media2.dev.to/x.png"}"#;

    fn report_of(body: &str, handle: &str) -> Report {
        let transport = ScriptedTransport::new(vec![Ok(json_ok(body))]);
        lookup(&transport, handle, "scan-dev", 1).expect("lookup runs")
    }

    fn tagged(report: &Report, kind: &EntityKind, value: &str, tag: &str) -> bool {
        report
            .entities
            .iter()
            .any(|e| e.kind == *kind && e.raw_value == value && e.has_tag(tag))
    }

    #[test]
    fn valid_handle_accepts_lower_case_dev_handles_only() {
        assert!(valid_handle("ben"));
        assert!(valid_handle("ada_lovelace42"));
        assert!(!valid_handle(""));
        assert!(!valid_handle("Ben"));
        assert!(!valid_handle("has-hyphen"));
        assert!(!valid_handle(&"x".repeat(31)));
        assert!(valid_twitter_handle("bendhalpern"));
        assert!(!valid_twitter_handle(&"x".repeat(16)));
        assert!(!valid_twitter_handle("bad-handle"));
    }

    #[test]
    fn the_urls_carry_the_handle() {
        assert_eq!(
            user_url("ben"),
            "https://dev.to/api/users/by_username?url=ben"
        );
        assert_eq!(profile_url("ben"), "https://dev.to/ben");
    }

    #[test]
    fn a_confirmed_account_emits_username_person_links_and_website() {
        let report = report_of(BEN, "Ben");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(tagged(&report, &EntityKind::Username, "ben", "devto"));
        assert!(tagged(
            &report,
            &EntityKind::Url,
            "https://dev.to/ben",
            "devto"
        ));
        assert!(tagged(
            &report,
            &EntityKind::Person,
            "Ben Halpern",
            "self-reported"
        ));
        // Linked accounts are self-reported cross-platform leads, never confirmed links.
        assert!(tagged(
            &report,
            &EntityKind::Username,
            "benhalpern",
            "github"
        ));
        assert!(tagged(
            &report,
            &EntityKind::Username,
            "benhalpern",
            "self-reported"
        ));
        assert!(tagged(
            &report,
            &EntityKind::Username,
            "bendhalpern",
            "twitter"
        ));
        assert!(tagged(
            &report,
            &EntityKind::Username,
            "bendhalpern",
            "linked-account"
        ));
        assert!(tagged(
            &report,
            &EntityKind::Url,
            "http://benhalpern.com",
            "self-reported"
        ));
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Domain && e.raw_value == "benhalpern.com")
        );
        let joined = report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.raw_value == "ben")
            .and_then(|e| e.evidence.first())
            .and_then(|ev| ev.attributes.get("joined_at"));
        assert_eq!(joined.map(String::as_str), Some("Dec 27, 2015"));
    }

    #[test]
    fn malformed_linked_handles_are_not_leads() {
        let body = r#"{"username":"ben","github_username":"-bad-","twitter_username":"way_too_long_for_x"}"#;
        let report = report_of(body, "ben");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(
            report
                .entities
                .iter()
                .filter(|e| e.kind == EntityKind::Username)
                .count(),
            1,
            "{:#?}",
            report.entities
        );
    }

    #[test]
    fn an_unknown_account_is_a_clean_negative() {
        let transport =
            OneResponse::with_headers(404, &[], r#"{"error":"not found","status":404}"#);
        let report = lookup(&transport, "zz_nobody", "scan-dev", 1).expect("lookup runs");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn a_payload_for_a_different_account_is_semantic_drift() {
        let report = report_of(r#"{"username":"someone_else"}"#, "ben");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SemanticDrift);
    }

    #[test]
    fn a_payload_without_a_username_is_schema_drift() {
        let report = report_of(r#"{"id":1}"#, "ben");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn an_invalid_handle_never_reaches_the_network() {
        let transport = ScriptedTransport::new(vec![]);
        let report = lookup(&transport, "bad-handle", "scan-dev", 1).expect("lookup runs");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Inconclusive);
    }
}
