//! Lobsters account lookup for a username selector. Keyless -- the public per-user JSON the site
//! serves at `https://lobste.rs/~{username}.json`.
//!
//! One handle resolves to the Lobsters account. Lobsters usernames are case-insensitive (the site
//! redirects a non-canonical case to the lower-case canonical form), so the engine's case-folded
//! selector resolves the account, and it is confirmed only when the returned `username` is the
//! queried handle, never a near-match. A `404` read as a plain upstream 4xx is the clean "no such
//! account" answer; a challenge page at that status is a wall, not a zero; a body that is not the
//! account document is schema or semantic drift, never a fabricated account.
//!
//! The account keeps its public profile `Url` (`lobste.rs/~`), its self-declared `github_username`
//! as a cross-platform `Username` lead -- a candidate the relation layer ties to the `github_user`
//! cohort, never a confirmed link -- and its karma, join date and self-written `about` bio as
//! verbatim evidence.
//!
//! This wires the previously dangling `lobsters` source id into the correlator's `forum` family,
//! beside `hacker_news` and `reddit_user`.

use serde::Deserialize;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{DEFAULT_USER_AGENT, Request, Transport, percent_encode_unreserved};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::textnorm::decode_html_entities;

pub const SRC: &str = "lobsters";
const API_BASE: &str = "https://lobste.rs";

/// Lobsters usernames are 1-25 characters: an ASCII letter, digit, underscore or hyphen.
const MIN_HANDLE_LEN: usize = 1;
const MAX_HANDLE_LEN: usize = 25;

/// Confirmed-on-Lobsters handle: a single-source, keyless account-existence lead.
const USERNAME_CONF: f64 = 0.80;
/// The public profile page the account authenticates nothing through.
const PROFILE_URL_CONF: f64 = 0.74;
/// A GitHub handle the account self-declares in its profile: a candidate cross-platform lead.
const GITHUB_LINK_CONF: f64 = 0.55;

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug, Deserialize)]
struct LobstersUser {
    #[serde(default)]
    username: String,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    karma: Option<i64>,
    #[serde(default)]
    about: Option<String>,
    #[serde(default)]
    github_username: Option<String>,
    #[serde(default)]
    is_admin: Option<bool>,
    #[serde(default)]
    is_moderator: Option<bool>,
}

/// Whether `handle` is a shape Lobsters keys an account on: 1-25 characters, each an ASCII letter,
/// digit, hyphen or underscore. **Pure.**
#[must_use]
pub fn valid_handle(handle: &str) -> bool {
    handle.len() >= MIN_HANDLE_LEN
        && handle.len() <= MAX_HANDLE_LEN
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// Whether `handle` is a plausible GitHub username: 1-39 ASCII letters, digits or single interior
/// hyphens. A self-declared handle outside this shape is junk, not a lead. **Pure.**
#[must_use]
fn valid_github_handle(handle: &str) -> bool {
    !handle.is_empty()
        && handle.len() <= 39
        && !handle.starts_with('-')
        && !handle.ends_with('-')
        && !handle.contains("--")
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// The `~{username}.json` URL. **Pure.**
#[must_use]
pub fn user_url(handle: &str) -> String {
    format!("{API_BASE}/~{}.json", percent_encode_unreserved(handle))
}

/// The public profile page a human reads for a handle. **Pure.**
fn profile_url(handle: &str) -> String {
    format!("{API_BASE}/~{}", percent_encode_unreserved(handle))
}

fn request(url: String) -> Request {
    Request::get(url)
        .header("accept", "application/json")
        .header("user-agent", DEFAULT_USER_AGENT)
}

/// Look up one Lobsters account, keyless.
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses the account URL.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    // Lobsters usernames are case-insensitive and lower-case canonical: an uppercase path 302-
    // redirects, which the no-redirects fetch treats as a wall. Lower-case in-module so a direct
    // mixed-case caller resolves the account too, as the crates_io and keybase legs do; the live
    // fan-out already hands this leg the engine's canonical lower-case form.
    let handle = username.trim().trim_start_matches('@').to_ascii_lowercase();
    if !valid_handle(&handle) {
        return Ok(miss(SourceExecutionOutcome::inconclusive(
            SRC,
            now_unix,
            "selector is not a valid Lobsters handle",
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
    let mut entities = build_entities(&user, scan_id);
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
/// no such account or a different one. A `404` read as a plain upstream 4xx is the clean negative;
/// a challenge page at that status is a wall, not a zero. Lobsters usernames are case-insensitive,
/// so the returned `username` is matched to the queried handle without regard to case. **Pure.**
fn interpret_user(
    fetched: &Fetched,
    handle: &str,
    now_unix: u64,
) -> Result<(LobstersUser, u16), SourceExecutionOutcome> {
    if let Some(response) = &fetched.response {
        if response.status == 404 && fetched.outcome.kind == SourceOutcomeKind::Upstream4xx {
            return Err(
                SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(response.status)
            );
        }
    }
    let response = whole_response(fetched, "Lobsters user")?;
    answer(fetched, "Lobsters user")?;
    let user: LobstersUser = decode_json(response, SRC, now_unix, "Lobsters user")?;
    if user.username.trim().is_empty() {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "Lobsters payload carried no username",
        ));
    }
    if !user.username.trim().eq_ignore_ascii_case(handle) {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SemanticDrift,
            Some(response.status),
            "Lobsters returned a different account than the queried handle",
        ));
    }
    Ok((user, response.status))
}

/// Build the report entities from the confirmed account. **Pure** (no network/IO), so the
/// account -> entity mapping is unit-testable off JSON fixtures.
fn build_entities(user: &LobstersUser, scan_id: &str) -> Vec<Entity> {
    let mut entities = Vec::new();
    add_account(user, scan_id, &mut entities);
    add_github_link(user, scan_id, &mut entities);
    entities
}

/// The confirmed account: its `Username` and public profile `Url`, with karma, join date, any
/// admin/moderator role and the verbatim decoded `about` bio kept as evidence. **Pure.**
fn add_account(user: &LobstersUser, scan_id: &str, entities: &mut Vec<Entity>) {
    let id = user.username.trim();
    let about = user
        .about
        .as_deref()
        .map(decode_html_entities)
        .map(|bio| bio.trim().to_owned())
        .filter(|bio| !bio.is_empty());
    let created = user
        .created_at
        .as_deref()
        .map(str::trim)
        .filter(|date| !date.is_empty());
    let karma = user.karma.map(|points| points.to_string());
    let role = if user.is_admin == Some(true) {
        Some("admin")
    } else if user.is_moderator == Some(true) {
        Some("moderator")
    } else {
        None
    };

    let evidence = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!(
            "Lobsters account {id}: a public forum account, a candidate to review, not a confirmed identity"
        ),
    )
    .with_attr("dataset", "Lobsters")
    .with_attr("profile_url", profile_url(id))
    .with_optional_attrs([
        ("karma", karma.as_deref()),
        ("created_at", created),
        ("role", role),
        ("about", about.as_deref()),
    ]);

    push_entity(
        entities,
        EntityKind::Username,
        id,
        USERNAME_CONF,
        scan_id,
        evidence.clone(),
        &["lobsters", "forum"],
    );
    push_entity(
        entities,
        EntityKind::Url,
        &profile_url(id),
        PROFILE_URL_CONF,
        scan_id,
        evidence,
        &["lobsters", "forum"],
    );
}

/// The account's self-declared GitHub handle as a cross-platform `Username` lead the relation layer
/// ties to the `github_user` cohort -- a candidate to review, never a confirmed link. **Pure.**
fn add_github_link(user: &LobstersUser, scan_id: &str, entities: &mut Vec<Entity>) {
    let Some(github) = user
        .github_username
        .as_deref()
        .map(|handle| handle.trim().trim_start_matches('@'))
        .filter(|handle| valid_github_handle(handle))
    else {
        return;
    };
    let evidence = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!(
            "GitHub handle self-declared on the Lobsters profile of {}: a candidate cross-platform lead, not a confirmed link",
            user.username.trim()
        ),
    )
    .with_attr("dataset", "Lobsters")
    .with_attr("declared_on", profile_url(user.username.trim()));
    push_entity(
        entities,
        EntityKind::Username,
        github,
        GITHUB_LINK_CONF,
        scan_id,
        evidence,
        &["github", "self-reported"],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{OneResponse, ScriptedTransport, json_ok};

    const USER: &str = r#"{"username":"jcs","created_at":"2012-06-30T16:39:19.000-05:00","is_admin":true,"is_moderator":true,"karma":16905,"about":"<p>hello, cyberpals</p>","avatar_url":"/avatars/jcs-100.png","invited_by_user":null,"github_username":"jcs"}"#;

    fn report_of(body: &str, handle: &str) -> Report {
        let transport = ScriptedTransport::new(vec![Ok(json_ok(body))]);
        lookup(&transport, handle, "scan-lob", 1).expect("lookup runs")
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
            .find(|e| e.kind == EntityKind::Username && e.raw_value == "jcs")
            .and_then(|e| e.evidence.first())
            .and_then(|ev| ev.attributes.get(key))
            .map(String::as_str)
    }

    #[test]
    fn valid_handle_accepts_lobsters_shaped_ids() {
        assert!(valid_handle("jcs"));
        assert!(valid_handle("ada_lovelace"));
        assert!(valid_handle("rhino-ryno23"));
        assert!(!valid_handle("")); // empty
        assert!(!valid_handle(&"x".repeat(26))); // too long
        assert!(!valid_handle("has space"));
        assert!(!valid_handle("../etc"));
    }

    #[test]
    fn valid_github_handle_rejects_junk() {
        assert!(valid_github_handle("jcs"));
        assert!(valid_github_handle("Octo-Cat"));
        assert!(!valid_github_handle(""));
        assert!(!valid_github_handle("-leading"));
        assert!(!valid_github_handle("trailing-"));
        assert!(!valid_github_handle("double--hyphen"));
        assert!(!valid_github_handle("under_score"));
        assert!(!valid_github_handle(&"x".repeat(40)));
    }

    #[test]
    fn the_user_url_and_profile_url_carry_the_handle() {
        assert_eq!(user_url("jcs"), "https://lobste.rs/~jcs.json");
        assert_eq!(profile_url("jcs"), "https://lobste.rs/~jcs");
    }

    #[test]
    fn a_confirmed_account_emits_username_profile_github_and_evidence() {
        let report = report_of(USER, "jcs");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(has(&report, &EntityKind::Username, "jcs"));
        assert!(has(&report, &EntityKind::Url, "https://lobste.rs/~jcs"));
        // The self-declared GitHub handle is a cross-platform lead, tagged github + self-reported.
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Username
                    && e.raw_value == "jcs"
                    && e.has_tag("github")
                    && e.has_tag("self-reported")),
            "{:#?}",
            report.entities
        );
        // Karma, join date, role and the decoded bio are kept verbatim as evidence.
        assert_eq!(account_attr(&report, "karma"), Some("16905"));
        assert_eq!(
            account_attr(&report, "created_at"),
            Some("2012-06-30T16:39:19.000-05:00")
        );
        assert_eq!(account_attr(&report, "role"), Some("admin"));
        assert!(
            account_attr(&report, "about").is_some_and(|bio| bio.contains("cyberpals")),
            "{:#?}",
            report.entities
        );
    }

    #[test]
    fn a_case_insensitive_echo_still_confirms_the_queried_handle() {
        // The engine queries lower-case; a response echoing a different case is the same account
        // (Lobsters is case-insensitive), so it confirms rather than drifting.
        let body = r#"{"username":"JCS","karma":1}"#;
        let report = report_of(body, "jcs");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(has(&report, &EntityKind::Username, "JCS"));
    }

    #[test]
    fn an_unknown_account_is_a_clean_negative() {
        let transport = OneResponse::with_headers(404, &[], "");
        let report = lookup(&transport, "nobody-xyz", "scan-lob", 1).expect("lookup runs");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn a_payload_for_a_different_account_is_semantic_drift() {
        let report = report_of(r#"{"username":"someone_else","karma":1}"#, "jcs");
        assert!(report.entities.is_empty(), "{:#?}", report.entities);
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SemanticDrift);
    }

    #[test]
    fn a_payload_without_a_username_is_schema_drift() {
        let report = report_of(r#"{"karma":5}"#, "jcs");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn an_account_without_a_github_handle_emits_only_the_account() {
        let report = report_of(r#"{"username":"quiet","karma":1}"#, "quiet");
        assert!(has(&report, &EntityKind::Username, "quiet"));
        // The only Username entity is the account itself; no self-reported github lead.
        assert!(
            !report
                .entities
                .iter()
                .any(|e| e.has_tag("github") && e.has_tag("self-reported"))
        );
    }

    #[test]
    fn a_junk_github_handle_is_dropped() {
        let report = report_of(
            r#"{"username":"dev","karma":1,"github_username":"not a handle"}"#,
            "dev",
        );
        assert!(has(&report, &EntityKind::Username, "dev"));
        assert!(
            !report
                .entities
                .iter()
                .any(|e| e.has_tag("github") && e.has_tag("self-reported"))
        );
    }

    #[test]
    fn a_github_handle_with_a_leading_at_is_stripped_and_kept() {
        // `@octocat` is a real self-declared handle, not junk: strip the `@` and keep the lead.
        let report = report_of(
            r#"{"username":"dev","karma":1,"github_username":"@octocat"}"#,
            "dev",
        );
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Username
                    && e.raw_value == "octocat"
                    && e.has_tag("github")
                    && e.has_tag("self-reported")),
            "{:#?}",
            report.entities
        );
    }

    #[test]
    fn the_lookup_lower_cases_a_mixed_case_handle_for_the_case_insensitive_site() {
        // A direct mixed-case caller must still reach the lower-case canonical path (an uppercase
        // `~JCS.json` would 302-redirect and fail closed under no-redirects).
        let transport =
            ScriptedTransport::new(vec![Ok(json_ok(r#"{"username":"jcs","karma":1}"#))]);
        lookup(&transport, "JCS", "scan-lob", 1).expect("lookup runs");
        let asked = &transport.seen.borrow()[0].url;
        assert!(asked.contains("/~jcs.json"), "{asked}");
    }
}
