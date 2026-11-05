//! Codewars account lookup for a username selector. Keyless -- the public user API Codewars
//! serves at `https://www.codewars.com/api/v1/users/{username}`.
//!
//! One handle resolves to the Codewars account. The API matches usernames case-sensitively (a
//! handle in another case is a `404`), so the account is confirmed only when the returned
//! `username` is exactly the queried handle. A `404` read as a plain upstream 4xx is the clean
//! "no such account" answer; a challenge page at that status is a wall, not a zero; a body that is
//! not the account document is schema or semantic drift.
//!
//! The account keeps its public profile `Url`, honor, overall rank, leaderboard position, clan and
//! completed-kata count as verbatim evidence. Its self-declared name (two or more words) is a
//! `Person` candidate: a lead to review, never proof of who controls the account.

use serde::Deserialize;

use crate::account_leg::{Absent, AccountLeg, HandleCase, Identity};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, push_entity};
use crate::error::Error;
use crate::http::{Request, Transport, percent_encode_unreserved};
use crate::textnorm::nonblank;

pub const SRC: &str = "codewars_user";
const API_BASE: &str = "https://www.codewars.com";

/// Codewars usernames are 1-64 characters: an ASCII letter, digit, hyphen or underscore.
const MAX_HANDLE_LEN: usize = 64;

/// Confirmed-on-Codewars handle: a single-source, keyless account-existence lead.
const USERNAME_CONF: f64 = 0.80;
/// The public profile page.
const PROFILE_URL_CONF: f64 = 0.74;
/// A self-declared name: a candidate lead.
const SELF_REPORTED_CONF: f64 = 0.55;

pub type Report = crate::account_leg::Report;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Account {
    #[serde(default)]
    username: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    honor: Option<i64>,
    #[serde(default)]
    clan: Option<String>,
    #[serde(default)]
    leaderboard_position: Option<u64>,
    #[serde(default)]
    ranks: Option<Ranks>,
    #[serde(default)]
    code_challenges: Option<Challenges>,
}

#[derive(Debug, Deserialize)]
struct Ranks {
    #[serde(default)]
    overall: Option<Rank>,
}

#[derive(Debug, Deserialize)]
struct Rank {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Challenges {
    #[serde(default)]
    total_completed: Option<u64>,
}

/// Whether `handle` is a shape Codewars keys an account on. **Pure.**
#[must_use]
pub fn valid_handle(handle: &str) -> bool {
    !handle.is_empty()
        && handle.len() <= MAX_HANDLE_LEN
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
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
    format!("{API_BASE}/users/{}", percent_encode_unreserved(handle))
}

/// This leg's messages and rules on the shared account-leg path.
const LEG: AccountLeg = AccountLeg {
    source: SRC,
    document: "Codewars user",
    invalid: "selector is not a valid Codewars handle",
    no_identity: "Codewars payload carried no username",
    other_account: "Codewars returned a different account than the queried handle",
    handle_case: HandleCase::AsTyped,
    identity: Identity::Exact,
    absent: Absent::NotFound,
};

/// Look up one Codewars account, keyless.
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses the account URL.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let handle = match LEG.handle(username, valid_handle, now_unix) {
        Ok(handle) => handle,
        Err(outcome) => return Ok(Report::miss(outcome)),
    };
    let found = LEG.fetch(
        transport,
        Request::get_json(user_url(&handle)),
        &handle,
        |account: &Account| account.username.as_str(),
        now_unix,
    )?;
    let (account, status) = match found {
        Ok(found) => found,
        Err(outcome) => return Ok(Report::miss(outcome)),
    };
    Ok(Report::found(
        SRC,
        build_entities(&account, scan_id),
        status,
        now_unix,
    ))
}

/// Build the report entities from the confirmed account. **Pure.**
fn build_entities(account: &Account, scan_id: &str) -> Vec<Entity> {
    let login = account.username.trim();
    let honor = account.honor.map(|n| n.to_string());
    let position = account.leaderboard_position.map(|n| n.to_string());
    let completed = account
        .code_challenges
        .as_ref()
        .and_then(|c| c.total_completed)
        .map(|n| n.to_string());
    let rank = account
        .ranks
        .as_ref()
        .and_then(|r| r.overall.as_ref())
        .and_then(|r| nonblank(r.name.as_deref()));
    // Codewars reports a missing clan as the literal "None".
    let clan = nonblank(account.clan.as_deref()).filter(|c| !c.eq_ignore_ascii_case("none"));
    let evidence = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!(
            "Codewars account {login}: a public coding-practice account, a candidate to review, not a confirmed identity"
        ),
    )
    .with_attr("dataset", "Codewars")
    .with_attr("profile_url", profile_url(login))
    .with_optional_attrs([
        ("name", nonblank(account.name.as_deref())),
        ("honor", honor.as_deref()),
        ("overall_rank", rank),
        ("leaderboard_position", position.as_deref()),
        ("clan", clan),
        ("completed_kata", completed.as_deref()),
    ]);

    let mut entities = Vec::new();
    push_entity(
        &mut entities,
        EntityKind::Username,
        login,
        USERNAME_CONF,
        scan_id,
        evidence.clone(),
        &["codewars", "code"],
    );
    push_entity(
        &mut entities,
        EntityKind::Url,
        &profile_url(login),
        PROFILE_URL_CONF,
        scan_id,
        evidence.clone(),
        &["codewars", "code"],
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
            evidence,
            &["codewars", "self-reported"],
        );
    }
    entities
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_outcome::SourceOutcomeKind;
    use crate::test_support::{OneResponse, ScriptedTransport, json_ok};

    /// Trimmed from `www.codewars.com/api/v1/users/g964` on 2026-11-04.
    const G964: &str = r#"{"id":"545207bac8e60b30fc000942","username":"g964","name":"","honor":489606,"clan":"None","leaderboardPosition":1,"skills":[],"ranks":{"overall":{"rank":-1,"name":"1 kyu","color":"purple","score":30497}},"codeChallenges":{"totalAuthored":3,"totalCompleted":7000}}"#;

    fn report_of(body: &str, handle: &str) -> Report {
        let transport = ScriptedTransport::new(vec![Ok(json_ok(body))]);
        lookup(&transport, handle, "scan-cw", 1).expect("lookup runs")
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
    fn valid_handle_accepts_codewars_handles_only() {
        assert!(valid_handle("g964"));
        assert!(valid_handle("Ada_Lovelace-1"));
        assert!(!valid_handle(""));
        assert!(!valid_handle("has space"));
        assert!(!valid_handle("../etc"));
        assert!(!valid_handle(&"x".repeat(65)));
    }

    #[test]
    fn the_urls_carry_the_handle() {
        assert_eq!(
            user_url("g964"),
            "https://www.codewars.com/api/v1/users/g964"
        );
        assert_eq!(profile_url("g964"), "https://www.codewars.com/users/g964");
    }

    #[test]
    fn a_confirmed_account_emits_username_profile_and_evidence() {
        let report = report_of(G964, "g964");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Username && e.raw_value == "g964")
        );
        assert!(
            report.entities.iter().any(|e| e.kind == EntityKind::Url
                && e.raw_value == "https://www.codewars.com/users/g964")
        );
        // A blank name is no Person, and the literal "None" clan is no clan.
        assert!(!report.entities.iter().any(|e| e.kind == EntityKind::Person));
        assert_eq!(attr(&report, "clan"), None);
        assert_eq!(attr(&report, "honor"), Some("489606"));
        assert_eq!(attr(&report, "overall_rank"), Some("1 kyu"));
        assert_eq!(attr(&report, "leaderboard_position"), Some("1"));
        assert_eq!(attr(&report, "completed_kata"), Some("7000"));
    }

    #[test]
    fn a_two_word_name_is_a_self_reported_person() {
        let report = report_of(
            r#"{"username":"ada","name":"Ada Lovelace","clan":"Analytical"}"#,
            "ada",
        );
        assert!(report.entities.iter().any(|e| e.kind == EntityKind::Person
            && e.raw_value == "Ada Lovelace"
            && e.has_tag("self-reported")));
        assert_eq!(attr(&report, "clan"), Some("Analytical"));
    }

    #[test]
    fn an_unknown_account_is_a_clean_negative() {
        let transport =
            OneResponse::with_headers(404, &[], r#"{"success":false,"reason":"not found"}"#);
        let report = lookup(&transport, "zz_nobody", "scan-cw", 1).expect("lookup runs");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn a_different_case_echo_is_semantic_drift() {
        // The API is case-sensitive, so an echo in another case is not the queried account.
        let report = report_of(r#"{"username":"G964"}"#, "g964");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SemanticDrift);
    }

    #[test]
    fn a_payload_without_a_username_is_schema_drift() {
        let report = report_of(r#"{"honor":5}"#, "g964");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }
}
