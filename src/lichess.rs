//! Lichess account lookup for a username selector. Keyless -- the public user document the site
//! serves at `https://lichess.org/api/user/{username}`.
//!
//! One handle resolves to the Lichess account. Usernames are case-insensitive: the document's `id`
//! is the lower-case canonical form and `username` the display case, so the account is confirmed
//! only when `id` is the queried handle, never a near-match. A `404` read as a plain upstream 4xx
//! is the clean "no such user" answer (`{"error":"Not found"}`); a challenge page at that status
//! is a wall, not a zero; a body that is not the user document is schema or semantic drift, never a
//! fabricated account.
//!
//! The account keeps its public profile `Url`, the real name it self-declares as a `Person`
//! candidate, each absolute link it self-declares as a `Url` lead, and its title, creation and
//! last-seen times, play time, game count, patron/verified flags, closed or ToS-violation state,
//! bio, location and country flag as verbatim evidence. Nothing here confirms who holds the account.

use serde::Deserialize;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport, percent_encode_unreserved};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::textnorm::nonblank;

pub const SRC: &str = "lichess";
const API_BASE: &str = "https://lichess.org";

/// Lichess usernames are 2-20 characters: an ASCII letter, digit, underscore or hyphen.
const MIN_HANDLE_LEN: usize = 2;
const MAX_HANDLE_LEN: usize = 20;
/// How many self-declared links are kept as leads.
const MAX_LINKS: usize = 8;

/// Confirmed-on-Lichess handle: a single-source, keyless account-existence lead.
const USERNAME_CONF: f64 = 0.80;
/// The public profile page the account authenticates nothing through.
const PROFILE_URL_CONF: f64 = 0.74;
/// A name or link the account self-declares: a candidate lead, never a confirmed link.
const SELF_DECLARED_CONF: f64 = 0.55;

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug, Deserialize)]
struct User {
    #[serde(default)]
    id: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default, rename = "createdAt")]
    created_at_ms: Option<u64>,
    #[serde(default, rename = "seenAt")]
    seen_at_ms: Option<u64>,
    #[serde(default, rename = "playTime")]
    play_time: Option<PlayTime>,
    #[serde(default)]
    count: Option<Count>,
    #[serde(default)]
    patron: Option<bool>,
    #[serde(default)]
    verified: Option<bool>,
    #[serde(default)]
    disabled: Option<bool>,
    #[serde(default, rename = "tosViolation")]
    tos_violation: Option<bool>,
    #[serde(default)]
    flair: Option<String>,
    #[serde(default)]
    profile: Option<Profile>,
}

#[derive(Debug, Default, Deserialize)]
struct PlayTime {
    #[serde(default)]
    total: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct Count {
    #[serde(default)]
    all: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct Profile {
    #[serde(default)]
    bio: Option<String>,
    #[serde(default, rename = "realName")]
    real_name: Option<String>,
    #[serde(default)]
    links: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    flag: Option<String>,
}

/// Whether `handle` is a shape Lichess keys an account on: 2-20 characters, each an ASCII letter,
/// digit, hyphen or underscore. **Pure.**
#[must_use]
pub fn valid_handle(handle: &str) -> bool {
    handle.len() >= MIN_HANDLE_LEN
        && handle.len() <= MAX_HANDLE_LEN
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// The `/api/user/{username}` URL. **Pure.**
#[must_use]
pub fn user_url(handle: &str) -> String {
    format!("{API_BASE}/api/user/{}", percent_encode_unreserved(handle))
}

/// The public profile page a human reads for a handle. **Pure.**
fn profile_url(handle: &str) -> String {
    format!("{API_BASE}/@/{}", percent_encode_unreserved(handle))
}

/// Look up one Lichess account, keyless.
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses the user URL.
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
            "selector is not a valid Lichess username",
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

fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

/// The confirmed user, with the response status; `Err` is the outcome of a response that named no
/// such user or a different one. The canonical `id` is matched, so display case is kept. **Pure.**
fn interpret_user(
    fetched: &Fetched,
    handle: &str,
    now_unix: u64,
) -> Result<(User, u16), SourceExecutionOutcome> {
    if let Some(response) = &fetched.response {
        if response.status == 404 && fetched.outcome.kind == SourceOutcomeKind::Upstream4xx {
            return Err(
                SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(response.status)
            );
        }
    }
    let response = whole_response(fetched, "Lichess user")?;
    answer(fetched, "Lichess user")?;
    let user: User = decode_json(response, SRC, now_unix, "Lichess user")?;
    if user.id.trim().is_empty() && user.username.trim().is_empty() {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "Lichess payload carried no user id",
        ));
    }
    let canonical = if user.id.trim().is_empty() {
        user.username.trim()
    } else {
        user.id.trim()
    };
    if !canonical.eq_ignore_ascii_case(handle) {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SemanticDrift,
            Some(response.status),
            "Lichess returned a different user than the queried handle",
        ));
    }
    Ok((user, response.status))
}

fn yes_no(flag: Option<bool>) -> Option<&'static str> {
    flag.map(|b| if b { "yes" } else { "no" })
}

/// The account's evidence: every public field of the document, verbatim. **Pure.**
fn account_evidence(user: &User, display: &str, profile: &str, scan_id: &str) -> Evidence {
    let empty = Profile::default();
    let about = user.profile.as_ref().unwrap_or(&empty);
    let created = user.created_at_ms.map(|n| n.to_string());
    let seen = user.seen_at_ms.map(|n| n.to_string());
    let play_time = user
        .play_time
        .as_ref()
        .and_then(|p| p.total)
        .map(|n| n.to_string());
    let games = user
        .count
        .as_ref()
        .and_then(|c| c.all)
        .map(|n| n.to_string());
    let links = nonblank(about.links.as_deref());
    Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!(
            "Lichess account {display}: a public game-site account, a candidate to review, not a confirmed identity"
        ),
    )
    .with_attr("dataset", "Lichess")
    .with_attr("profile_url", profile)
    .with_optional_attrs([
        ("title", nonblank(user.title.as_deref())),
        ("created_at_ms", created.as_deref()),
        ("seen_at_ms", seen.as_deref()),
        ("play_time_secs", play_time.as_deref()),
        ("games", games.as_deref()),
        ("patron", yes_no(user.patron)),
        ("verified", yes_no(user.verified)),
        ("closed", yes_no(user.disabled)),
        ("tos_violation", yes_no(user.tos_violation)),
        ("flair", nonblank(user.flair.as_deref())),
        ("bio", nonblank(about.bio.as_deref())),
        ("real_name", nonblank(about.real_name.as_deref())),
        ("location", nonblank(about.location.as_deref())),
        ("flag", nonblank(about.flag.as_deref())),
        ("links", links),
    ])
}

/// Build the report entities from the confirmed user. **Pure.**
fn build_entities(user: &User, scan_id: &str) -> Vec<Entity> {
    let display = nonblank(Some(&user.username)).unwrap_or(user.id.trim());
    let profile = nonblank(user.url.as_deref())
        .filter(|url| url.starts_with("https://"))
        .map_or_else(|| profile_url(display), str::to_owned);
    let empty = Profile::default();
    let about = user.profile.as_ref().unwrap_or(&empty);
    let links = nonblank(about.links.as_deref());
    let evidence = account_evidence(user, display, &profile, scan_id);
    let mut tags: Vec<&str> = vec!["lichess", "gaming"];
    if user.disabled == Some(true) {
        tags.push("closed");
    }
    let mut entities = Vec::new();
    push_entity(
        &mut entities,
        EntityKind::Username,
        display,
        USERNAME_CONF,
        scan_id,
        evidence.clone(),
        &tags,
    );
    push_entity(
        &mut entities,
        EntityKind::Url,
        &profile,
        PROFILE_URL_CONF,
        scan_id,
        evidence,
        &tags,
    );
    if let Some(name) = nonblank(about.real_name.as_deref()) {
        push_entity(
            &mut entities,
            EntityKind::Person,
            name,
            SELF_DECLARED_CONF,
            scan_id,
            Evidence::new(
                EvidenceProvenance::for_scan(SRC, scan_id),
                format!(
                    "Real name self-declared on the Lichess profile of {display}: a candidate, never a confirmed identity"
                ),
            )
            .with_attr("dataset", "Lichess")
            .with_attr("declared_on", profile.as_str()),
            &["lichess", "self-reported"],
        );
    }
    for link in links
        .into_iter()
        .flat_map(str::lines)
        .map(str::trim)
        .filter(|l| l.starts_with("https://") || l.starts_with("http://"))
        .take(MAX_LINKS)
    {
        push_entity(
            &mut entities,
            EntityKind::Url,
            link,
            SELF_DECLARED_CONF,
            scan_id,
            Evidence::new(
                EvidenceProvenance::for_scan(SRC, scan_id),
                format!(
                    "Link self-declared on the Lichess profile of {display}: a candidate cross-platform lead, not a confirmed link"
                ),
            )
            .with_attr("dataset", "Lichess")
            .with_attr("declared_on", profile.as_str()),
            &["lichess", "self-reported"],
        );
    }
    entities
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{OneResponse, ScriptedTransport, json_ok};

    /// Recorded from `GET /api/user/thibault` on 2026-11-03, shortened; the links line is the
    /// site's own newline-separated form.
    const USER: &str = "{\"id\":\"thibault\",\"username\":\"thibault\",\"perfs\":{\"blitz\":{\"games\":11924,\"rating\":1744}},\"flair\":\"symbols.transgender-flag\",\"patron\":true,\"verified\":true,\"createdAt\":1290415680000,\"profile\":{\"bio\":\"I also produce organic dog meat at https://www.elwooddogmeat.com/\",\"realName\":\"Thibault Duplessis\",\"links\":\"github.com/ornicar\\nhttps://mas.to/@thibault\"},\"seenAt\":1793746617972,\"playTime\":{\"total\":6701989,\"tv\":18024},\"url\":\"https://lichess.org/@/thibault\",\"count\":{\"all\":23933,\"rated\":21534}}";

    fn report_of(body: &str, handle: &str) -> Report {
        let transport = ScriptedTransport::new(vec![Ok(json_ok(body))]);
        lookup(&transport, handle, "scan-li", 1).expect("lookup runs")
    }

    fn account_attr<'a>(report: &'a Report, key: &str) -> Option<&'a str> {
        report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Username)
            .and_then(|e| e.evidence.first())
            .and_then(|ev| ev.attributes.get(key))
            .map(String::as_str)
    }

    #[test]
    fn valid_handle_accepts_lichess_shaped_ids() {
        assert!(valid_handle("thibault"));
        assert!(valid_handle("a_b-1"));
        assert!(!valid_handle("x"));
        assert!(!valid_handle(&"x".repeat(21)));
        assert!(!valid_handle("has space"));
    }

    #[test]
    fn the_urls_carry_the_handle() {
        assert_eq!(
            user_url("thibault"),
            "https://lichess.org/api/user/thibault"
        );
        assert_eq!(profile_url("thibault"), "https://lichess.org/@/thibault");
    }

    #[test]
    fn a_confirmed_user_emits_username_profile_name_links_and_evidence() {
        let report = report_of(USER, "Thibault");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        let has = |kind: EntityKind, value: &str| {
            report
                .entities
                .iter()
                .any(|e| e.kind == kind && e.raw_value == value)
        };
        assert!(has(EntityKind::Username, "thibault"));
        assert!(has(EntityKind::Url, "https://lichess.org/@/thibault"));
        assert!(has(EntityKind::Person, "Thibault Duplessis"));
        // Only an absolute link becomes a lead; the bare host path stays in the verbatim attribute.
        assert!(has(EntityKind::Url, "https://mas.to/@thibault"));
        assert!(!has(EntityKind::Url, "github.com/ornicar"));
        assert_eq!(
            account_attr(&report, "links"),
            Some("github.com/ornicar\nhttps://mas.to/@thibault")
        );
        assert_eq!(
            account_attr(&report, "created_at_ms"),
            Some("1290415680000")
        );
        assert_eq!(account_attr(&report, "play_time_secs"), Some("6701989"));
        assert_eq!(account_attr(&report, "games"), Some("23933"));
        assert_eq!(account_attr(&report, "patron"), Some("yes"));
        assert_eq!(account_attr(&report, "verified"), Some("yes"));
        assert_eq!(
            account_attr(&report, "real_name"),
            Some("Thibault Duplessis")
        );
        assert!(account_attr(&report, "closed").is_none());
    }

    #[test]
    fn a_closed_account_is_still_confirmed_and_tagged() {
        let report = report_of(r#"{"id":"gone","username":"Gone","disabled":true}"#, "gone");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Username && e.has_tag("closed"))
        );
        assert_eq!(account_attr(&report, "closed"), Some("yes"));
    }

    #[test]
    fn an_unknown_user_is_a_clean_negative() {
        let transport = OneResponse::with_headers(
            404,
            &[("content-type", "application/json")],
            r#"{"error":"Not found"}"#,
        );
        let report = lookup(&transport, "nobody-xyz", "scan-li", 1).expect("lookup runs");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn a_payload_for_a_different_user_is_semantic_drift() {
        let report = report_of(
            r#"{"id":"someone_else","username":"Someone_Else"}"#,
            "thibault",
        );
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SemanticDrift);
    }

    #[test]
    fn a_payload_without_an_id_is_schema_drift() {
        let report = report_of(r#"{"perfs":{}}"#, "thibault");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }
}
