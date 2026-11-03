//! Chess.com account lookup for a username selector. Keyless -- the public player document the
//! site serves at `https://api.chess.com/pub/player/{username}` (the Published-Data API).
//!
//! One handle resolves to the Chess.com account. Usernames are case-insensitive and lower-case
//! canonical (the API 301-redirects any other case, which the no-redirects fetch would read as a
//! wall), so the handle is lower-cased here and the account is confirmed only when the returned
//! `username` is the queried handle, never a near-match. A `404` read as a plain upstream 4xx is the
//! clean "no such player" answer (the API says so in JSON); a challenge page at that status is a
//! wall, not a zero; a body that is not the player document is schema or semantic drift, never a
//! fabricated account.
//!
//! The account keeps its public profile `Url`, its self-declared display name as a `Person`
//! candidate, its self-declared Twitch channel as a `Url` lead, and its title, country, location,
//! join and last-seen times, status, league and follower count as verbatim evidence. Nothing here
//! confirms who holds the account.

use serde::Deserialize;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport, percent_encode_unreserved};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::textnorm::nonblank;

pub const SRC: &str = "chess_com";
const API_BASE: &str = "https://api.chess.com";
const SITE_BASE: &str = "https://www.chess.com";

/// Chess.com usernames are 3-25 characters: an ASCII letter, digit, underscore or hyphen.
const MIN_HANDLE_LEN: usize = 3;
const MAX_HANDLE_LEN: usize = 25;

/// Confirmed-on-Chess.com handle: a single-source, keyless account-existence lead.
const USERNAME_CONF: f64 = 0.80;
/// The public profile page the account authenticates nothing through.
const PROFILE_URL_CONF: f64 = 0.74;
/// A display name or channel the account self-declares: a candidate lead, never a confirmed link.
const SELF_DECLARED_CONF: f64 = 0.55;

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug, Deserialize)]
struct Player {
    #[serde(default)]
    username: String,
    #[serde(default, rename = "player_id")]
    id: Option<u64>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    joined: Option<u64>,
    #[serde(default)]
    last_online: Option<u64>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    league: Option<String>,
    #[serde(default)]
    followers: Option<u64>,
    #[serde(default)]
    is_streamer: Option<bool>,
    #[serde(default)]
    verified: Option<bool>,
    #[serde(default)]
    twitch_url: Option<String>,
}

/// Whether `handle` is a shape Chess.com keys an account on: 3-25 characters, each an ASCII
/// letter, digit, hyphen or underscore. **Pure.**
#[must_use]
pub fn valid_handle(handle: &str) -> bool {
    handle.len() >= MIN_HANDLE_LEN
        && handle.len() <= MAX_HANDLE_LEN
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// The `/pub/player/{username}` URL. **Pure.**
#[must_use]
pub fn player_url(handle: &str) -> String {
    format!(
        "{API_BASE}/pub/player/{}",
        percent_encode_unreserved(handle)
    )
}

/// The public profile page a human reads for a handle. **Pure.**
fn profile_url(handle: &str) -> String {
    format!("{SITE_BASE}/member/{}", percent_encode_unreserved(handle))
}

/// The two-letter code at the end of the API's country URL (`.../pub/country/US`). **Pure.**
fn country_code(country: &str) -> Option<&str> {
    let code = country.trim().trim_end_matches('/').rsplit('/').next()?;
    (code.len() == 2 && code.bytes().all(|b| b.is_ascii_alphabetic())).then_some(code)
}

/// Look up one Chess.com account, keyless.
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses the player URL.
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
            "selector is not a valid Chess.com username",
        )));
    }
    let fetched = fetch(
        transport,
        Request::get_json(player_url(&handle)),
        None,
        &FetchOptions::no_redirects().paced(),
        SRC,
        now_unix,
    )?;
    let (player, status) = match interpret_player(&fetched, &handle, now_unix) {
        Ok(found) => found,
        Err(outcome) => return Ok(miss(outcome)),
    };
    let mut entities = build_entities(&player, scan_id);
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

/// The confirmed player, with the response status; `Err` is the outcome of a response that named
/// no such player or a different one. **Pure.**
fn interpret_player(
    fetched: &Fetched,
    handle: &str,
    now_unix: u64,
) -> Result<(Player, u16), SourceExecutionOutcome> {
    if let Some(response) = &fetched.response {
        if response.status == 404 && fetched.outcome.kind == SourceOutcomeKind::Upstream4xx {
            return Err(
                SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(response.status)
            );
        }
    }
    let response = whole_response(fetched, "Chess.com player")?;
    answer(fetched, "Chess.com player")?;
    let player: Player = decode_json(response, SRC, now_unix, "Chess.com player")?;
    if player.username.trim().is_empty() {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "Chess.com payload carried no username",
        ));
    }
    if !player.username.trim().eq_ignore_ascii_case(handle) {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SemanticDrift,
            Some(response.status),
            "Chess.com returned a different player than the queried handle",
        ));
    }
    Ok((player, response.status))
}

/// Build the report entities from the confirmed player. **Pure.**
fn build_entities(player: &Player, scan_id: &str) -> Vec<Entity> {
    let id = player.username.trim();
    let profile = nonblank(player.url.as_deref())
        .filter(|url| url.starts_with("https://"))
        .map_or_else(|| profile_url(id), str::to_owned);
    let player_id = player.id.map(|n| n.to_string());
    let joined = player.joined.map(|n| n.to_string());
    let last_online = player.last_online.map(|n| n.to_string());
    let followers = player.followers.map(|n| n.to_string());
    let evidence = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!(
            "Chess.com account {id}: a public game-site account, a candidate to review, not a confirmed identity"
        ),
    )
    .with_attr("dataset", "Chess.com")
    .with_attr("profile_url", profile.as_str())
    .with_optional_attrs([
        ("player_id", player_id.as_deref()),
        ("name", nonblank(player.name.as_deref())),
        ("title", nonblank(player.title.as_deref())),
        (
            "country",
            player.country.as_deref().and_then(country_code),
        ),
        ("location", nonblank(player.location.as_deref())),
        ("joined_unix", joined.as_deref()),
        ("last_online_unix", last_online.as_deref()),
        ("status", nonblank(player.status.as_deref())),
        ("league", nonblank(player.league.as_deref())),
        ("followers", followers.as_deref()),
        (
            "streamer",
            player.is_streamer.map(|b| if b { "yes" } else { "no" }),
        ),
        (
            "verified",
            player.verified.map(|b| if b { "yes" } else { "no" }),
        ),
    ]);
    let mut entities = Vec::new();
    push_entity(
        &mut entities,
        EntityKind::Username,
        id,
        USERNAME_CONF,
        scan_id,
        evidence.clone(),
        &["chess_com", "gaming"],
    );
    push_entity(
        &mut entities,
        EntityKind::Url,
        &profile,
        PROFILE_URL_CONF,
        scan_id,
        evidence,
        &["chess_com", "gaming"],
    );
    if let Some(name) = nonblank(player.name.as_deref()) {
        push_entity(
            &mut entities,
            EntityKind::Person,
            name,
            SELF_DECLARED_CONF,
            scan_id,
            Evidence::new(
                EvidenceProvenance::for_scan(SRC, scan_id),
                format!(
                    "Display name self-declared on the Chess.com profile of {id}: a candidate, never a confirmed identity"
                ),
            )
            .with_attr("dataset", "Chess.com")
            .with_attr("declared_on", profile.as_str()),
            &["chess_com", "self-reported"],
        );
    }
    if let Some(twitch) =
        nonblank(player.twitch_url.as_deref()).filter(|url| url.starts_with("https://"))
    {
        push_entity(
            &mut entities,
            EntityKind::Url,
            twitch,
            SELF_DECLARED_CONF,
            scan_id,
            Evidence::new(
                EvidenceProvenance::for_scan(SRC, scan_id),
                format!(
                    "Twitch channel self-declared on the Chess.com profile of {id}: a candidate cross-platform lead, not a confirmed link"
                ),
            )
            .with_attr("dataset", "Chess.com")
            .with_attr("declared_on", profile.as_str()),
            &["twitch", "self-reported"],
        );
    }
    entities
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{OneResponse, ScriptedTransport, json_ok};

    /// Recorded from `GET /pub/player/hikaru` on 2026-11-03, shortened.
    const PLAYER: &str = r#"{"avatar":"https://images.chesscomfiles.com/uploads/v1/user/15448422.png","player_id":15448422,"@id":"https://api.chess.com/pub/player/hikaru","url":"https://www.chess.com/member/Hikaru","name":"Hikaru Nakamura","username":"hikaru","title":"GM","followers":1423410,"country":"https://api.chess.com/pub/country/US","location":"Florida","last_online":1793735897,"joined":1389043258,"status":"premium","is_streamer":true,"twitch_url":"https://twitch.tv/gmhikaru","verified":false,"league":"Legend","streaming_platforms":[{"type":"twitch","channel_url":"https://twitch.tv/gmhikaru"}]}"#;

    fn report_of(body: &str, handle: &str) -> Report {
        let transport = ScriptedTransport::new(vec![Ok(json_ok(body))]);
        lookup(&transport, handle, "scan-chess", 1).expect("lookup runs")
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
    fn valid_handle_accepts_chess_com_shaped_ids() {
        assert!(valid_handle("hikaru"));
        assert!(valid_handle("magnus_carlsen-1"));
        assert!(!valid_handle("ab"));
        assert!(!valid_handle(&"x".repeat(26)));
        assert!(!valid_handle("has space"));
        assert!(!valid_handle("../etc"));
    }

    #[test]
    fn the_urls_carry_the_handle_and_the_country_code_is_the_url_tail() {
        assert_eq!(
            player_url("hikaru"),
            "https://api.chess.com/pub/player/hikaru"
        );
        assert_eq!(profile_url("hikaru"), "https://www.chess.com/member/hikaru");
        assert_eq!(
            country_code("https://api.chess.com/pub/country/US"),
            Some("US")
        );
        assert_eq!(country_code("https://api.chess.com/pub/country/"), None);
        assert_eq!(country_code("nonsense"), None);
    }

    #[test]
    fn a_confirmed_player_emits_username_profile_name_twitch_and_evidence() {
        let report = report_of(PLAYER, "Hikaru");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        let has = |kind: EntityKind, value: &str| {
            report
                .entities
                .iter()
                .any(|e| e.kind == kind && e.raw_value == value)
        };
        assert!(has(EntityKind::Username, "hikaru"));
        assert!(has(EntityKind::Url, "https://www.chess.com/member/Hikaru"));
        assert!(has(EntityKind::Person, "Hikaru Nakamura"));
        assert!(has(EntityKind::Url, "https://twitch.tv/gmhikaru"));
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Person && e.has_tag("self-reported"))
        );
        assert_eq!(account_attr(&report, "title"), Some("GM"));
        assert_eq!(account_attr(&report, "country"), Some("US"));
        assert_eq!(account_attr(&report, "location"), Some("Florida"));
        assert_eq!(account_attr(&report, "joined_unix"), Some("1389043258"));
        assert_eq!(account_attr(&report, "league"), Some("Legend"));
        assert_eq!(account_attr(&report, "followers"), Some("1423410"));
        assert_eq!(account_attr(&report, "streamer"), Some("yes"));
        assert_eq!(account_attr(&report, "verified"), Some("no"));
        assert_eq!(account_attr(&report, "player_id"), Some("15448422"));
    }

    #[test]
    fn an_unknown_player_is_a_clean_negative() {
        // The API answers 404 with `{"code":0,"message":"User \"x\" not found."}`.
        let transport = OneResponse::with_headers(
            404,
            &[("content-type", "application/json")],
            r#"{"code":0,"message":"User \"nobody\" not found."}"#,
        );
        let report = lookup(&transport, "nobody-xyz", "scan-chess", 1).expect("lookup runs");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn a_payload_for_a_different_player_is_semantic_drift() {
        let report = report_of(r#"{"username":"someone_else","player_id":1}"#, "hikaru");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SemanticDrift);
    }

    #[test]
    fn a_payload_without_a_username_is_schema_drift() {
        let report = report_of(r#"{"player_id":5}"#, "hikaru");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn a_bare_player_emits_only_the_account_and_a_fallback_profile_url() {
        let report = report_of(r#"{"username":"quiet"}"#, "quiet");
        assert_eq!(report.entities.len(), 2);
        assert!(
            report.entities.iter().any(|e| e.kind == EntityKind::Url
                && e.raw_value == "https://www.chess.com/member/quiet")
        );
    }
}
