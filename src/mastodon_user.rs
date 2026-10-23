//! Keyless Mastodon public-account lookup.
//!
//! One lookup is one `GET https://mastodon.social/api/v1/accounts/lookup?acct={username}`, the
//! documented public endpoint a Mastodon server answers for its own accounts without a token.
//! A username routes here as it is written; Mastodon usernames are ASCII letters, digits and
//! `_`, so a handle with `.` or `-` cannot name one and is inconclusive, not absent. Only the
//! server's own "Record not found" answer is a zero: any other refusal (a block page, a rate
//! limit, a suspended account) says nothing about whether the account exists.

use serde::Deserialize;

use crate::classifier;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport, append_query_param};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SRC: &str = "mastodon_user";
/// The server asked: the largest Mastodon server, run by the project itself.
pub const INSTANCE: &str = "mastodon.social";
const API: &str = "https://mastodon.social/api/v1/accounts/lookup";
/// The longest username Mastodon accepts.
const MAX_USERNAME: usize = 30;

const USERNAME_CONF: f64 = 0.85;
const PERSON_CONF: f64 = 0.60;
const URL_CONF: f64 = 0.75;
const BIO_CONF_CAP: f64 = 0.70;

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    error: String,
}

#[derive(Debug, Deserialize)]
struct Account {
    username: String,
    #[serde(default)]
    acct: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    bot: Option<bool>,
}

/// Whether `name` can be a Mastodon username: 1 to 30 ASCII letters, digits or `_`. **Pure.**
#[must_use]
pub fn valid_username(name: &str) -> bool {
    (1..=MAX_USERNAME).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Look `username` up on [`INSTANCE`].
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses the URL.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    lookup_with_options(
        transport,
        username,
        scan_id,
        now_unix,
        &FetchOptions::no_redirects().paced(),
    )
}

/// Internal transport adapter. Scripted unit tests opt out of process-global
/// pacing, which belongs to the separately tested fetch/circuit layer.
fn lookup_with_options<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    scan_id: &str,
    now_unix: u64,
    options: &FetchOptions,
) -> Result<Report, Error> {
    let name = username.trim().trim_start_matches('@');
    if !valid_username(name) {
        return Ok(miss(SourceExecutionOutcome::inconclusive(
            SRC,
            now_unix,
            "selector cannot be a Mastodon username (letters, digits and _ only, at most 30)",
        )));
    }
    let fetched = fetch(
        transport,
        Request::get(append_query_param(API, "acct", name))
            .header("accept", "application/json")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
        None,
        options,
        SRC,
        now_unix,
    )?;
    Ok(interpret(&fetched, scan_id, now_unix).unwrap_or_else(miss))
}

/// A report that found nothing, carrying only its outcome. **Pure.**
fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

/// One fetched lookup as a report; `Err` is the outcome of a response that named no account.
/// **Pure.**
fn interpret(
    fetched: &Fetched,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, SourceExecutionOutcome> {
    let response = whole_response(fetched, "Mastodon")?;
    if response.status == 404
        && serde_json::from_slice::<ApiError>(&response.body)
            .is_ok_and(|error| error.error == "Record not found")
    {
        return Err(SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(404));
    }
    answer(fetched, "Mastodon")?;
    let account: Account = decode_json(response, SRC, now_unix, "Mastodon")?;
    if !valid_username(account.username.trim()) {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "Mastodon account has no valid username",
        ));
    }
    let mut entities = build_entities(&account, scan_id);
    merge_by_uid(&mut entities);
    Ok(Report {
        entities,
        outcome: SourceExecutionOutcome::success(SRC, now_unix, 1)
            .with_http_status(response.status),
    })
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

/// The account's own address, `username@mastodon.social`, whatever `acct` the server gives.
fn address(account: &Account) -> String {
    format!(
        "{}@{INSTANCE}",
        account.username.trim().to_ascii_lowercase()
    )
}

fn evidence(account: &Account, scan_id: &str) -> Evidence {
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!("Mastodon public account {}", address(account)),
    )
    .with_attr("dataset", "Mastodon public accounts")
    .with_attr("instance", INSTANCE)
    .with_attr("mastodon_acct", address(account));
    for (name, value) in [
        ("display_name", non_empty(account.display_name.as_deref())),
        ("created_at", non_empty(account.created_at.as_deref())),
        ("server_acct", non_empty(account.acct.as_deref())),
    ] {
        if let Some(value) = value {
            evidence = evidence.with_attr(name, value);
        }
    }
    if account.bot == Some(true) {
        evidence = evidence.with_attr("bot", "true");
    }
    evidence
}

/// The profile URL the server gives, kept only when it is on [`INSTANCE`]: a remote or hostile
/// value stays out of the entities.
fn profile_url(account: &Account) -> Option<&str> {
    non_empty(account.url.as_deref())
        .filter(|url| url.starts_with(&format!("https://{INSTANCE}/@")))
}

fn build_entities(account: &Account, scan_id: &str) -> Vec<Entity> {
    let found = evidence(account, scan_id);
    let tags: &[&str] = &["mastodon", "public-profile"];
    let mut entities = Vec::new();
    push_entity(
        &mut entities,
        EntityKind::Username,
        &account.username.trim().to_ascii_lowercase(),
        USERNAME_CONF,
        scan_id,
        found.clone(),
        tags,
    );
    if let Some(url) = profile_url(account) {
        push_entity(
            &mut entities,
            EntityKind::Url,
            url,
            URL_CONF,
            scan_id,
            found.clone(),
            tags,
        );
    }
    // Two words or more, as the Bluesky leg reads a display name: one word is a handle, not a
    // name, and a name here is only what the account calls itself.
    if let Some(name) = non_empty(account.display_name.as_deref())
        .filter(|name| name.split_whitespace().count() >= 2)
    {
        push_entity(
            &mut entities,
            EntityKind::Person,
            name,
            PERSON_CONF,
            scan_id,
            found.clone(),
            tags,
        );
    }
    if let Some(note) = account.note.as_deref() {
        let text = crate::textnorm::decode_html_entities(&strip_tags(note));
        for classified in classifier::extract(&text)
            .into_iter()
            .filter(|item| matches!(item.kind, EntityKind::Email | EntityKind::Url))
        {
            push_entity(
                &mut entities,
                classified.kind,
                &classified.value,
                classified.confidence.min(BIO_CONF_CAP),
                scan_id,
                found.clone().inferred(),
                &["mastodon", "bio"],
            );
        }
    }
    entities
}

/// A note's HTML as text. Mastodon splits a link's text into spans (`https://`, then the host)
/// and a mention's into `@` and a span, so an inline tag is dropped without a gap; a paragraph or
/// line break becomes a space, so `<p>a</p><p>b</p>` is not `ab`. **Pure.**
fn strip_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut tag: Option<String> = None;
    for c in html.chars() {
        match (&mut tag, c) {
            (None, '<') => tag = Some(String::new()),
            (None, _) => out.push(c),
            (Some(name), '>') => {
                let name = name.trim_start_matches('/').to_ascii_lowercase();
                if name == "p" || name.starts_with("p ") || name.starts_with("br") {
                    out.push(' ');
                }
                tag = None;
            }
            (Some(name), _) => name.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Response;
    use crate::test_support::ScriptedTransport;

    fn lookup_fixture<T: Transport + ?Sized>(
        transport: &T,
        username: &str,
        scan_id: &str,
        now_unix: u64,
    ) -> Result<Report, Error> {
        lookup_with_options(
            transport,
            username,
            scan_id,
            now_unix,
            &FetchOptions::no_redirects(),
        )
    }

    fn urls(transport: &ScriptedTransport) -> Vec<String> {
        transport
            .seen
            .borrow()
            .iter()
            .map(|r| r.url.clone())
            .collect()
    }

    fn reply(status: u16, body: &str) -> Response {
        Response {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    /// The account shape `mastodon.social` gave for `Gargron` on 2026-10-23, trimmed; the note's
    /// link is written in the markup Mastodon gives links, and its mention as it gave this one.
    const FOUND: &str = r#"{"id":"1","username":"Gargron","acct":"Gargron","display_name":"Eugen Rochko","locked":false,"bot":false,"created_at":"2016-03-16T00:00:00.000Z","note":"<p>Advisor of <span class=\"h-card\" translate=\"no\"><a href=\"https://mastodon.social/@Mastodon\" class=\"u-url mention\">@<span>Mastodon</span></a></span> &amp; more.</p><p>See <a href=\"https://joinmastodon.org\" target=\"_blank\" rel=\"nofollow noopener\" translate=\"no\"><span class=\"invisible\">https://</span><span class=\"\">joinmastodon.org</span><span class=\"invisible\"></span></a></p>","url":"https://mastodon.social/@Gargron"}"#;
    /// What it gives for an account it does not hold.
    const MISSING: &str = r#"{"error":"Record not found"}"#;

    #[test]
    fn an_account_becomes_a_username_its_profile_and_its_name() {
        let transport = ScriptedTransport::new(vec![Ok(reply(200, FOUND))]);
        let report = lookup_fixture(&transport, "@Gargron", "scan", 1).unwrap();
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(
            urls(&transport),
            ["https://mastodon.social/api/v1/accounts/lookup?acct=Gargron"]
        );
        let found = |kind: EntityKind, value: &str| {
            report
                .entities
                .iter()
                .any(|e| e.kind == kind && e.raw_value == value)
        };
        assert!(
            found(EntityKind::Username, "gargron"),
            "{:?}",
            report.entities
        );
        assert!(found(EntityKind::Url, "https://mastodon.social/@Gargron"));
        assert!(found(EntityKind::Person, "Eugen Rochko"));
        assert!(
            found(EntityKind::Url, "https://joinmastodon.org"),
            "{:?}",
            report.entities
        );
        let evidence = &report.entities[0].evidence[0];
        assert_eq!(
            evidence.attributes.get("mastodon_acct").map(String::as_str),
            Some("gargron@mastodon.social")
        );
    }

    #[test]
    fn only_the_servers_not_found_answer_is_a_zero() {
        let missing = ScriptedTransport::new(vec![Ok(reply(404, MISSING))]);
        let report = lookup_fixture(&missing, "nobody_here", "scan", 1).unwrap();
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
        assert!(report.entities.is_empty());
        // A block page, a bare 404 or a rate limit names no account and is not absence.
        for (status, body) in [(403, "<html>blocked</html>"), (404, "{}"), (429, "{}")] {
            let refused = ScriptedTransport::new(vec![Ok(reply(status, body))]);
            let report = lookup_fixture(&refused, "nobody_here", "scan", 1).unwrap();
            assert_ne!(
                report.outcome.kind,
                SourceOutcomeKind::ValidZero,
                "{status}"
            );
            assert_ne!(report.outcome.kind, SourceOutcomeKind::Success, "{status}");
            assert!(report.entities.is_empty());
        }
    }

    #[test]
    fn a_handle_mastodon_cannot_hold_sends_nothing() {
        for name in ["jane.doe", "jane-doe", "a234567890123456789012345678901"] {
            let transport = ScriptedTransport::new(Vec::new());
            let report = lookup_fixture(&transport, name, "scan", 1).unwrap();
            assert_eq!(
                report.outcome.kind,
                SourceOutcomeKind::Inconclusive,
                "{name}"
            );
            assert!(urls(&transport).is_empty(), "{name}");
        }
    }

    #[test]
    fn a_note_reads_as_its_text() {
        assert_eq!(
            strip_tags("<p>a <span>@<span>b</span></span></p><p>c<br/>d</p>")
                .split_whitespace()
                .collect::<Vec<_>>(),
            ["a", "@b", "c", "d"]
        );
        assert_eq!(
            strip_tags(
                "<a href=\"x\"><span class=\"invisible\">https://</span><span>e.org</span></a>"
            ),
            "https://e.org"
        );
    }

    #[test]
    fn a_remote_profile_url_is_not_taken_as_this_accounts() {
        let hostile = FOUND.replace(
            "https://mastodon.social/@Gargron\"}",
            "https://evil.example/@Gargron\"}",
        );
        let transport = ScriptedTransport::new(vec![Ok(reply(200, &hostile))]);
        let report = lookup_fixture(&transport, "Gargron", "scan", 1).unwrap();
        assert!(
            !report
                .entities
                .iter()
                .any(|e| e.raw_value.contains("evil.example"))
        );
    }
}
