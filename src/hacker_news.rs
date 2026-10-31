//! Hacker News account lookup for a username selector. Keyless -- the official public Firebase API
//! (`GET /v0/user/{id}.json`).
//!
//! One handle resolves to the Hacker News account -- confirmed only when the returned `id` is
//! exactly the queried handle, never a near-match. Hacker News ids are case-sensitive, so the
//! original-case selector is preserved through CLI, scan and HTTP routing specifically for this
//! source; other username sources retain their existing canonical handling. The exact-echo check
//! rejects any id the API returns that is not the one queried. The account
//! keeps its public profile `Url` (`news.ycombinator.com/user?id=`), which ties it back to the
//! `username` cohort through the relation layer, and its self-written `about` bio is kept verbatim
//! as evidence with any `http(s)` links in it surfaced as `Url` (and non-platform host `Domain`)
//! pivots -- candidates to review, never confirmed identity. Karma and the account's creation time
//! are evidence, not entities.
//!
//! This wires the previously dangling `hacker_news` source id the correlator's `forum` family
//! already references to a real producer.

use serde::Deserialize;

use crate::canonical::canonical_url;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{DEFAULT_USER_AGENT, Request, Transport, percent_encode_unreserved};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::textnorm::decode_html_entities;

pub const SRC: &str = "hacker_news";
const API_BASE: &str = "https://hacker-news.firebaseio.com";
const PROFILE_BASE: &str = "https://news.ycombinator.com";

/// Hacker News ids are 2-15 characters (the Arc `goodlogin` rule).
const MIN_HANDLE_LEN: usize = 2;
const MAX_HANDLE_LEN: usize = 15;

/// Confirmed-on-Hacker-News handle: a single-source, keyless account-existence lead.
const USERNAME_CONF: f64 = 0.80;
/// The public profile page the account authenticates nothing through -- just a readable profile.
const PROFILE_URL_CONF: f64 = 0.74;
/// A link the account self-published in its `about` bio.
const BIO_URL_CONF: f64 = 0.55;
/// The host of a self-published bio link, as a pivot.
const BIO_DOMAIN_CONF: f64 = 0.55;

/// Hosts that are noise as a `Domain` pivot: the bio link is already a `Url`, and the host names a
/// platform, not the account owner's own domain.
const NOISE_HOSTS: &[&str] = &[
    "github.com",
    "gitlab.com",
    "twitter.com",
    "x.com",
    "mastodon.social",
    "linkedin.com",
    "news.ycombinator.com",
    "ycombinator.com",
];

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug, Deserialize)]
struct HnUser {
    #[serde(default)]
    id: String,
    #[serde(default)]
    created: Option<i64>,
    #[serde(default)]
    karma: Option<i64>,
    #[serde(default)]
    about: Option<String>,
}

/// Whether `handle` is a shape Hacker News keys an account on: 2-15 characters, each an ASCII
/// letter, digit, hyphen or underscore. Case is preserved (Hacker News ids are case-sensitive).
/// **Pure.**
#[must_use]
pub fn valid_handle(handle: &str) -> bool {
    handle.len() >= MIN_HANDLE_LEN
        && handle.len() <= MAX_HANDLE_LEN
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// The `/v0/user/{id}.json` URL. **Pure.**
#[must_use]
pub fn user_url(handle: &str) -> String {
    format!(
        "{API_BASE}/v0/user/{}.json",
        percent_encode_unreserved(handle)
    )
}

/// The public profile page a human reads for a handle. **Pure.**
fn profile_url(handle: &str) -> String {
    format!(
        "{PROFILE_BASE}/user?id={}",
        percent_encode_unreserved(handle)
    )
}

fn request(url: String) -> Request {
    Request::get(url)
        .header("accept", "application/json")
        .header("user-agent", DEFAULT_USER_AGENT)
}

/// Look up one Hacker News account, keyless.
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
            "selector is not a valid Hacker News handle",
        )));
    }
    let fetched = fetch(
        transport,
        request(user_url(handle)),
        None,
        &FetchOptions::no_redirects().paced(),
        SRC,
        now_unix,
    )?;
    let (user, status) = match interpret_user(&fetched, handle, now_unix) {
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

/// The confirmed account, with the response status; `Err` is the outcome of a response that named no
/// such account or a different one. The Firebase API answers `null` (a 200, not a 404) for an
/// unknown id, which is a clean negative; a payload whose `id` is not the queried handle is semantic
/// drift, never attributed to the query. **Pure.**
fn interpret_user(
    fetched: &Fetched,
    handle: &str,
    now_unix: u64,
) -> Result<(HnUser, u16), SourceExecutionOutcome> {
    let response = whole_response(fetched, "Hacker News user")?;
    answer(fetched, "Hacker News user")?;
    let parsed: Option<HnUser> = decode_json(response, SRC, now_unix, "Hacker News user")?;
    let Some(user) = parsed else {
        // `null`: the id is not a Hacker News account.
        return Err(
            SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(response.status)
        );
    };
    if user.id.trim().is_empty() {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "Hacker News payload carried no id",
        ));
    }
    if user.id.trim() != handle {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SemanticDrift,
            Some(response.status),
            "Hacker News returned a different account than the queried handle",
        ));
    }
    Ok((user, response.status))
}

/// Build the report entities from the confirmed account. **Pure** (no network/IO), so the
/// account -> entity mapping is unit-testable off JSON fixtures.
fn build_entities(user: &HnUser, scan_id: &str) -> Vec<Entity> {
    let mut entities = Vec::new();
    add_account(user, scan_id, &mut entities);
    add_bio_links(user, scan_id, &mut entities);
    entities
}

/// The confirmed account: its `Username` and public profile `Url`, with karma, creation time and the
/// verbatim decoded `about` bio kept as evidence. **Pure.**
fn add_account(user: &HnUser, scan_id: &str, entities: &mut Vec<Entity>) {
    let id = user.id.trim();
    let about = user
        .about
        .as_deref()
        .map(decode_html_entities)
        .map(|bio| bio.trim().to_owned())
        .filter(|bio| !bio.is_empty());
    let created = user.created.map(|seconds| seconds.to_string());
    let karma = user.karma.map(|points| points.to_string());

    let evidence = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!(
            "Hacker News account {id}: a public forum account, a candidate to review, not a confirmed identity"
        ),
    )
    .with_attr("dataset", "Hacker News")
    .with_attr("profile_url", profile_url(id))
    .with_optional_attrs([
        ("karma", karma.as_deref()),
        ("created_unix", created.as_deref()),
        ("about", about.as_deref()),
    ]);

    push_entity(
        entities,
        EntityKind::Username,
        id,
        USERNAME_CONF,
        scan_id,
        evidence.clone(),
        &["hacker-news", "forum"],
    );
    push_entity(
        entities,
        EntityKind::Url,
        &profile_url(id),
        PROFILE_URL_CONF,
        scan_id,
        evidence,
        &["hacker-news", "forum"],
    );
}

/// Each `http(s)` link the account self-published in its `about` bio as a `Url`, and its non-platform
/// host as a `Domain`, de-duplicated. A self-declared link is a lead to review, never proof of who
/// controls the account. **Pure.**
fn add_bio_links(user: &HnUser, scan_id: &str, entities: &mut Vec<Entity>) {
    let Some(about) = user.about.as_deref() else {
        return;
    };
    let mut seen_urls: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut seen_domains: std::collections::HashSet<String> = std::collections::HashSet::new();
    for link in bio_urls(about) {
        if !seen_urls.insert(link.clone()) {
            continue;
        }
        let evidence = Evidence::new(
            EvidenceProvenance::for_scan(SRC, scan_id),
            "Hacker News bio link: self-published, a candidate to review".to_owned(),
        )
        .with_attr("dataset", "Hacker News");
        push_entity(
            entities,
            EntityKind::Url,
            &link,
            BIO_URL_CONF,
            scan_id,
            evidence.clone(),
            &["hacker-news", "self-reported"],
        );
        if let Some((kind, host)) = crate::domains::link_host(&link) {
            if !NOISE_HOSTS.contains(&host.as_str()) && seen_domains.insert(host.clone()) {
                push_entity(
                    entities,
                    kind,
                    &host,
                    BIO_DOMAIN_CONF,
                    scan_id,
                    evidence,
                    &["hacker-news", crate::tags::DERIVED],
                );
            }
        }
    }
}

/// The `http(s)` links in a Hacker News `about` bio: HTML entities decoded first, then every
/// `http://` or `https://` run taken up to the first delimiter (whitespace, quote, angle bracket or
/// backtick), with trailing sentence punctuation and any unbalanced trailing `)` (a link wrapped in
/// prose parentheses) removed, while a balanced `…/Foo_(bar)` is kept whole. Parentheses are legal
/// URL characters, so they are not delimiters. Kept only when [`canonical_url`] accepts it.
/// Order-preserving. **Pure.**
fn bio_urls(about: &str) -> Vec<String> {
    let decoded = decode_html_entities(about);
    let mut out = Vec::new();
    let mut rest = decoded.as_str();
    while let Some(start) = find_scheme(rest) {
        let tail = &rest[start..];
        let end = tail
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '`'))
            .unwrap_or(tail.len());
        let trimmed = tail[..end].trim_end_matches(['.', ',', ';', ':', '!', '?']);
        let candidate = strip_unbalanced_trailing_parens(trimmed);
        if !candidate.is_empty() && canonical_url(candidate).is_some() {
            out.push(candidate.to_owned());
        }
        rest = &tail[end..];
    }
    out
}

/// `url` with any trailing `)` that has no matching `(` removed, so a link wrapped in prose
/// parentheses (`(https://example.com)`) loses the wrapper while a balanced path segment
/// (`…/Mercury_(planet)`) is kept whole. **Pure.**
fn strip_unbalanced_trailing_parens(url: &str) -> &str {
    let opens = url.bytes().filter(|&byte| byte == b'(').count();
    let mut closes = url.bytes().filter(|&byte| byte == b')').count();
    let mut end = url.len();
    while closes > opens && url[..end].ends_with(')') {
        end -= 1;
        closes -= 1;
    }
    &url[..end]
}

/// The byte offset of the next `http://` or `https://` in `text`, or `None`. **Pure.**
fn find_scheme(text: &str) -> Option<usize> {
    let https = text.find("https://");
    let http = text.find("http://");
    match (https, http) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, other) => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{ScriptedTransport, json_ok};

    const USER: &str = r#"{"id":"pg","created":1160418092,"karma":157316,"about":"Bug fixer. Site: &lt;a href=&quot;https://paulgraham.com&quot;&gt;paulgraham.com&lt;/a&gt;","submitted":[1,2,3]}"#;

    fn report_of(body: &str, handle: &str) -> Report {
        let transport = ScriptedTransport::new(vec![Ok(json_ok(body))]);
        lookup(&transport, handle, "scan-hn", 1).expect("lookup runs")
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
            .find(|e| e.kind == EntityKind::Username)
            .and_then(|e| e.evidence.first())
            .and_then(|ev| ev.attributes.get(key))
            .map(String::as_str)
    }

    #[test]
    fn valid_handle_accepts_hacker_news_shaped_ids() {
        assert!(valid_handle("pg"));
        assert!(valid_handle("ada_lovelace"));
        assert!(valid_handle("rhino-ryno23"));
        assert!(valid_handle("PaulG"));
        assert!(!valid_handle("a")); // too short
        assert!(!valid_handle("")); // empty
        assert!(!valid_handle(&"x".repeat(16))); // too long
        assert!(!valid_handle("has space"));
        assert!(!valid_handle("../etc"));
    }

    #[test]
    fn the_user_url_and_profile_url_carry_the_handle() {
        assert_eq!(
            user_url("pg"),
            "https://hacker-news.firebaseio.com/v0/user/pg.json"
        );
        assert_eq!(profile_url("pg"), "https://news.ycombinator.com/user?id=pg");
    }

    #[test]
    fn a_confirmed_account_emits_username_profile_and_bio_pivots() {
        let report = report_of(USER, "pg");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(has(&report, &EntityKind::Username, "pg"));
        assert!(has(
            &report,
            &EntityKind::Url,
            "https://news.ycombinator.com/user?id=pg"
        ));
        // The bio link is decoded out of the HTML and surfaced as a Url + Domain pivot.
        assert!(has(&report, &EntityKind::Url, "https://paulgraham.com"));
        assert!(has(&report, &EntityKind::Domain, "paulgraham.com"));
        // Karma, creation time and the decoded bio are kept verbatim as evidence.
        assert_eq!(account_attr(&report, "karma"), Some("157316"));
        assert_eq!(account_attr(&report, "created_unix"), Some("1160418092"));
        assert!(
            account_attr(&report, "about").is_some_and(|bio| bio.contains("Bug fixer.")),
            "{:#?}",
            report.entities
        );
    }

    #[test]
    fn an_unknown_account_is_a_clean_negative() {
        // The Firebase API answers `null` with a 200 for an id that is not an account.
        let report = report_of("null", "nobody-xyz");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn a_payload_for_a_different_account_is_semantic_drift() {
        let other = r#"{"id":"someone_else","created":1,"karma":1}"#;
        let report = report_of(other, "pg");
        assert!(report.entities.is_empty(), "{:#?}", report.entities);
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SemanticDrift);
    }

    #[test]
    fn a_payload_without_an_id_is_schema_drift() {
        let report = report_of(r#"{"karma":5}"#, "pg");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn a_case_mismatch_is_semantic_drift_not_a_confirmation() {
        // Hacker News ids are case-sensitive; a differently-cased id is not the queried handle.
        let report = report_of(r#"{"id":"PG","created":1,"karma":1}"#, "pg");
        assert!(report.entities.is_empty(), "{:#?}", report.entities);
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SemanticDrift);
    }

    #[test]
    fn an_account_without_a_bio_emits_only_the_account() {
        let report = report_of(r#"{"id":"quiet","created":1,"karma":1}"#, "quiet");
        assert!(has(&report, &EntityKind::Username, "quiet"));
        assert!(!report.entities.iter().any(|e| e.kind == EntityKind::Domain));
        assert_eq!(account_attr(&report, "about"), None);
    }

    #[test]
    fn bio_urls_extracts_and_validates_links() {
        // Entity-encoded anchor, a bare link with trailing punctuation, and a platform link.
        let bio = "see &lt;a href=&quot;https://example.org/me&quot;&gt;site&lt;/a&gt; and https://blog.example.net, also https://github.com/someone.";
        let urls = bio_urls(bio);
        assert!(
            urls.contains(&"https://example.org/me".to_owned()),
            "{urls:?}"
        );
        assert!(
            urls.contains(&"https://blog.example.net".to_owned()),
            "{urls:?}"
        );
        assert!(
            urls.contains(&"https://github.com/someone".to_owned()),
            "{urls:?}"
        );
        // No scheme -> nothing.
        assert!(bio_urls("just text, no links").is_empty());
    }

    #[test]
    fn bio_urls_keep_balanced_parens_and_strip_prose_wrappers() {
        // A balanced parenthesis is a legal URL character, so the link is kept whole.
        assert_eq!(
            bio_urls("ref https://en.wikipedia.org/wiki/Mercury_(planet) end"),
            ["https://en.wikipedia.org/wiki/Mercury_(planet)"]
        );
        // A link wrapped in prose parentheses loses only the wrapper.
        assert_eq!(
            bio_urls("see (https://example.com) now"),
            ["https://example.com"]
        );
        // A balanced URL that is itself wrapped keeps its own parens and drops the wrapper.
        assert_eq!(
            bio_urls("(https://en.wikipedia.org/wiki/Mercury_(planet))"),
            ["https://en.wikipedia.org/wiki/Mercury_(planet)"]
        );
    }

    #[test]
    fn a_github_bio_link_is_a_url_but_its_host_is_not_a_domain_pivot() {
        let body = r#"{"id":"dev","created":1,"karma":1,"about":"https://github.com/dev"}"#;
        let report = report_of(body, "dev");
        assert!(has(&report, &EntityKind::Url, "https://github.com/dev"));
        assert!(!has(&report, &EntityKind::Domain, "github.com"));
    }
}
