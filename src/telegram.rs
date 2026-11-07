//! Telegram public page lookup for a username selector. Keyless -- the server-rendered page
//! Telegram serves to browsers at `https://t.me/{handle}`.
//!
//! One page covers every kind of public Telegram name: a channel (`N subscribers`), a group
//! (`N members, M online`), a bot (`@handle` and `N monthly users`, a `Start Bot` button) and a
//! person who published a profile (`Send Message`). The kind is read from those markers, never
//! guessed from the handle.
//!
//! A handle nobody owns and an account that shows nothing publicly answer the same placeholder
//! (`Telegram: Contact @handle`, no page title), so that page is `Inconclusive`, never a clean
//! zero: Telegram does not reveal whether such an account exists. A redirect, a wall or a page
//! without the markers is never read as absence either.
//!
//! The page title is kept as evidence, never promoted to a `Person`: whoever administers a channel
//! or group writes it, and it routinely names a brand or a community. A verified badge is kept as
//! Telegram's own marker. Addresses and links in the self-written description are candidate leads;
//! a link to another `t.me` name is a Telegram pivot.

use crate::canonical::canonical_url;
use crate::classifier;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, fetch, whole_response};
use crate::html_text::{attribute, html_to_text};
use crate::http::{Request, Transport};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SRC: &str = "telegram";
const PAGE_BASE: &str = "https://t.me";
const MAX_PAGE_BYTES: usize = 1024 * 1024;
const MAX_TEXT_CHARS: usize = 2_048;
const MAX_DESCRIPTION_LEADS: usize = 8;

/// A public Telegram page confirmed for the queried handle.
const USERNAME_CONF: f64 = 0.80;
const PAGE_URL_CONF: f64 = 0.74;
/// An address or link the description's author wrote: a candidate lead.
const SELF_REPORTED_CONF: f64 = 0.55;
const DOMAIN_CONF: f64 = 0.50;

pub type Report = crate::lookup_report::SourceReport;

/// What a public Telegram name is, read from the page's own markers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Channel,
    Group,
    Bot,
    User,
}

impl Kind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Channel => "channel",
            Self::Group => "group",
            Self::Bot => "bot",
            Self::User => "user",
        }
    }
}

/// The public fields of a Telegram page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub kind: Kind,
    pub title: String,
    pub verified: bool,
    pub description: Option<String>,
    /// Every `tgme_page_extra` line verbatim (counts, the bot's `@handle`).
    pub extras: Vec<String>,
    pub subscribers: Option<u64>,
    pub members: Option<u64>,
    pub online: Option<u64>,
    pub monthly_users: Option<u64>,
    /// `href` values of links inside the description.
    pub description_links: Vec<String>,
}

pub use crate::value_syntax::{
    telegram_handle_from_link as handle_from_link, valid_telegram_handle as valid_handle,
};

/// The public page URL for a handle. **Pure.**
#[must_use]
pub fn page_url(handle: &str) -> String {
    format!("{PAGE_BASE}/{handle}")
}

/// Look up one Telegram public page, keyless.
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses the page URL.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let handle = username.trim().trim_start_matches('@');
    if !valid_handle(handle) {
        return Ok(empty(SourceExecutionOutcome::inconclusive(
            SRC,
            now_unix,
            "selector is not a valid Telegram handle",
        )));
    }
    let fetched = fetch(
        transport,
        Request::get(page_url(handle))
            .header("accept", "text/html")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
        None,
        &FetchOptions::no_redirects().paced(),
        SRC,
        now_unix,
    )?;
    Ok(interpret(&fetched, handle, scan_id, now_unix).unwrap_or_else(empty))
}

fn empty(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

fn interpret(
    fetched: &Fetched,
    handle: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, SourceExecutionOutcome> {
    let response = whole_response(fetched, "Telegram page")?;
    if (300..400).contains(&response.status) {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::Inconclusive,
            Some(response.status),
            "Telegram redirected instead of serving the page; nothing is known about the handle",
        ));
    }
    answer(fetched, "Telegram page")?;
    let drift = |detail: &str| {
        SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::ParserDrift,
            Some(response.status),
            detail,
        )
    };
    if response.body.len() > MAX_PAGE_BYTES {
        return Err(drift("Telegram page exceeded the bounded parser budget"));
    }
    let html = std::str::from_utf8(&response.body)
        .map_err(|_| drift("Telegram returned a page that is not UTF-8"))?;
    if !html.contains("tgme_page") {
        return Err(drift("Telegram page carried none of its page markers"));
    }
    let Some(page) = parse_page(html) else {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::Inconclusive,
            Some(response.status),
            format!(
                "no public Telegram page for @{handle}: an unowned handle and an account that shows nothing publicly look the same"
            ),
        ));
    };
    let entities = build_entities(&page, handle, scan_id);
    Ok(Report {
        outcome: SourceExecutionOutcome::success(SRC, now_unix, entities.len())
            .with_http_status(response.status),
        entities,
    })
}

/// The inner HTML of every `div` whose class list holds `class`, in page order. Telegram's page
/// blocks hold no nested `div`, so each runs to the next `</div>`. **Pure.**
fn blocks<'a>(html: &'a str, class: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(open) = rest.find("<div") {
        let Some(after) = rest.get(open + 4..) else {
            break;
        };
        let Some(tag_end) = after.find('>') else {
            break;
        };
        let attrs = after.get(..tag_end).unwrap_or_default();
        let body = after.get(tag_end + 1..).unwrap_or_default();
        let matches = attribute(attrs, "class")
            .is_some_and(|classes| classes.split_ascii_whitespace().any(|c| c == class));
        if matches {
            let close = body.find("</div>").unwrap_or(body.len());
            out.push(body.get(..close).unwrap_or_default());
            rest = body.get(close..).unwrap_or_default();
        } else {
            rest = body;
        }
    }
    out
}

/// The first number in `text`, its digits possibly grouped by spaces, commas or dots. **Pure.**
fn leading_count(text: &str) -> Option<u64> {
    let digits: String = text
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_digit() || matches!(c, ' ' | ',' | '.' | '\u{a0}' | '\u{202f}'))
        .filter(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// The count written before `label` in `text` (`"16 998 members, 1 635 online"`). **Pure.**
fn count_before(text: &str, label: &str) -> Option<u64> {
    text.split(',')
        .map(str::trim)
        .find(|part| part.ends_with(label))
        .and_then(|part| leading_count(part.strip_suffix(label)?))
}

/// Every `href` inside an HTML fragment, in order. **Pure.**
fn hrefs(fragment: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = fragment;
    while let Some(open) = rest.find("<a") {
        let Some(after) = rest.get(open + 2..) else {
            break;
        };
        let Some(end) = after.find('>') else {
            break;
        };
        if let Some(href) = attribute(after.get(..end).unwrap_or_default(), "href") {
            out.push(crate::textnorm::decode_html_entities(href));
        }
        rest = after.get(end..).unwrap_or_default();
    }
    out
}

/// The public page read from Telegram's HTML, or `None` for the placeholder page Telegram serves
/// when a handle shows nothing publicly. **Pure.**
#[must_use]
pub fn parse_page(html: &str) -> Option<Page> {
    let title_block = blocks(html, "tgme_page_title").into_iter().next()?;
    let title = html_to_text(title_block, MAX_TEXT_CHARS)?
        .trim_end_matches('✔')
        .trim()
        .to_owned();
    if title.is_empty() {
        return None;
    }
    let verified = title_block.contains("verified-icon");
    let extras: Vec<String> = blocks(html, "tgme_page_extra")
        .into_iter()
        .filter_map(|b| html_to_text(b, MAX_TEXT_CHARS))
        .collect();
    let description_html = blocks(html, "tgme_page_description").into_iter().next();
    let description = description_html.and_then(|d| html_to_text(d, MAX_TEXT_CHARS));
    let description_links = description_html.map(hrefs).unwrap_or_default();
    let action = blocks(html, "tgme_page_action")
        .into_iter()
        .next()
        .and_then(|a| html_to_text(a, 64))
        .unwrap_or_default();

    let subscribers = extras.iter().find_map(|e| count_before(e, "subscribers"));
    let members = extras.iter().find_map(|e| count_before(e, "members"));
    let online = extras.iter().find_map(|e| count_before(e, "online"));
    let monthly_users = extras.iter().find_map(|e| count_before(e, "monthly users"));
    let kind = if monthly_users.is_some() || action == "Start Bot" {
        Kind::Bot
    } else if members.is_some() {
        Kind::Group
    } else if subscribers.is_some() {
        Kind::Channel
    } else {
        Kind::User
    };
    Some(Page {
        kind,
        title,
        verified,
        description,
        extras,
        subscribers,
        members,
        online,
        monthly_users,
        description_links,
    })
}

fn page_evidence(page: &Page, handle: &str, scan_id: &str) -> Evidence {
    let subscribers = page.subscribers.map(|n| n.to_string());
    let members = page.members.map(|n| n.to_string());
    let online = page.online.map(|n| n.to_string());
    let monthly = page.monthly_users.map(|n| n.to_string());
    let extras = page.extras.join(" | ");
    Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!(
            "Telegram public {} @{handle}: a public page, a candidate to review, not a confirmed identity",
            page.kind.as_str()
        ),
    )
    .with_attr("dataset", "Telegram")
    .with_attr("page_url", page_url(handle))
    .with_attr("telegram_kind", page.kind.as_str())
    .with_attr("title", page.title.as_str())
    .with_attr("verified", if page.verified { "true" } else { "false" })
    .with_optional_attrs([
        ("subscribers", subscribers.as_deref()),
        ("members", members.as_deref()),
        ("online", online.as_deref()),
        ("monthly_users", monthly.as_deref()),
        ("page_extra", Some(extras.as_str())),
        ("description", page.description.as_deref()),
    ])
}

/// Build the report entities from a confirmed public page. **Pure.**
fn build_entities(page: &Page, handle: &str, scan_id: &str) -> Vec<Entity> {
    let evidence = page_evidence(page, handle, scan_id);
    let kind_tag = format!("telegram-{}", page.kind.as_str());
    let own = handle.to_ascii_lowercase();
    let mut entities = Vec::new();
    push_entity(
        &mut entities,
        EntityKind::Username,
        handle,
        USERNAME_CONF,
        scan_id,
        evidence.clone(),
        &["telegram", &kind_tag],
    );
    push_entity(
        &mut entities,
        EntityKind::Url,
        &page_url(handle),
        PAGE_URL_CONF,
        scan_id,
        evidence.clone(),
        &["telegram", &kind_tag],
    );
    let lead = evidence
        .with_attr("source_field", "description")
        .with_attr("relationship", "self_asserted_not_identity_verified")
        .inferred();

    let text = page.description.as_deref().unwrap_or_default();
    for item in classifier::extract(text)
        .into_iter()
        .filter(|item| item.kind == EntityKind::Email)
        .take(MAX_DESCRIPTION_LEADS)
    {
        push_entity(
            &mut entities,
            EntityKind::Email,
            &item.value,
            item.confidence.min(SELF_REPORTED_CONF),
            scan_id,
            lead.clone(),
            &["telegram", "self-reported", crate::tags::CANDIDATE],
        );
    }

    let mut links: Vec<String> = page.description_links.clone();
    links.extend(
        classifier::extract(text)
            .into_iter()
            .filter(|item| item.kind == EntityKind::Url)
            .map(|item| item.value),
    );
    let mut seen = std::collections::BTreeSet::new();
    for link in links {
        let Some(link) = canonical_url(&link).filter(|l| l.starts_with("http")) else {
            continue;
        };
        if !seen.insert(link.clone()) || seen.len() > MAX_DESCRIPTION_LEADS {
            continue;
        }
        if let Some(other) = handle_from_link(&link) {
            if other == own {
                continue;
            }
            push_entity(
                &mut entities,
                EntityKind::Url,
                &page_url(&other),
                SELF_REPORTED_CONF,
                scan_id,
                lead.clone(),
                &["telegram", "telegram-pivot", crate::tags::CANDIDATE],
            );
            continue;
        }
        push_entity(
            &mut entities,
            EntityKind::Url,
            &link,
            SELF_REPORTED_CONF,
            scan_id,
            lead.clone(),
            &["telegram", "self-reported", crate::tags::CANDIDATE],
        );
        if let Some((kind, host)) = crate::entity::link_host(&link) {
            push_entity(
                &mut entities,
                kind,
                &host,
                DOMAIN_CONF,
                scan_id,
                lead.clone(),
                &["telegram", crate::tags::DERIVED],
            );
        }
    }
    merge_by_uid(&mut entities);
    entities
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{OneResponse, ScriptedTransport, html_ok};

    fn wrap(inner: &str) -> String {
        format!(
            "<!DOCTYPE html><html><head><meta property=\"og:title\" content=\"x\"></head><body><div class=\"tgme_page_wrap\"><div class=\"tgme_body_wrap\">\n<div class=\"tgme_page\">\n{inner}\n<!-- WEBOGRAM_BTN -->\n</div></div></div></body></html>"
        )
    }

    /// Captured from `t.me/durov` on 2026-11-07 (photo element dropped).
    fn channel() -> String {
        wrap(
            "<div class=\"tgme_page_title\" dir=\"auto\">\n  <span dir=\"auto\">Pavel Durov</span><i class=\"verified-icon\"> ✔</i>\n</div>\n<div class=\"tgme_page_extra\">10 091 124 subscribers</div>\n<div class=\"tgme_page_description\" dir=\"auto\">Founder of Telegram.</div>\n<div class=\"tgme_page_action\">\n  <a class=\"tgme_action_button_new shine\" href=\"tg://resolve?domain=durov\">View in Telegram</a>\n</div>\n<div class=\"tgme_page_context_link_wrap\"><a class=\"tgme_page_context_link\" href=\"/s/durov\">Preview channel</a></div>",
        )
    }

    /// Captured from `t.me/ru_python` on 2026-11-07.
    fn group() -> String {
        wrap(
            "<div class=\"tgme_page_title\" dir=\"auto\">\n  <span dir=\"auto\">Python</span>\n</div>\n<div class=\"tgme_page_extra\">16 998 members, 1 635 online</div>\n<div class=\"tgme_page_description\" dir=\"auto\">Уютный чат.<br/><br/>Как не получить бан: <br/>https://t.me/ru_python/2755095</div>\n<div class=\"tgme_page_action\">\n  <a class=\"tgme_action_button_new shine\" href=\"tg://resolve?domain=ru_python\">View in Telegram</a>\n</div>",
        )
    }

    /// Captured from `t.me/BotFather` on 2026-11-07.
    fn bot() -> String {
        wrap(
            "<div class=\"tgme_page_title\"><span dir=\"auto\">BotFather</span><i class=\"verified-icon\"> ✔</i></div>\n<div class=\"tgme_page_extra\">\n  @BotFather\n</div>\n<div class=\"tgme_page_extra\">8 045 824 monthly users</div>\n<div class=\"tgme_page_description \">BotFather is the one bot to rule them all.</div>\n<div class=\"tgme_page_action\">\n  <a class=\"tgme_action_button_new shine\" href=\"tg://resolve?domain=BotFather\">Start Bot</a>\n</div>",
        )
    }

    /// Captured from `t.me/zzqqxxnobody9381` on 2026-11-07: the page for an unowned handle.
    fn placeholder() -> String {
        wrap(
            "<div class=\"tgme_page_icon\">\n  <i class=\"tgme_icon_user\"></i>\n</div>\n<div class=\"tgme_page_description\">\n  If you have <strong>Telegram</strong>, you can contact <a class=\"tgme_username_link\" href=\"tg://resolve?domain=zzqqxxnobody9381\">@zzqqxxnobody9381</a> right away.\n</div>\n<div class=\"tgme_page_action\">\n  <a class=\"tgme_action_button_new\" href=\"tg://resolve?domain=zzqqxxnobody9381\">Send Message</a>\n</div>",
        )
    }

    fn user() -> String {
        wrap(
            "<div class=\"tgme_page_title\" dir=\"auto\"><span dir=\"auto\">Ada &amp; Co</span></div>\n<div class=\"tgme_page_extra\">@ada_lovelace</div>\n<div class=\"tgme_page_description\" dir=\"auto\">Mail press@example.org, site <a href=\"https://ada.example.org/about\">ada.example.org</a>, partner https://t.me/s/partner_chan and me t.me/ada_lovelace</div>\n<div class=\"tgme_page_action\"><a class=\"tgme_action_button_new\" href=\"tg://resolve?domain=ada_lovelace\">Send Message</a></div>",
        )
    }

    fn report_of(body: &str, handle: &str) -> Report {
        let transport = ScriptedTransport::new(vec![Ok(html_ok(body))]);
        lookup(&transport, handle, "scan-tg", 1).expect("lookup runs")
    }

    fn has(report: &Report, kind: &EntityKind, value: &str) -> bool {
        report
            .entities
            .iter()
            .any(|e| e.kind == *kind && e.raw_value == value)
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
    fn valid_handle_follows_telegram_grammar() {
        assert!(valid_handle("durov"));
        assert!(valid_handle("Bot_Father1"));
        assert!(!valid_handle("abcd"));
        assert!(!valid_handle("1abcde"));
        assert!(!valid_handle("abcde_"));
        assert!(!valid_handle("ab__cd"));
        assert!(!valid_handle("ab-cde"));
        assert!(!valid_handle("joinchat"));
        assert!(!valid_handle(&"a".repeat(33)));
    }

    #[test]
    fn handle_from_link_reads_names_and_skips_routes() {
        assert_eq!(
            handle_from_link("https://t.me/Durov").as_deref(),
            Some("durov")
        );
        assert_eq!(
            handle_from_link("https://t.me/s/durov").as_deref(),
            Some("durov")
        );
        assert_eq!(
            handle_from_link("https://t.me/durov/552").as_deref(),
            Some("durov")
        );
        assert_eq!(
            handle_from_link("http://www.telegram.me/durov?x=1").as_deref(),
            Some("durov")
        );
        assert_eq!(handle_from_link("t.me/durov").as_deref(), Some("durov"));
        assert_eq!(handle_from_link("https://t.me/joinchat/AAAA"), None);
        assert_eq!(handle_from_link("https://t.me/+AbCdEf"), None);
        assert_eq!(handle_from_link("https://t.me/c/123/4"), None);
        assert_eq!(handle_from_link("https://example.org/durov"), None);
        assert_eq!(handle_from_link("https://evilt.me/durov"), None);
    }

    #[test]
    fn a_channel_is_confirmed_with_its_subscribers_and_badge() {
        let report = report_of(&channel(), "durov");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(has(&report, &EntityKind::Username, "durov"));
        assert!(has(&report, &EntityKind::Url, "https://t.me/durov"));
        assert_eq!(attr(&report, "telegram_kind"), Some("channel"));
        assert_eq!(attr(&report, "subscribers"), Some("10091124"));
        assert_eq!(attr(&report, "verified"), Some("true"));
        assert_eq!(attr(&report, "title"), Some("Pavel Durov"));
        assert_eq!(attr(&report, "description"), Some("Founder of Telegram."));
        assert!(
            !report.entities.iter().any(|e| e.kind == EntityKind::Person),
            "a page title is never promoted to a Person"
        );
    }

    #[test]
    fn a_group_keeps_members_and_online_and_skips_its_own_post_link() {
        let report = report_of(&group(), "ru_python");
        assert_eq!(attr(&report, "telegram_kind"), Some("group"));
        assert_eq!(attr(&report, "members"), Some("16998"));
        assert_eq!(attr(&report, "online"), Some("1635"));
        assert_eq!(attr(&report, "verified"), Some("false"));
        let urls = report
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Url)
            .count();
        assert_eq!(urls, 1, "a link to the group's own post is not a new lead");
    }

    #[test]
    fn a_bot_is_classified_by_its_markers() {
        let report = report_of(&bot(), "BotFather");
        assert_eq!(attr(&report, "telegram_kind"), Some("bot"));
        assert_eq!(attr(&report, "monthly_users"), Some("8045824"));
        assert!(report.entities.iter().any(|e| e.has_tag("telegram-bot")));
    }

    #[test]
    fn a_user_description_yields_candidate_leads_and_a_telegram_pivot() {
        let report = report_of(&user(), "ada_lovelace");
        assert_eq!(attr(&report, "telegram_kind"), Some("user"));
        assert_eq!(attr(&report, "title"), Some("Ada & Co"));
        assert!(report.entities.iter().any(|e| e.kind == EntityKind::Email
            && e.raw_value == "press@example.org"
            && e.has_tag(crate::tags::CANDIDATE)));
        assert!(has(
            &report,
            &EntityKind::Url,
            "https://ada.example.org/about"
        ));
        assert!(has(&report, &EntityKind::Domain, "ada.example.org"));
        assert!(report.entities.iter().any(|e| e.kind == EntityKind::Url
            && e.raw_value == "https://t.me/partner_chan"
            && e.has_tag("telegram-pivot")));
        let own = report
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Url && e.raw_value.contains("ada_lovelace"))
            .count();
        assert_eq!(own, 1, "the page's own link appears once");
    }

    #[test]
    fn the_placeholder_page_is_inconclusive_never_a_clean_zero() {
        let report = report_of(&placeholder(), "zzqqxxnobody9381");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Inconclusive);
        assert_ne!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn a_redirect_is_inconclusive() {
        let transport =
            OneResponse::with_headers(302, &[("location", "https://telegram.org/")], "");
        let report = lookup(&transport, "durovxx", "scan-tg", 1).expect("lookup runs");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Inconclusive);
    }

    #[test]
    fn a_page_without_markers_is_parser_drift() {
        let report = report_of("<html><body>maintenance</body></html>", "durov");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ParserDrift);
    }

    #[test]
    fn a_server_error_is_not_absence() {
        let transport = OneResponse::with_headers(500, &[], "oops");
        let report = lookup(&transport, "durov", "scan-tg", 1).expect("lookup runs");
        assert!(report.entities.is_empty());
        assert_ne!(report.outcome.kind, SourceOutcomeKind::ValidZero);
        assert_ne!(report.outcome.kind, SourceOutcomeKind::Success);
    }

    #[test]
    fn an_invalid_handle_never_reaches_the_network() {
        let transport = ScriptedTransport::new(vec![]);
        let report = lookup(&transport, "bad handle", "scan-tg", 1).expect("lookup runs");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Inconclusive);
    }

    #[test]
    fn counts_read_grouped_digits() {
        assert_eq!(leading_count("10 091 124"), Some(10_091_124));
        assert_eq!(leading_count("1,234"), Some(1_234));
        assert_eq!(
            count_before("16 998 members, 1 635 online", "online"),
            Some(1_635)
        );
        assert_eq!(count_before("@BotFather", "monthly users"), None);
    }
}
