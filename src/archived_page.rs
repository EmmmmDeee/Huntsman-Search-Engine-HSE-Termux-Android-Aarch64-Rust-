//! The contact details an archived web page published, read one way whichever web archive holds
//! the capture (the Internet Archive's Wayback replay, a Common Crawl WARC record).
//!
//! A source chooses at most [`MAX_PAGES`] of its captures with [`choose`] (contact, about and
//! team pages first, then the site root, then the rest, each newest first), checks each answer
//! with [`web_page`] and hands the page to [`contacts`]. Every e-mail address and phone number
//! the page shows in its text or in a `mailto:`/`tel:` link becomes a historical lead naming the
//! capture: what a page said when it was archived, never proof that it is current. Script and
//! style text, comments and attribute values other than those links are not published contacts.

use crate::canonical::canonical_url;
use crate::classifier;
use crate::domains::host_only;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, push_entity};
use crate::html_text::{Markup, Piece, attribute, html_to_text};
use crate::source_outcome::SourceExecutionOutcome;

/// Archived pages one source reads per lookup.
pub const MAX_PAGES: usize = 3;
/// Largest page body read; a larger one is named, never read in part.
pub const MAX_PAGE_BYTES: usize = 1024 * 1024;
/// Text characters of one page searched for contacts.
const MAX_PAGE_CHARS: usize = 200_000;
/// Contacts kept from one page, so a directory page cannot flood a report.
const MAX_CONTACTS_PER_PAGE: usize = 32;
/// Longest original URL kept as evidence.
const MAX_URL_BYTES: usize = 2048;
/// Ceiling on a historical contact's confidence: a page published it, nobody confirmed it since.
pub const CONFIDENCE_CAP: f64 = 0.6;
/// Path words that mark the pages most likely to publish contact details.
const CONTACT_WORDS: &[&str] = &[
    "contact",
    "about",
    "team",
    "staff",
    "people",
    "impressum",
    "imprint",
    "support",
];

/// A web-archive source's answer for one domain: its entities and its typed outcome.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

/// One capture to read: its 14-digit UTC timestamp and its canonical original URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capture {
    pub timestamp: String,
    pub url: String,
}

/// Where a capture is held: the source reporting it, the dataset named in evidence, the archive
/// named in the summary, and the address a person opens to see the capture.
#[derive(Debug, Clone)]
pub struct Archive<'a> {
    pub source: &'a str,
    pub dataset: &'a str,
    pub holder: &'a str,
    pub snapshot_url: String,
}

/// At most [`MAX_PAGES`] distinct captures, by URL: contact-like pages first, then the site
/// root, then the rest, each group newest first. **Pure.**
#[must_use]
pub fn choose(captures: impl IntoIterator<Item = Capture>) -> Vec<Capture> {
    let mut ranked: Vec<(u8, Capture)> = Vec::new();
    for capture in captures {
        if ranked.iter().any(|(_, seen)| seen.url == capture.url) {
            continue;
        }
        let path = capture
            .url
            .split_once("://")
            .and_then(|(_, rest)| rest.split_once('/'))
            .map_or("", |(_, path)| path)
            .to_ascii_lowercase();
        let rank = if CONTACT_WORDS.iter().any(|word| path.contains(word)) {
            0
        } else if path.is_empty() {
            1
        } else {
            2
        };
        ranked.push((rank, capture));
    }
    ranked.sort_by(|(a_rank, a), (b_rank, b)| {
        a_rank
            .cmp(b_rank)
            .then_with(|| b.timestamp.cmp(&a.timestamp))
            .then_with(|| a.url.cmp(&b.url))
    });
    ranked
        .into_iter()
        .take(MAX_PAGES)
        .map(|(_, capture)| capture)
        .collect()
}

/// Whether an archived answer is a web page small enough to read, or why not. **Pure.**
///
/// # Errors
/// "not a web page" for a type other than HTML or plain text, "page over 1 MiB" past
/// [`MAX_PAGE_BYTES`].
pub fn web_page(content_type: &str, bytes: usize) -> Result<(), String> {
    if !is_web_page_type(content_type) {
        return Err("not a web page".to_owned());
    }
    if bytes > MAX_PAGE_BYTES {
        return Err("page over 1 MiB".to_owned());
    }
    Ok(())
}

/// Whether `content_type` (a response's, or the type an archive's index recorded for a capture)
/// is a web page, by its media type without parameters: HTML (`text/html`, and the
/// `text/x-server-parsed-html` an old server sends for its server-side includes), XHTML (a
/// `…xhtml+xml` type) or plain text. A type that only names HTML, as a compiled help file's
/// `application/vnd.ms-htmlhelp` does, is no web page. **Pure.**
#[must_use]
pub fn is_web_page_type(content_type: &str) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let subtype = essence.split_once('/').map_or("", |(_, subtype)| subtype);
    essence == "text/plain"
        || subtype == "html"
        || subtype == "x-server-parsed-html"
        || subtype.ends_with("xhtml+xml")
}

/// The e-mail addresses and phone numbers `html` publishes in its text and in its `mailto:` and
/// `tel:` links, each a historical lead naming `capture` as held by `archive`. **Pure.**
#[must_use]
pub fn contacts(
    html: &str,
    capture: &Capture,
    archive: &Archive<'_>,
    scan_id: &str,
) -> Vec<Entity> {
    let mut text = html_to_text(html, MAX_PAGE_CHARS).unwrap_or_default();
    for piece in Markup::new(html) {
        let Piece::Tag {
            name,
            end: false,
            attrs,
        } = piece
        else {
            continue;
        };
        if !name.eq_ignore_ascii_case("a") {
            continue;
        }
        let Some(href) = attribute(attrs, "href") else {
            continue;
        };
        let href = crate::textnorm::decode_html_entities(href.trim());
        let target = href
            .strip_prefix("mailto:")
            .or_else(|| href.strip_prefix("tel:"))
            .map(|rest| {
                rest.split(['?', '#'])
                    .next()
                    .unwrap_or_default()
                    .replace("%40", "@")
                    .replace("%20", " ")
            });
        if let Some(target) = target {
            text.push(' ');
            text.push_str(&target);
        }
    }
    let mut entities = Vec::new();
    for found in classifier::extract(&text)
        .into_iter()
        .filter(|found| {
            found.is_actionable() && matches!(found.kind, EntityKind::Email | EntityKind::Phone)
        })
        .take(MAX_CONTACTS_PER_PAGE)
    {
        let evidence = Evidence::new(
            EvidenceProvenance::for_scan(archive.source, scan_id),
            format!(
                "published on {} as archived by {} at {} UTC (historical; not proof it is current)",
                capture.url, archive.holder, capture.timestamp
            ),
        )
        .with_attr("dataset", archive.dataset)
        .with_attr("capture_timestamp_utc", &capture.timestamp)
        .with_attr("original_url", &capture.url)
        .with_attr("archive_snapshot_url", &archive.snapshot_url)
        .with_attr("signal", found.signal);
        push_entity(
            &mut entities,
            found.kind,
            &found.value,
            found.confidence.min(CONFIDENCE_CAP),
            scan_id,
            evidence,
            &[archive.source, "historical_content"],
        );
    }
    entities
}

/// What an archive index's original URL is to a lookup of one domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// The canonical URL and its lowercase host, the domain or a subdomain of it.
    Admit { url: String, host: String },
    /// A URL with a query, fragment or user-info, which may carry a session token or an
    /// address: it is not persisted.
    Sensitive,
}

/// Whether an archive index's `original` URL belongs to `domain` and may be kept. **Pure.**
///
/// # Errors
/// Why the index answer is not a URL of the domain: too long, not HTTP(S), or another host.
pub fn admit(original: &str, domain: &str) -> Result<Admission, &'static str> {
    if original.len() > MAX_URL_BYTES {
        return Err("a capture URL over the local evidence limit");
    }
    let Some(url) = canonical_url(original) else {
        return Err("an invalid HTTP(S) URL");
    };
    let host = host_only(&url).trim_end_matches('.').to_ascii_lowercase();
    if host != domain
        && !host
            .strip_suffix(domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
    {
        return Err("a URL outside the requested domain");
    }
    if original
        .bytes()
        .any(|byte| matches!(byte, b'?' | b'#' | b'@'))
    {
        return Ok(Admission::Sensitive);
    }
    Ok(Admission::Admit { url, host })
}

/// Whether `raw` is a real `YYYYMMDDhhmmss` UTC instant: a calendar date (leap years included)
/// and a time of day. **Pure.**
#[must_use]
pub fn valid_timestamp(raw: &str) -> bool {
    if raw.len() != 14 || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let parse = |start: usize, end: usize| raw[start..end].parse::<u32>().ok();
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        parse(0, 4),
        parse(4, 6),
        parse(6, 8),
        parse(8, 10),
        parse(10, 12),
        parse(12, 14),
    ) else {
        return false;
    };
    if year == 0 || hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A web page is HTML, XHTML or plain text by its media type, whatever its parameters or
    /// case; a type that only names HTML is none.
    #[test]
    fn a_web_page_is_html_xhtml_or_plain_text_by_its_media_type() {
        for page in [
            "text/html",
            "TEXT/HTML; charset=utf-8",
            "application/xhtml+xml",
            "application/vnd.wap.xhtml+xml",
            "text/x-server-parsed-html",
            "text/plain; charset=iso-8859-1",
        ] {
            assert!(is_web_page_type(page), "{page}");
        }
        for other in [
            "application/vnd.ms-htmlhelp",
            "application/pdf",
            "image/png",
            "text/plainly",
            "",
        ] {
            assert!(!is_web_page_type(other), "{other}");
        }
    }

    fn capture(timestamp: &str, url: &str) -> Capture {
        Capture {
            timestamp: timestamp.to_owned(),
            url: url.to_owned(),
        }
    }

    #[test]
    fn contact_pages_come_first_then_the_root_then_the_newest_rest() {
        let chosen = choose([
            capture("20240101000000", "https://example.org/b"),
            capture("20180101000000", "https://example.org/about"),
            capture("20220101000000", "https://example.org"),
            capture("20230101000000", "https://example.org/team"),
            capture("20250101000000", "https://example.org/team"),
        ]);
        let urls: Vec<&str> = chosen.iter().map(|c| c.url.as_str()).collect();
        assert_eq!(
            urls,
            [
                "https://example.org/team",
                "https://example.org/about",
                "https://example.org"
            ]
        );
        // The first capture of a URL is kept; a later duplicate is not a second page.
        assert_eq!(chosen[0].timestamp, "20230101000000");
    }

    #[test]
    fn only_bounded_web_pages_are_read() {
        assert!(web_page("text/html; charset=utf-8", 10).is_ok());
        assert!(web_page("TEXT/PLAIN", 10).is_ok());
        assert_eq!(web_page("image/png", 10).unwrap_err(), "not a web page");
        assert_eq!(
            web_page("text/html", MAX_PAGE_BYTES + 1).unwrap_err(),
            "page over 1 MiB"
        );
        assert!(web_page("text/html", MAX_PAGE_BYTES).is_ok());
    }

    #[test]
    fn contacts_name_the_archive_and_capture_and_are_capped() {
        let archive = Archive {
            source: "test_archive",
            dataset: "Test dataset",
            holder: "the test archive",
            snapshot_url: "https://archive.test/snap".to_owned(),
        };
        let found = contacts(
            r#"<p>Mail <a href="mailto:desk%40example.org">desk</a>, tel 555-0123.</p><script>x="hidden@example.org"</script>"#,
            &capture("20200101000000", "https://example.org/contact"),
            &archive,
            "scan",
        );
        let email = found
            .iter()
            .find(|e| e.value == "desk@example.org")
            .unwrap_or_else(|| panic!("{found:?}"));
        assert!(email.has_tag("test_archive") && email.has_tag("historical_content"));
        assert!(email.confidence <= CONFIDENCE_CAP);
        let evidence = &email.evidence[0];
        assert!(evidence.summary.contains("archived by the test archive"));
        assert_eq!(evidence.attr_values("dataset").next(), Some("Test dataset"));
        assert_eq!(
            evidence.attr_values("archive_snapshot_url").next(),
            Some("https://archive.test/snap")
        );
        assert!(!found.iter().any(|e| e.value.contains("hidden")));
    }

    #[test]
    fn timestamp_rejects_impossible_calendar_dates_and_times() {
        for invalid in [
            "00000101000000",
            "20261301000000",
            "20260001000000",
            "20260431000000",
            "20230229000000",
            "19000229000000",
            "20240230000000",
            "20240101240000",
            "20240101236000",
            "20240101235960",
            "2024010123595x",
        ] {
            assert!(!valid_timestamp(invalid), "{invalid}");
        }
        for valid in ["20000229000000", "20240229235959", "20241231235959"] {
            assert!(valid_timestamp(valid), "{valid}");
        }
    }

    #[test]
    fn only_urls_of_the_domain_are_admitted_and_query_urls_are_withheld() {
        assert_eq!(
            admit("https://old.example.org/a", "example.org"),
            Ok(Admission::Admit {
                url: "https://old.example.org/a".to_owned(),
                host: "old.example.org".to_owned()
            })
        );
        assert_eq!(
            admit("https://example.org/?token=x", "example.org"),
            Ok(Admission::Sensitive)
        );
        assert!(admit("https://fakeexample.org/", "example.org").is_err());
        assert!(admit("ftp://example.org/", "example.org").is_err());
        assert!(
            admit(
                &format!("https://example.org/{}", "a".repeat(2048)),
                "example.org"
            )
            .is_err()
        );
    }
}
