//! Australian people-finder — True People Search AU HTML scrape.
//!
//! Endpoint: `https://www.truepeoplesearch.com.au/results?name={Full+Name}`
//! (keyless). Blocking, over an injected [`crate::http::Transport`]. Challenge
//! pages, truncated bodies, and non-success HTTP statuses other than 404 are
//! never turned into evidence. A 404 is treated as a validated empty answer
//! (the results path moved, not a statement about the person).
//!
//! White Pages AU is retired (live 404 since 2026-07-13) and is not queried.
//! Addresses and emails from the results page are candidate leads: the scan
//! cannot attribute a line to the subject. Coordinates use
//! [`crate::postcode_au::offline_centroid`] (L3), not `geo` (L6). ATT&CK
//! self-labels from the legacy module are not copied. Not called from `people`.

use std::collections::HashSet;

use crate::address_au;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::error::Error;
use crate::fetch::{self, FetchOptions, Fetched};
use crate::http::{self, Request, Transport};
use crate::postcode_au;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};
use crate::textnorm::{find_ascii_ci, title_case};

const SRC: &str = "au_people";
const SEARCH_BASE: &str = "https://www.truepeoplesearch.com.au/results";
const DATASET: &str = "True People Search AU";

/// Listed address before candidate demotion (legacy `confidence::MEDIUM_LIGHT`).
const CONF_ADDRESS: f64 = 0.52;
/// Contact email before candidate demotion (legacy `confidence::LOW_MEDIUM`).
const CONF_EMAIL: f64 = 0.45;
/// Same-surname relative (legacy `confidence::LOW_MEDIUM`; below MEDIUM expansion).
const CONF_RELATIVE: f64 = 0.45;
/// Name confirmed by a genuine TPS address line (legacy `confidence::NOTABLE`).
const CONF_PERSON: f64 = 0.62;

const RELATIVE_WINDOW: usize = 300;
const RELATIVE_PHRASES: &[&str] = &[
    "possible relatives",
    "possible associates",
    "known associates",
    "household members",
    "household member",
    "also known as",
    "related to",
    "lives with",
    "relatives",
    "associates",
];

const NAME_CHROME: &[&str] = &[
    "view",
    "profile",
    "background",
    "check",
    "search",
    "report",
    "address",
    "phone",
    "age",
    "record",
    "records",
    "details",
    "more",
    "see",
    "full",
    "results",
    "result",
    "public",
    "people",
    "find",
    "lookup",
    "contact",
    "email",
    "relatives",
    "associates",
    "possible",
    "known",
    "related",
    "lives",
    "household",
    "also",
    "aka",
    "name",
    "names",
    "mobile",
    "landline",
    "current",
    "former",
    "city",
    "state",
    "suburb",
    "this",
    "person",
    "and",
    "the",
    "with",
    "nsw",
    "vic",
    "qld",
    "sa",
    "wa",
    "tas",
    "act",
    "nt",
];

/// One name lookup against True People Search AU.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

/// Look up residential-directory listings for `name`.
///
/// A name with fewer than two alphabetic tokens of length ≥ 2 makes no request.
/// Egress refusals are [`Error::Network`]. An unreadable or challenged response
/// with no entities is [`Error::Invalid`]. HTTP 404 and a validated empty
/// answer are empty reports.
///
/// # Errors
///
/// [`Error::Network`] when egress blocks the request. [`Error::Invalid`] when
/// the request never produced readable HTML and nothing was emitted.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    name: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let full_name = name.trim();
    let (first, last) = split_name(full_name);
    if name_tokens(full_name).len() < 2 || first.is_empty() || last.is_empty() {
        return Ok(Report {
            entities: Vec::new(),
            outcomes: Vec::new(),
        });
    }

    let options = FetchOptions {
        max_redirects: fetch::DEFAULT_MAX_REDIRECTS,
    };
    let url = http::append_query_param(SEARCH_BASE, "name", full_name);
    let request = Request::get(url)
        .header("User-Agent", http::DEFAULT_USER_AGENT)
        .header("Accept", "text/html,application/xhtml+xml");
    let fetched = fetch::fetch(transport, request, None, &options, SRC, now_unix)?;
    let (outcome, mut entities) = parse_fetched(fetched, full_name, scan_id, now_unix);
    let html_read_ok = outcome.kind.is_accepted();
    let found_any = !entities.is_empty();
    if request_failed(html_read_ok, found_any) {
        return Err(Error::Invalid(outcome.detail.clone().unwrap_or_else(
            || {
                "True People Search AU request failed at the transport level, returned a \
             non-success HTTP status, was truncated, or was a challenge page — not \
             \"no directory records for this name\""
                    .into()
            },
        )));
    }
    merge_by_uid(&mut entities);
    Ok(Report {
        entities,
        outcomes: vec![outcome],
    })
}

/// Split a full name into first/last for URL construction. `last` is every
/// token after the first.
#[must_use]
pub fn split_name(full: &str) -> (&str, &str) {
    let trimmed = full.trim();
    if let Some(pos) = trimmed.find(' ') {
        (&trimmed[..pos], trimmed[pos + 1..].trim_start())
    } else {
        (trimmed, "")
    }
}

fn parse_fetched(
    fetched: Fetched,
    full_name: &str,
    scan_id: &str,
    now_unix: u64,
) -> (SourceExecutionOutcome, Vec<Entity>) {
    let some_status = |kind: SourceOutcomeKind, status: Option<u16>, detail: Option<String>| {
        let mut outcome = SourceExecutionOutcome::success(SRC, now_unix, 0);
        outcome.kind = kind;
        outcome.found = None;
        outcome.http_status = status;
        outcome.detail = detail;
        (outcome, Vec::new())
    };

    let Some(response) = fetched.response else {
        return (fetched.outcome, Vec::new());
    };
    if response.truncated {
        return some_status(
            SourceOutcomeKind::ParserDrift,
            Some(response.status),
            Some("truncated True People Search AU body is not evidence".into()),
        );
    }
    let html = String::from_utf8_lossy(&response.body);
    let kind = classify_fetch(response.status, &html);
    if kind == SourceOutcomeKind::BotWaf {
        return some_status(
            SourceOutcomeKind::BotWaf,
            Some(response.status),
            Some("challenge page is not evidence".into()),
        );
    }
    if response.status == 404 {
        return (
            SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(404),
            Vec::new(),
        );
    }
    if !(200..300).contains(&response.status) {
        return some_status(
            kind,
            Some(response.status),
            Some(format!(
                "HTTP {} is not a readable directory page",
                response.status
            )),
        );
    }

    let mut entities = parse_tps_html(&html, full_name, scan_id);
    entities.extend(parse_relatives(&html, full_name, scan_id));
    if entities
        .iter()
        .any(|e| e.kind == EntityKind::Address && e.has_tag("tps-au"))
    {
        let mut person = Entity::new(EntityKind::Person, full_name, CONF_PERSON, scan_id);
        person.tag(SRC);
        person.tag("au-directory");
        person.tag("confirmed-in-directory");
        person.add_evidence(
            Evidence::new(
                provenance(scan_id),
                format!("Name '{full_name}' found in AU residential directory"),
            )
            .with_attr("source", "tps_au")
            .with_attr("dataset", DATASET),
        );
        entities.push(person);
    }
    let outcome = if entities.is_empty() {
        SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(response.status)
    } else {
        SourceExecutionOutcome::success(SRC, now_unix, entities.len())
            .with_http_status(response.status)
    };
    (outcome, entities)
}

fn name_tokens(full: &str) -> Vec<String> {
    full.split(|c: char| !c.is_alphabetic())
        .filter(|token| token.len() >= 2)
        .map(str::to_ascii_lowercase)
        .collect()
}

fn merge_by_uid(entities: &mut Vec<Entity>) {
    let mut merged: Vec<Entity> = Vec::new();
    for entity in entities.drain(..) {
        if let Some(existing) = merged.iter_mut().find(|seen| seen.uid == entity.uid) {
            existing.absorb(entity);
        } else {
            merged.push(entity);
        }
    }
    *entities = merged;
}

fn provenance(scan_id: &str) -> EvidenceProvenance {
    EvidenceProvenance::for_scan(SRC, scan_id)
}

fn state_tag_from_text(text: &str) -> Option<String> {
    address_au::state_code(text).map(|s| format!("au-state:{s}"))
}

fn tps_display_postcode(value: &str) -> bool {
    postcode_au::is_shaped(value)
        && value
            .parse::<u32>()
            .is_ok_and(|n| (2000..=7999).contains(&n))
}

fn postcode_in_line(line: &str) -> Option<&str> {
    line.split_whitespace()
        .find(|tok| tps_display_postcode(tok))
}

fn parse_tps_html(html: &str, full_name: &str, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let stripped = strip_html(html);

    for line in stripped.lines().map(str::trim) {
        if !(6..=120).contains(&line.len()) {
            continue;
        }
        if address_au::state_code(line).is_none() {
            continue;
        }
        if postcode_in_line(line).is_none() {
            continue;
        }
        let mut ae = Entity::new(EntityKind::Address, line, CONF_ADDRESS, scan_id);
        ae.tag(SRC);
        ae.tag("au-directory");
        ae.tag("tps-au");
        ae.tag("country:AU");
        if let Some(st) = state_tag_from_text(line) {
            ae.tag(st);
        }
        ae.add_evidence(
            Evidence::new(
                provenance(scan_id),
                format!(
                    "Address listed on the True People Search AU results page for {full_name} (attribution unconfirmed)"
                ),
            )
            .with_attr("line", line)
            .with_attr("source", "tps_au")
            .with_attr("dataset", DATASET),
        );
        ae.demote_to_candidate();
        out.push(ae);
    }

    let tps_coords: Vec<_> = out
        .iter()
        .filter(|e| e.kind == EntityKind::Address && e.has_tag("tps-au"))
        .filter_map(|e| {
            let pcode = postcode_in_line(&e.value)?;
            let (lat, lon) = postcode_au::offline_centroid(pcode)?;
            let coord_val = format!("{lat:.4},{lon:.4}");
            let mut c = Entity::new(EntityKind::Coordinates, &coord_val, CONF_ADDRESS, scan_id);
            c.tag(SRC);
            c.tag("addr-derived");
            c.tag("geoint");
            c.tag("country:AU");
            c.add_evidence(Evidence::new(
                provenance(scan_id),
                format!(
                    "Geocode of an address listed on the True People Search AU results page for {full_name} (attribution unconfirmed)"
                ),
            ).with_attr("dataset", DATASET));
            c.demote_to_candidate();
            Some(c)
        })
        .collect();
    out.extend(tps_coords);

    out.extend(page_emails(&stripped).into_iter().map(|email| {
        let mut e = Entity::new(EntityKind::Email, &email, CONF_EMAIL, scan_id);
        e.tag(SRC);
        e.tag("au-directory");
        e.tag("tps-au");
        e.add_evidence(
            Evidence::new(
                provenance(scan_id),
                format!("TPS AU contact email for {full_name} (attribution unconfirmed)"),
            )
            .with_attr("source", "tps_au")
            .with_attr("dataset", DATASET),
        );
        e.demote_to_candidate();
        e
    }));

    out
}

fn parse_relatives(html: &str, full_name: &str, scan_id: &str) -> Vec<Entity> {
    let text = strip_html(html);
    let full = full_name.trim();
    let surname_lc = match full.rsplit(' ').next() {
        Some(s) if s.chars().filter(char::is_ascii_alphabetic).count() >= 2 => s.to_lowercase(),
        _ => return Vec::new(),
    };
    let subject_lc = full.to_lowercase();

    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for window in relative_windows(&text) {
        let words: Vec<&str> = window.split_whitespace().collect();
        for (i, w) in words.iter().enumerate() {
            if strip_punct(w) != surname_lc {
                continue;
            }
            let mut given: Vec<&str> = Vec::new();
            for j in (0..i).rev() {
                if given.len() >= 2 || !is_name_token(words[j]) {
                    break;
                }
                given.push(words[j]);
            }
            if given.is_empty() {
                continue;
            }
            given.reverse();
            let raw = format!(
                "{} {}",
                given.join(" "),
                w.trim_matches(|c: char| !c.is_alphabetic())
            );
            let name = title_case(&raw);
            let name_lc = name.to_lowercase();
            if name.len() < 5 || name_lc == subject_lc || !seen.insert(name_lc) {
                continue;
            }
            let mut e = Entity::new(EntityKind::Person, &name, CONF_RELATIVE, scan_id);
            e.tag(SRC);
            e.tag("au-directory");
            e.tag("relatives");
            e.tag("family-candidate");
            e.tag("country:AU");
            e.add_evidence(
                Evidence::new(
                    provenance(scan_id),
                    format!("AU residential directory lists {name} as a relative of {full}"),
                )
                .with_attr("relationship", "relative")
                .with_attr("related_to", full)
                .with_attr("source", "au_people_relatives")
                .with_attr("dataset", DATASET),
            );
            out.push(e);
        }
    }
    out
}

fn strip_punct(w: &str) -> String {
    w.trim_matches(|c: char| !c.is_alphabetic()).to_lowercase()
}

fn is_name_token(t: &str) -> bool {
    let tl = strip_punct(t);
    t.chars().next().is_some_and(char::is_uppercase)
        && t.len() <= 20
        && t.chars()
            .all(|c| c.is_alphabetic() || matches!(c, '.' | '\'' | '-'))
        && !NAME_CHROME.contains(&tl.as_str())
}

fn relative_windows(text: &str) -> Vec<String> {
    let mut windows = Vec::new();
    let mut offset = 0;
    while offset < text.len() {
        let rest = &text[offset..];
        let mut best: Option<(usize, usize)> = None;
        for phrase in RELATIVE_PHRASES {
            let Some(at) = find_ascii_ci(rest, phrase) else {
                continue;
            };
            if !is_word_bounded(rest, at, phrase.len()) {
                continue;
            }
            if best.is_none_or(|(best_at, _)| at < best_at) {
                best = Some((at, phrase.len()));
            }
        }
        let Some((at, plen)) = best else {
            break;
        };
        let after = offset + at + plen;
        let window: String = text[after..].chars().take(RELATIVE_WINDOW).collect();
        windows.push(window);
        offset = after;
    }
    windows
}

fn is_word_bounded(hay: &str, start: usize, needle_len: usize) -> bool {
    let before_ok = start == 0
        || hay[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_ascii_alphanumeric());
    let end = start + needle_len;
    let after_ok = end >= hay.len()
        || hay[end..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_ascii_alphanumeric());
    before_ok && after_ok
}

fn strip_html(html: &str) -> String {
    decode_entities(&replace_tags_with_space(&drop_script_and_style(html)))
}

fn drop_script_and_style(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let mut out = String::with_capacity(html.len());
    let mut i = 0;
    while i < html.len() {
        if lower[i..].starts_with("<script") {
            if let Some(end) = lower[i..].find("</script>") {
                i += end + "</script>".len();
                out.push(' ');
                continue;
            }
            break;
        }
        if lower[i..].starts_with("<style") {
            if let Some(end) = lower[i..].find("</style>") {
                i += end + "</style>".len();
                out.push(' ');
                continue;
            }
            break;
        }
        let ch = html[i..].chars().next().expect("non-empty");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn replace_tags_with_space(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    let mut tag = String::new();
    for c in s.chars() {
        if in_tag {
            if c == '>' {
                in_tag = false;
                let name = tag
                    .trim_start_matches('/')
                    .split(|ch: char| ch.is_whitespace() || ch == '/')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if matches!(
                    name.as_str(),
                    "p" | "div"
                        | "li"
                        | "tr"
                        | "br"
                        | "h1"
                        | "h2"
                        | "h3"
                        | "h4"
                        | "h5"
                        | "ul"
                        | "ol"
                        | "table"
                        | "section"
                ) {
                    out.push('\n');
                } else {
                    out.push(' ');
                }
                tag.clear();
            } else {
                tag.push(c);
            }
        } else if c == '<' {
            in_tag = true;
            tag.clear();
        } else {
            out.push(c);
        }
    }
    out
}

fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while !rest.is_empty() {
        let decoded = if rest.as_bytes()[0] == b'&' {
            decode_one_entity(rest)
        } else {
            None
        };
        if let Some((ch, consumed)) = decoded {
            out.push(ch);
            rest = &rest[consumed..];
        } else {
            let ch = rest.chars().next().expect("non-empty");
            out.push(ch);
            rest = &rest[ch.len_utf8()..];
        }
    }
    out
}

fn decode_one_entity(rest: &str) -> Option<(char, usize)> {
    let after_amp = rest.get(1..)?;
    if after_amp.starts_with('#') {
        let hex = after_amp
            .as_bytes()
            .get(1)
            .is_some_and(|b| *b == b'x' || *b == b'X');
        let digits = if hex {
            after_amp.get(2..)?
        } else {
            after_amp.get(1..)?
        };
        let end = digits.find(';')?;
        let raw = &digits[..end];
        if raw.is_empty() {
            return None;
        }
        let value = if hex {
            u32::from_str_radix(raw, 16).ok()?
        } else {
            raw.parse::<u32>().ok()?
        };
        let ch = char::from_u32(value)?;
        let consumed = 2 + usize::from(hex) + raw.len() + 1;
        return Some((ch, consumed));
    }
    let end = after_amp.find(';')?;
    let name = &after_amp[..end];
    let ch = match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        "nbsp" => ' ',
        _ => return None,
    };
    Some((ch, 1 + name.len() + 1))
}

fn page_emails(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'@' || i == 0 || i + 1 >= bytes.len() {
            i += 1;
            continue;
        }
        if !is_email_local_byte(bytes[i - 1]) || !bytes[i + 1].is_ascii_alphanumeric() {
            i += 1;
            continue;
        }
        let mut local_start = i;
        while local_start > 0 && is_email_local_byte(bytes[local_start - 1]) {
            local_start -= 1;
        }
        let mut domain_end = i + 1;
        while domain_end < bytes.len() && is_domain_byte(bytes[domain_end]) {
            domain_end += 1;
        }
        while domain_end > i + 1 && bytes[domain_end - 1] == b'.' {
            domain_end -= 1;
        }
        let Ok(domain) = std::str::from_utf8(&bytes[i + 1..domain_end]) else {
            i += 1;
            continue;
        };
        if local_start < i && host_has_alpha_tld(domain) && domain_end - local_start <= 254 {
            let email = text[local_start..domain_end].to_ascii_lowercase();
            let local_lower = &email[..i - local_start];
            let is_asset = email.contains("@2x.")
                || email.contains("@3x.")
                || matches!(
                    email.rsplit_once('.').map(|(_, ext)| ext),
                    Some("png" | "jpg" | "gif" | "webp")
                );
            let is_script = local_lower.contains(".php") || local_lower.contains(".html");
            if !is_asset && !is_script && seen.insert(email.clone()) {
                out.push(email);
            }
        }
        i = domain_end.max(i + 1);
    }
    out
}

fn is_email_local_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn is_domain_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')
}

fn host_has_alpha_tld(domain: &str) -> bool {
    let tld = domain.rsplit('.').next().unwrap_or("");
    tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic()) && domain.contains('.')
}

fn request_failed(html_read_ok: bool, found_any_entity: bool) -> bool {
    !html_read_ok && !found_any_entity
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use crate::entity;
    use crate::http::{Response, TransportFailure};
    use crate::tags;

    struct Fake {
        script: RefCell<VecDeque<Result<Response, TransportFailure>>>,
        seen: RefCell<Vec<Request>>,
    }

    impl Fake {
        fn new(script: Vec<Result<Response, TransportFailure>>) -> Self {
            Self {
                script: RefCell::new(script.into()),
                seen: RefCell::new(Vec::new()),
            }
        }
    }

    impl Transport for Fake {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.seen.borrow_mut().push(request.clone());
            self.script.borrow_mut().pop_front().unwrap_or_else(|| {
                Err(TransportFailure {
                    kind: SourceOutcomeKind::ConnectFailure,
                    detail: "unexpected request".into(),
                    blocked: false,
                })
            })
        }
    }

    fn html_ok(body: &str) -> Response {
        Response {
            status: 200,
            headers: vec![("content-type".into(), "text/html".into())],
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    #[test]
    fn single_token_name_makes_no_request() {
        let fake = Fake::new(vec![Ok(html_ok("unused"))]);
        let report = lookup(&fake, "Haigen", "t", 1).expect("no-op");
        let empty = report.entities.is_empty();
        assert!(empty);
        let seen = fake.seen.borrow();
        assert!(seen.is_empty(), "{seen:?}");
    }

    #[test]
    fn lookup_emits_candidate_address_and_person_from_scripted_html() {
        let html = "<div>Results for Haigen Bamford</div><p>Sydney NSW 2000</p>";
        let fake = Fake::new(vec![Ok(html_ok(html))]);
        let report = lookup(&fake, "Haigen Bamford", "scan", 1).expect("lookup");
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Address && e.has_tag("tps-au")),
            "expected address: {:?}",
            report.entities
        );
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Person && e.has_tag("confirmed-in-directory")),
            "expected person anchor: {:?}",
            report.entities
        );
        let seen = fake.seen.borrow();
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0].url.contains("truepeoplesearch.com.au"),
            "{}",
            seen[0].url
        );
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::Success);
    }

    #[test]
    fn challenge_page_is_not_a_directory_miss() {
        let fake = Fake::new(vec![Ok(Response {
            status: 200,
            headers: vec![("content-type".into(), "text/html".into())],
            body: b"<html>Just a moment... cloudflare checking your browser</html>".to_vec(),
            truncated: false,
        })]);
        let err = lookup(&fake, "Haigen Bamford", "scan", 1).expect_err("waf");
        assert!(matches!(err, Error::Invalid(_)), "{err}");
    }

    #[test]
    fn http_404_is_valid_zero() {
        let fake = Fake::new(vec![Ok(Response {
            status: 404,
            headers: Vec::new(),
            body: b"not found".to_vec(),
            truncated: false,
        })]);
        let report = lookup(&fake, "Haigen Bamford", "scan", 1).expect("404");
        let empty = report.entities.is_empty();
        assert!(empty, "{:?}", report.entities);
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn parse_relatives_extracts_same_surname_family_and_binds_to_subject() {
        let html = r"
      <h2>Possible Relatives</h2>
      <ul>
        <li><a href='/x'>Stephen R Moreau</a> — View Profile</li>
        <li><a href='/y'>HELENE MOREAU</a> Background Check</li>
        <li>Marianne Moreau, Sunshine Coast QLD</li>
        <li>Fletcher Moreau (this person)</li>
      </ul>
      <h2>Possible Associates</h2>
      <p>Jane Smith and Bob Jones also appear.</p>
    ";
        let rel = parse_relatives(html, "Fletcher Moreau", "s");
        let names: std::collections::BTreeSet<&str> =
            rel.iter().map(|e| e.value.as_str()).collect();

        assert!(
            names.contains("stephen r moreau"),
            "title-case + middle initial, then Entity canonical_name: {names:?}"
        );
        assert!(
            names.contains("helene moreau"),
            "UPPER-case normalised, then Entity canonical_name: {names:?}"
        );
        assert!(names.contains("marianne moreau"), "{names:?}");
        assert!(
            !names.contains("fletcher moreau"),
            "the subject is never their own relative: {names:?}"
        );
        assert!(
            !names
                .iter()
                .any(|n| n.contains("Smith") || n.contains("Jones"))
        );

        for e in &rel {
            assert_eq!(e.kind, EntityKind::Person);
            assert!(e.has_tag("family-candidate") && e.has_tag("relatives"));
            assert!(
                e.confidence < 0.50,
                "below the expansion floor (recorded, not auto-pivoted)"
            );
            let related = e
                .evidence
                .iter()
                .find_map(|ev| ev.attributes.get("related_to"))
                .map(String::as_str);
            assert_eq!(related, Some("Fletcher Moreau"), "bound to the subject");
        }

        let none = parse_relatives(
            "<p>No results found for that name.</p>",
            "Fletcher Moreau",
            "s",
        );
        assert!(none.is_empty(), "{none:?}");
    }

    #[test]
    fn parse_relatives_entities_never_carry_the_tps_au_anchor_tag() {
        let html = r"
      <h2>Possible Relatives</h2>
      <ul>
        <li><a href='/x'>Stephen R Moreau</a> — View Profile</li>
        <li><a href='/y'>HELENE MOREAU</a> Background Check</li>
      </ul>
    ";
        let rel = parse_relatives(html, "Fletcher Moreau", "s");
        let empty = rel.is_empty();
        assert!(!empty, "fixture must actually produce relatives");
        assert!(
            rel.iter().all(|e| !e.has_tag("tps-au")),
            "parse_relatives entities must never carry the tps-au anchor tag: {:?}",
            rel.iter().map(|e| &e.tags).collect::<Vec<_>>()
        );
    }

    #[test]
    fn split_name_standard() {
        assert_eq!(split_name("Haigen Bamford"), ("Haigen", "Bamford"));
        assert_eq!(split_name("Mary Jane Watson"), ("Mary", "Jane Watson"));
        assert_eq!(split_name("Solo"), ("Solo", ""));
    }

    #[test]
    fn parse_tps_html_extracts_au_address() {
        let html =
            "<div>Results for Test Person</div><p>Bondi Beach, NSW 2026</p><p>Other line</p>";
        let ents = parse_tps_html(html, "Test Person", "s");
        assert!(
            ents.iter().any(|e| e.kind == EntityKind::Address
                && e.value.contains("nsw")
                && e.has_tag("au-state:NSW")),
            "should extract NSW address: {ents:?}"
        );
    }

    #[test]
    fn parse_tps_html_skips_non_au_lines() {
        let html = "<p>London, UK</p><p>New York, NY 10001</p>";
        let ents = parse_tps_html(html, "Test Person", "s");
        assert!(
            ents.iter().all(|e| e.kind != EntityKind::Address),
            "non-AU addresses should not be emitted: {ents:?}"
        );
    }

    #[test]
    fn parse_tps_html_chrome_emails_are_tps_au_tagged_but_never_address_kind() {
        let html = "<div>Results for Test Person</div>\
                    <p>No matching records found.</p>\
                    <footer>Questions? contact@truepeoplesearch.com.au</footer>";
        let ents = parse_tps_html(html, "Test Person", "s");
        assert!(
            ents.iter()
                .any(|e| e.kind == EntityKind::Email && e.has_tag("tps-au")),
            "the chrome email must still be mined and tagged tps-au: {ents:?}"
        );
        assert!(
            !ents
                .iter()
                .any(|e| e.kind == EntityKind::Address && e.has_tag("tps-au")),
            "a chrome-only page must yield no tps-au Address hit: {ents:?}"
        );
    }

    #[test]
    fn parse_tps_html_addresses_are_candidate_leads_not_confirmed() {
        let html = "<div>Results for Test Person</div>\
                    <p>Bondi Beach, NSW 2026</p>\
                    <p>Sydney NSW 2000</p>";
        let ents = parse_tps_html(html, "Test Person", "s");
        let addrs: Vec<_> = ents
            .iter()
            .filter(|e| e.kind == EntityKind::Address)
            .collect();
        let no_addrs = addrs.is_empty();
        assert!(!no_addrs, "the scan must still surface the address leads");
        for a in &addrs {
            assert!(
                a.has_tag(tags::CANDIDATE),
                "a TPS address must be a candidate lead, tags = {:?}",
                a.tags
            );
            assert!(
                a.confidence <= entity::CANDIDATE_CONF,
                "a TPS address must not exceed candidate confidence, got {}",
                a.confidence
            );
        }
        for c in ents.iter().filter(|e| e.kind == EntityKind::Coordinates) {
            assert!(
                c.has_tag(tags::CANDIDATE),
                "a TPS-derived coordinate must be a candidate lead, tags = {:?}",
                c.tags
            );
        }
    }

    #[test]
    fn dedup_removes_same_kind_value() {
        let mut ents = vec![
            Entity::new(EntityKind::Address, "Sydney NSW 2000", 0.5, "s"),
            Entity::new(EntityKind::Address, "Sydney NSW 2000", 0.6, "s"),
            Entity::new(EntityKind::Email, "a@b.com", 0.5, "s"),
        ];
        merge_by_uid(&mut ents);
        assert_eq!(ents.len(), 2);
    }

    #[test]
    fn dedup_greatest_merges_duplicates_preserving_both_sources() {
        let mut wp = Entity::new(EntityKind::Address, "Sydney NSW 2000", 0.5, "s");
        wp.add_evidence(
            Evidence::new(provenance("s"), "White Pages AU listing")
                .with_attr("source", "whitepages_au"),
        );
        let mut tps = Entity::new(EntityKind::Address, "Sydney NSW 2000", 0.7, "s");
        tps.add_evidence(
            Evidence::new(provenance("s"), "True People Search AU listing")
                .with_attr("source", "tps_au"),
        );

        let mut ents = vec![wp, tps];
        merge_by_uid(&mut ents);

        assert_eq!(ents.len(), 1, "same (kind, value) collapses to one entity");
        let merged = &ents[0];
        assert!(
            (merged.confidence - 0.7).abs() < 1e-9,
            "GREATEST confidence wins, not the first-seen 0.5 (got {})",
            merged.confidence
        );
        assert_eq!(
            merged.corroboration, 2,
            "both independent directory sources are counted"
        );
        assert_eq!(
            merged.evidence.len(),
            2,
            "both directories' evidence records are retained, not just the first"
        );
        let summaries: Vec<&str> = merged.evidence.iter().map(|e| e.summary.as_str()).collect();
        assert!(summaries.iter().any(|s| s.contains("White Pages")));
        assert!(summaries.iter().any(|s| s.contains("True People Search")));
    }

    #[test]
    fn state_tag_from_text_recognises_au_states() {
        assert_eq!(
            state_tag_from_text("Bondi Beach NSW 2026"),
            Some("au-state:NSW".into())
        );
        assert_eq!(
            state_tag_from_text("Melbourne VIC 3000"),
            Some("au-state:VIC".into())
        );
        assert!(state_tag_from_text("London UK").is_none());
    }

    #[test]
    fn relatives_only_page_does_not_confirm_the_subject() {
        let html = r"
      <h2>Possible Relatives</h2>
      <ul>
        <li>Stephen R Moreau</li>
      </ul>
    ";
        let fake = Fake::new(vec![Ok(html_ok(html))]);
        let report = lookup(&fake, "Fletcher Moreau", "scan", 1).expect("lookup");
        assert!(
            !report
                .entities
                .iter()
                .any(|e| e.has_tag("confirmed-in-directory")),
            "relatives-only must not confirm the subject: {:?}",
            report.entities
        );
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.has_tag("family-candidate")),
            "relatives should still emit: {:?}",
            report.entities
        );
    }

    #[test]
    fn parse_tps_html_never_panics_on_adversarial_bytes() {
        for s in [
            "",
            "<",
            "&&&&",
            "<script>x</script>",
            "é<html>",
            &"<p>".repeat(64),
        ] {
            let _ = parse_tps_html(s, "Jordan Avery", "s");
            let _ = parse_relatives(s, "Jordan Avery", "s");
        }
    }
}
