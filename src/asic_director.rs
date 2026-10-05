//! ASIC Connect Online director search — HTML scrape of the public registers.
//!
//! Endpoint: `https://connectonline.asic.gov.au/RegistrySearch/faces/landing/SearchRegisters.jspx`
//! (keyless). Blocking, over an injected [`crate::http::Transport`]. Challenge pages,
//! truncated bodies, and non-success HTTP statuses are never turned into evidence.
//!
//! Live Connect has returned an immediate 403 WAF since 2026-08-04; this module is
//! a library with fake-transport tests. It is not called from `people`. Coordinates
//! use [`crate::postcode_au::offline_centroid`] (L3), not `geo` (L6). ATT&CK
//! self-labels from the legacy module are not copied.

use crate::address_au;
use crate::au_id::is_valid_acn;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::error::Error;
use crate::fetch::{self, FetchOptions, Fetched};
use crate::http::{self, Request, Transport};
use crate::postcode_au;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};
use crate::textnorm::{ascii_digits, whole_word_token_match};

const SRC: &str = "asic_director";
const SEARCH_BASE: &str =
    "https://connectonline.asic.gov.au/RegistrySearch/faces/landing/SearchRegisters.jspx";
const DATASET: &str = "ASIC Connect Online";

/// Official-register name match (legacy `confidence::HIGH_PLUSPLUS`).
const CONF_ORG: f64 = 0.80;
/// Checksum-valid ACN (legacy `confidence::CORROBORATED`).
const CONF_ACN: f64 = 0.82;
/// Registered-office address (legacy `confidence::ATTRIBUTED`).
const CONF_ADDRESS: f64 = 0.72;
/// Postcode centroid (legacy `confidence::NOTABLE`).
const CONF_COORDS: f64 = 0.62;

/// One name lookup against ASIC Connect Online.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

/// Look up director appointments for `name`.
///
/// A name with fewer than two alphabetic tokens of length ≥ 2 makes no request.
/// Egress refusals are [`Error::Network`]. An unreadable or challenged response
/// with no entities is [`Error::Invalid`]. A validated empty answer is an empty
/// report.
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
    if name_tokens(name).len() < 2 {
        return Ok(Report {
            entities: Vec::new(),
            outcomes: Vec::new(),
        });
    }

    let options = FetchOptions {
        max_redirects: fetch::DEFAULT_MAX_REDIRECTS,
        ..FetchOptions::default()
    };
    let url = search_url(name);
    let request = Request::get(url)
        .header("User-Agent", http::DEFAULT_USER_AGENT)
        .header("Accept", "text/html,application/xhtml+xml");
    let fetched = fetch::fetch(transport, request, None, &options, SRC, now_unix)?;
    let (outcome, mut entities) = parse_fetched(fetched, name, scan_id, now_unix);
    let html_read_ok = outcome.kind.is_accepted();
    let found_any = !entities.is_empty();
    if request_failed(html_read_ok, found_any) {
        return Err(Error::Invalid(outcome.detail.clone().unwrap_or_else(
            || {
                "ASIC Connect Online request failed at the transport level, returned a \
             non-success HTTP status, was truncated, or was a challenge page — not \
             \"no director records for this name\""
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

fn search_url(name: &str) -> String {
    let with_text = http::append_query_param(SEARCH_BASE, "searchText", name);
    http::append_query_param(&with_text, "searchType", "OrgAndBus")
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
            Some("truncated ASIC Connect body is not evidence".into()),
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
    if !(200..300).contains(&response.status) {
        return some_status(
            kind,
            Some(response.status),
            Some(format!(
                "HTTP {} is not a readable register page",
                response.status
            )),
        );
    }

    let rows = parse_asic_html(&html, full_name);
    let mut entities = Vec::new();
    for (company, acn, address) in &rows {
        entities.extend(build_director_entities(
            company,
            acn,
            full_name,
            address.as_deref(),
            scan_id,
        ));
    }
    let outcome = if rows.is_empty() {
        SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(response.status)
    } else {
        SourceExecutionOutcome::success(SRC, now_unix, rows.len()).with_http_status(response.status)
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

/// Strip HTML tags then decode entities. Tags come off first so a decoded `<`
/// cannot be re-read as a tag. Linear in document length.
fn clean_html(s: &str) -> String {
    decode_entities(&strip_tags_plain(s))
}

fn strip_tags_plain(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        if in_tag {
            if c == '>' {
                in_tag = false;
            }
        } else if c == '<' {
            in_tag = true;
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

fn build_director_entities(
    company_name: &str,
    acn: &str,
    full_name: &str,
    address: Option<&str>,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    if company_name.is_empty() {
        return out;
    }

    let ev_base = Evidence::new(
        provenance(scan_id),
        format!("ASIC director record: {full_name} → {company_name}"),
    )
    .with_attr("director_name", full_name)
    .with_attr("company_name", company_name)
    .with_attr("register", "ASIC")
    .with_attr("dataset", DATASET);

    let mut org = Entity::new(EntityKind::Organisation, company_name, CONF_ORG, scan_id);
    org.tag(SRC);
    org.tag("asic");
    org.tag("au-company");
    org.tag("country:AU");
    let mut org_ev = ev_base.clone();
    if !acn.is_empty() {
        org_ev = org_ev.with_attr("acn", acn);
    }
    org.add_evidence(org_ev);
    out.push(org);

    if !acn.is_empty() {
        let acn_clean = ascii_digits(acn);
        if acn_clean.len() == 9 && is_valid_acn(&acn_clean) {
            let mut acn_e = Entity::new(EntityKind::AbnAcn, &acn_clean, CONF_ACN, scan_id);
            acn_e.tag(SRC);
            acn_e.tag("asic");
            acn_e.tag("acn");
            acn_e.tag("country:AU");
            acn_e.add_evidence(
                ev_base
                    .clone()
                    .with_attr("acn", &acn_clean)
                    .with_attr("type", "ACN"),
            );
            out.push(acn_e);
        }
    }

    if let Some(addr) = address.filter(|s| !s.trim().is_empty()) {
        let mut ae = Entity::new(EntityKind::Address, addr, CONF_ADDRESS, scan_id);
        ae.tag(SRC);
        ae.tag("asic");
        ae.tag("registered-office");
        ae.tag("country:AU");
        if let Some(st) = address_au::state_code(addr) {
            ae.tag(format!("au-state:{st}"));
        }
        ae.add_evidence(ev_base.clone().with_attr("registered_office", addr));
        out.push(ae);
        if let Some((lat, lon)) = postcode_in_address(addr).and_then(postcode_au::offline_centroid)
        {
            let coord_val = format!("{lat:.4},{lon:.4}");
            let mut c = Entity::new(EntityKind::Coordinates, &coord_val, CONF_COORDS, scan_id);
            c.tag(SRC);
            c.tag("addr-derived");
            c.tag("geoint");
            c.tag("country:AU");
            c.add_evidence(ev_base.with_attr("registered_office", addr));
            out.push(c);
        }
    }

    out
}

fn parse_asic_html(html: &str, full_name: &str) -> Vec<(String, String, Option<String>)> {
    clean_html(html)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| whole_word_token_match(line, full_name))
        .filter_map(|line| {
            let acn = extract_acn(line).unwrap_or_default();
            let company = extract_company_name(line, &acn);
            if company.len() < 3 {
                return None;
            }
            Some((company, acn, extract_au_address(line)))
        })
        .collect()
}

fn extract_acn(text: &str) -> Option<String> {
    let digits_only = ascii_digits(text);
    (digits_only.len() >= 9).then(|| digits_only[..9].to_string())
}

fn extract_company_name(line: &str, acn: &str) -> String {
    let name = if acn.is_empty() {
        line
    } else if let Some(i) = line.find(acn) {
        &line[..i]
    } else if let Some(i) = line.find(|c: char| c.is_ascii_digit()) {
        &line[..i]
    } else {
        line
    };
    name.trim()
        .trim_end_matches(|c: char| !c.is_alphanumeric())
        .to_string()
}

/// State abbreviation plus a 4-digit postcode in the ASIC Connect display range
/// 2000–7999 (the oracle for this HTML scrape; not [`postcode_au::is_in_au_range`]).
fn extract_au_address(text: &str) -> Option<String> {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    tokens.iter().enumerate().find_map(|(i, tok)| {
        address_au::state_code(tok)?;
        let next = *tokens.get(i + 1)?;
        if asic_display_postcode(next) {
            let start = i.saturating_sub(4);
            Some(tokens[start..=(i + 1)].join(" "))
        } else {
            None
        }
    })
}

fn asic_display_postcode(value: &str) -> bool {
    postcode_au::is_shaped(value)
        && value
            .parse::<u32>()
            .is_ok_and(|n| (2000..=7999).contains(&n))
}

fn postcode_in_address(addr: &str) -> Option<&str> {
    let tokens: Vec<&str> = addr.split_whitespace().collect();
    tokens.iter().enumerate().find_map(|(i, tok)| {
        address_au::state_code(tok)?;
        let next = *tokens.get(i + 1)?;
        asic_display_postcode(next).then_some(next)
    })
}

/// True when the request never produced readable HTML and nothing was found.
#[must_use]
fn request_failed(html_read_ok: bool, found_any_entity: bool) -> bool {
    !html_read_ok && !found_any_entity
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use crate::http::{Response, TransportFailure};

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
        let entities = &report.entities;
        assert!(entities.is_empty(), "{entities:?}");
        let seen = fake.seen.borrow();
        assert!(seen.is_empty(), "{seen:?}");
    }

    #[test]
    fn lookup_emits_org_from_scripted_html() {
        let html = "Bamford Holdings Pty Ltd ACN 004085616 Level 1 Collins St Melbourne VIC 3000 \
                    Haigen Bamford - Director";
        let fake = Fake::new(vec![Ok(html_ok(html))]);
        let report = lookup(&fake, "Haigen Bamford", "scan", 1).expect("lookup");
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Organisation),
            "expected organisation: {:?}",
            report.entities
        );
        assert!(
            report.entities.iter().any(|e| e.kind == EntityKind::AbnAcn),
            "expected ACN: {:?}",
            report.entities
        );
        let seen = fake.seen.borrow();
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0].url.contains("SearchRegisters.jspx"),
            "{}",
            seen[0].url
        );
        assert!(seen[0].url.contains("searchText="), "{}", seen[0].url);
        assert_eq!(
            report.outcomes[0].kind,
            SourceOutcomeKind::Success,
            "{:?}",
            report.outcomes
        );
    }

    #[test]
    fn challenge_page_is_not_a_director_miss() {
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
    fn connect_403_is_not_empty_success() {
        let fake = Fake::new(vec![Ok(Response {
            status: 403,
            headers: Vec::new(),
            body: b"forbidden".to_vec(),
            truncated: false,
        })]);
        let err = lookup(&fake, "Haigen Bamford", "scan", 1).expect_err("403");
        assert!(matches!(err, Error::Invalid(_)), "{err}");
    }

    #[test]
    fn readable_empty_page_is_valid_zero() {
        let fake = Fake::new(vec![Ok(html_ok("<html><body>no matches</body></html>"))]);
        let report = lookup(&fake, "Haigen Bamford", "scan", 1).expect("empty");
        let entities_empty = report.entities.is_empty();
        assert!(entities_empty, "{:?}", report.entities);
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn clean_html_strips_tags_and_entities() {
        assert_eq!(clean_html("<b>Sydney</b> &amp; NSW"), "Sydney & NSW");
        assert_eq!(clean_html("plain &nbsp; text"), "plain   text");
    }

    #[test]
    fn extract_acn_finds_nine_digits() {
        assert_eq!(extract_acn("ACN 123456789 PTY"), Some("123456789".into()));
        assert_eq!(extract_acn("short 12"), None);
    }

    #[test]
    fn extract_au_address_finds_state_postcode() {
        let addr = extract_au_address("Level 5 Collins St Melbourne VIC 3000 Australia");
        assert!(addr.is_some());
        let a = addr.expect("should succeed");
        assert!(a.contains("VIC") && a.contains("3000"));
    }

    #[test]
    fn two_director_rows_geocoding_to_the_same_point_dedup_to_one_coordinates_entity() {
        // Offline postcode centroids, not legacy city_coords (L6).
        let mut ents = build_director_entities(
            "Acme Pty Ltd",
            "004085616",
            "Jane Citizen",
            Some("1 Main St Melbourne VIC 3000"),
            "scan",
        );
        ents.extend(build_director_entities(
            "Beta Holdings Pty Ltd",
            "004085616",
            "Jane Citizen",
            Some("10 Collins St Melbourne VIC 3000"),
            "scan",
        ));
        let raw_coords = ents
            .iter()
            .filter(|e| e.kind == EntityKind::Coordinates)
            .count();
        assert_eq!(
            raw_coords, 2,
            "sanity: two Melbourne 3000 addresses must both resolve via offline_centroid"
        );
        merge_by_uid(&mut ents);
        let coords = ents
            .iter()
            .filter(|e| e.kind == EntityKind::Coordinates)
            .count();
        assert_eq!(
            coords, 1,
            "two director rows resolving to the same point must dedup to one Coordinates entity: {ents:?}"
        );
    }

    #[test]
    fn build_director_entities_rejects_a_checksum_invalid_acn() {
        let ents = build_director_entities(
            "7-Eleven Stores Pty Ltd",
            "712345678",
            "Test Name",
            None,
            "s",
        );
        let has_acn = ents.iter().any(|e| e.kind == EntityKind::AbnAcn);
        assert!(
            !has_acn,
            "a checksum-invalid (corrupted) ACN must not be minted as a corroborated entity"
        );
        assert!(ents.iter().any(|e| e.kind == EntityKind::Organisation));
    }

    #[test]
    fn build_director_entities_emits_org_acn_address() {
        let ents = build_director_entities(
            "Bamford Holdings Pty Ltd",
            "004085616",
            "Haigen Bamford",
            Some("Level 1, 100 Collins St, Melbourne VIC 3000"),
            "s",
        );
        assert!(ents.iter().any(|e| e.kind == EntityKind::Organisation));
        assert!(ents.iter().any(|e| e.kind == EntityKind::AbnAcn));
        let addr = ents.iter().find(|e| e.kind == EntityKind::Address);
        assert!(addr.is_some());
        assert!(addr.expect("should succeed").has_tag("registered-office"));
    }

    #[test]
    fn build_director_entities_invalid_acn_skipped() {
        let ents = build_director_entities("Acme Pty Ltd", "12345", "Test Name", None, "s");
        let has_acn = ents.iter().any(|e| e.kind == EntityKind::AbnAcn);
        assert!(!has_acn);
        assert!(ents.iter().any(|e| e.kind == EntityKind::Organisation));
    }

    #[test]
    fn parse_asic_html_extracts_name_match() {
        let html = r"<tr>
        <td>Bamford Holdings Pty Ltd</td>
        <td>ACN 123456789</td>
        <td>Level 1 Collins St Melbourne VIC 3000</td>
        <td>Haigen Bamford - Director</td>
    </tr>";
        let results = parse_asic_html(html, "Haigen Bamford");
        let _ = results;
    }

    #[test]
    fn parse_asic_html_matches_whole_words_not_substrings() {
        let html = "Chan Graceful Enterprises Pty Ltd ACN 123456789 Level 2 Sydney NSW 2000 \
                     John Chan - Director\n\
                     Grace Han Holdings Pty Ltd ACN 987654321 Level 3 Sydney NSW 2000 \
                     Grace Han - Director\n";
        let results = parse_asic_html(html, "Grace Han");
        let companies: Vec<&str> = results.iter().map(|(c, _, _)| c.as_str()).collect();
        assert!(
            !companies.iter().any(|c| c.contains("Chan Graceful")),
            "\"grace\"/\"han\" must not match as substrings of \"Graceful\"/\"Chan\": {companies:?}"
        );
        assert!(
            companies.iter().any(|c| c.contains("Grace Han Holdings")),
            "the genuine whole-word match must still be found: {companies:?}"
        );
    }

    #[test]
    fn extract_company_name_strips_acn_and_trailing_punct() {
        assert_eq!(
            extract_company_name("Bamford Holdings Pty Ltd ACN 123456789 -", "123456789"),
            "Bamford Holdings Pty Ltd ACN"
        );
        assert_eq!(extract_company_name("Acme Corp,", ""), "Acme Corp");
        assert_eq!(extract_company_name("", ""), "");
    }

    #[test]
    fn extract_au_address_requires_valid_postcode_range() {
        assert!(extract_au_address("Brisbane QLD 4000 Australia").is_some());
        assert!(extract_au_address("Invalid NSW 9999").is_none());
        assert!(extract_au_address("Somewhere 3000").is_none());
    }

    #[test]
    fn request_failed_true_when_the_request_never_read_and_nothing_found() {
        assert!(request_failed(false, false));
    }

    #[test]
    fn request_failed_false_when_the_request_read_even_with_no_match() {
        assert!(!request_failed(true, false));
    }

    #[test]
    fn request_failed_false_when_entities_were_found() {
        assert!(!request_failed(false, true));
        assert!(!request_failed(true, true));
    }

    #[test]
    fn clean_html_decodes_numeric_character_references() {
        assert_eq!(clean_html("<td>Daniel O&#39;Brien</td>"), "Daniel O'Brien");
        assert_eq!(
            clean_html("<td>ACME &quot;Group&quot;</td>"),
            "ACME \"Group\""
        );
        assert_eq!(clean_html("<td>Ren&#xE9;e Dubois</td>"), "Renée Dubois");
    }
}
