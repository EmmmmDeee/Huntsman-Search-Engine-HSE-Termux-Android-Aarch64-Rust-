//! State electoral-roll lookups (NSW, VIC, QLD).
//!
//! Keyless HTML scrape of:
//! - NSW Electoral Commission — `https://check.elections.nsw.gov.au/search`
//! - VEC (Victoria) — `https://check.vec.vic.gov.au/search`
//! - ECQ (Queensland) — `https://enrol.ecq.qld.gov.au/check`
//!
//! Blocking, over an injected [`crate::http::Transport`]. Challenge pages,
//! truncated bodies, and non-success HTTP are not enrolment statements
//! ([`RollOutcome::Unreachable`]). A readable page that names no division is
//! [`RollOutcome::Answered`] with no entities — a genuine negative for that
//! commission, not an outage. If every attempted leg is unreachable, lookup
//! fails rather than reading as "not enrolled" (enrolment is compulsory).
//!
//! No AEC national leg: `electorate.aec.gov.au/NameSearch.aspx` is retired.
//! Coordinates come from an offline division-centroid table, not `geo` (L6).
//! ATT&CK self-labels from the legacy module are not copied. Not called from
//! `people`.

use crate::address_au;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::error::Error;
use crate::fetch::{self, FetchOptions, Fetched};
use crate::http::{self, Request, Transport};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};
use crate::textnorm::find_ascii_ci;

const SRC: &str = "au_electoral";
const DATASET: &str = "AU electoral commissions";
const NEGATION_WINDOW: usize = 60;

/// Suburb-level address (legacy `confidence::ATTRIBUTED`).
const CONF_ADDRESS_SUBURB: f64 = 0.72;
/// Division-only address (legacy `confidence::MEDIUM_SOLID`).
const CONF_ADDRESS_DIVISION: f64 = 0.58;
/// Offline division centroid (legacy `confidence::HIGH`).
const CONF_COORDS: f64 = 0.65;

const LEGS: &[(&str, &str)] = &[
    (
        "au_electoral.nsw",
        "https://check.elections.nsw.gov.au/search",
    ),
    ("au_electoral.vic", "https://check.vec.vic.gov.au/search"),
    ("au_electoral.qld", "https://enrol.ecq.qld.gov.au/check"),
];

const DIVISION_MARKER: &str = "division of ";
const ENROLLED_MARKERS: &[&str] = &["enrolled in ", "enrolled for "];
const NEGATION_MARKERS: &[&str] = &[
    "not enrolled",
    "not currently enrolled",
    "no longer enrolled",
    "unable to find",
    "no record",
    "not found",
    "no match",
    "lapsed",
    "cancelled",
    "removed from the roll",
    "removed from the electoral roll",
];

/// One name lookup across the three state commissions (first hit wins).
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

/// What a single commission established about enrolment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RollOutcome {
    /// The commission answered and its page was read.
    Answered,
    /// The request failed, was truncated, challenged, or was not 2xx.
    Unreachable,
}

/// Look up electoral enrolment for `name`.
///
/// An empty name makes no request. Egress refusals are [`Error::Network`].
/// When every attempted commission is unreachable, [`Error::Invalid`] — an
/// empty success would read as "not enrolled".
///
/// # Errors
///
/// [`Error::Network`] when egress blocks a request. [`Error::Invalid`] when
/// no commission answered.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    name: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let full_name = name.trim();
    if full_name.is_empty() {
        return Ok(Report {
            entities: Vec::new(),
            outcomes: Vec::new(),
        });
    }

    let options = FetchOptions {
        max_redirects: fetch::DEFAULT_MAX_REDIRECTS,
        ..FetchOptions::default()
    };
    let mut entities = Vec::new();
    let mut outcomes = Vec::new();
    let mut rolls = Vec::new();

    for (module, base) in LEGS {
        if !entities.is_empty() {
            break;
        }
        let url = http::append_query_param(base, "name", full_name);
        let request = Request::get(url)
            .header("User-Agent", http::DEFAULT_USER_AGENT)
            .header("Accept", "text/html,application/xhtml+xml");
        let fetched = fetch::fetch(transport, request, None, &options, module, now_unix)?;
        let (outcome, roll, found) = parse_fetched(fetched, module, full_name, scan_id, now_unix);
        entities.extend(found);
        outcomes.push(outcome);
        rolls.push(roll);
    }

    if rolls_wholly_unreachable(&rolls) {
        return Err(Error::Invalid(format!(
            "no electoral commission answered for {full_name}: all {} lookups \
             (NSW, VIC, QLD) failed to respond or returned a reply that could \
             not be read. Enrolment is compulsory in Australia, so an empty \
             result would read as 'not enrolled' — which nothing established.",
            rolls.len()
        )));
    }
    Ok(Report { entities, outcomes })
}

fn parse_fetched(
    fetched: Fetched,
    module: &str,
    full_name: &str,
    scan_id: &str,
    now_unix: u64,
) -> (SourceExecutionOutcome, RollOutcome, Vec<Entity>) {
    let unreachable = |kind: SourceOutcomeKind, status: Option<u16>, detail: Option<String>| {
        let mut outcome = SourceExecutionOutcome::success(module, now_unix, 0);
        outcome.kind = kind;
        outcome.found = None;
        outcome.http_status = status;
        outcome.detail = detail;
        (outcome, RollOutcome::Unreachable, Vec::new())
    };

    let Some(response) = fetched.response else {
        return (fetched.outcome, RollOutcome::Unreachable, Vec::new());
    };
    if response.truncated {
        return unreachable(
            SourceOutcomeKind::ParserDrift,
            Some(response.status),
            Some("truncated electoral body is not evidence".into()),
        );
    }
    let html = String::from_utf8_lossy(&response.body);
    let kind = classify_fetch(response.status, &html);
    if kind == SourceOutcomeKind::BotWaf {
        return unreachable(
            SourceOutcomeKind::BotWaf,
            Some(response.status),
            Some("challenge page is not an enrolment statement".into()),
        );
    }
    if !(200..300).contains(&response.status) {
        return unreachable(
            kind,
            Some(response.status),
            Some(format!(
                "HTTP {} is not a readable enrolment page",
                response.status
            )),
        );
    }

    match extract_division(&html) {
        Some((div, suburb)) => {
            let found = build_electoral_entities(&div, suburb.as_deref(), full_name, scan_id);
            let outcome = SourceExecutionOutcome::success(module, now_unix, found.len())
                .with_http_status(response.status);
            (outcome, RollOutcome::Answered, found)
        }
        None => (
            SourceExecutionOutcome::valid_zero(module, now_unix).with_http_status(response.status),
            RollOutcome::Answered,
            Vec::new(),
        ),
    }
}

fn rolls_wholly_unreachable(outcomes: &[RollOutcome]) -> bool {
    !outcomes.is_empty() && outcomes.iter().all(|o| *o == RollOutcome::Unreachable)
}

fn provenance(scan_id: &str) -> EvidenceProvenance {
    EvidenceProvenance::for_scan(SRC, scan_id)
}

struct DivisionInfo {
    state: &'static str,
    suburb: &'static str,
    lat: f64,
    lon: f64,
}

fn division_centroid(division: &str) -> Option<DivisionInfo> {
    let div = division.to_lowercase();
    const TABLE: &[(&str, &str, &str, f64, f64)] = &[
        ("sydney", "NSW", "Sydney CBD", -33.8688, 151.2093),
        ("north sydney", "NSW", "North Sydney", -33.8404, 151.2072),
        ("chifley", "NSW", "Fairfield", -33.8784, 150.9530),
        ("grayndler", "NSW", "Marrickville", -33.9099, 151.1577),
        ("kingsford smith", "NSW", "Botany", -33.9484, 151.1928),
        ("barton", "NSW", "Rockdale", -33.9518, 151.1330),
        ("watson", "NSW", "Eastlakes", -33.9273, 151.2167),
        ("reid", "NSW", "Camperdown", -33.8901, 151.1827),
        ("banks", "NSW", "Revesby", -33.9482, 151.0120),
        ("blaxland", "NSW", "Auburn", -33.8652, 150.9961),
        ("werriwa", "NSW", "Liverpool", -33.9200, 150.9239),
        ("fowler", "NSW", "Cabramatta", -33.8988, 150.9467),
        ("greenway", "NSW", "Quakers Hill", -33.7270, 150.8760),
        ("mitchell", "NSW", "Blacktown", -33.7690, 150.9068),
        ("parramatta", "NSW", "Parramatta", -33.8148, 151.0017),
        ("macquarie", "NSW", "Penrith", -33.7514, 150.6942),
        ("eden-monaro", "NSW", "Queanbeyan", -35.3530, 149.2340),
        ("newcastle", "NSW", "Newcastle", -32.9283, 151.7817),
        ("hunter", "NSW", "Cessnock", -32.8312, 151.3560),
        ("page", "NSW", "Lismore", -28.8133, 153.2752),
        ("melbourne", "VIC", "Melbourne CBD", -37.8136, 144.9631),
        ("wills", "VIC", "Coburg", -37.7408, 144.9651),
        ("batman", "VIC", "Preston", -37.7473, 145.0166),
        ("kooyong", "VIC", "Hawthorn", -37.8264, 145.0385),
        ("goldstein", "VIC", "Brighton", -37.9065, 145.0023),
        ("isaacs", "VIC", "Dandenong", -37.9870, 145.2150),
        ("holt", "VIC", "Cranbourne", -38.1098, 145.2828),
        ("bruce", "VIC", "Clayton", -37.9271, 145.1224),
        ("chisholm", "VIC", "Box Hill", -37.8191, 145.1239),
        ("deakin", "VIC", "Ringwood", -37.8148, 145.2300),
        ("lalor", "VIC", "Werribee", -37.9035, 144.6593),
        ("gorton", "VIC", "Sunshine", -37.7898, 144.8313),
        ("maribyrnong", "VIC", "Footscray", -37.8007, 144.9032),
        ("geelong", "VIC", "Geelong", -38.1499, 144.3617),
        ("ballarat", "VIC", "Ballarat", -37.5622, 143.8503),
        ("brisbane", "QLD", "Brisbane CBD", -27.4698, 153.0251),
        ("griffith", "QLD", "South Brisbane", -27.4869, 153.0222),
        ("ryan", "QLD", "Toowong", -27.4836, 152.9978),
        ("moreton", "QLD", "Springwood", -27.6170, 153.1220),
        ("bonner", "QLD", "Clayfield", -27.4097, 153.0487),
        ("lilley", "QLD", "Chermside", -27.3870, 153.0269),
        ("petrie", "QLD", "Redcliffe", -27.2310, 153.0990),
        ("dickson", "QLD", "Aspley", -27.3450, 153.0070),
        ("mcpherson", "QLD", "Robina", -28.0740, 153.3620),
        ("gold coast", "QLD", "Surfers Paradise", -28.0023, 153.4145),
        ("boothby", "SA", "Mitcham", -35.0104, 138.5985),
        ("sturt", "SA", "West Lakes", -34.8820, 138.5038),
        ("adelaide", "SA", "Adelaide CBD", -34.9285, 138.6007),
        ("hindmarsh", "SA", "Hindmarsh", -34.9000, 138.5600),
        ("perth", "WA", "Perth CBD", -31.9505, 115.8605),
        ("curtin", "WA", "Cottesloe", -31.9926, 115.7621),
        ("cowan", "WA", "Joondalup", -31.7440, 115.7680),
        ("burt", "WA", "Armadale", -32.1529, 116.0136),
        ("hasluck", "WA", "Midland", -31.8882, 116.0065),
        ("swan", "WA", "Midvale", -31.8800, 116.0360),
        ("fremantle", "WA", "Fremantle", -32.0569, 115.7439),
        ("canning", "WA", "Cannington", -32.0153, 115.9381),
        ("bean", "ACT", "Tuggeranong", -35.4244, 149.0886),
        ("canberra", "ACT", "Canberra", -35.2809, 149.1300),
        ("fenner", "ACT", "Gungahlin", -35.1823, 149.1332),
        ("bass", "TAS", "Launceston", -41.4332, 147.1441),
        ("braddon", "TAS", "Devonport", -41.1800, 146.3500),
        ("clark", "TAS", "Hobart", -42.8821, 147.3272),
        ("franklin", "TAS", "Kingston", -42.9773, 147.2804),
        ("lyons", "TAS", "New Norfolk", -42.7820, 147.0580),
        ("lingiari", "NT", "Darwin", -12.4634, 130.8456),
        ("solomon", "NT", "Darwin CBD", -12.4578, 130.8413),
    ];
    TABLE
        .iter()
        .find(|(d, _, _, _, _)| *d == div.as_str())
        .map(|(_, state, suburb, lat, lon)| DivisionInfo {
            state,
            suburb,
            lat: *lat,
            lon: *lon,
        })
}

fn infer_state_from_division(division: &str) -> Option<&'static str> {
    let lc = division.to_lowercase();
    if lc.contains("sydney")
        || lc.contains("parramatta")
        || lc.contains("hunter")
        || lc.contains("newcastle")
    {
        Some("NSW")
    } else if lc.contains("melbourne") || lc.contains("geelong") || lc.contains("ballarat") {
        Some("VIC")
    } else if lc.contains("brisbane") || lc.contains("gold coast") {
        Some("QLD")
    } else if lc.contains("perth") || lc.contains("fremantle") {
        Some("WA")
    } else if lc.contains("adelaide") {
        Some("SA")
    } else if lc.contains("hobart") || lc.contains("launceston") {
        Some("TAS")
    } else if lc.contains("canberra") {
        Some("ACT")
    } else if lc.contains("darwin") {
        Some("NT")
    } else {
        None
    }
}

fn build_electoral_entities(
    division: &str,
    suburb_hint: Option<&str>,
    full_name: &str,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    let evid = Evidence::new(
        provenance(scan_id),
        format!("Electoral division: {division}"),
    )
    .with_attr("dataset", DATASET);

    let (state, suburb, lat, lon) = if let Some(info) = division_centroid(division) {
        (
            info.state,
            suburb_hint.unwrap_or(info.suburb).to_string(),
            Some(info.lat),
            Some(info.lon),
        )
    } else {
        let state = infer_state_from_division(division).unwrap_or("AU");
        (state, suburb_hint.unwrap_or("").to_string(), None, None)
    };

    let (addr_value, addr_conf) = if suburb.is_empty() {
        (
            format!("{division} (electoral division), {state}"),
            CONF_ADDRESS_DIVISION,
        )
    } else {
        (format!("{suburb}, {state}"), CONF_ADDRESS_SUBURB)
    };
    let mut addr = Entity::new(EntityKind::Address, &addr_value, addr_conf, scan_id);
    addr.add_evidence(
        evid.clone()
            .with_attr("division", division)
            .with_attr("source_name", full_name),
    );
    addr.tag(format!("au-state:{state}"));
    addr.tag("country:AU");
    addr.tag("source:electoral");
    out.push(addr);

    if let (Some(lat), Some(lon)) = (lat, lon) {
        let coord_value = format!("{lat:.4},{lon:.4}");
        let mut coord = Entity::new(EntityKind::Coordinates, &coord_value, CONF_COORDS, scan_id);
        coord.add_evidence(
            evid.with_attr("division", division)
                .with_attr("suburb", &suburb)
                .with_attr("source_name", full_name),
        );
        coord.tag(format!("au-state:{state}"));
        coord.tag("country:AU");
        out.push(coord);
    }
    out
}

fn extract_division(html: &str) -> Option<(String, Option<String>)> {
    let text = strip_electoral_html(html);
    match find_ascii_ci_range(&text, DIVISION_MARKER) {
        Some((start, end)) if !has_nearby_negation(&text, start, end) => {
            if let Some(name) = take_division_name(&text[end..]) {
                return Some((name, extract_suburb_hint(&text[end..])));
            }
        }
        _ => {}
    }
    match first_enrolled_marker(&text) {
        Some((start, end)) if !has_nearby_negation(&text, start, end) => {
            if let Some(name) = take_division_name(&text[end..]) {
                return Some((name, extract_suburb_hint(&text[end..])));
            }
        }
        _ => {}
    }
    None
}

fn take_division_name(rest: &str) -> Option<String> {
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphabetic() || *c == '-' || *c == ' ' || *c == '\'')
        .collect();
    let name = name.trim().to_string();
    (!name.is_empty() && name.chars().count() < 40).then_some(name)
}

fn first_enrolled_marker(text: &str) -> Option<(usize, usize)> {
    ENROLLED_MARKERS
        .iter()
        .filter_map(|marker| find_ascii_ci_range(text, marker))
        .min_by_key(|(start, _)| *start)
}

fn find_ascii_ci_range(haystack: &str, needle: &str) -> Option<(usize, usize)> {
    find_ascii_ci(haystack, needle).map(|start| (start, start + needle.len()))
}

fn has_nearby_negation(text: &str, marker_start: usize, marker_end: usize) -> bool {
    let mut win_start = marker_start.saturating_sub(NEGATION_WINDOW).min(text.len());
    while win_start > 0 && !text.is_char_boundary(win_start) {
        win_start -= 1;
    }
    let mut win_end = (marker_end + NEGATION_WINDOW).min(text.len());
    while win_end < text.len() && !text.is_char_boundary(win_end) {
        win_end += 1;
    }
    let window = &text[win_start..win_end];
    NEGATION_MARKERS
        .iter()
        .any(|marker| find_ascii_ci(window, marker).is_some())
}

fn strip_electoral_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => {
                in_tag = true;
                out.push(' ');
            }
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    let mut result = String::with_capacity(out.len());
    let mut prev_space = false;
    for ch in out.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                result.push(' ');
            }
            prev_space = true;
        } else {
            result.push(ch);
            prev_space = false;
        }
    }
    result
}

fn extract_suburb_hint(window: &str) -> Option<String> {
    let bytes = window.as_bytes();
    for i in 0..bytes.len().saturating_sub(3) {
        if address_au::is_standalone_postcode_at(bytes, i) {
            let before = window[..i].trim_end();
            let suburb: String = before
                .chars()
                .rev()
                .take_while(|c| c.is_alphabetic() || *c == ' ' || *c == '\'')
                .collect::<String>()
                .chars()
                .rev()
                .collect();
            let suburb = suburb.trim().to_string();
            if !suburb.is_empty() && suburb.chars().count() < 30 {
                return Some(suburb);
            }
        }
    }
    None
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
    fn empty_name_makes_no_request() {
        let fake = Fake::new(vec![Ok(html_ok("unused"))]);
        let report = lookup(&fake, "  ", "t", 1).expect("no-op");
        let entities = &report.entities;
        assert!(entities.is_empty(), "{entities:?}");
        let seen = fake.seen.borrow();
        assert!(seen.is_empty(), "{seen:?}");
    }

    #[test]
    fn first_hit_stops_remaining_legs() {
        let html = "<p>You are enrolled for the Division of Sydney, NSW.</p>";
        let fake = Fake::new(vec![Ok(html_ok(html))]);
        let report = lookup(&fake, "Haigen Bamford", "scan", 1).expect("lookup");
        let seen = fake.seen.borrow();
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert!(
            seen[0].url.contains("elections.nsw.gov.au"),
            "{}",
            seen[0].url
        );
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Address),
            "{:?}",
            report.entities
        );
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::Success);
    }

    #[test]
    fn empty_nsw_continues_to_vic() {
        let fake = Fake::new(vec![
            Ok(html_ok("<p>No results found.</p>")),
            Ok(html_ok(
                "<p>You are enrolled for the Division of Melbourne</p>",
            )),
        ]);
        let report = lookup(&fake, "Jane Citizen", "scan", 1).expect("lookup");
        let seen = fake.seen.borrow();
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert!(seen[1].url.contains("vec.vic.gov.au"), "{}", seen[1].url);
        assert!(
            report.entities.iter().any(|e| e.has_tag("au-state:VIC")),
            "{:?}",
            report.entities
        );
    }

    #[test]
    fn all_unreachable_is_not_not_enrolled() {
        let fake = Fake::new(vec![
            Ok(Response {
                status: 403,
                headers: Vec::new(),
                body: b"forbidden".to_vec(),
                truncated: false,
            }),
            Ok(Response {
                status: 403,
                headers: Vec::new(),
                body: b"forbidden".to_vec(),
                truncated: false,
            }),
            Ok(Response {
                status: 403,
                headers: Vec::new(),
                body: b"forbidden".to_vec(),
                truncated: false,
            }),
        ]);
        let err = lookup(&fake, "Haigen Bamford", "scan", 1).expect_err("outage");
        assert!(matches!(err, Error::Invalid(_)), "{err}");
        let seen = fake.seen.borrow();
        assert_eq!(seen.len(), 3, "{seen:?}");
    }

    #[test]
    fn challenge_page_is_unreachable_not_a_negative() {
        let wall = Response {
            status: 200,
            headers: vec![("content-type".into(), "text/html".into())],
            body: b"<html>Just a moment... cloudflare checking your browser</html>".to_vec(),
            truncated: false,
        };
        let fake = Fake::new(vec![Ok(wall.clone()), Ok(wall.clone()), Ok(wall)]);
        let err = lookup(&fake, "Haigen Bamford", "scan", 1).expect_err("waf");
        assert!(matches!(err, Error::Invalid(_)), "{err}");
    }

    #[test]
    fn readable_empty_pages_are_valid_zero() {
        let empty = html_ok("<p>No results found.</p>");
        let fake = Fake::new(vec![Ok(empty.clone()), Ok(empty.clone()), Ok(empty)]);
        let report = lookup(&fake, "Haigen Bamford", "scan", 1).expect("negatives");
        let entities_empty = report.entities.is_empty();
        assert!(entities_empty, "{:?}", report.entities);
        assert!(
            report
                .outcomes
                .iter()
                .all(|o| o.kind == SourceOutcomeKind::ValidZero),
            "{:?}",
            report.outcomes
        );
    }

    #[test]
    fn no_aec_national_leg() {
        assert_eq!(LEGS.len(), 3);
        assert!(LEGS.iter().all(|(_, url)| !url.contains("aec.gov.au")));
    }

    #[test]
    fn division_centroid_returns_sydney_for_sydney() {
        let info = division_centroid("Sydney").expect("should succeed");
        assert_eq!(info.state, "NSW");
        assert!((info.lat - -33.8688).abs() < 0.01);
        assert!((info.lon - 151.2093).abs() < 0.01);
    }

    #[test]
    fn division_centroid_is_case_insensitive() {
        assert!(division_centroid("MELBOURNE").is_some());
        assert!(division_centroid("brisbane").is_some());
        assert!(division_centroid("Perth").is_some());
    }

    #[test]
    fn division_centroid_returns_none_for_unknown() {
        assert!(division_centroid("Xyzzy").is_none());
        assert!(division_centroid("").is_none());
    }

    #[test]
    fn extract_division_parses_aec_pattern() {
        let cases: &[(&str, &str)] = &[
            (
                "<p>You are enrolled for the Division of Sydney, NSW.</p>",
                "Sydney",
            ),
            (
                "<div>enrolled for Melbourne (VIC) 3000 Southbank</div>",
                "Melbourne",
            ),
            (
                "<span>You are enrolled in the Division of Brisbane</span>",
                "Brisbane",
            ),
            (
                "Division of North Sydney – electorate details",
                "North Sydney",
            ),
        ];
        for (html, expected_div) in cases {
            let result = extract_division(html);
            assert!(result.is_some(), "expected a division from: {html}");
            let (div, _) = result.expect("should succeed");
            assert!(
                div.to_lowercase().contains(&expected_div.to_lowercase()),
                "expected '{expected_div}' in div '{div}'"
            );
        }
    }

    #[test]
    fn extract_division_returns_none_for_not_enrolled() {
        let cases = &[
            "We could not find an enrolment for this name.",
            "No results found.",
            "<p>Your name was not found on the electoral roll.</p>",
        ];
        for html in cases {
            assert!(
                extract_division(html).is_none(),
                "should not extract from: {html}"
            );
        }
    }

    #[test]
    fn build_electoral_entities_emits_address_and_coords() {
        let ents = build_electoral_entities("Sydney", None, "Haigen Bamford", "s");
        assert!(!ents.is_empty(), "Sydney division must produce entities");
        assert!(ents.iter().any(|e| e.kind == EntityKind::Address));
        assert!(ents.iter().any(|e| e.kind == EntityKind::Coordinates));
        for e in &ents {
            assert!(e.has_tag("country:AU"), "entity must carry country:AU");
            assert!(e.has_tag("au-state:NSW"), "Sydney division must be NSW");
        }
    }

    #[test]
    fn build_electoral_entities_unknown_division_emits_address_only() {
        let ents = build_electoral_entities("Xyzzy", None, "Test", "s");
        assert!(ents.iter().any(|e| e.kind == EntityKind::Address));
        let has_coords = ents.iter().any(|e| e.kind == EntityKind::Coordinates);
        assert!(!has_coords);
    }

    #[test]
    fn address_confidence_reflects_whether_a_suburb_was_resolved() {
        let with_suburb = build_electoral_entities("Sydney", None, "Test", "s");
        let addr = with_suburb
            .iter()
            .find(|e| e.kind == EntityKind::Address)
            .expect("should succeed");
        assert!(
            (addr.confidence - 0.72).abs() < 1e-9,
            "suburb-level match must score 0.72, got {}",
            addr.confidence
        );
        let division_only = build_electoral_entities("Xyzzy", None, "Test", "s");
        let addr2 = division_only
            .iter()
            .find(|e| e.kind == EntityKind::Address)
            .expect("should succeed");
        assert!(
            (addr2.confidence - 0.58).abs() < 1e-9,
            "division-only match must score 0.58, got {}",
            addr2.confidence
        );
    }

    #[test]
    fn build_electoral_entities_suburb_hint_overrides_centroid_suburb() {
        let ents = build_electoral_entities("Sydney", Some("Newtown"), "Test", "s");
        let addr = ents
            .iter()
            .find(|e| e.kind == EntityKind::Address)
            .expect("should succeed");
        assert!(
            addr.value.contains("newtown"),
            "suburb hint should override centroid suburb: {}",
            addr.value
        );
    }

    #[test]
    fn strip_electoral_html_separates_adjacent_tags() {
        let html = "<div>Division</div><span>of</span><p>Sydney</p>";
        let text = strip_electoral_html(html);
        assert!(
            !text.contains("Divisionof"),
            "tags must inject word breaks: {text}"
        );
        assert!(text.contains("Division"), "content must survive: {text}");
        assert!(text.contains("Sydney"), "content must survive: {text}");
    }

    #[test]
    fn extract_division_returns_none_for_the_real_retired_aec_namesearch_response() {
        let html = include_str!(
            "../legacy/hse-monolith-v1.41.0/src/modules/au_electoral/testdata/aec_namesearch_retired.html"
        );
        assert!(
            extract_division(html).is_none(),
            "the retired AEC error page must not parse as an enrolment result"
        );
    }

    #[test]
    fn infer_state_from_division_maps_name_fragments() {
        assert_eq!(infer_state_from_division("North Sydney"), Some("NSW"));
        assert_eq!(infer_state_from_division("parramatta"), Some("NSW"));
        assert_eq!(infer_state_from_division("Hunter"), Some("NSW"));
        assert_eq!(infer_state_from_division("Newcastle"), Some("NSW"));
        assert_eq!(infer_state_from_division("MELBOURNE"), Some("VIC"));
        assert_eq!(infer_state_from_division("Geelong"), Some("VIC"));
        assert_eq!(infer_state_from_division("Ballarat"), Some("VIC"));
        assert_eq!(infer_state_from_division("Brisbane"), Some("QLD"));
        assert_eq!(infer_state_from_division("Gold Coast"), Some("QLD"));
        assert_eq!(infer_state_from_division("Perth"), Some("WA"));
        assert_eq!(infer_state_from_division("Fremantle"), Some("WA"));
        assert_eq!(infer_state_from_division("Adelaide"), Some("SA"));
        assert_eq!(infer_state_from_division("Hobart"), Some("TAS"));
        assert_eq!(infer_state_from_division("Launceston"), Some("TAS"));
        assert_eq!(infer_state_from_division("Canberra"), Some("ACT"));
        assert_eq!(infer_state_from_division("Darwin"), Some("NT"));
        assert_eq!(infer_state_from_division("Wentworth"), None);
    }

    #[test]
    fn extract_division_no_panic_on_multibyte_before_marker() {
        let html = "<p>İstanbul — Division of Sydney.</p>";
        let (div, _) = extract_division(html).expect("division parses without panic");
        assert!(div.starts_with("Sydney"), "got {div:?}");
    }

    #[test]
    fn extract_division_never_panics_on_adversarial_bytes() {
        for s in [
            "",
            "\0",
            "<",
            "division of ",
            "enrolled for ",
            "İdivision of Sydney",
            &"x".repeat(256),
            "<p>You are not enrolled for the Division of Sydney</p>",
        ] {
            let _ = extract_division(s);
        }
    }

    #[test]
    fn an_unreachable_commission_is_not_the_same_as_an_absent_enrolment() {
        assert!(rolls_wholly_unreachable(&[
            RollOutcome::Unreachable,
            RollOutcome::Unreachable,
            RollOutcome::Unreachable,
        ]));
        assert!(!rolls_wholly_unreachable(&[RollOutcome::Answered]));
        assert!(rolls_wholly_unreachable(&[RollOutcome::Unreachable]));
        assert!(!rolls_wholly_unreachable(&[
            RollOutcome::Unreachable,
            RollOutcome::Answered,
            RollOutcome::Unreachable,
        ]));
        assert!(!rolls_wholly_unreachable(&[
            RollOutcome::Unreachable,
            RollOutcome::Unreachable,
            RollOutcome::Answered,
        ]));
        assert!(!rolls_wholly_unreachable(&[]));
    }

    #[test]
    fn aec_division_of_pattern() {
        let html = "<div>You are enrolled for the Division of Sydney (2026)</div>";
        let (name, _) = extract_division(html).expect("should succeed");
        assert_eq!(name, "Sydney");
    }

    #[test]
    fn state_ec_enrolled_for_pattern() {
        let html = "<p>You are enrolled for Bondi Beach 2026</p>";
        let (name, _) = extract_division(html).expect("should succeed");
        assert_eq!(name, "Bondi Beach");
    }

    #[test]
    fn state_ec_enrolled_in_pattern() {
        let html = "<p>You are enrolled in Parramatta</p>";
        let (name, _) = extract_division(html).expect("should succeed");
        assert_eq!(name, "Parramatta");
    }

    #[test]
    fn suburb_hint_excludes_the_marker_phrase() {
        let (name, hint) =
            extract_division("<p>You are enrolled for Bondi Beach 2026</p>").expect("matches");
        assert_eq!(name, "Bondi Beach");
        assert_eq!(hint.as_deref(), Some("Bondi Beach"));
        let (name, hint) =
            extract_division("<div>Division of Sydney NSW 2000</div>").expect("matches");
        assert_eq!(name, "Sydney NSW");
        assert_eq!(hint.as_deref(), Some("Sydney NSW"));
    }

    #[test]
    fn no_marker_returns_none() {
        assert_eq!(extract_division("<p>Nothing electoral here</p>"), None);
    }

    #[test]
    fn a_negated_enrolment_is_not_read_as_a_confirmed_match() {
        assert_eq!(
            extract_division("<p>You are not enrolled for the Division of Sydney</p>"),
            None
        );
        assert_eq!(
            extract_division("<p>Your enrolment for the Division of Sydney has lapsed</p>"),
            None
        );
        assert_eq!(
            extract_division("<p>We were unable to find you enrolled for Bondi Beach</p>"),
            None
        );
        assert_eq!(
            extract_division("<p>No record found: not currently enrolled in Parramatta</p>"),
            None
        );
    }

    #[test]
    fn an_unrelated_negation_far_from_the_marker_does_not_suppress_a_real_match() {
        let filler = "x".repeat(200);
        let html = format!(
            "<p>Some unrelated notice: not found in a different system. {filler} You are enrolled for the Division of Sydney</p>"
        );
        let (name, _) =
            extract_division(&html).expect("a distant negation must not suppress this match");
        assert_eq!(name, "Sydney");
    }

    #[test]
    fn case_insensitive_match() {
        let html = "<p>DIVISION OF Melbourne</p>";
        let (name, _) = extract_division(html).expect("should succeed");
        assert_eq!(name, "Melbourne");
    }

    #[test]
    fn apostrophe_division_name_is_not_truncated() {
        let html = "<div>You are enrolled for the Division of O'Connor (2026)</div>";
        let (name, _) = extract_division(html).expect("should succeed");
        assert_eq!(name, "O'Connor");
    }

    #[test]
    fn anchors_suburb_on_in_range_postcode() {
        assert_eq!(
            extract_suburb_hint("Bondi Beach 2026 NSW"),
            Some("Bondi Beach".to_string())
        );
    }

    #[test]
    fn out_of_range_postcode_yields_none() {
        assert_eq!(extract_suburb_hint("Suburbia 0100"), None);
    }

    #[test]
    fn no_postcode_yields_none() {
        assert_eq!(extract_suburb_hint("Division of Sydney NSW"), None);
    }

    #[test]
    fn postcode_with_no_preceding_alpha_yields_none() {
        assert_eq!(extract_suburb_hint("2000 only"), None);
    }

    #[test]
    fn five_digit_run_is_not_a_postcode() {
        assert_eq!(extract_suburb_hint("Bondi Beach 20267"), None);
        assert_eq!(extract_suburb_hint("Bondi Beach 12026"), None);
    }

    #[test]
    fn apostrophe_suburb_hint_is_not_truncated() {
        assert_eq!(
            extract_suburb_hint("O'Malley 2606"),
            Some("O'Malley".to_string())
        );
    }
}
