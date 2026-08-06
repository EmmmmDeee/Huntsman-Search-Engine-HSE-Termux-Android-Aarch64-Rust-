//! Parsing helpers: HTML stripping, name matching, record extraction, entity building.

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
};

pub(super) const SRC: &str = "au_property";

// ─── Name parsing helpers ─────────────────────────────────────────────────

/// Split `"First Last"` into `("First", "Last")`. Pure.
pub(super) fn split_name(full: &str) -> (&str, &str) {
    let trimmed = full.trim();
    match trimmed.find(' ') {
        Some(pos) => (&trimmed[..pos], trimmed[pos + 1..].trim_start()),
        None => (trimmed, ""),
    }
}

/// Return the last whitespace-separated token as a surname. Pure.
pub(super) fn surname(full: &str) -> &str {
    full.split_whitespace().next_back().unwrap_or(full.trim())
}

// ─── HTML stripping ───────────────────────────────────────────────────────

pub(super) use crate::util::html::strip_html;

// ─── Result parsing ───────────────────────────────────────────────────────

/// A parsed property record: owner name, suburb, state, optional postcode.
#[derive(Debug, PartialEq)]
pub(crate) struct PropertyRecord {
    pub owner_name: String,
    pub suburb: String,
    pub state: &'static str,
    pub postcode: Option<String>,
}

/// Try to match the subject's full name against a text window. Returns true when
/// every token of the full name appears as a WHOLE WORD in the text
/// (case-insensitive). Pure.
///
/// Whole-word, not substring: a substring gate wrongly admits a coincidental
/// line for AU-common short surnames (Le, Ng, Ha, Vo, Do) — and since a matched
/// record now stamps an `owner` attribute and an `exact-name-match` tag that the
/// relation layer turns into a Person→property `LocatedAt` edge, a loose match
/// would FABRICATE a subject↔property link.
///
/// Deliberately NOT the shared [`crate::util::str_util::whole_word_token_match`]
/// (which folds ASCII-only): AU property registers carry accented owner names
/// (e.g. `NGUYỄN`, `LÊ`), and an ASCII fold would miss an accented letter in
/// mismatched case (seed `José` vs register `JOSÉ`). This matcher stays
/// full-Unicode (`to_lowercase`) on purpose — do not collapse it into the ASCII
/// helper.
pub(crate) fn name_matches(text: &str, full_name: &str) -> bool {
    let text_lc = text.to_lowercase();
    let full_lc = full_name.to_lowercase();
    full_lc.split_whitespace().all(|token| {
        text_lc
            .split(|c: char| !c.is_alphanumeric())
            .any(|word| word == token)
    })
}

/// Extract AU state abbreviation from a text window. Returns the canonical
/// 2–3 char state code when found. Pure.
pub(crate) fn extract_state(text: &str) -> Option<&'static str> {
    crate::util::address_au::state_code(text)
}

/// Extract a 4-digit AU postcode in range 2000–9999 from a text window. Pure.
///
/// The standalone-postcode boundary test is the shared
/// [`crate::util::address_au::is_standalone_postcode_at`] so this and the
/// `au_electoral` suburb-hint scan cannot diverge on what a postcode is.
pub(crate) fn extract_postcode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    for i in 0..bytes.len().saturating_sub(3) {
        if crate::util::address_au::is_standalone_postcode_at(bytes, i) {
            // The predicate confirmed four ASCII digits, so `i..i + 4` is a
            // valid char boundary.
            return Some(text[i..i + 4].to_string());
        }
    }
    None
}

/// Extract a suburb name from a line, stopping before the state abbreviation
/// token. Returns an empty string when no suburb can be identified. Pure.
fn extract_suburb_from_line(line: &str, state: &str) -> String {
    // Walk backwards from the state code to collect the suburb name. The state
    // token is ASCII, so an ASCII-case-insensitive search over the original
    // `line` yields a char-boundary-safe offset — unlike `to_lowercase().find()`,
    // whose offset can land mid-codepoint in `line` and panic on a multibyte
    // uppercase char before the state token.
    if let Some(pos) = crate::util::str_util::find_ascii_ci(line, state) {
        // Suburb is the sequence of alpha tokens immediately before the state.
        let before = line[..pos].trim_end();
        let suburb: String = before
            .split_whitespace()
            .rev()
            // A suburb is all-alpha or hyphenated; stop on digits/punctuation.
            .take_while(|tok| {
                tok.chars()
                    .all(|c| c.is_alphabetic() || c == '-' || c == '\'')
            })
            .collect::<Vec<_>>()
            .iter()
            .rev()
            .copied()
            .collect::<Vec<_>>()
            .join(" ");
        if !suburb.is_empty() && suburb.len() <= 30 {
            return suburb;
        }
    }
    String::new()
}

/// Parse owner records from a property-portal response: keep lines matching the
/// seed name, then extract suburb/state/postcode. `default_state` applies when a
/// line names no state. Pure. The per-portal wrappers differ only in that default.
fn parse_response(text: &str, full_name: &str, default_state: &'static str) -> Vec<PropertyRecord> {
    strip_html(text)
        .lines()
        .filter(|line| name_matches(line, full_name))
        .filter_map(|line| {
            let state = extract_state(line).unwrap_or(default_state);
            let suburb = extract_suburb_from_line(line, state);
            (!suburb.is_empty()).then(|| PropertyRecord {
                owner_name: full_name.to_string(),
                suburb,
                state,
                postcode: extract_postcode(line),
            })
        })
        .collect()
}

/// Parse owner records from a NSW Spatial / ELVIS cadastral API response. Pure.
pub(crate) fn parse_nsw_response(text: &str, full_name: &str) -> Vec<PropertyRecord> {
    parse_response(text, full_name, "NSW")
}

/// Parse owner records from a VIC MapShare response. Pure.
pub(crate) fn parse_vic_response(text: &str, full_name: &str) -> Vec<PropertyRecord> {
    parse_response(text, full_name, "VIC")
}

/// Parse owner records from a QLD Globe / titles response. Pure.
pub(crate) fn parse_qld_response(text: &str, full_name: &str) -> Vec<PropertyRecord> {
    parse_response(text, full_name, "QLD")
}

// ─── Entity building ──────────────────────────────────────────────────────

/// Build Address + Coordinates entities from a [`PropertyRecord`]. Pure.
pub(crate) fn record_to_entities(rec: &PropertyRecord, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();

    let addr_value = match &rec.postcode {
        Some(pc) => format!("{}, {} {}", rec.suburb, rec.state, pc),
        None => format!("{}, {}", rec.suburb, rec.state),
    };
    let conf = if rec.postcode.is_some() { 0.74 } else { 0.62 };
    let evid = Evidence::new(
        SRC,
        format!("Property title owner match: {}", rec.owner_name),
    )
    // `owner` is a PERSON_NAME_ATTRS key, so `core::relation::derive_residency`
    // binds this place to the matching subject Person as a LocatedAt edge — the
    // record is whole-word name-matched by construction (see `name_matches`).
    .with_attr("owner", &rec.owner_name)
    .with_attr("suburb", &rec.suburb)
    .with_attr("state", rec.state);

    let mut addr = Entity::new(EntityKind::Address, &addr_value, conf, scan_id);
    addr.add_evidence(evid.clone());
    addr.tag(format!("au-state:{}", rec.state));
    addr.tag("country:AU");
    addr.tag("source:property");
    // Name-matched register hit → geo_family can anchor the precise suburb
    // Address on the subject (mirrors qld_unclaimed's exact register hits).
    addr.tag("exact-name-match");
    out.push(addr);

    // Derive coordinates by an HONEST precision ladder — a coarse guess must
    // never masquerade as a name-matched suburb centroid:
    //   1. suburb centroid (precise, name-matched)        -> MEDIUM_PLUS
    //   2. the parsed postcode's exact gazetteer centroid -> MEDIUM
    //   3. the postcode's leading-two-digit region centroid -> LOW_MEDIUM
    //   4. the state capital, last resort                 -> LOW, coarse
    // Previously every suburb miss fell straight to the state capital yet was
    // stamped MEDIUM_PLUS + exact-name-match + derived_from:suburb_centroid, so a
    // rural owner was pinned to the capital indistinguishably from a real suburb
    // fix, and the parsed postcode (a finer, honest signal, already in the
    // Address) was never used to geocode.
    let suburb_lc = rec.suburb.to_lowercase();
    let coord_fix: Option<((f64, f64), f64, &str, bool)> =
        crate::util::city_coords::city_coords(&suburb_lc)
            .map(|c| (c, confidence::MEDIUM_PLUS, "suburb_centroid", true))
            .or_else(|| {
                let pc = rec.postcode.as_deref()?;
                crate::util::city_coords::postcode_coords(pc)
                    .map(|c| (c, confidence::MEDIUM, "postcode_centroid", false))
                    .or_else(|| {
                        crate::util::city_coords::au_postcode_region(pc)
                            .map(|c| (c, confidence::LOW_MEDIUM, "postcode_region", false))
                    })
            })
            .or_else(|| {
                state_capital_coords(rec.state)
                    .map(|c| (c, confidence::LOW, "state_capital_fallback", false))
            });
    if let Some(((lat, lon), coord_conf, derived_from, name_matched)) = coord_fix {
        let coord_value = format!("{lat:.4},{lon:.4}");
        let mut coord = Entity::new(EntityKind::Coordinates, &coord_value, coord_conf, scan_id);
        coord.add_evidence(evid.with_attr("derived_from", derived_from));
        coord.tag(format!("au-state:{}", rec.state));
        coord.tag("country:AU");
        // `exact-name-match` (which lets the correlator anchor this as a precise
        // residence) belongs only to a genuine suburb centroid; every fallback is
        // region-grain and is tagged `coarse` instead.
        if name_matched {
            coord.tag("exact-name-match");
        } else {
            coord.tag("coarse");
        }
        out.push(coord);
    }

    out
}

/// State-capital centroid fallback when a suburb isn't in the offline table.
pub(super) fn state_capital_coords(state: &str) -> Option<(f64, f64)> {
    match state {
        "NSW" => Some((-33.8688, 151.2093)),
        "VIC" => Some((-37.8136, 144.9631)),
        "QLD" => Some((-27.4698, 153.0251)),
        "SA" => Some((-34.9285, 138.6007)),
        "WA" => Some((-31.9505, 115.8605)),
        "TAS" => Some((-42.8821, 147.3272)),
        "ACT" => Some((-35.2809, 149.1300)),
        "NT" => Some((-12.4634, 130.8456)),
        _ => None,
    }
}

// ─── Dedup ────────────────────────────────────────────────────────────────

/// Remove duplicate entities by (kind, value) keeping the highest-confidence
/// copy. Pure after the sort. Allocates one pass.
pub(super) fn dedup_entities(entities: &mut Vec<Entity>) {
    entities.sort_by(|a, b| {
        format!("{}", a.kind)
            .cmp(&format!("{}", b.kind))
            .then(a.value.cmp(&b.value))
            .then(
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
    });
    entities.dedup_by(|a, b| a.kind == b.kind && a.value == b.value);
}

#[cfg(test)]
mod suburb_line_tests {
    use super::extract_suburb_from_line;

    #[test]
    fn walks_back_alpha_tokens_until_a_digit() {
        assert_eq!(
            extract_suburb_from_line("25 SURRY HILLS NSW", "NSW"),
            "SURRY HILLS"
        );
    }

    #[test]
    fn returns_empty_when_state_token_absent() {
        assert_eq!(extract_suburb_from_line("just some words", "NSW"), "");
    }

    #[test]
    fn returns_empty_when_suburb_exceeds_thirty_chars() {
        assert_eq!(
            extract_suburb_from_line("Supercalifragilisticexpialidocious Township NSW", "NSW"),
            ""
        );
    }

    #[test]
    fn returns_empty_when_nothing_precedes_state() {
        assert_eq!(extract_suburb_from_line("NSW 2000", "NSW"), "");
    }

    #[test]
    fn does_not_panic_on_multibyte_uppercase_before_state() {
        // Regression (PROBLEM_TREE T0.2): a multibyte uppercase char before the
        // state token shifted a `to_lowercase()` offset onto a non-char-boundary
        // in the original line → `str` slice panic. `find_ascii_ci` is safe.
        let s = extract_suburb_from_line("İstanbul Heights NSW", "NSW");
        assert!(s.contains("Heights") && s.contains("İstanbul"), "got {s:?}");
    }
}
