//! Parsing helpers: HTML stripping, name matching, record extraction, entity building.

use crate::core::entity::{Entity, EntityKind, Evidence};

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

/// Strip HTML tags from a property portal response, injecting a space at
/// each tag boundary to prevent word concatenation. Pure.
pub(super) fn strip_html(html: &str) -> String {
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
            '&' if !in_tag => out.push(' '), // entity start
            ';' if !in_tag => out.push(' '), // entity end
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    // Collapse whitespace runs.
    let mut result = String::with_capacity(out.len());
    let mut prev_ws = false;
    for ch in out.chars() {
        if ch.is_whitespace() {
            if !prev_ws {
                result.push(' ');
            }
            prev_ws = true;
        } else {
            result.push(ch);
            prev_ws = false;
        }
    }
    result.trim().to_string()
}

// ─── Result parsing ───────────────────────────────────────────────────────

/// A parsed property record: owner name, suburb, state, optional postcode.
#[derive(Debug, PartialEq)]
pub(crate) struct PropertyRecord {
    pub owner_name: String,
    pub suburb: String,
    pub state: &'static str,
    pub postcode: Option<String>,
}

/// Try to match a name token against the subject's full name. Returns true
/// when the surname and at least one given-name token appear in the text
/// (case-insensitive). Pure.
pub(crate) fn name_matches(text: &str, full_name: &str) -> bool {
    let text_lc = text.to_lowercase();
    let full_lc = full_name.to_lowercase();
    // Every token of the full name must appear somewhere in the text.
    full_lc
        .split_whitespace()
        .all(|token| text_lc.contains(token))
}

/// Extract AU state abbreviation from a text window. Returns the canonical
/// 2–3 char state code when found. Pure.
pub(crate) fn extract_state(text: &str) -> Option<&'static str> {
    crate::util::address_au::state_code(text)
}

/// Extract a 4-digit AU postcode in range 2000–9999 from a text window. Pure.
pub(crate) fn extract_postcode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    for i in 0..bytes.len().saturating_sub(3) {
        if bytes[i].is_ascii_digit()
            && bytes[i + 1].is_ascii_digit()
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3].is_ascii_digit()
            // Reject 5+ digit runs (not a standalone 4-digit code).
            && !bytes.get(i + 4).is_some_and(u8::is_ascii_digit)
            && (i == 0 || !bytes[i - 1].is_ascii_digit())
        {
            let pc: u32 = text[i..i + 4].parse().ok()?;
            if (2000..=9999).contains(&pc) {
                return Some(text[i..i + 4].to_string());
            }
        }
    }
    None
}

/// Extract a suburb name from a line, stopping before the state abbreviation
/// token. Returns an empty string when no suburb can be identified. Pure.
fn extract_suburb_from_line(line: &str, state: &str) -> String {
    // Walk backwards from the state code to collect the suburb name.
    let lc = line.to_lowercase();
    let state_lc = state.to_lowercase();
    if let Some(pos) = lc.find(&state_lc) {
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
    .with_attr("suburb", &rec.suburb)
    .with_attr("state", rec.state);

    let mut addr = Entity::new(EntityKind::Address, &addr_value, conf, scan_id);
    addr.add_evidence(evid.clone());
    addr.tag(format!("au-state:{}", rec.state));
    addr.tag("country:AU");
    addr.tag("source:property");
    out.push(addr);

    // Derive coordinates from the suburb centroid via the offline city table.
    let suburb_lc = rec.suburb.to_lowercase();
    if let Some((lat, lon)) = crate::util::city_coords::city_coords(&suburb_lc).or_else(|| {
        // State-capital fallback when suburb not in the offline table.
        state_capital_coords(rec.state)
    }) {
        let coord_value = format!("{lat:.4},{lon:.4}");
        let mut coord = Entity::new(EntityKind::Coordinates, &coord_value, 0.60, scan_id);
        coord.add_evidence(evid.with_attr("derived_from", "suburb_centroid"));
        coord.tag(format!("au-state:{}", rec.state));
        coord.tag("country:AU");
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
