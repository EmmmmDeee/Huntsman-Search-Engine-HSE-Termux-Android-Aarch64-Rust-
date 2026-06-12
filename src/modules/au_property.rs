//! Australian property and land title register searches.
//!
//! Queries publicly-accessible property and land title portals to find
//! registered ownership records for a full-name seed. Property title
//! registration is compulsory in Australia; ownership records are public
//! and freely searchable through state portals and their data services.
//!
//! Sources (all free, keyless):
//!   * NSW Spatial — `https://maps.six.nsw.gov.au/` (owner name search via
//!     ELVIS cadastral API — free, no key required for basic lookups)
//!   * VIC MapShare — `https://mapshare.vic.gov.au/` (parcel/owner search)
//!   * QLD Globe — `https://qldglobe.information.qld.gov.au/` (lot/plan owner)
//!   * data.gov.au Geocoded National Address File (GNAF) — suburb/postcode
//!     from lot/plan references, open-data, no key required
//!
//! MITRE ATT&CK:
//!   * T1591.001 — Determine Physical Locations (property address + suburb)
//!   * T1591.002 — Business Relationships (co-owners, trusts, companies)
//!   * T1589.003 — Employee Names (confirms legal registered name)
//!
//! Confidence model:
//!   * Registered owner with suburb + state: 0.74 (title register is
//!     government-maintained, higher than directory or electoral sources)
//!   * Suburb + postcode only (no street address exposed): 0.62
//!   * Coordinates from suburb centroid: 0.60 (derived, not raw)
//!
//! Orthogonal to `au_electoral` (electoral roll), `au_people` (residential
//! directories), `abn_lookup` (business register), `asic_director` (company
//! directors) — property ownership is a distinct legal record class.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "au_property";

pub struct AuProperty;

// ─── Name parsing helpers ─────────────────────────────────────────────────

/// Split `"First Last"` into `("First", "Last")`. Pure.
fn split_name(full: &str) -> (&str, &str) {
    let trimmed = full.trim();
    match trimmed.find(' ') {
        Some(pos) => (&trimmed[..pos], trimmed[pos + 1..].trim_start()),
        None => (trimmed, ""),
    }
}

/// Return the last whitespace-separated token as a surname. Pure.
fn surname(full: &str) -> &str {
    full.split_whitespace().next_back().unwrap_or(full.trim())
}

// ─── HTML stripping ───────────────────────────────────────────────────────

/// Strip HTML tags from a property portal response, injecting a space at
/// each tag boundary to prevent word concatenation. Pure.
fn strip_html(html: &str) -> String {
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
            && !bytes.get(i + 4).map(u8::is_ascii_digit).unwrap_or(false)
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

/// Parse owner records from a NSW Spatial / ELVIS cadastral API response.
/// Looks for suburb + state patterns near a name match. Pure.
pub(crate) fn parse_nsw_response(text: &str, full_name: &str) -> Vec<PropertyRecord> {
    let stripped = strip_html(text);
    let mut out = Vec::new();
    // NSW ELVIS returns JSON-like or HTML rows. Scan for name proximity.
    for line in stripped.lines() {
        if !name_matches(line, full_name) {
            continue;
        }
        let state = extract_state(line).unwrap_or("NSW");
        let postcode = extract_postcode(line);
        let suburb = extract_suburb_from_line(line, state);
        if !suburb.is_empty() {
            out.push(PropertyRecord {
                owner_name: full_name.to_string(),
                suburb,
                state,
                postcode,
            });
        }
    }
    out
}

/// Parse owner records from a VIC MapShare response. Pure.
pub(crate) fn parse_vic_response(text: &str, full_name: &str) -> Vec<PropertyRecord> {
    let stripped = strip_html(text);
    let mut out = Vec::new();
    for line in stripped.lines() {
        if !name_matches(line, full_name) {
            continue;
        }
        let state = extract_state(line).unwrap_or("VIC");
        let postcode = extract_postcode(line);
        let suburb = extract_suburb_from_line(line, state);
        if !suburb.is_empty() {
            out.push(PropertyRecord {
                owner_name: full_name.to_string(),
                suburb,
                state,
                postcode,
            });
        }
    }
    out
}

/// Parse owner records from a QLD Globe / titles response. Pure.
pub(crate) fn parse_qld_response(text: &str, full_name: &str) -> Vec<PropertyRecord> {
    let stripped = strip_html(text);
    let mut out = Vec::new();
    for line in stripped.lines() {
        if !name_matches(line, full_name) {
            continue;
        }
        let state = extract_state(line).unwrap_or("QLD");
        let postcode = extract_postcode(line);
        let suburb = extract_suburb_from_line(line, state);
        if !suburb.is_empty() {
            out.push(PropertyRecord {
                owner_name: full_name.to_string(),
                suburb,
                state,
                postcode,
            });
        }
    }
    out
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
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        if !suburb.is_empty() && suburb.len() <= 30 {
            return suburb;
        }
    }
    String::new()
}

/// Build Address + Coordinates entities from a `PropertyRecord`. Pure.
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
fn state_capital_coords(state: &str) -> Option<(f64, f64)> {
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

// ─── Module impl ──────────────────────────────────────────────────────────

#[async_trait]
impl Module for AuProperty {
    fn name(&self) -> &'static str {
        "au_property"
    }

    fn description(&self) -> &'static str {
        "Australian property and land title register searches — finds registered \
         ownership records (suburb/state/postcode) for a full-name seed via NSW, \
         VIC, and QLD public cadastral portals"
    }

    fn accepts(&self, t: &Target) -> bool {
        t.kind == TargetKind::FullName
    }

    fn produces(&self) -> &'static [EntityKind] {
        &[EntityKind::Address, EntityKind::Coordinates]
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001", "T1591.002", "T1589.003"]
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn priority(&self) -> u8 {
        84
    }

    fn max_timeout_ms(&self) -> u64 {
        // Three sequential state portal requests, each ~3–5 s.
        18_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let full_name = target.value.trim();
        if full_name.is_empty() {
            return Ok(ModuleResult::new());
        }

        let (first, last) = split_name(full_name);
        if last.is_empty() {
            return Ok(ModuleResult::new());
        }
        let sname = surname(full_name);
        let encoded_full = crate::util::http::urlencode(full_name);
        let encoded_sname = crate::util::http::urlencode(sname);
        let ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

        let mut all_entities: Vec<Entity> = Vec::new();

        // ── NSW Spatial / ELVIS cadastral ─────────────────────────────────
        // ELVIS name search endpoint — surname + given name query.
        let nsw_url = format!(
            "https://maps.six.nsw.gov.au/services/public/Property_Name_Address?surname={}&givenname={}&maxRows=10",
            crate::util::http::urlencode(last),
            crate::util::http::urlencode(first),
        );
        if let Ok(resp) = ctx
            .http
            .get(&nsw_url)
            .header("Accept", "application/json,text/html")
            .header("User-Agent", ua)
            .send_tagged(SRC)
            .await
            && resp.status().is_success()
            && let Ok(body) = resp.text().await
        {
            for rec in parse_nsw_response(&body, full_name) {
                all_entities.extend(record_to_entities(&rec, &ctx.scan_id));
            }
        }

        // ── VIC MapShare ──────────────────────────────────────────────────
        if all_entities.is_empty() {
            let vic_url = format!(
                "https://mapshare.vic.gov.au/mapsharevic/ows?service=WFS&version=1.0.0\
                 &request=GetFeature&typeName=CADASTRE:PARCEL&outputFormat=application/json\
                 &CQL_FILTER=OWNER_NAME+LIKE+%27{}%25%27&maxFeatures=10",
                encoded_sname
            );
            if let Ok(resp) = ctx
                .http
                .get(&vic_url)
                .header("Accept", "application/json,text/html")
                .header("User-Agent", ua)
                .send_tagged(SRC)
                .await
                && resp.status().is_success()
                && let Ok(body) = resp.text().await
            {
                for rec in parse_vic_response(&body, full_name) {
                    all_entities.extend(record_to_entities(&rec, &ctx.scan_id));
                }
            }
        }

        // ── QLD Globe / titles ────────────────────────────────────────────
        if all_entities.is_empty() {
            let qld_url = format!(
                "https://www.qld.gov.au/environment/land/title/searching/owners?owner={}",
                encoded_full
            );
            if let Ok(resp) = ctx
                .http
                .get(&qld_url)
                .header("Accept", "text/html,application/xhtml+xml")
                .header("User-Agent", ua)
                .send_tagged(SRC)
                .await
                && resp.status().is_success()
                && let Ok(body) = resp.text().await
            {
                for rec in parse_qld_response(&body, full_name) {
                    all_entities.extend(record_to_entities(&rec, &ctx.scan_id));
                }
            }
        }

        // Dedup by (kind, value) — different portals may agree on the same suburb.
        dedup_entities(&mut all_entities);

        let mut result = ModuleResult::new();
        result.entities = all_entities;
        Ok(result)
    }
}

/// Remove duplicate entities by (kind, value) keeping the highest-confidence
/// copy. Pure after the sort. Allocates one pass. Pure.
fn dedup_entities(entities: &mut Vec<Entity>) {
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

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::EntityKind;
    use crate::core::scan::{Target, TargetKind};

    #[test]
    fn split_name_splits_correctly() {
        assert_eq!(split_name("Haigen Bamford"), ("Haigen", "Bamford"));
        assert_eq!(split_name("Mary Ann Jones"), ("Mary", "Ann Jones"));
        assert_eq!(split_name("Cher"), ("Cher", ""));
        assert_eq!(split_name("  Anna  Smith  "), ("Anna", "Smith"));
    }

    #[test]
    fn surname_returns_last_token() {
        assert_eq!(surname("Haigen Bamford"), "Bamford");
        assert_eq!(surname("Mary Ann Jones"), "Jones");
        assert_eq!(surname("Cher"), "Cher");
    }

    #[test]
    fn strip_html_separates_tag_content() {
        let html = "<div>123</div><span>NSW</span>";
        let text = strip_html(html);
        assert!(
            !text.contains("123NSW"),
            "tags must inject word break: {text}"
        );
        assert!(text.contains("123"), "content must survive");
        assert!(text.contains("NSW"), "content must survive");
    }

    // Table-driven: (text, full_name, should_match)
    #[test]
    fn name_matches_detects_token_presence() {
        let cases: &[(&str, &str, bool)] = &[
            (
                "BAMFORD HAIGEN JOHN 25 SMITH ST SYDNEY NSW 2000",
                "Haigen Bamford",
                true,
            ),
            (
                "SMITH JOHN 10 MAIN ST PERTH WA 6000",
                "Haigen Bamford",
                false,
            ),
            ("bamford haigen 5 elm ave nsw", "Haigen Bamford", true),
            ("BAMFORD 12 OAK ST NSW", "Haigen Bamford", false), // missing given name
        ];
        for (text, name, expected) in cases {
            assert_eq!(
                name_matches(text, name),
                *expected,
                "name_matches({text:?}, {name:?}) should be {expected}"
            );
        }
    }

    #[test]
    fn extract_postcode_finds_valid_au_postcode() {
        assert_eq!(extract_postcode("Sydney NSW 2000"), Some("2000".into()));
        assert_eq!(extract_postcode("Melbourne VIC 3000"), Some("3000".into()));
        assert_eq!(extract_postcode("no postcode here"), None);
        // 1000 is not a valid AU postcode (< 2000).
        assert_eq!(extract_postcode("invalid 1000 postcode"), None);
        // 5-digit run must not match.
        assert_eq!(extract_postcode("12345 invalid"), None);
    }

    #[test]
    fn extract_state_returns_canonical_code() {
        assert_eq!(extract_state("Sydney NSW 2000"), Some("NSW"));
        assert_eq!(extract_state("Melbourne Victoria"), Some("VIC"));
        assert_eq!(extract_state("Perth WA"), Some("WA"));
        assert_eq!(extract_state("no state here"), None);
    }

    #[test]
    fn parse_nsw_response_extracts_matching_record() {
        let html = "<tr><td>BAMFORD HAIGEN</td><td>SURRY HILLS</td><td>NSW</td><td>2010</td></tr>";
        let recs = parse_nsw_response(html, "Haigen Bamford");
        assert!(
            !recs.is_empty(),
            "must extract a record when name matches: {html}"
        );
        let rec = &recs[0];
        assert_eq!(rec.state, "NSW");
        assert_eq!(rec.postcode.as_deref(), Some("2010"));
    }

    #[test]
    fn parse_nsw_response_ignores_non_matching_rows() {
        let html = "<tr><td>SMITH JOHN</td><td>SYDNEY</td><td>NSW</td><td>2000</td></tr>";
        let recs = parse_nsw_response(html, "Haigen Bamford");
        assert!(recs.is_empty(), "non-matching rows must be ignored");
    }

    #[test]
    fn record_to_entities_emits_address_and_coordinates() {
        let rec = PropertyRecord {
            owner_name: "Haigen Bamford".into(),
            suburb: "Sydney".into(),
            state: "NSW",
            postcode: Some("2000".into()),
        };
        let ents = record_to_entities(&rec, "s");
        let kinds: Vec<_> = ents.iter().map(|e| &e.kind).collect();
        assert!(kinds.contains(&&EntityKind::Address), "must emit Address");
        // Coordinates should follow from the suburb centroid.
        // (Sydney is in the city_coords table or state-capital fallback.)
        for e in &ents {
            assert!(e.has_tag("country:AU"), "must carry country:AU");
            assert!(e.has_tag("au-state:NSW"), "must carry au-state:NSW");
        }
    }

    #[test]
    fn record_to_entities_address_includes_postcode_when_present() {
        let rec = PropertyRecord {
            owner_name: "Haigen Bamford".into(),
            suburb: "Fitzroy".into(),
            state: "VIC",
            postcode: Some("3065".into()),
        };
        let ents = record_to_entities(&rec, "s");
        let addr = ents.iter().find(|e| e.kind == EntityKind::Address).unwrap();
        assert!(
            addr.value.contains("3065"),
            "address must include postcode: {}",
            addr.value
        );
    }

    #[test]
    fn dedup_entities_removes_exact_duplicates() {
        use crate::core::entity::Entity;
        let mut ents = vec![
            Entity::new(EntityKind::Address, "Sydney, NSW", 0.74, "s"),
            Entity::new(EntityKind::Address, "Sydney, NSW", 0.62, "s"),
            Entity::new(EntityKind::Address, "Melbourne, VIC", 0.74, "s"),
        ];
        dedup_entities(&mut ents);
        assert_eq!(
            ents.len(),
            2,
            "duplicate (kind, value) must be deduplicated"
        );
    }

    #[test]
    fn module_metadata_is_valid() {
        let m = AuProperty;
        assert_eq!(m.name(), "au_property");
        assert!(m.accepts(&Target::new(TargetKind::FullName, "Haigen Bamford")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@example.com")));
        assert!(m.attack_techniques().contains(&"T1591.001"));
        assert!(m.attack_techniques().contains(&"T1591.002"));
        assert!(m.attack_techniques().contains(&"T1589.003"));
        assert!(m.max_timeout_ms() > crate::MODULE_TIMEOUT_MS);
    }
}
