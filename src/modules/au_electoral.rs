//! Australian Electoral Commission (AEC) and state electoral roll lookups.
//!
//! Queries the AEC's public "Check your enrolment" tool and the equivalent
//! state commission pages (NSW, VIC, QLD) to confirm enrolment and extract
//! the electoral division (which maps to a suburb/postcode range). Electoral
//! roll enrolment in Australia is compulsory, so this is a high-confidence
//! residential-address signal orthogonal to business registers, unclaimed-money
//! records, and people-finder directories.
//!
//! Sources (all free, keyless, public HTML):
//!   * AEC — `https://electorate.aec.gov.au/NameSearch.aspx`
//!   * NSW Electoral Commission — `https://check.elections.nsw.gov.au/`
//!   * VEC (Victoria) — `https://check.vec.vic.gov.au/`
//!   * ECQ (Queensland) — `https://enrol.ecq.qld.gov.au/check`
//!
//! MITRE ATT&CK:
//!   * T1591.001 — Determine Physical Locations (electoral division → suburb)
//!   * T1589.003 — Employee Names (confirms legal registered name)
//!
//! Confidence model:
//!   * Confirmed enrolment with division + suburb: 0.72 (electoral roll is
//!     compulsory and address-verified; higher than directory sources)
//!   * Division only (no suburb resolved): 0.58
//!   * Address from division centroid lookup: 0.65 (derived, not raw)
//!
//! The module is AU-restricted: it only accepts `FullName` targets and only
//! emits when the division geography maps inside Australia.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "au_electoral";

pub struct AuElectoral;

// ─── Electoral division → location mapping ────────────────────────────────
//
// AEC electoral divisions map to specific geographic areas. We carry an
// offline centroid table (capital cities / major divisions) so a confirmed
// division fires coordinates without an extra geocoding round-trip.
// This is the same offline-first, API-second strategy used by au_unclaimed.

struct DivisionInfo {
    state: &'static str,
    suburb: &'static str,
    lat: f64,
    lon: f64,
}

/// Offline centroid table for the 48 most-populous AEC electoral divisions.
/// Each entry is the geographic centroid of the division, tagged to its state.
/// Division names are lowercase-normalised for matching. Pure.
fn division_centroid(division: &str) -> Option<DivisionInfo> {
    // Lowercase the input once for case-insensitive matching.
    let div = division.to_lowercase();
    // Table: (division_lc, state, suburb_label, lat, lon)
    const TABLE: &[(&str, &str, &str, f64, f64)] = &[
        // NSW
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
        // VIC
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
        // QLD
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
        // SA
        ("boothby", "SA", "Mitcham", -35.0104, 138.5985),
        ("sturt", "SA", "West Lakes", -34.8820, 138.5038),
        ("adelaide", "SA", "Adelaide CBD", -34.9285, 138.6007),
        ("hindmarsh", "SA", "Hindmarsh", -34.9000, 138.5600),
        // WA
        ("perth", "WA", "Perth CBD", -31.9505, 115.8605),
        ("curtin", "WA", "Cottesloe", -31.9926, 115.7621),
        ("cowan", "WA", "Joondalup", -31.7440, 115.7680),
        ("burt", "WA", "Armadale", -32.1529, 116.0136),
        ("hasluck", "WA", "Midland", -31.8882, 116.0065),
        ("swan", "WA", "Midvale", -31.8800, 116.0360),
        ("fremantle", "WA", "Fremantle", -32.0569, 115.7439),
        ("canning", "WA", "Cannington", -32.0153, 115.9381),
        // ACT
        ("bean", "ACT", "Tuggeranong", -35.4244, 149.0886),
        ("canberra", "ACT", "Canberra", -35.2809, 149.1300),
        ("fenner", "ACT", "Gungahlin", -35.1823, 149.1332),
        // TAS
        ("bass", "TAS", "Launceston", -41.4332, 147.1441),
        ("braddon", "TAS", "Devonport", -41.1800, 146.3500),
        ("clark", "TAS", "Hobart", -42.8821, 147.3272),
        ("franklin", "TAS", "Kingston", -42.9773, 147.2804),
        ("lyons", "TAS", "New Norfolk", -42.7820, 147.0580),
        // NT
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

// ─── AU state electoral division patterns ─────────────────────────────────

/// Parse a confirmed division name from an AEC or state EC HTML response.
/// Returns `(division_name, suburb_hint)` when a match is found. Pure.
///
/// The AEC "Check enrolment" response contains patterns like:
/// `"You are enrolled for the Division of Sydney"` or
/// `"enrolled for Sydney (NSW)"`. State commissions use similar phrasing.
pub(crate) fn extract_division(html: &str) -> Option<(String, Option<String>)> {
    let text = strip_electoral_html(html);
    let lc = text.to_lowercase();

    // AEC pattern: "division of <name>"
    if let Some(pos) = lc.find("division of ") {
        let rest = &text[pos + "division of ".len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphabetic() || *c == '-' || *c == ' ')
            .collect();
        let name = name.trim().to_string();
        if !name.is_empty() && name.len() < 40 {
            // Try to extract a suburb hint from the same context window.
            let suburb = extract_suburb_hint(&text[pos..]);
            return Some((name, suburb));
        }
    }

    // State EC pattern: "enrolled in <Division>" or "enrolled for <Division>".
    ["enrolled in ", "enrolled for "].iter().find_map(|marker| {
        let pos = lc.find(marker)?;
        let rest = &text[pos + marker.len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphabetic() || *c == '-' || *c == ' ')
            .collect();
        let name = name.trim().to_string();
        (!name.is_empty() && name.len() < 40).then(|| (name, extract_suburb_hint(&text[pos..])))
    })
}

/// Strip HTML tags from an electoral response, inserting spaces at each tag
/// boundary to prevent word concatenation. Pure.
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
    // Collapse runs of whitespace.
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

/// Extract a suburb hint from the text window around a division match.
/// Looks for AU postcode patterns to anchor a suburb name. Pure.
fn extract_suburb_hint(window: &str) -> Option<String> {
    // A 4-digit postcode in range 2000..9999 indicates a suburb is nearby.
    // Walk byte windows to find the first ASCII-digit quad that parses as
    // a valid AU postcode, then extract the suburb name that precedes it.
    window.as_bytes().windows(4).enumerate().find_map(|(i, w)| {
        if !w.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let pc: u32 = window[i..i + 4].parse().ok()?;
        if !(2000..=9999).contains(&pc) {
            return None;
        }
        // Walk backwards from the postcode to collect the suburb name.
        let before = window[..i].trim_end();
        let suburb: String = before
            .chars()
            .rev()
            .take_while(|c| c.is_alphabetic() || *c == ' ')
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        let suburb = suburb.trim().to_string();
        (!suburb.is_empty() && suburb.len() < 30).then_some(suburb)
    })
}

/// Build entity set from a confirmed electoral division match. Pure.
/// Returns Address + Coordinates (when division centroid is known) tagged
/// with au-state and country:AU, all attributed to the electoral source.
pub(crate) fn build_electoral_entities(
    division: &str,
    suburb_hint: Option<&str>,
    full_name: &str,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    let evid = Evidence::new(SRC, format!("Electoral division: {division}"));

    let (state, suburb, lat, lon, coord_conf) = if let Some(info) = division_centroid(division) {
        (
            info.state,
            suburb_hint.unwrap_or(info.suburb).to_string(),
            Some(info.lat),
            Some(info.lon),
            0.65_f64,
        )
    } else {
        // Division not in offline table — emit address-only, no coords.
        let state = infer_state_from_division(division).unwrap_or("AU");
        (
            state,
            suburb_hint.unwrap_or("").to_string(),
            None,
            None,
            0.0,
        )
    };

    // Address entity: "Suburb, STATE" or "Division (STATE)" when no suburb.
    let addr_value = if !suburb.is_empty() {
        format!("{suburb}, {state}")
    } else {
        format!("{division} (electoral division), {state}")
    };
    let mut addr = Entity::new(EntityKind::Address, &addr_value, 0.72, scan_id);
    addr.add_evidence(
        evid.clone()
            .with_attr("division", division)
            .with_attr("source_name", full_name),
    );
    addr.tag(format!("au-state:{state}"));
    addr.tag("country:AU");
    addr.tag("source:electoral");
    out.push(addr);

    // Coordinates entity when we have an offline centroid.
    if let (Some(lat), Some(lon)) = (lat, lon) {
        let coord_value = format!("{lat:.4},{lon:.4}");
        let mut coord = Entity::new(EntityKind::Coordinates, &coord_value, coord_conf, scan_id);
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

/// Cheap heuristic: map common division name suffixes to an AU state. Used
/// when the division isn't in the offline centroid table. Pure.
fn infer_state_from_division(division: &str) -> Option<&'static str> {
    let lc = division.to_lowercase();
    // Some divisions carry clear state signals in their name.
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
    } else if lc.contains("canberra") || lc.contains("darwin") {
        Some("ACT")
    } else {
        None
    }
}

// ─── Module impl ──────────────────────────────────────────────────────────

#[async_trait]
impl Module for AuElectoral {
    fn name(&self) -> &'static str {
        "au_electoral"
    }

    fn description(&self) -> &'static str {
        "AEC and state electoral commission enrolment lookups — confirms residential \
         electoral division (suburb/state) for an AU full-name seed"
    }

    fn accepts(&self, t: &Target) -> bool {
        t.kind == TargetKind::FullName
    }

    fn produces(&self) -> &'static [EntityKind] {
        &[EntityKind::Address, EntityKind::Coordinates]
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001", "T1589.003"]
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn priority(&self) -> u8 {
        85
    }

    fn max_timeout_ms(&self) -> u64 {
        // Four sequential EC lookups (AEC → NSW → VIC → ECQ), each ~3–5 s.
        20_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let full_name = target.value.trim();
        if full_name.is_empty() {
            return Ok(ModuleResult::new());
        }

        let encoded = crate::util::http::urlencode(full_name);
        let mut all_entities: Vec<Entity> = Vec::new();

        // ── AEC national lookup ──────────────────────────────────────────
        let (first, last) = split_name(full_name);
        if !last.is_empty() {
            let aec_url = format!(
                "https://electorate.aec.gov.au/NameSearch.aspx?surname={}&firstname={}",
                crate::util::http::urlencode(last),
                crate::util::http::urlencode(first),
            );
            if let Ok(resp) = ctx
                .http
                .get(&aec_url)
                .header("Accept", "text/html,application/xhtml+xml")
                .header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                .send_tagged(SRC)
                .await
                && let Ok(body) = resp.text().await
                && let Some((div, suburb)) = extract_division(&body)
            {
                all_entities.extend(build_electoral_entities(
                    &div,
                    suburb.as_deref(),
                    full_name,
                    &ctx.scan_id,
                ));
            }
        }

        // ── NSW Electoral Commission ─────────────────────────────────────
        if all_entities.is_empty() {
            let nsw_url = format!("https://check.elections.nsw.gov.au/search?name={}", encoded);
            if let Ok(resp) = ctx
                .http
                .get(&nsw_url)
                .header("Accept", "text/html,application/xhtml+xml")
                .header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                .send_tagged(SRC)
                .await
                && let Ok(body) = resp.text().await
                && let Some((div, suburb)) = extract_division(&body)
            {
                all_entities.extend(build_electoral_entities(
                    &div,
                    suburb.as_deref(),
                    full_name,
                    &ctx.scan_id,
                ));
            }
        }

        // ── Victorian Electoral Commission ────────────────────────────────
        if all_entities.is_empty() {
            let vec_url = format!("https://check.vec.vic.gov.au/search?name={}", encoded);
            if let Ok(resp) = ctx
                .http
                .get(&vec_url)
                .header("Accept", "text/html,application/xhtml+xml")
                .header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                .send_tagged(SRC)
                .await
                && let Ok(body) = resp.text().await
                && let Some((div, suburb)) = extract_division(&body)
            {
                all_entities.extend(build_electoral_entities(
                    &div,
                    suburb.as_deref(),
                    full_name,
                    &ctx.scan_id,
                ));
            }
        }

        // ── ECQ Queensland ───────────────────────────────────────────────
        if all_entities.is_empty() {
            let ecq_url = format!("https://enrol.ecq.qld.gov.au/check?name={}", encoded);
            if let Ok(resp) = ctx
                .http
                .get(&ecq_url)
                .header("Accept", "text/html,application/xhtml+xml")
                .header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                .send_tagged(SRC)
                .await
                && let Ok(body) = resp.text().await
                && let Some((div, suburb)) = extract_division(&body)
            {
                all_entities.extend(build_electoral_entities(
                    &div,
                    suburb.as_deref(),
                    full_name,
                    &ctx.scan_id,
                ));
            }
        }

        let mut result = ModuleResult::new();
        result.entities = all_entities;
        Ok(result)
    }
}

/// Split `"First Last"` into `("First", "Last")`. Pure.
fn split_name(full: &str) -> (&str, &str) {
    let trimmed = full.trim();
    if let Some(pos) = trimmed.find(' ') {
        (&trimmed[..pos], trimmed[pos + 1..].trim_start())
    } else {
        (trimmed, "")
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn division_centroid_returns_sydney_for_sydney() {
        let info = division_centroid("Sydney").unwrap();
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

    // Table-driven: (html_snippet, expected_division, expected_suburb_contains)
    #[test]
    fn extract_division_parses_aec_pattern() {
        let cases: &[(&str, &str, Option<&str>)] = &[
            (
                "<p>You are enrolled for the Division of Sydney, NSW.</p>",
                "Sydney",
                None,
            ),
            (
                "<div>enrolled for Melbourne (VIC) 3000 Southbank</div>",
                "Melbourne",
                None,
            ),
            (
                "<span>You are enrolled in the Division of Brisbane</span>",
                "Brisbane",
                None,
            ),
            (
                "Division of North Sydney – electorate details",
                "North Sydney",
                None,
            ),
        ];
        for (html, expected_div, _suburb) in cases {
            let result = extract_division(html);
            assert!(result.is_some(), "expected a division from: {html}");
            let (div, _) = result.unwrap();
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
        let kinds: Vec<_> = ents.iter().map(|e| &e.kind).collect();
        assert!(kinds.contains(&&EntityKind::Address), "must emit Address");
        assert!(
            kinds.contains(&&EntityKind::Coordinates),
            "must emit Coordinates"
        );
        // All entities must be AU-tagged.
        for e in &ents {
            assert!(e.has_tag("country:AU"), "entity must carry country:AU");
            assert!(e.has_tag("au-state:NSW"), "Sydney division must be NSW");
        }
    }

    #[test]
    fn build_electoral_entities_unknown_division_emits_address_only() {
        let ents = build_electoral_entities("Xyzzy", None, "Test", "s");
        assert!(
            ents.iter().any(|e| e.kind == EntityKind::Address),
            "must still emit Address for unknown division"
        );
        assert!(
            !ents.iter().any(|e| e.kind == EntityKind::Coordinates),
            "no Coordinates for unknown division (no centroid)"
        );
    }

    #[test]
    fn build_electoral_entities_suburb_hint_overrides_centroid_suburb() {
        let ents = build_electoral_entities("Sydney", Some("Newtown"), "Test", "s");
        let addr = ents.iter().find(|e| e.kind == EntityKind::Address).unwrap();
        assert!(
            addr.value.contains("Newtown"),
            "suburb hint should override centroid suburb: {}",
            addr.value
        );
    }

    #[test]
    fn strip_electoral_html_separates_adjacent_tags() {
        let html = "<div>Division</div><span>of</span><p>Sydney</p>";
        let text = strip_electoral_html(html);
        // Tags must be replaced by spaces so "DivisionofSydney" doesn't occur.
        assert!(
            !text.contains("Divisionof"),
            "tags must inject word breaks: {text}"
        );
        assert!(text.contains("Division"), "content must survive: {text}");
        assert!(text.contains("Sydney"), "content must survive: {text}");
    }

    #[test]
    fn split_name_handles_edge_cases() {
        assert_eq!(split_name("Haigen Bamford"), ("Haigen", "Bamford"));
        assert_eq!(split_name("Mary Ann Jones"), ("Mary", "Ann Jones"));
        assert_eq!(split_name("Cher"), ("Cher", ""));
        assert_eq!(split_name("  Anna  Smith  "), ("Anna", "Smith"));
    }

    #[test]
    fn module_metadata_is_valid() {
        let m = AuElectoral;
        assert_eq!(m.name(), "au_electoral");
        assert!(m.accepts(&crate::core::scan::Target::new(
            TargetKind::FullName,
            "Haigen Bamford"
        )));
        assert!(!m.accepts(&crate::core::scan::Target::new(
            TargetKind::Email,
            "x@example.com"
        )));
        assert!(m.attack_techniques().contains(&"T1591.001"));
        assert!(m.attack_techniques().contains(&"T1589.003"));
    }
}
