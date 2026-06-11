//! Bidirectional geocoding via OpenStreetMap Nominatim.
//!
//! Merges forward (Address → Coordinates) and reverse (Coordinates → Address)
//! geocoding into a single module.  The process() method dispatches based on
//! target kind:
//!
//!   * `TargetKind::Address`     → forward geocode (Nominatim /search)
//!   * `TargetKind::Coordinates` → reverse geocode (Nominatim /reverse)
//!
//! Free, no API key.  Nominatim usage policy: max 1 request per second,
//! must include a valid User-Agent identifying the application.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::urlencode;

// ── Nominatim response types (forward) ──────────────────────────────

#[derive(Deserialize)]
struct NominatimResult {
    #[serde(default)]
    lat: Option<String>,
    #[serde(default)]
    lon: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default, rename = "type")]
    place_type: Option<String>,
}

// ── Nominatim response types (reverse) ──────────────────────────────

#[derive(Deserialize)]
struct NominatimResp {
    display_name: Option<String>,
    address: Option<NominatimAddr>,
}

#[derive(Deserialize)]
struct NominatimAddr {
    road: Option<String>,
    house_number: Option<String>,
    suburb: Option<String>,
    city: Option<String>,
    town: Option<String>,
    village: Option<String>,
    municipality: Option<String>,
    county: Option<String>,
    state: Option<String>,
    postcode: Option<String>,
    country: Option<String>,
    country_code: Option<String>,
}

// ── Module ──────────────────────────────────────────────────────────

const SRC: &str = "geocode";

pub struct Geocode;

#[async_trait]
impl Module for Geocode {
    fn name(&self) -> &'static str {
        "geocode"
    }

    fn description(&self) -> &'static str {
        "Bidirectional geocoding via OpenStreetMap Nominatim (Address \u{2194} Coordinates)"
    }

    fn priority(&self) -> u8 {
        21
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Address | TargetKind::Coordinates)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates, EntityKind::Address];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        match target.kind {
            TargetKind::Address => self.forward(target, ctx).await,
            TargetKind::Coordinates => self.reverse(target, ctx).await,
            _ => Ok(ModuleResult::new()),
        }
    }
}

impl Geocode {
    // ── Forward geocode: Address → Coordinates ──────────────────────

    async fn forward(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let addr = target.value.trim();
        if addr.is_empty() || addr.len() <= 2 {
            return Ok(ModuleResult::new());
        }

        // Offline fast-path: resolve known AU suburb centroids without a
        // Nominatim round-trip. This is especially valuable on Termux/aarch64
        // where network latency is higher and offline operation is desirable.
        if let Some((lat, lon, postcode)) = offline_au_suburb_centroid(addr) {
            let mut result = ModuleResult::new();
            let coords = format!("{lat:.6},{lon:.6}");
            let mut e = build_forward_entity(lat, lon, &coords, &ctx.scan_id);
            e.tag("offline");
            e.add_evidence(
                Evidence::new(SRC, format!("Offline centroid for \"{addr}\" → {coords}"))
                    .with_attr("input_address", addr)
                    .with_attr("latitude", lat.to_string())
                    .with_attr("longitude", lon.to_string())
                    .with_attr("postcode", postcode)
                    .with_attr("method", "logan_suburb_centroid"),
            );
            result.push(e);
            return Ok(result);
        }

        let url = format!(
            "https://nominatim.openstreetmap.org/search?q={}&format=json&limit=1&addressdetails=1",
            urlencode(addr)
        );

        let resp = ctx
            .http
            .get(&url)
            .header(
                "User-Agent",
                "huntsman-search-engine/1.0 (+https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-)",
            )
            .send()
            .await;

        let results: Vec<NominatimResult> = match resp {
            Ok(r) if r.status().is_success() => crate::util::http::json_scanned(r, SRC)
                .await
                .unwrap_or_default(),
            _ => {
                if let Some(body) = crate::util::curl::fetch(&url, crate::MODULE_TIMEOUT_MS).await {
                    serde_json::from_str(&body).unwrap_or_default()
                } else {
                    return Ok(ModuleResult::new());
                }
            }
        };

        let mut result = ModuleResult::new();

        if let Some(first) = results.first()
            && let (Some(lat_str), Some(lon_str)) = (&first.lat, &first.lon)
            && let (Ok(lat), Ok(lon)) = (lat_str.parse::<f64>(), lon_str.parse::<f64>())
            && crate::util::geo::is_valid_coords(lat, lon)
        {
            let coords = format!("{lat:.6},{lon:.6}");
            let mut e = build_forward_entity(lat, lon, &coords, &ctx.scan_id);
            let mut ev = Evidence::new(SRC, format!("Geocoded \"{addr}\" \u{2192} {coords}"))
                .with_attr("input_address", addr)
                .with_attr("latitude", lat_str)
                .with_attr("longitude", lon_str);
            if let Some(dn) = &first.display_name {
                ev = ev.with_attr("display_name", dn);
            }
            if let Some(pt) = &first.place_type {
                ev = ev.with_attr("place_type", pt);
            }
            e.add_evidence(ev);
            result.push(e);
        }

        Ok(result)
    }

    // ── Reverse geocode: Coordinates → Address ──────────────────────

    async fn reverse(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let (lat, lon) = crate::util::geo::parse_coords(&target.value)?;

        let url = format!(
            "https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat={lat}&lon={lon}&zoom=18&addressdetails=1"
        );

        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module("geocode", e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Error::module("geocode", format!("HTTP {}", resp.status())));
        }

        let data: NominatimResp = crate::util::http::json_scanned(resp, SRC)
            .await
            .map_err(|e| Error::module(SRC, e))?;

        let mut result = ModuleResult::new();
        result.push(build_reverse_entity(lat, lon, &data, &ctx.scan_id));
        Ok(result)
    }
}

/// Build the forward-geocode Coordinates entity, shaping confidence and tags by
/// AU relevance of the resolved point (offline [`crate::util::geo::is_in_australia`]):
/// a fix that lands in Australia is a strong on-region anchor (0.70,
/// `au-relevant`); one abroad is demoted to a candidate (0.40, `off-region` +
/// `candidate`) so it sits below the 0.50 expansion floor and is quarantined
/// from confirmed correlations — an ambiguous address string can't drag an
/// AU-focused scan off-region. Pure (no I/O); the caller attaches evidence.
fn build_forward_entity(lat: f64, lon: f64, coords: &str, scan_id: &str) -> Entity {
    let in_au = crate::util::geo::is_in_australia(lat, lon);
    let confidence = if in_au { 0.70 } else { 0.40 };
    let mut e = Entity::new(EntityKind::Coordinates, coords, confidence, scan_id);
    e.tag("geocoded");
    if in_au {
        for t in crate::util::geo::au_coord_tags(lat, lon) {
            e.tag(t);
        }
    } else {
        e.tag("off-region");
        e.tag("candidate");
    }
    e
}

/// Offline AU suburb lookup: strips postcode and state suffix, then searches
/// the Logan City suburb centroid table. Returns `(lat, lon, postcode)` when
/// the address resolves to a known Logan suburb without a network call.
///
/// Used as a fast-path before the Nominatim round-trip when the address is
/// a bare suburb string (e.g. "Park Ridge", "Regents Park QLD 4118").
pub(crate) fn offline_au_suburb_centroid(addr: &str) -> Option<(f64, f64, &'static str)> {
    // Strip trailing postcode and state abbreviation ("QLD 4118", "NSW", "4118").
    let cleaned: String = addr
        .split_whitespace()
        .filter(|w| {
            // Drop 4-digit postcodes and state abbreviations.
            let up = w.to_ascii_uppercase();
            let is_state = matches!(
                up.as_str(),
                "QLD" | "NSW" | "VIC" | "SA" | "WA" | "TAS" | "NT" | "ACT" | "AUSTRALIA"
            );
            let is_postcode = w.len() == 4 && w.bytes().all(|b| b.is_ascii_digit());
            !is_state && !is_postcode
        })
        .collect::<Vec<_>>()
        .join(" ");
    crate::util::geo::logan_suburb_centroid(cleaned.trim())
}

/// AU-relevance verdict for a reverse-geocoded coordinate, deciding how much an
/// off-region fix may anchor an Australia-focused scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuRelevance {
    /// Resolved in Australia (by Nominatim country code, or by bounding box when
    /// the code is absent) — a strong, on-region anchor.
    InAustralia,
    /// Resolved to a known country that is not Australia — a candidate-grade
    /// lead that AU-focused correlation rules (confidence ≥ 0.50) must not
    /// anchor on, so it can't pull an investigation off-region.
    OffRegion,
    /// Region could not be determined (no country code, not in the AU box) —
    /// kept at a neutral, middling confidence.
    Unknown,
}

/// Classify a reverse-geocoded fix for AU relevance. The Nominatim country code
/// is authoritative when present; otherwise we fall back to the offline
/// [`crate::util::geo::is_in_australia`] bounding box so a bare coordinate seed
/// is still gated.
fn au_relevance(lat: f64, lon: f64, addr: Option<&NominatimAddr>) -> AuRelevance {
    match addr.and_then(|a| a.country_code.as_deref()) {
        Some(cc) if cc.eq_ignore_ascii_case("au") => AuRelevance::InAustralia,
        Some(_) => AuRelevance::OffRegion,
        None if crate::util::geo::is_in_australia(lat, lon) => AuRelevance::InAustralia,
        None => AuRelevance::Unknown,
    }
}

/// Build the reverse-geocode Address entity, shaping confidence and tags by
/// [`au_relevance`]. Pure (no I/O) so the AU-gating is unit-tested directly.
fn build_reverse_entity(lat: f64, lon: f64, data: &NominatimResp, scan_id: &str) -> Entity {
    let display = data.display_name.as_deref().unwrap_or("-");
    let relevance = au_relevance(lat, lon, data.address.as_ref());

    let confidence = match relevance {
        AuRelevance::InAustralia => 0.78,
        AuRelevance::Unknown => 0.55,
        AuRelevance::OffRegion => 0.40,
    };

    let mut entity = Entity::new(EntityKind::Address, display, confidence, scan_id);
    entity.tag("geoint");
    entity.tag("reverse-geocoded");
    match relevance {
        AuRelevance::InAustralia => {
            entity.tag("country:AU");
            for t in crate::util::geo::au_coord_tags(lat, lon) {
                entity.tag(t);
            }
        }
        AuRelevance::OffRegion => entity.tag("candidate"),
        AuRelevance::Unknown => {}
    }

    let mut ev = Evidence::new(SRC, format!("Reverse geocode for {lat},{lon}"))
        .with_attr("latitude", lat.to_string())
        .with_attr("longitude", lon.to_string())
        .with_attr("source", "OpenStreetMap Nominatim");

    if let Some(addr) = &data.address {
        let city = addr
            .city
            .as_deref()
            .or(addr.town.as_deref())
            .or(addr.village.as_deref())
            .or(addr.municipality.as_deref());

        if let Some(c) = city {
            ev = ev.with_attr("city", c);
        }
        if let Some(s) = addr.state.as_deref() {
            ev = ev.with_attr("state", s);
        }
        if let Some(c) = addr.country.as_deref() {
            ev = ev.with_attr("country", c);
        }
        if let Some(cc) = addr.country_code.as_deref() {
            ev = ev.with_attr("country_code", cc.to_uppercase());
            // The on-region `country:AU` tag is set above; for off-region fixes
            // record the resolved country so the lead stays explainable.
            if !cc.eq_ignore_ascii_case("au") {
                entity.tag(format!("country:{}", cc.to_uppercase()));
            }
        }
        if let Some(p) = addr.postcode.as_deref() {
            ev = ev.with_attr("postcode", p);
        }
        if let Some(r) = addr.road.as_deref() {
            let street = match addr.house_number.as_deref() {
                Some(n) => format!("{n} {r}"),
                None => r.to_string(),
            };
            ev = ev.with_attr("street", street);
        }
        if let Some(sub) = addr.suburb.as_deref() {
            ev = ev.with_attr("suburb", sub);
        }
        if let Some(county) = addr.county.as_deref() {
            ev = ev.with_attr("county", county);
        }
    }

    entity.add_evidence(ev);
    entity
}

// ── Helpers ─────────────────────────────────────────────────────────

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::geo::parse_coords;

    // -- acceptance tests (from forward_geocode) -------------------------

    #[test]
    fn accepts_address() {
        let m = Geocode;
        assert!(m.accepts(&Target::new(TargetKind::Address, "Brisbane")));
    }

    #[test]
    fn rejects_domain_and_email() {
        let m = Geocode;
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }

    // -- acceptance tests (from reverse_geocode) --------------------------

    #[test]
    fn accepts_coordinates() {
        let m = Geocode;
        assert!(m.accepts(&Target::new(TargetKind::Coordinates, "0,0")));
    }

    #[test]
    fn rejects_ip_address() {
        let m = Geocode;
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    // -- parse_coords tests (from reverse_geocode) ------------------------

    #[test]
    fn parse_coords_valid() {
        let (lat, lon) = parse_coords("-33.8688,151.2093").unwrap();
        assert!((lat - (-33.8688)).abs() < 1e-4);
        assert!((lon - 151.2093).abs() < 1e-4);
    }

    #[test]
    fn parse_coords_with_spaces() {
        let (lat, lon) = parse_coords(" 40.7128 , -74.0060 ").unwrap();
        assert!((lat - 40.7128).abs() < 1e-4);
        assert!((lon - (-74.0060)).abs() < 1e-4);
    }

    #[test]
    fn parse_coords_invalid() {
        assert!(parse_coords("not-coords").is_err());
        assert!(parse_coords("").is_err());
    }

    // -- module metadata --------------------------------------------------

    #[test]
    fn module_metadata() {
        let m = Geocode;
        assert_eq!(m.name(), "geocode");
        assert_eq!(m.priority(), 21);
        assert_eq!(m.max_timeout_ms(), 8_000);
    }

    // -- AU-relevance shaping of reverse geocode --------------------------

    fn resp(json: serde_json::Value) -> NominatimResp {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn offline_suburb_centroid_resolves_park_ridge() {
        let (lat, lon, pc) = offline_au_suburb_centroid("Park Ridge").unwrap();
        assert!((lat - (-27.6955)).abs() < 0.001);
        assert!((lon - 152.8918).abs() < 0.001);
        assert_eq!(pc, "4125");
    }

    #[test]
    fn offline_suburb_centroid_strips_state_and_postcode() {
        // "Regents Park QLD 4118" → "Regents Park" → match.
        let r = offline_au_suburb_centroid("Regents Park QLD 4118");
        assert!(r.is_some());
        assert_eq!(r.unwrap().2, "4118");
    }

    #[test]
    fn offline_suburb_centroid_unknown_returns_none() {
        assert!(offline_au_suburb_centroid("Fake Suburb NSW 2000").is_none());
    }

    #[test]
    fn build_forward_entity_tags_lga_for_logan() {
        let e = build_forward_entity(-27.6954, 152.8918, "-27.695400,152.891800", "scan");
        assert!(e.has_tag("au-lga:logan-city"));
        assert!(e.has_tag("au-state:QLD"));
        assert!(e.has_tag("au-relevant"));
    }

    #[test]
    fn build_reverse_entity_tags_lga_for_logan() {
        let data = NominatimResp {
            display_name: Some("Park Ridge, Logan City, QLD, Australia".into()),
            address: Some(NominatimAddr {
                suburb: Some("Park Ridge".into()),
                city: None,
                town: None,
                village: None,
                municipality: None,
                county: Some("Logan City".into()),
                state: Some("Queensland".into()),
                postcode: Some("4125".into()),
                country: Some("Australia".into()),
                country_code: Some("au".into()),
                road: None,
                house_number: None,
            }),
        };
        let e = build_reverse_entity(-27.6955, 152.8918, &data, "scan");
        assert!(e.has_tag("au-lga:logan-city"));
        assert!(e.has_tag("au-state:QLD"));
        assert!(e.has_tag("au-relevant"));
    }

    #[test]
    fn forward_geocode_shapes_confidence_by_au_relevance() {
        // An AU result is a strong on-region anchor; a foreign one is a demoted
        // candidate that won't be expanded or counted as confirmed.
        let au = build_forward_entity(-27.4766, 153.0166, "-27.476600,153.016600", "scan");
        assert!((au.confidence - 0.70).abs() < 1e-9);
        assert!(au.has_tag("au-relevant"));
        assert!(au.has_tag("au-state:QLD")); // Brisbane
        assert!(au.has_tag("geocoded"));
        assert!(!au.has_tag("candidate"));

        let foreign = build_forward_entity(51.5074, -0.1278, "51.507400,-0.127800", "scan");
        assert!((foreign.confidence - 0.40).abs() < 1e-9);
        assert!(foreign.has_tag("off-region"));
        assert!(foreign.has_tag("candidate"));
        assert!(!foreign.has_tag("au-relevant"));
    }

    #[test]
    fn reverse_in_australia_by_country_code_is_a_strong_anchor() {
        let data = resp(serde_json::json!({
            "display_name": "Brisbane City, QLD, Australia",
            "address": { "city": "Brisbane", "state": "Queensland", "country_code": "au" }
        }));
        let e = build_reverse_entity(-27.4766, 153.0166, &data, "scan");
        assert!((e.confidence - 0.78).abs() < 1e-9);
        assert!(e.has_tag("au-relevant"));
        assert!(e.has_tag("country:AU"));
        assert!(e.has_tag("au-state:QLD"));
        assert!(!e.has_tag("candidate"));
    }

    #[test]
    fn reverse_off_region_by_country_code_is_a_candidate() {
        let data = resp(serde_json::json!({
            "display_name": "Manhattan, New York, USA",
            "address": { "city": "New York", "country_code": "us" }
        }));
        let e = build_reverse_entity(40.7128, -74.0060, &data, "scan");
        assert!((e.confidence - 0.40).abs() < 1e-9);
        assert!(e.has_tag("candidate"));
        assert!(e.has_tag("country:US"));
        assert!(!e.has_tag("au-relevant"));
    }

    #[test]
    fn reverse_without_country_code_falls_back_to_the_bounding_box() {
        // No country code: an AU coordinate is still recognised on-region via
        // the offline bounding box, while a foreign one stays Unknown (neutral).
        let bare = resp(serde_json::json!({ "display_name": "somewhere" }));
        let au = build_reverse_entity(-33.8688, 151.2093, &bare, "scan");
        assert!((au.confidence - 0.78).abs() < 1e-9);
        assert!(au.has_tag("au-relevant"));

        let foreign = build_reverse_entity(48.8566, 2.3522, &bare, "scan");
        assert!((foreign.confidence - 0.55).abs() < 1e-9);
        assert!(!foreign.has_tag("au-relevant"));
        assert!(!foreign.has_tag("candidate"));
    }
}
