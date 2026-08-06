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

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use crate::util::http::urlencode;

// ── Nominatim response types (forward) ──────────────────────────────

#[derive(Deserialize)]
pub(super) struct NominatimResult {
    #[serde(default)]
    pub(super) lat: Option<String>,
    #[serde(default)]
    pub(super) lon: Option<String>,
    #[serde(default)]
    pub(super) display_name: Option<String>,
    #[serde(default, rename = "type")]
    pub(super) place_type: Option<String>,
    /// Only populated when the request carries `addressdetails=1` (the forward
    /// `/search` call always sets it) — same shared shape as the reverse
    /// `/reverse` response, folded via [`fold_address_attrs`].
    #[serde(default)]
    pub(super) address: Option<NominatimAddr>,
}

// ── Nominatim response types (reverse) ──────────────────────────────

#[derive(Deserialize)]
pub(super) struct NominatimResp {
    pub(super) display_name: Option<String>,
    pub(super) address: Option<NominatimAddr>,
}

#[derive(Deserialize)]
pub(super) struct NominatimAddr {
    pub(super) road: Option<String>,
    pub(super) house_number: Option<String>,
    pub(super) suburb: Option<String>,
    pub(super) city: Option<String>,
    pub(super) town: Option<String>,
    pub(super) village: Option<String>,
    pub(super) municipality: Option<String>,
    pub(super) county: Option<String>,
    pub(super) state: Option<String>,
    pub(super) postcode: Option<String>,
    pub(super) country: Option<String>,
    pub(super) country_code: Option<String>,
}

// ── Module ──────────────────────────────────────────────────────────

pub(super) const SRC: &str = "geocode";

pub struct Geocode;

#[async_trait]
impl Module for Geocode {
    fn name(&self) -> &'static str {
        "geocode"
    }

    fn description(&self) -> &'static str {
        "Bidirectional geocoding via OpenStreetMap Nominatim — resolves Address ↔ Coordinates both ways"
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
        // A bare country name geocodes to the country CENTROID — the middle of
        // the whole nation, not the subject's location — yet it arrives as a
        // precise-looking fix and cascades into the geo-convergence rules (a
        // coarse carrier-country signal inventing a street-level location, as a
        // live +61 phone scan reproduced). Refuse to mint a coordinate from it;
        // a finer address (street / suburb / comma-qualified) still geocodes.
        if crate::util::place_grain::is_bare_country(addr) {
            return Ok(ModuleResult::new());
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
            if let Some(addr) = &first.address {
                ev = fold_address_attrs(ev, addr);
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
            .send_tagged("geocode")
            .await?;

        if !resp.status().is_success() {
            return Err(crate::util::http::http_status_error(SRC, resp).await);
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
/// a fix that lands in Australia is a strong on-region anchor (confidence::HIGH_PLUS,
/// `au-relevant`); one abroad is demoted to a candidate (confidence::LOW, `off-region` +
/// `candidate`) so it sits below the confidence::MEDIUM expansion floor and is quarantined
/// from confirmed correlations — an ambiguous address string can't drag an
/// AU-focused scan off-region. Pure (no I/O); the caller attaches evidence.
#[must_use]
pub(super) fn build_forward_entity(lat: f64, lon: f64, coords: &str, scan_id: &str) -> Entity {
    let in_au = crate::util::geo::is_in_australia(lat, lon);
    let confidence = if in_au {
        confidence::HIGH_PLUS
    } else {
        confidence::LOW
    };
    let mut e = Entity::new(EntityKind::Coordinates, coords, confidence, scan_id);
    e.tag("geocoded");
    if in_au {
        e.tag("au-relevant");
        if let Some(state) = crate::util::geo::au_state_for_coords(lat, lon) {
            e.tag(format!("au-state:{state}"));
        }
    } else {
        e.tag("off-region");
        e.tag("candidate");
    }
    e
}

/// AU-relevance verdict for a reverse-geocoded coordinate, deciding how much an
/// off-region fix may anchor an Australia-focused scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuRelevance {
    /// Resolved in Australia (by Nominatim country code, or by bounding box when
    /// the code is absent) — a strong, on-region anchor.
    InAustralia,
    /// Resolved to a known country that is not Australia — a candidate-grade
    /// lead that AU-focused correlation rules (confidence ≥ confidence::MEDIUM) must not
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
pub(super) fn au_relevance(lat: f64, lon: f64, addr: Option<&NominatimAddr>) -> AuRelevance {
    match addr.and_then(|a| a.country_code.as_deref()) {
        Some(cc) if cc.eq_ignore_ascii_case("au") => AuRelevance::InAustralia,
        Some(_) => AuRelevance::OffRegion,
        None if crate::util::geo::is_in_australia(lat, lon) => AuRelevance::InAustralia,
        None => AuRelevance::Unknown,
    }
}

/// Build the reverse-geocode Address entity, shaping confidence and tags by
/// [`au_relevance`]. Pure (no I/O) so the AU-gating is unit-tested directly.
#[must_use]
pub(super) fn build_reverse_entity(
    lat: f64,
    lon: f64,
    data: &NominatimResp,
    scan_id: &str,
) -> Entity {
    let display = data.display_name.as_deref().unwrap_or("-");
    let relevance = au_relevance(lat, lon, data.address.as_ref());

    let confidence = match relevance {
        AuRelevance::InAustralia => confidence::STRONG,
        AuRelevance::Unknown => confidence::MEDIUM_HIGH,
        AuRelevance::OffRegion => confidence::LOW,
    };

    let mut entity = Entity::new(EntityKind::Address, display, confidence, scan_id);
    entity.tag("geoint");
    entity.tag("reverse-geocoded");
    match relevance {
        AuRelevance::InAustralia => {
            entity.tag("country:AU");
            entity.tag("au-relevant");
            if let Some(state) = crate::util::geo::au_state_for_coords(lat, lon) {
                entity.tag(format!("au-state:{state}"));
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
        ev = fold_address_attrs(ev, addr);
        // The on-region `country:AU` tag is set above; for off-region fixes
        // record the resolved country so the lead stays explainable.
        if let Some(cc) = addr.country_code.as_deref()
            && !cc.eq_ignore_ascii_case("au")
        {
            entity.tag(format!("country:{}", cc.to_uppercase()));
        }
    }

    entity.add_evidence(ev);
    entity
}

/// Fold a Nominatim `address` breakdown (city/state/country/postcode/street/
/// suburb/county) into evidence attributes. Shared by both the forward
/// (`/search?addressdetails=1`) and reverse (`/reverse?addressdetails=1`)
/// geocode paths so a structured address hit is reported identically
/// regardless of which direction produced it — single-sourced, not
/// hand-duplicated per call site. Pure (no I/O), directly unit-tested.
pub(super) fn fold_address_attrs(mut ev: Evidence, addr: &NominatimAddr) -> Evidence {
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
    ev
}
