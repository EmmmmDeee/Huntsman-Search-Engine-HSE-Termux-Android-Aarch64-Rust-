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
    module::{Module, ModuleContext, ModuleResult},
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
        22
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Address | TargetKind::Coordinates)
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
            Ok(r) if r.status().is_success() => r.json().await.unwrap_or_default(),
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
        {
            let coords = format!("{lat:.6},{lon:.6}");
            let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.60, &ctx.scan_id);
            e.tag("geocoded");
            let mut ev = Evidence::new("geocode", format!("Geocoded \"{addr}\" \u{2192} {coords}"))
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
        let (lat, lon) = parse_coords(&target.value)?;

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

        let data: NominatimResp = resp
            .json()
            .await
            .map_err(|e| Error::module("geocode", e.to_string()))?;

        let mut result = ModuleResult::new();

        let display = data.display_name.as_deref().unwrap_or("-");

        let mut entity = Entity::new(EntityKind::Address, display, 0.72, &ctx.scan_id);
        entity.tag("geoint");
        entity.tag("reverse-geocoded");

        let mut ev = Evidence::new("geocode", format!("Reverse geocode for {lat},{lon}"))
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
                entity.tag(format!("country:{}", cc.to_uppercase()));
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
        result.push(entity);
        Ok(result)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn parse_coords(value: &str) -> Result<(f64, f64)> {
    let (lat_s, lon_s) = value
        .split_once(',')
        .ok_or_else(|| Error::module("geocode", "expected lat,lon"))?;
    let lat: f64 = lat_s
        .trim()
        .parse()
        .map_err(|_| Error::module("geocode", "invalid latitude"))?;
    let lon: f64 = lon_s
        .trim()
        .parse()
        .map_err(|_| Error::module("geocode", "invalid longitude"))?;
    Ok((lat, lon))
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(m.priority(), 22);
        assert_eq!(m.max_timeout_ms(), 8_000);
    }
}
