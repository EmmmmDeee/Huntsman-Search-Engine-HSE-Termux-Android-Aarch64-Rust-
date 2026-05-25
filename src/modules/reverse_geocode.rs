//! Reverse geocoding via OpenStreetMap Nominatim — free, no API key.
//!
//! Accepts Coordinates targets (lat,lon) and converts them to
//! human-readable address data via the Nominatim reverse geocoding API.
//! Produces an Address entity with full location detail.
//!
//! This bridges the gap between geolocation modules (ip_geo, gps_fix)
//! that produce Coordinates entities and human-readable intelligence.
//! During expansion with depth > 0, Coordinates from ip_geo feed into
//! this module to produce Address entities with country, state, city,
//! street, and postal code.
//!
//! Nominatim usage policy: max 1 request per second, must include
//! a valid User-Agent identifying the application.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

pub struct ReverseGeocode;

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

#[async_trait]
impl Module for ReverseGeocode {
    fn name(&self) -> &'static str {
        "reverse_geocode"
    }

    fn description(&self) -> &'static str {
        "Coordinates to address via OpenStreetMap Nominatim"
    }

    fn priority(&self) -> u8 {
        22
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Coordinates)
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let (lat, lon) = parse_coords(&target.value)?;

        let url = format!(
            "https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat={lat}&lon={lon}&zoom=18&addressdetails=1"
        );

        let resp = ctx.http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module("reverse_geocode", e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Error::module(
                "reverse_geocode",
                format!("HTTP {}", resp.status()),
            ));
        }

        let data: NominatimResp = resp
            .json()
            .await
            .map_err(|e| Error::module("reverse_geocode", e.to_string()))?;

        let mut result = ModuleResult::new();

        let display = data.display_name.as_deref().unwrap_or("-");

        let mut entity = Entity::new(EntityKind::Address, display, 0.72, &ctx.scan_id);
        entity.tag("geoint");
        entity.tag("reverse-geocoded");

        let mut ev = Evidence::new(
            "reverse_geocode",
            format!("Reverse geocode for {lat},{lon}"),
        )
        .with_attr("latitude", lat.to_string())
        .with_attr("longitude", lon.to_string())
        .with_attr("source", "OpenStreetMap Nominatim");

        if let Some(addr) = &data.address {
            let city = addr.city.as_deref()
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

fn parse_coords(value: &str) -> Result<(f64, f64)> {
    let (lat_s, lon_s) = value
        .split_once(',')
        .ok_or_else(|| Error::module("reverse_geocode", "expected lat,lon"))?;
    let lat: f64 = lat_s
        .trim()
        .parse()
        .map_err(|_| Error::module("reverse_geocode", "invalid latitude"))?;
    let lon: f64 = lon_s
        .trim()
        .parse()
        .map_err(|_| Error::module("reverse_geocode", "invalid longitude"))?;
    Ok((lat, lon))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_coordinates_only() {
        let m = ReverseGeocode;
        assert!(m.accepts(&Target::new(TargetKind::Coordinates, "0,0")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

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
}
