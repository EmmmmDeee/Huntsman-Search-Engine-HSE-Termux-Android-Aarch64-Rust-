//! OpenStreetMap Nominatim — free geocoding and reverse-geocoding.
//!
//! Two modes, selected by target kind:
//!
//! * `Address` → forward geocode → Coordinates entity (lat/lng).
//! * `Coordinates` → reverse geocode → Address entity (display_name).
//!
//! Endpoint: `https://nominatim.openstreetmap.org/{search|reverse}`
//! Auth:     none — free, but rate-limited to 1 req/s per the usage
//!           policy. The engine's `throttle_ms` (default 100 ms) and
//!           the per-module timeout handle this naturally.
//!
//! Fills the SpiderFoot `sfp_openstreetmap` / `sfp_geolocation` gap.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::urlencode;

#[derive(Deserialize)]
struct SearchResult {
    #[serde(default)]
    lat: Option<String>,
    #[serde(default)]
    lon: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default, rename = "type")]
    place_type: Option<String>,
    #[serde(default)]
    importance: Option<f64>,
}

#[derive(Deserialize)]
struct ReverseResult {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    address: Option<ReverseAddress>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ReverseAddress {
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    suburb: Option<String>,
    #[serde(default)]
    road: Option<String>,
    #[serde(default)]
    postcode: Option<String>,
}

pub struct Nominatim;

#[async_trait]
impl Module for Nominatim {
    fn name(&self) -> &'static str {
        "nominatim"
    }
    fn priority(&self) -> u8 {
        65
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Address | TargetKind::Coordinates)
    }
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let value = target.value.trim();
        if value.is_empty() {
            return Ok(ModuleResult::new());
        }

        match target.kind {
            TargetKind::Address => self.forward_geocode(value, ctx).await,
            TargetKind::Coordinates => self.reverse_geocode(value, ctx).await,
            _ => Ok(ModuleResult::new()),
        }
    }
}

impl Nominatim {
    async fn forward_geocode(&self, address: &str, ctx: &ModuleContext) -> Result<ModuleResult> {
        let url = format!(
            "https://nominatim.openstreetmap.org/search?q={}&format=json&limit=1&addressdetails=1",
            urlencode(address)
        );
        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module("nominatim", e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Error::module(
                "nominatim",
                format!("HTTP {}", resp.status()),
            ));
        }

        let results: Vec<SearchResult> = resp
            .json()
            .await
            .map_err(|e| Error::module("nominatim", e.to_string()))?;

        let Some(hit) = results.first() else {
            return Ok(ModuleResult::new());
        };
        let (Some(lat), Some(lon)) = (hit.lat.as_deref(), hit.lon.as_deref()) else {
            return Ok(ModuleResult::new());
        };

        let coord_value = format!("{lat},{lon}");
        let mut entity = Entity::new(EntityKind::Coordinates, &coord_value, 0.80, &ctx.scan_id);
        entity.tag("geoint");
        entity.tag("nominatim");
        entity.tag("geocoded");

        let mut ev = Evidence::new("nominatim", format!("Geocoded '{address}' → {coord_value}"))
            .with_attr("lat", lat)
            .with_attr("lon", lon)
            .with_attr("source_address", address);

        if let Some(dn) = hit.display_name.as_deref() {
            ev = ev.with_attr("display_name", dn);
        }
        if let Some(pt) = hit.place_type.as_deref() {
            ev = ev.with_attr("place_type", pt);
        }
        if let Some(imp) = hit.importance {
            ev = ev.with_attr("importance", format!("{imp:.3}"));
        }

        entity.add_evidence(ev);
        let mut result = ModuleResult::new();
        result.push(entity);
        Ok(result)
    }

    async fn reverse_geocode(&self, coords: &str, ctx: &ModuleContext) -> Result<ModuleResult> {
        let parts: Vec<&str> = coords.split(',').collect();
        if parts.len() != 2 {
            return Ok(ModuleResult::new());
        }
        let (lat, lon) = (parts[0].trim(), parts[1].trim());
        if lat.parse::<f64>().is_err() || lon.parse::<f64>().is_err() {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={lon}&format=json&addressdetails=1"
        );
        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module("nominatim", e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Error::module(
                "nominatim",
                format!("HTTP {}", resp.status()),
            ));
        }

        let body: ReverseResult = resp
            .json()
            .await
            .map_err(|e| Error::module("nominatim", e.to_string()))?;

        let Some(display_name) = body.display_name.as_deref() else {
            return Ok(ModuleResult::new());
        };

        let mut entity = Entity::new(EntityKind::Address, display_name, 0.78, &ctx.scan_id);
        entity.tag("nominatim");
        entity.tag("reverse-geocoded");

        let mut ev = Evidence::new(
            "nominatim",
            format!("Reverse-geocoded {coords} → {display_name}"),
        )
        .with_attr("lat", lat)
        .with_attr("lon", lon)
        .with_attr("display_name", display_name);

        if let Some(addr) = &body.address {
            if let Some(c) = addr.country.as_deref() {
                ev = ev.with_attr("country", c);
            }
            if let Some(cc) = addr.country_code.as_deref() {
                entity.tag(format!("country:{}", cc.to_uppercase()));
                ev = ev.with_attr("country_code", cc);
            }
            if let Some(s) = addr.state.as_deref() {
                ev = ev.with_attr("state", s);
            }
            if let Some(c) = addr.city.as_deref() {
                ev = ev.with_attr("city", c);
            }
            if let Some(p) = addr.postcode.as_deref() {
                ev = ev.with_attr("postcode", p);
            }
        }

        entity.add_evidence(ev);
        let mut result = ModuleResult::new();
        result.push(entity);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_address_and_coordinates() {
        let m = Nominatim;
        assert!(m.accepts(&Target::new(TargetKind::Address, "Sydney")));
        assert!(m.accepts(&Target::new(TargetKind::Coordinates, "-33.8,151.2")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }
}
