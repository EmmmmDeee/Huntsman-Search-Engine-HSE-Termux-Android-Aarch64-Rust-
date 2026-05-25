//! geocoded.me — free geocoding API. No key, no signup, no rate limits.
//!
//! Endpoint: `GET https://api.geocoded.me/search?q={address}`
//!
//! Returns country, state, city with coordinates and timezone for a
//! location query. Edge-deployed on Cloudflare Workers for near-zero
//! latency. Complements Nominatim (which has a 1 req/s policy) as a
//! second forward-geocoding source.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

#[derive(Deserialize)]
#[allow(dead_code)]
struct Resp {
    #[serde(default)]
    data: Vec<GeoEntry>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct GeoEntry {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    timezone: Option<String>,
}

pub struct Geocoded;

#[async_trait]
impl Module for Geocoded {
    fn name(&self) -> &'static str {
        "geocoded"
    }
    fn priority(&self) -> u8 {
        63
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Address)
    }
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(address) = target.trimmed() else {
            return Ok(ModuleResult::new());
        };
        if address.len() < 3 {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://api.geocoded.me/search?q={}",
            crate::util::http::urlencode(address)
        );
        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module("geocoded", e.to_string()))?;

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let body: Resp = resp
            .json()
            .await
            .map_err(|e| Error::module("geocoded", e.to_string()))?;

        let Some(hit) = body.data.first() else {
            return Ok(ModuleResult::new());
        };

        let (Some(lat), Some(lon)) = (hit.latitude, hit.longitude) else {
            return Ok(ModuleResult::new());
        };

        let coord_value = format!("{lat},{lon}");
        let mut entity = Entity::new(EntityKind::Coordinates, &coord_value, 0.78, &ctx.scan_id);
        entity.tag("geoint");
        entity.tag("geocoded");

        if let Some(cc) = hit.country_code.as_deref() {
            entity.tag_country(cc);
        }

        let ev = Evidence::new("geocoded", format!("Geocoded '{address}' → {coord_value}"))
            .with_attr("lat", lat.to_string())
            .with_attr("lon", lon.to_string())
            .with_attr("source_address", address)
            .opt_attr("country", hit.country.as_deref())
            .opt_attr("state", hit.state.as_deref())
            .opt_attr("city", hit.name.as_deref())
            .opt_attr("timezone", hit.timezone.as_deref());

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
    fn accepts_address() {
        assert!(Geocoded.accepts(&Target::new(TargetKind::Address, "Sydney")));
        assert!(!Geocoded.accepts(&Target::new(TargetKind::Email, "x@y")));
    }
}
