//! Photon geocoder (Komoot). Free, no API key.
//!
//! Forward: `GET https://photon.komoot.io/api/?q={address}&limit=1`
//! Reverse: `GET https://photon.komoot.io/reverse?lon={lon}&lat={lat}`
//!
//! Complements the Nominatim-based `geocode` module with a second
//! independent geocoding source for corroboration.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::urlencode;

const SRC: &str = "photon";

pub struct Photon;

#[derive(Deserialize)]
struct PhotonResp {
    #[serde(default)]
    features: Vec<Feature>,
}

#[derive(Deserialize)]
struct Feature {
    #[serde(default)]
    geometry: Option<Geometry>,
    #[serde(default)]
    properties: Option<Props>,
}

#[derive(Deserialize)]
struct Geometry {
    #[serde(default)]
    coordinates: Vec<f64>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct Props {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    street: Option<String>,
    #[serde(default)]
    housenumber: Option<String>,
    #[serde(default)]
    postcode: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    countrycode: Option<String>,
    #[serde(rename = "type")]
    #[serde(default)]
    place_type: Option<String>,
    #[serde(default)]
    osm_key: Option<String>,
    #[serde(default)]
    osm_value: Option<String>,
}

#[async_trait]
impl Module for Photon {
    fn name(&self) -> &'static str {
        "photon"
    }
    fn description(&self) -> &'static str {
        "Photon geocoder (Komoot) — independent forward/reverse geocoding for corroboration"
    }
    fn priority(&self) -> u8 {
        20
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Address | TargetKind::Coordinates)
    }
    fn max_timeout_ms(&self) -> u64 {
        4_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        match target.kind {
            TargetKind::Address => self.forward(target, ctx).await,
            TargetKind::Coordinates => self.reverse(target, ctx).await,
            _ => Ok(ModuleResult::new()),
        }
    }
}

impl Photon {
    async fn forward(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let addr = target.value.trim();
        if addr.is_empty() || addr.len() <= 2 {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://photon.komoot.io/api/?q={}&limit=1",
            urlencode(addr),
        );

        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let body: PhotonResp = match resp.json().await {
            Ok(b) => b,
            Err(_) => return Ok(ModuleResult::new()),
        };

        let Some(feature) = body.features.first() else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();

        if let Some(geom) = &feature.geometry
            && geom.coordinates.len() >= 2
        {
            let lon = geom.coordinates[0];
            let lat = geom.coordinates[1];
            let coords = format!("{lat:.6},{lon:.6}");
            let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.60, &ctx.scan_id);
            e.tag("photon");
            e.tag("geocoded");
            let mut ev = Evidence::new(SRC, format!("Photon geocoded \"{addr}\" -> {coords}"))
                .with_attr("input_address", addr)
                .with_attr("latitude", format!("{lat:.6}"))
                .with_attr("longitude", format!("{lon:.6}"));
            if let Some(props) = &feature.properties {
                if let Some(cc) = props.countrycode.as_deref() {
                    ev = ev.with_attr("country_code", cc);
                    e.tag(format!("country:{}", cc.to_uppercase()));
                }
                if let Some(pt) = props.place_type.as_deref() {
                    ev = ev.with_attr("place_type", pt);
                }
            }
            e.add_evidence(ev);
            result.push(e);
        }

        Ok(result)
    }

    async fn reverse(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let (lat, lon) = crate::util::geo::parse_coords(&target.value)?;

        let url = format!("https://photon.komoot.io/reverse?lon={lon:.6}&lat={lat:.6}",);

        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let body: PhotonResp = match resp.json().await {
            Ok(b) => b,
            Err(_) => return Ok(ModuleResult::new()),
        };

        let Some(feature) = body.features.first() else {
            return Ok(ModuleResult::new());
        };
        let Some(props) = &feature.properties else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();

        let parts: Vec<&str> = [
            props.housenumber.as_deref(),
            props.street.as_deref(),
            props.city.as_deref(),
            props.state.as_deref(),
            props.country.as_deref(),
        ]
        .iter()
        .filter_map(|p| *p)
        .filter(|p| !p.is_empty())
        .collect();

        if parts.len() >= 2 {
            let display = parts.join(", ");
            let mut ae = Entity::new(EntityKind::Address, &display, 0.70, &ctx.scan_id);
            ae.tag("photon");
            ae.tag("reverse-geocoded");
            ae.tag("geoint");

            let mut ev =
                Evidence::new(SRC, format!("Photon reverse geocode for {lat:.6},{lon:.6}"))
                    .with_attr("latitude", format!("{lat:.6}"))
                    .with_attr("longitude", format!("{lon:.6}"));

            if let Some(c) = props.city.as_deref() {
                ev = ev.with_attr("city", c);
            }
            if let Some(s) = props.state.as_deref() {
                ev = ev.with_attr("state", s);
            }
            if let Some(c) = props.country.as_deref() {
                ev = ev.with_attr("country", c);
            }
            if let Some(cc) = props.countrycode.as_deref() {
                ev = ev.with_attr("country_code", cc);
                ae.tag(format!("country:{}", cc.to_uppercase()));
            }
            if let Some(p) = props.postcode.as_deref() {
                ev = ev.with_attr("postcode", p);
            }

            ae.add_evidence(ev);
            result.push(ae);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_address_and_coordinates() {
        let m = Photon;
        assert!(m.accepts(&Target::new(TargetKind::Address, "Sydney")));
        assert!(m.accepts(&Target::new(TargetKind::Coordinates, "-33.8,151.2")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }

    #[test]
    fn module_metadata() {
        assert_eq!(Photon.name(), "photon");
        assert_eq!(Photon.priority(), 20);
        assert_eq!(Photon.max_timeout_ms(), 4_000);
    }

    #[test]
    fn parse_forward_response() {
        let raw = r#"{
            "features": [{
                "geometry": {"type": "Point", "coordinates": [151.2093, -33.8688]},
                "properties": {
                    "name": "Sydney",
                    "city": "Sydney",
                    "state": "New South Wales",
                    "country": "Australia",
                    "countrycode": "AU",
                    "type": "city"
                }
            }]
        }"#;
        let r: PhotonResp = serde_json::from_str(raw).unwrap();
        let f = &r.features[0];
        let coords = &f.geometry.as_ref().unwrap().coordinates;
        assert!((coords[0] - 151.2093).abs() < 0.001);
        assert!((coords[1] - (-33.8688)).abs() < 0.001);
        assert_eq!(
            f.properties.as_ref().unwrap().countrycode.as_deref(),
            Some("AU")
        );
    }
}
