//! Photon geocoder (Komoot). Free, no API key.
//!
//! Forward: `GET https://photon.komoot.io/api/?q={address}&limit=1`
//! Reverse: `GET https://photon.komoot.io/reverse?lon={lon}&lat={lat}`
//!
//! Complements the Nominatim-based `geocode` module with a second independent
//! geocoding source for corroboration. Every property Photon returns is used:
//! the resolved place **name** confirms *what* was matched, and the OSM
//! `key`/`value` classify its *nature* (e.g. `place/city` vs `amenity/restaurant`
//! — a coarse city hit vs a precise POI), surfaced as an `osm:<value>` tag.
//!
//! The two response → entity mappings live in the pure [`build_forward`] /
//! [`build_reverse`] so they are unit-tested without a live API; the
//! `forward`/`reverse` methods own only transport.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
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

use crate::util::str_util::nonempty;

/// Join the present address parts in order, dropping case-insensitive duplicates
/// (the place `name` is often also the `city`, e.g. "Sydney").
fn join_unique(parts: &[Option<&str>]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    parts
        .iter()
        .filter_map(|o| *o)
        .filter(|s| seen.insert(s.to_lowercase()))
        .map(String::from)
        .collect()
}

/// Add the OSM feature classification (`key`/`value`) to a geocode result, both
/// as evidence attributes and an `osm:<value>` tag that conveys precision/nature.
fn osm_attrs(ev: Evidence, entity: &mut Entity, props: &Props) -> Evidence {
    let mut ev = ev;
    if let Some(v) = nonempty(&props.osm_value) {
        ev = ev.with_attr("osm_value", v);
        entity.tag(format!("osm:{v}"));
    }
    if let Some(k) = nonempty(&props.osm_key) {
        ev = ev.with_attr("osm_key", k);
    }
    ev
}

/// Forward geocode (`Address` → `Coordinates`). Returns `None` when the feature
/// has no usable geometry.
fn build_forward(addr: &str, feature: &Feature, scan_id: &str) -> Option<Entity> {
    let geom = feature.geometry.as_ref()?;
    if geom.coordinates.len() < 2 {
        return None;
    }
    let (lon, lat) = (geom.coordinates[0], geom.coordinates[1]);
    let coords = format!("{lat:.6},{lon:.6}");

    let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.60, scan_id);
    e.tag("photon");
    e.tag("geocoded");
    let mut ev = Evidence::new(SRC, format!("Photon geocoded \"{addr}\" -> {coords}"))
        .with_attr("input_address", addr)
        .with_attr("latitude", format!("{lat:.6}"))
        .with_attr("longitude", format!("{lon:.6}"));
    if let Some(props) = &feature.properties {
        if let Some(name) = nonempty(&props.name) {
            ev = ev.with_attr("place_name", name);
        }
        if let Some(cc) = nonempty(&props.countrycode) {
            ev = ev.with_attr("country_code", cc);
            e.tag(format!("country:{}", cc.to_uppercase()));
        }
        if let Some(pt) = nonempty(&props.place_type) {
            ev = ev.with_attr("place_type", pt);
        }
        ev = osm_attrs(ev, &mut e, props);
    }
    e.add_evidence(ev);
    Some(e)
}

/// Reverse geocode (`Coordinates` → `Address`). The resolved place **name** is
/// the most-specific component of the display (deduped against city). Returns
/// `None` when fewer than two address components resolve.
fn build_reverse(lat: f64, lon: f64, props: &Props, scan_id: &str) -> Option<Entity> {
    let parts = join_unique(&[
        nonempty(&props.name),
        nonempty(&props.housenumber),
        nonempty(&props.street),
        nonempty(&props.city),
        nonempty(&props.state),
        nonempty(&props.country),
    ]);
    if parts.len() < 2 {
        return None;
    }
    let display = parts.join(", ");

    let mut ae = Entity::new(EntityKind::Address, &display, 0.70, scan_id);
    ae.tag("photon");
    ae.tag("reverse-geocoded");
    ae.tag("geoint");
    let mut ev = Evidence::new(SRC, format!("Photon reverse geocode for {lat:.6},{lon:.6}"))
        .with_attr("latitude", format!("{lat:.6}"))
        .with_attr("longitude", format!("{lon:.6}"));
    if let Some(name) = nonempty(&props.name) {
        ev = ev.with_attr("place_name", name);
    }
    if let Some(c) = nonempty(&props.city) {
        ev = ev.with_attr("city", c);
    }
    if let Some(s) = nonempty(&props.state) {
        ev = ev.with_attr("state", s);
    }
    if let Some(c) = nonempty(&props.country) {
        ev = ev.with_attr("country", c);
    }
    if let Some(cc) = nonempty(&props.countrycode) {
        ev = ev.with_attr("country_code", cc);
        ae.tag(format!("country:{}", cc.to_uppercase()));
    }
    if let Some(p) = nonempty(&props.postcode) {
        ev = ev.with_attr("postcode", p);
    }
    ev = osm_attrs(ev, &mut ae, props);
    ae.add_evidence(ev);
    Some(ae)
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

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates, EntityKind::Address];
        KINDS
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
        if addr.len() <= 2 {
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
        let body: PhotonResp = match crate::util::http::json_scanned(resp, SRC).await {
            Ok(b) => b,
            Err(_) => return Ok(ModuleResult::new()),
        };

        let mut result = ModuleResult::new();
        if let Some(feature) = body.features.first()
            && let Some(e) = build_forward(addr, feature, &ctx.scan_id)
        {
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
        let body: PhotonResp = match crate::util::http::json_scanned(resp, SRC).await {
            Ok(b) => b,
            Err(_) => return Ok(ModuleResult::new()),
        };

        let mut result = ModuleResult::new();
        if let Some(props) = body.features.first().and_then(|f| f.properties.as_ref())
            && let Some(e) = build_reverse(lat, lon, props, &ctx.scan_id)
        {
            result.push(e);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn props(json: &str) -> Props {
        serde_json::from_str(json).unwrap()
    }

    // ── Module surface ──────────────────────────────────────────────────
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
        let raw = r#"{"features":[{"geometry":{"type":"Point","coordinates":[151.2093,-33.8688]},
            "properties":{"name":"Sydney","country":"Australia","countrycode":"AU","type":"city"}}]}"#;
        let r: PhotonResp = serde_json::from_str(raw).unwrap();
        let coords = &r.features[0].geometry.as_ref().unwrap().coordinates;
        assert!((coords[0] - 151.2093).abs() < 0.001);
    }

    // ── Forward: Coordinates with name + OSM classification ─────────────
    #[test]
    fn build_forward_emits_coordinates_with_name_and_osm() {
        let feature: Feature = serde_json::from_str(
            r#"{"geometry":{"coordinates":[151.2153,-33.8568]},
                "properties":{"name":"Sydney Opera House","countrycode":"au","type":"house",
                              "osm_key":"amenity","osm_value":"theatre"}}"#,
        )
        .unwrap();
        let e = build_forward("opera house sydney", &feature, "s").unwrap();
        assert_eq!(e.kind, EntityKind::Coordinates);
        assert_eq!(e.value, "-33.856800,151.215300");
        assert!(e.has_tag("geocoded") && e.has_tag("country:AU"));
        assert!(e.has_tag("osm:theatre")); // the recovered classification
        let ev = &e.evidence[0];
        assert_eq!(
            ev.attributes.get("place_name").map(String::as_str),
            Some("Sydney Opera House")
        );
        assert_eq!(
            ev.attributes.get("osm_key").map(String::as_str),
            Some("amenity")
        );
        assert_eq!(
            ev.attributes.get("osm_value").map(String::as_str),
            Some("theatre")
        );
        assert_eq!(
            ev.attributes.get("input_address").map(String::as_str),
            Some("opera house sydney")
        );
    }

    #[test]
    fn build_forward_without_geometry_is_none() {
        let feature: Feature = serde_json::from_str(r#"{"properties":{"name":"X"}}"#).unwrap();
        assert!(build_forward("x", &feature, "s").is_none());
        let no_coords: Feature =
            serde_json::from_str(r#"{"geometry":{"coordinates":[1.0]}}"#).unwrap();
        assert!(build_forward("x", &no_coords, "s").is_none());
    }

    // ── Reverse: Address with name folded in + OSM classification ────────
    #[test]
    fn build_reverse_uses_name_and_dedupes_against_city() {
        // POI: the name is the most-specific component and must lead the display.
        let p = props(
            r#"{"name":"Sydney Opera House","street":"Bennelong Point","city":"Sydney",
                "state":"NSW","country":"Australia","countrycode":"AU","postcode":"2000",
                "osm_key":"tourism","osm_value":"attraction"}"#,
        );
        let e = build_reverse(-33.8568, 151.2153, &p, "s").unwrap();
        assert_eq!(e.kind, EntityKind::Address);
        assert_eq!(
            e.value,
            "Sydney Opera House, Bennelong Point, Sydney, NSW, Australia"
        );
        assert!(
            e.has_tag("reverse-geocoded") && e.has_tag("country:AU") && e.has_tag("osm:attraction")
        );
        let ev = &e.evidence[0];
        assert_eq!(
            ev.attributes.get("place_name").map(String::as_str),
            Some("Sydney Opera House")
        );
        assert_eq!(
            ev.attributes.get("postcode").map(String::as_str),
            Some("2000")
        );

        // A city whose name == city collapses to one occurrence.
        let city = props(r#"{"name":"Sydney","city":"Sydney","country":"Australia"}"#);
        let ce = build_reverse(-33.8, 151.2, &city, "s").unwrap();
        assert_eq!(ce.value, "Sydney, Australia");
    }

    #[test]
    fn build_reverse_too_few_parts_is_none() {
        assert!(build_reverse(0.0, 0.0, &props(r#"{"country":"Australia"}"#), "s").is_none());
        assert!(build_reverse(0.0, 0.0, &props("{}"), "s").is_none());
    }
}
