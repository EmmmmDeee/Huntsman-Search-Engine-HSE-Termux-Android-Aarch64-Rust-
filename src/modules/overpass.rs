//! Overpass API — extract physical infrastructure from OpenStreetMap.
//!
//! Endpoint: `POST https://overpass-api.de/api/interpreter`
//! Auth:     None (free, public).
//!
//! Given a Coordinates target, queries for nearby infrastructure nodes
//! (cell towers, substations, surveillance cameras) within a 500m radius.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "overpass";

pub struct Overpass;

#[derive(Deserialize)]
struct OverpassResp {
    #[serde(default)]
    elements: Vec<OsmElement>,
}

#[derive(Deserialize)]
struct OsmElement {
    #[allow(dead_code)]
    #[serde(default, rename = "type")]
    osm_type: Option<String>,
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    lat: Option<f64>,
    #[serde(default)]
    lon: Option<f64>,
    #[serde(default)]
    tags: Option<std::collections::HashMap<String, String>>,
}

#[async_trait]
impl Module for Overpass {
    fn name(&self) -> &'static str {
        "overpass"
    }
    fn description(&self) -> &'static str {
        "OpenStreetMap infrastructure query — cell towers, substations, cameras near coordinates"
    }
    fn priority(&self) -> u8 {
        15
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Coordinates)
    }
    fn max_timeout_ms(&self) -> u64 {
        30_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let (lat, lon) = crate::util::geo::parse_coords(&target.value)?;

        let query = format!(
            r#"[out:json][timeout:25];
(
  node["man_made"="mast"](around:500,{lat},{lon});
  node["man_made"="tower"]["tower:type"="communication"](around:500,{lat},{lon});
  node["man_made"="surveillance"](around:500,{lat},{lon});
  node["power"="substation"](around:500,{lat},{lon});
  node["amenity"="police"](around:500,{lat},{lon});
  node["amenity"="fire_station"](around:500,{lat},{lon});
);
out body;"#
        );

        let resp = ctx
            .http
            .post("https://overpass-api.de/api/interpreter")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!("data={}", crate::util::http::urlencode(&query)))
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let status = resp.status();
        if status.as_u16() == 429 {
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
            return Err(Error::module(SRC, format!("HTTP {status}")));
        }

        let body: OverpassResp = crate::util::http::json_scanned(resp, SRC)
            .await
            .map_err(|e| Error::module(SRC, e))?;

        if body.elements.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();

        let mut coords_entity =
            Entity::new(EntityKind::Coordinates, &target.value, 0.70, &ctx.scan_id);
        coords_entity.tag("overpass");
        coords_entity.tag("geoint");
        coords_entity.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "Overpass: {} infrastructure node(s) within 500m of {}",
                    body.elements.len(),
                    target.value
                ),
            )
            .with_attr("node_count", body.elements.len().to_string()),
        );
        result.push(coords_entity);

        let mut categories: std::collections::BTreeMap<&str, u32> =
            std::collections::BTreeMap::new();
        for elem in body.elements.iter().take(20) {
            let tags = match &elem.tags {
                Some(t) => t,
                None => continue,
            };

            let category = if tags.get("man_made").map(|v| v == "mast") == Some(true) {
                "cell_tower"
            } else if tags.get("tower:type").map(|v| v == "communication") == Some(true) {
                "comm_tower"
            } else if tags.get("man_made").map(|v| v == "surveillance") == Some(true) {
                "surveillance"
            } else if tags.get("power").map(|v| v == "substation") == Some(true) {
                "substation"
            } else if tags.get("amenity").map(|v| v == "police") == Some(true) {
                "police"
            } else if tags.get("amenity").map(|v| v == "fire_station") == Some(true) {
                "fire_station"
            } else {
                "infrastructure"
            };

            *categories.entry(category).or_default() += 1;

            if let (Some(nlat), Some(nlon)) = (elem.lat, elem.lon) {
                let node_coords = format!("{nlat:.6},{nlon:.6}");
                let mut ce = Entity::new(EntityKind::Coordinates, &node_coords, 0.55, &ctx.scan_id);
                ce.tag("overpass");
                ce.tag("geoint");
                ce.tag(format!("infra:{category}"));
                let mut ev = Evidence::new(SRC, format!("OSM {category} near {}", target.value))
                    .with_attr("category", category);
                if let Some(name) = tags.get("name") {
                    ev = ev.with_attr("name", name);
                }
                if let Some(operator) = tags.get("operator") {
                    ev = ev.with_attr("operator", operator);
                }
                if let Some(id) = elem.id {
                    ev = ev.with_attr("osm_id", id.to_string());
                }
                ce.add_evidence(ev);
                result.push(ce);
            }
        }

        if let Some(first) = result.entities.first_mut() {
            let summary: String = categories
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(", ");
            first.add_evidence(
                Evidence::new(SRC, format!("Infrastructure breakdown: {summary}"))
                    .with_attr("categories", summary),
            );
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_coordinates_only() {
        let m = Overpass;
        assert!(m.accepts(&Target::new(TargetKind::Coordinates, "-33.8,151.2")));
        assert!(!m.accepts(&Target::new(TargetKind::Address, "Sydney")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn module_metadata() {
        assert_eq!(Overpass.name(), "overpass");
        assert_eq!(Overpass.priority(), 15);
        assert_eq!(Overpass.max_timeout_ms(), 30_000);
    }

    #[test]
    fn parse_response() {
        let raw = r#"{
            "version": 0.6,
            "elements": [
                {
                    "type": "node",
                    "id": 12345,
                    "lat": -33.8688,
                    "lon": 151.2093,
                    "tags": {
                        "man_made": "mast",
                        "operator": "Telstra",
                        "name": "Cell Tower A"
                    }
                }
            ]
        }"#;
        let r: OverpassResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.elements.len(), 1);
        let e = &r.elements[0];
        assert_eq!(e.id, Some(12345));
        assert_eq!(e.tags.as_ref().unwrap().get("operator").unwrap(), "Telstra");
    }
}
