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
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
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

/// Per-node entities mapped from one Overpass response — a busy urban query can
/// return hundreds; the first 20 are plenty to characterise the locale.
const MAX_NODES: usize = 20;

/// Classify an OSM node by its tags into one of the infrastructure categories
/// this module queries for. **Pure**. Falls back to the generic
/// `"infrastructure"` for a node that matched the query but carries none of the
/// discriminating tags (e.g. a multi-tagged element).
fn classify_element(tags: &std::collections::HashMap<String, String>) -> &'static str {
    let is = |k: &str, v: &str| tags.get(k).map(String::as_str) == Some(v);
    if is("man_made", "mast") {
        "cell_tower"
    } else if is("tower:type", "communication") {
        "comm_tower"
    } else if is("man_made", "surveillance") {
        "surveillance"
    } else if is("power", "substation") {
        "substation"
    } else if is("amenity", "police") {
        "police"
    } else if is("amenity", "fire_station") {
        "fire_station"
    } else {
        "infrastructure"
    }
}

/// Build the entities for an Overpass response. **Pure** (no network/IO): emits a
/// summary `Coordinates` entity for the queried point (carrying the node count
/// and a per-category breakdown), then one `Coordinates` entity per located
/// infrastructure node (capped at [`MAX_NODES`], classified via
/// [`classify_element`], with name/operator/osm_id evidence). Caller guarantees
/// `elements` is non-empty.
fn build_entities(coord: &str, elements: &[OsmElement], scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();

    let mut summary = Entity::new(EntityKind::Coordinates, coord, 0.70, scan_id);
    summary.tag("overpass");
    summary.tag("geoint");
    summary.add_evidence(
        Evidence::new(
            SRC,
            format!(
                "Overpass: {} infrastructure node(s) within 500m of {coord}",
                elements.len()
            ),
        )
        .with_attr("node_count", elements.len().to_string()),
    );
    out.push(summary);

    let mut categories: std::collections::BTreeMap<&str, u32> = std::collections::BTreeMap::new();
    for elem in elements.iter().take(MAX_NODES) {
        let Some(tags) = &elem.tags else {
            continue;
        };
        let category = classify_element(tags);
        *categories.entry(category).or_default() += 1;

        if let (Some(nlat), Some(nlon)) = (elem.lat, elem.lon) {
            let node_coords = format!("{nlat:.6},{nlon:.6}");
            let mut ce = Entity::new(EntityKind::Coordinates, &node_coords, 0.55, scan_id);
            ce.tag("overpass");
            ce.tag("geoint");
            ce.tag(format!("infra:{category}"));
            let mut ev = Evidence::new(SRC, format!("OSM {category} near {coord}"))
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
            out.push(ce);
        }
    }

    if let Some(first) = out.first_mut() {
        let breakdown: String = categories
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ");
        first.add_evidence(
            Evidence::new(SRC, format!("Infrastructure breakdown: {breakdown}"))
                .with_attr("categories", breakdown),
        );
    }

    out
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

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
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
        result.entities = build_entities(&target.value, &body.elements, &ctx.scan_id);
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

    fn tags(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn classify_element_covers_every_category() {
        assert_eq!(
            classify_element(&tags(&[("man_made", "mast")])),
            "cell_tower"
        );
        assert_eq!(
            classify_element(&tags(&[("tower:type", "communication")])),
            "comm_tower"
        );
        assert_eq!(
            classify_element(&tags(&[("man_made", "surveillance")])),
            "surveillance"
        );
        assert_eq!(
            classify_element(&tags(&[("power", "substation")])),
            "substation"
        );
        assert_eq!(classify_element(&tags(&[("amenity", "police")])), "police");
        assert_eq!(
            classify_element(&tags(&[("amenity", "fire_station")])),
            "fire_station"
        );
        // Matched the query but carries none of the discriminating tags.
        assert_eq!(
            classify_element(&tags(&[("man_made", "antenna")])),
            "infrastructure"
        );
    }

    fn elements(json: &str) -> Vec<OsmElement> {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn build_entities_emits_summary_plus_classified_nodes() {
        let els = elements(
            r#"[
              {"type":"node","id":1,"lat":-33.8688,"lon":151.2093,
               "tags":{"man_made":"mast","operator":"Telstra","name":"Tower A"}},
              {"type":"node","id":2,"lat":-33.8690,"lon":151.2095,
               "tags":{"man_made":"surveillance"}},
              {"type":"node","id":3,"lat":-33.8692,"lon":151.2097,
               "tags":{"man_made":"mast"}}
            ]"#,
        );
        let out = build_entities("-33.8688,151.2093", &els, "s");
        // Summary + 3 node entities.
        assert_eq!(out.len(), 4);

        let summary = &out[0];
        assert!(summary.has_tag("overpass") && summary.has_tag("geoint"));
        assert_eq!(
            summary.evidence[0]
                .attributes
                .get("node_count")
                .map(String::as_str),
            Some("3")
        );
        // Breakdown evidence is appended as the summary's second evidence row;
        // BTreeMap → deterministic category order.
        assert_eq!(
            summary.evidence[1]
                .attributes
                .get("categories")
                .map(String::as_str),
            Some("cell_tower=2, surveillance=1")
        );

        // First node: classified cell_tower with name/operator/osm_id evidence.
        let n1 = &out[1];
        assert!(n1.has_tag("infra:cell_tower"));
        assert_eq!(
            n1.evidence[0]
                .attributes
                .get("operator")
                .map(String::as_str),
            Some("Telstra")
        );
        assert_eq!(
            n1.evidence[0].attributes.get("osm_id").map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn build_entities_caps_nodes_but_counts_all_in_summary() {
        let els: Vec<OsmElement> = elements(&format!(
            "[{}]",
            (0..MAX_NODES + 10)
                .map(|i| format!(
                    r#"{{"type":"node","id":{i},"lat":{},"lon":151.0,"tags":{{"man_made":"mast"}}}}"#,
                    -33.0 - i as f64 / 1000.0
                ))
                .collect::<Vec<_>>()
                .join(",")
        ));
        let out = build_entities("-33.0,151.0", &els, "s");
        // Summary node_count reflects ALL elements...
        assert_eq!(
            out[0].evidence[0]
                .attributes
                .get("node_count")
                .map(String::as_str),
            Some(&(MAX_NODES + 10).to_string()[..])
        );
        // ...but only MAX_NODES node entities are emitted (+1 summary).
        assert_eq!(out.len(), MAX_NODES + 1);
    }
}
