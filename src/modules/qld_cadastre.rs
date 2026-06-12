//! Queensland DCDB cadastre — lot/plan + locality for a coordinate (QLD only).
//!
//! Endpoint: `GET .../PlanningCadastre/LandParcelPropertyFramework/MapServer/4/query`
//! Auth:     none (free, public Queensland Government ArcGIS REST service).
//!
//! Given a `Coordinates` target **inside Queensland**, runs a point-in-polygon
//! query against the Digital Cadastral DataBase ("Cadastral parcels", layer 4)
//! and returns the lot/plan, locality, local authority and tenure of the parcel
//! the point falls in. Coordinates outside QLD are skipped before any network
//! call (`crate::util::geo::au_state_for_coords`).
//!
//! This is the coordinate-keyed complement to `au_property` (which is
//! name-keyed): it surfaces the parcel identifier an analyst takes to the
//! Queensland Titles Registry for ownership — ownership itself is not public,
//! so this module deliberately emits none.

use std::collections::HashMap;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "qld_cadastre";

/// Queensland Globe / QSpatial ArcGIS REST — DCDB "Cadastral parcels" layer (id 4).
const LAYER_QUERY_BASE: &str = "https://spatial-gis.information.qld.gov.au/arcgis/rest/services/PlanningCadastre/LandParcelPropertyFramework/MapServer/4/query";

pub struct QldCadastre;

#[derive(Deserialize)]
struct QueryResp {
    #[serde(default)]
    features: Vec<Feature>,
}

#[derive(Deserialize)]
struct Feature {
    #[serde(default)]
    attributes: HashMap<String, Value>,
}

/// Pull a trimmed, non-empty string out of an ArcGIS attribute map, tolerating
/// the string- or number-typed fields ArcGIS may return. Returns `None` for an
/// absent, null, blank, or `"null"`-sentinel value. **Pure.**
fn attr(attrs: &HashMap<String, Value>, key: &str) -> Option<String> {
    let v = match attrs.get(key)? {
        Value::String(s) => s.trim().to_string(),
        Value::Number(n) => n.to_string(),
        _ => return None,
    };
    if v.is_empty() || v.eq_ignore_ascii_case("null") {
        None
    } else {
        Some(v)
    }
}

/// Build the point-in-polygon query URL for a WGS84 lon/lat. ArcGIS point
/// geometry is `x,y` = `lon,lat`; `inSR=4326` declares the input projection.
/// **Pure.**
fn build_query_url(lat: f64, lon: f64) -> String {
    format!(
        "{LAYER_QUERY_BASE}?geometry={lon:.6},{lat:.6}&geometryType=esriGeometryPoint\
         &inSR=4326&spatialRel=esriSpatialRelIntersects\
         &outFields=lot,plan,lotplan,locality,shire_name,tenure,parcel_typ\
         &returnGeometry=false&f=json"
    )
}

/// Build entities from one parcel feature's attributes. **Pure** (no network).
/// Emits a `Coordinates` entity for the queried point carrying the parcel's
/// lot/plan/locality/tenure as evidence (an authoritative cadastre
/// corroborating the location), plus an `Address` for the locality when
/// present. Returns empty when the feature has neither a lot/plan nor a
/// locality.
fn build_entities(coord: &str, attrs: &HashMap<String, Value>, scan_id: &str) -> Vec<Entity> {
    let lot = attr(attrs, "lot");
    let plan = attr(attrs, "plan");
    let lotplan = attr(attrs, "lotplan").or_else(|| match (&lot, &plan) {
        (Some(l), Some(p)) => Some(format!("{l}{p}")),
        _ => None,
    });
    let locality = attr(attrs, "locality");
    let lga = attr(attrs, "shire_name");
    let tenure = attr(attrs, "tenure");
    let parcel_typ = attr(attrs, "parcel_typ");

    if lotplan.is_none() && locality.is_none() {
        return Vec::new();
    }

    let mut out = Vec::new();

    let mut coords = Entity::new(EntityKind::Coordinates, coord, 0.78, scan_id);
    coords.tag(SRC);
    coords.tag("geoint");
    coords.tag("country:AU");
    coords.tag("au-state:QLD");
    if let Some(lp) = &lotplan {
        coords.tag(format!("lotplan:{lp}"));
    }
    let ev = [
        ("lotplan", &lotplan),
        ("lot", &lot),
        ("plan", &plan),
        ("locality", &locality),
        ("local_authority", &lga),
        ("tenure", &tenure),
        ("parcel_type", &parcel_typ),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.as_deref().map(|v| (key, v)))
    .fold(
        Evidence::new(SRC, format!("QLD DCDB cadastral parcel at {coord}")),
        |ev, (key, v)| ev.with_attr(key, v),
    );
    coords.add_evidence(ev);
    out.push(coords);

    if let Some(loc) = &locality {
        let addr_value = format!("{loc}, Queensland");
        let mut addr = Entity::new(EntityKind::Address, &addr_value, 0.55, scan_id);
        addr.tag(SRC);
        addr.tag("cadastre-derived");
        addr.tag("country:AU");
        addr.tag("au-state:QLD");
        if let Some(lp) = &lotplan {
            addr.tag(format!("lotplan:{lp}"));
        }
        let mut aev = Evidence::new(SRC, format!("Locality from QLD DCDB parcel at {coord}"))
            .with_attr("locality", loc);
        if let Some(v) = &lga {
            aev = aev.with_attr("local_authority", v);
        }
        addr.add_evidence(aev);
        out.push(addr);
    }

    out
}

#[async_trait]
impl Module for QldCadastre {
    fn name(&self) -> &'static str {
        "qld_cadastre"
    }
    fn description(&self) -> &'static str {
        "Queensland DCDB cadastre — lot/plan, locality and tenure for coordinates inside QLD"
    }
    fn priority(&self) -> u8 {
        18
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Coordinates)
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }
    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates, EntityKind::Address];
        KINDS
    }
    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let (lat, lon) = crate::util::geo::parse_coords(&target.value)?;

        // QLD-only: skip (no network) when the point isn't in Queensland.
        if crate::util::geo::au_state_for_coords(lat, lon) != Some("QLD") {
            return Ok(ModuleResult::new());
        }

        let resp = ctx
            .http
            .get(build_query_url(lat, lon))
            .send_tagged(SRC)
            .await?;

        let status = resp.status();
        if status.as_u16() == 429 {
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
            return Err(Error::module(SRC, format!("HTTP {status}")));
        }

        let body: QueryResp = crate::util::http::json_scanned(resp, SRC)
            .await
            .map_err(|e| Error::module(SRC, e))?;

        let Some(feature) = body.features.into_iter().next() else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.entities = build_entities(&target.value, &feature.attributes, &ctx.scan_id);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::module::ModuleCost;

    fn attrs(pairs: &[(&str, &str)]) -> HashMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), Value::String((*v).to_string())))
            .collect()
    }

    #[test]
    fn accepts_coordinates_only() {
        let m = QldCadastre;
        assert!(m.accepts(&Target::new(TargetKind::Coordinates, "-27.47,153.02")));
        assert!(!m.accepts(&Target::new(TargetKind::Address, "Brisbane")));
        assert!(!m.accepts(&Target::new(TargetKind::MacAddress, "aa:bb:cc:dd:ee:ff")));
    }

    #[test]
    fn module_metadata() {
        let m = QldCadastre;
        assert_eq!(m.name(), "qld_cadastre");
        assert_eq!(m.priority(), 18);
        assert!(matches!(m.cost(), ModuleCost::Free));
        assert_eq!(m.category(), ModuleCategory::Geo);
        assert!(m.produces().contains(&EntityKind::Coordinates));
        assert!(m.produces().contains(&EntityKind::Address));
        // Geo category yields a non-empty ATT&CK Reconnaissance mapping (guarded
        // in tests/architecture.rs); confirm the default propagates here too.
        assert!(!m.attack_techniques().is_empty());
    }

    #[test]
    fn build_query_url_targets_layer_4_point_in_qld() {
        let url = build_query_url(-27.4766, 153.0166);
        assert!(url.contains("spatial-gis.information.qld.gov.au"));
        assert!(url.contains("/LandParcelPropertyFramework/MapServer/4/query"));
        assert!(url.contains("geometryType=esriGeometryPoint"));
        assert!(url.contains("inSR=4326"));
        // ArcGIS point geometry is x,y = lon,lat (not lat,lon).
        assert!(url.contains("geometry=153.016600,-27.476600"));
        assert!(url.contains("f=json"));
    }

    #[test]
    fn build_entities_emits_coordinates_and_address_with_parcel_evidence() {
        let a = attrs(&[
            ("lot", "12"),
            ("plan", "RP123456"),
            ("lotplan", "12RP123456"),
            ("locality", "NUNDAH"),
            ("shire_name", "BRISBANE CITY"),
            ("tenure", "Freehold"),
            ("parcel_typ", "Lot Type Parcel"),
        ]);
        let out = build_entities("-27.4766,153.0166", &a, "s");
        assert_eq!(out.len(), 2);

        let coords = &out[0];
        assert_eq!(coords.kind, EntityKind::Coordinates);
        assert!(coords.has_tag("qld_cadastre"));
        assert!(coords.has_tag("au-state:QLD"));
        assert!(coords.has_tag("lotplan:12RP123456"));
        let ev = &coords.evidence[0];
        assert_eq!(
            ev.attributes.get("lotplan").map(String::as_str),
            Some("12RP123456")
        );
        assert_eq!(
            ev.attributes.get("local_authority").map(String::as_str),
            Some("BRISBANE CITY")
        );
        assert_eq!(
            ev.attributes.get("tenure").map(String::as_str),
            Some("Freehold")
        );

        let addr = &out[1];
        assert_eq!(addr.kind, EntityKind::Address);
        assert_eq!(addr.value, "NUNDAH, Queensland");
        assert!(addr.has_tag("cadastre-derived"));
        assert!(addr.has_tag("lotplan:12RP123456"));
    }

    #[test]
    fn build_entities_derives_lotplan_from_lot_and_plan() {
        let a = attrs(&[
            ("lot", "5"),
            ("plan", "SP181800"),
            ("locality", "TENERIFFE"),
        ]);
        let out = build_entities("-27.45,153.04", &a, "s");
        assert!(out[0].has_tag("lotplan:5SP181800"));
    }

    #[test]
    fn build_entities_empty_when_no_parcel_or_locality() {
        let a = attrs(&[("tenure", "Freehold")]);
        assert!(build_entities("-27.45,153.04", &a, "s").is_empty());
    }

    #[test]
    fn attr_handles_strings_numbers_blanks_and_nulls() {
        let mut a: HashMap<String, Value> = HashMap::new();
        a.insert("s".into(), Value::String("  hi  ".into()));
        a.insert("n".into(), Value::from(42));
        a.insert("blank".into(), Value::String("   ".into()));
        a.insert("nul".into(), Value::Null);
        assert_eq!(attr(&a, "s").as_deref(), Some("hi"));
        assert_eq!(attr(&a, "n").as_deref(), Some("42"));
        assert_eq!(attr(&a, "blank"), None);
        assert_eq!(attr(&a, "nul"), None);
        assert_eq!(attr(&a, "missing"), None);
    }

    #[test]
    fn parse_response_extracts_attributes() {
        let raw = r#"{"features":[{"attributes":{"lot":"12","plan":"RP123456",
            "lotplan":"12RP123456","locality":"NUNDAH"}}],"exceededTransferLimit":false}"#;
        let r: QueryResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.features.len(), 1);
        assert_eq!(
            r.features[0].attributes.get("lotplan"),
            Some(&Value::String("12RP123456".into()))
        );
    }
}
