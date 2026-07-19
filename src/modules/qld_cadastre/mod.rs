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

use crate::core::{confidence, 
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
        let mut addr = Entity::new(EntityKind::Address, &addr_value, confidence::MEDIUM_HIGH, scan_id);
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
        "Queensland DCDB cadastre recon — resolves coordinates inside QLD to lot/plan, locality, and tenure"
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
        // Budget for two requests plus a bounded Retry-After sleep on a 429
        // (see the retry in `process`), not just the single original call —
        // 15s left no headroom for a real retry path.
        25_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let (lat, lon) = crate::util::geo::parse_coords(&target.value)?;

        // QLD-only: skip (no network) when the point isn't in Queensland.
        if crate::util::geo::au_state_for_coords(lat, lon) != Some("QLD") {
            return Ok(ModuleResult::new());
        }

        let mut resp = ctx
            .http
            .get(build_query_url(lat, lon))
            .send_tagged(SRC)
            .await?;

        // A 429 here used to degrade straight to Ok(empty) — indistinguishable
        // from "no cadastre parcel at this point" — with no retry, no backoff,
        // and no circuit-breaker engagement at all (this module calls
        // send_tagged directly rather than the shared fetch_json_inner/
        // fetch_keyed_json helpers that every other rate-limit-aware module
        // routes through). Honour a real server Retry-After (clamped so the
        // retry path stays inside this module's own 15s budget) and retry
        // once before giving up; a second 429 is now a real, surfaced error
        // instead of a silent empty success.
        if resp.status().as_u16() == 429 {
            let delay = crate::util::http::retry_after_secs(resp.headers(), 3, 5);
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            resp = ctx
                .http
                .get(build_query_url(lat, lon))
                .send_tagged(SRC)
                .await?;
        }

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::module(SRC, format!("HTTP {status}")));
        }

        let body: QueryResp = crate::util::http::json_scanned(resp, SRC)
            .await
            .map_err(|e| Error::module(SRC, e))?;

        let mut result = ModuleResult::new();
        result.entities = build_all_features(&target.value, &body.features, &ctx.scan_id);
        Ok(result)
    }
}

/// Build entities for EVERY intersecting cadastral parcel, not just the first. A
/// point query at a boundary, on strata / stacked cadastre, or where the DCDB
/// returns several intersecting polygons yields multiple features; emitting only
/// `features[0]` dropped the rest — omitting AU government parcel data (lot/plan,
/// locality, tenure) the no-omission directive requires.
///
/// No de-duplication here: parcels at one point share the query Coordinates value
/// AND (when in one suburb) the locality Address value, distinguished only by
/// their `lotplan:` TAG. The engine's downstream value-merge folds the shared
/// values into one entity while UNIONing those per-parcel tags, so every parcel's
/// lot/plan survives — whereas a value-dedup here would silently drop all but the
/// first parcel's lotplan. Pure, bounded (`MAX_FEATURES`), deterministic.
fn build_all_features(coord: &str, features: &[Feature], scan_id: &str) -> Vec<Entity> {
    const MAX_FEATURES: usize = 8;
    features
        .iter()
        .take(MAX_FEATURES)
        .flat_map(|feature| build_entities(coord, &feature.attributes, scan_id))
        .collect()
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
