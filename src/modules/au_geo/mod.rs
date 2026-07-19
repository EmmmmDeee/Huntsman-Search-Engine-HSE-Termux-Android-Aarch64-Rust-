//! Australian administrative & statistical geography for a coordinate. Free, no
//! API key.
//!
//! Every point in Australia falls inside a nested set of official boundaries
//! published by the ABS in the Australian Statistical Geography Standard
//! (ASGS). This module resolves a coordinate against the ABS's public ArcGIS
//! boundary service (point-in-polygon, no key) to attribute it to:
//!
//! * **Postcode** (POA) and **suburb / locality** (SAL) — the human-meaningful
//!   "where",
//! * **Local Government Area** (LGA) — the council,
//! * **Commonwealth electoral division** (CED) — the federal electorate,
//! * **State electoral division** (SED) — the state electorate,
//! * **Remoteness Area** (RA) — the Major-Cities…Very-Remote classification,
//! * **Statistical Areas** (SA2 / SA4) — the ABS census small area and the
//!   labour-market region it sits in, and
//! * **Mesh-block land use** — the finest ASGS unit's category (Residential /
//!   Commercial / Industrial / …): is this coordinate a home or a business?
//!
//! plus the state/territory. This is foundational GEOINT that applies to
//! essentially every Australian address: it turns a bare lat/lon (e.g. the
//! coordinate [`crate::modules::geocode`] resolves from an address) into the
//! administrative and political geography around it — councils and electorates
//! the keyed OSINT stacks don't surface. A coordinate outside Australia is
//! skipped before any request (a clean miss). No mock: the boundaries are
//! queried live from the ABS's own service.

use async_trait::async_trait;
use futures::future::join_all;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::geo::parse_coords;
use crate::util::http::{RequestBuilderExt, UA_BROWSER, read_text, urlencode};

const SRC: &str = "au_geo";
/// ABS ASGS Edition 3 (2021) public ArcGIS service root.
const BASE: &str = "https://geo.abs.gov.au/arcgis/rest/services/ASGS2021";

/// One ASGS boundary layer to resolve, with the attribute fields it exposes.
struct LayerSpec {
    /// Service path segment (`CED`, `LGA`, …).
    path: &'static str,
    /// JSON attribute holding the region name.
    name_field: &'static str,
    /// JSON attribute holding the region code.
    code_field: &'static str,
    /// `Other(_)` entity kind tag emitted for this layer.
    kind: &'static str,
    /// Snake-case evidence-attribute key for the coordinate roll-up.
    attr_key: &'static str,
    /// Human-readable label for evidence summaries.
    label: &'static str,
    /// Confidence for the emitted region entity.
    conf: f64,
}

/// The high-value, broadly-applicable layers, resolved together. Order is the
/// contract between [`AuGeo::process`]'s concurrent fetch and [`assemble`].
const LAYERS: &[LayerSpec] = &[
    LayerSpec {
        path: "POA",
        name_field: "poa_name_2021",
        code_field: "poa_code_2021",
        kind: "au-postcode",
        attr_key: "au_postcode",
        label: "postcode",
        conf: 0.90,
    },
    LayerSpec {
        path: "SAL",
        name_field: "sal_name_2021",
        code_field: "sal_code_2021",
        kind: "au-suburb",
        attr_key: "au_suburb",
        label: "suburb/locality",
        conf: 0.88,
    },
    LayerSpec {
        path: "LGA",
        name_field: "lga_name_2021",
        code_field: "lga_code_2021",
        kind: "au-lga",
        attr_key: "au_lga",
        label: "local government area",
        conf: 0.90,
    },
    LayerSpec {
        path: "CED",
        name_field: "ced_name_2021",
        code_field: "ced_code_2021",
        kind: "au-federal-electorate",
        attr_key: "au_federal_electorate",
        label: "federal electoral division",
        conf: 0.90,
    },
    LayerSpec {
        path: "SED",
        name_field: "sed_name_2021",
        code_field: "sed_code_2021",
        kind: "au-state-electorate",
        attr_key: "au_state_electorate",
        label: "state electoral division",
        conf: 0.88,
    },
    LayerSpec {
        path: "RA",
        name_field: "ra_name_2021",
        code_field: "ra_code_2021",
        kind: "au-remoteness",
        attr_key: "au_remoteness",
        label: "remoteness area",
        conf: 0.88,
    },
    LayerSpec {
        path: "SA2",
        name_field: "sa2_name_2021",
        code_field: "sa2_code_2021",
        kind: "au-sa2",
        attr_key: "au_sa2",
        label: "statistical area level 2",
        conf: 0.85,
    },
    LayerSpec {
        path: "SA4",
        name_field: "sa4_name_2021",
        code_field: "sa4_code_2021",
        kind: "au-sa4",
        attr_key: "au_sa4",
        label: "statistical area level 4",
        conf: 0.85,
    },
    LayerSpec {
        // The finest ASGS unit carries a land-use category (Residential /
        // Commercial / Industrial / Parkland / …) — a "what kind of place is
        // this coordinate" signal: is an address a home or a business?
        path: "MB",
        name_field: "mb_category_2021",
        code_field: "mb_code_2021",
        kind: "au-land-use",
        attr_key: "au_land_use",
        label: "mesh-block land use",
        conf: 0.85,
    },
];

pub struct AuGeo;

#[derive(Deserialize, Default)]
#[serde(default)]
struct QueryResp {
    features: Vec<Feature>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Feature {
    attributes: Map<String, Value>,
}

#[async_trait]
impl Module for AuGeo {
    fn name(&self) -> &'static str {
        "au_geo"
    }

    fn description(&self) -> &'static str {
        "Australian geolocation recon — resolves a coordinate to postcode, suburb, LGA, and federal & state electorate via ABS ASGS"
    }

    fn priority(&self) -> u8 {
        70
    }

    fn accepts(&self, t: &Target) -> bool {
        // Kind-only; the AU bounding-box gate is applied in process() so a
        // non-Australian coordinate issues no request.
        matches!(t.kind, TargetKind::Coordinates)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        // Also emits `Other("au-postcode" | "au-suburb" | "au-lga" |
        // "au-federal-electorate" | "au-state-electorate")`, which cannot live in
        // a `const` slice; the enriched pivot is the seed Coordinates.
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let Ok((lat, lon)) = parse_coords(&target.value) else {
            return Ok(result);
        };
        // Australia (mainland + Tasmania) bounding box — a point outside it has
        // no ASGS coverage, so skip it before any request.
        if !(-44.0..=-9.5).contains(&lat) || !(112.0..=154.5).contains(&lon) {
            return Ok(result);
        }

        // ArcGIS points are x,y = lon,lat.
        let geom = urlencode(&format!("{lon},{lat}"));
        // Resolve every layer concurrently (join_all preserves LAYERS order).
        let resolved = join_all(LAYERS.iter().map(|spec| query_layer(ctx, &geom, spec))).await;

        // A point outside a given layer's coverage is `Ok(None)`; a real ABS
        // outage (host down, WAF 403, non-2xx) is `Err`. Tolerate partial
        // failures and genuine misses — but if EVERY layer hard-failed, the ABS
        // service is down, so surface that instead of silently reporting the
        // point as having no Australian geography (cf. the total-failure
        // surfacing in au_unclaimed / api_key_probe).
        if !resolved.is_empty() && resolved.iter().all(Result::is_err) {
            return Err(resolved
                .into_iter()
                .find_map(Result::err)
                .expect("all-Err implies at least one Err"));
        }
        let resolved: Vec<Option<(String, String, Option<String>)>> =
            resolved.into_iter().map(|r| r.ok().flatten()).collect();

        assemble(&target.value, &resolved, &ctx.scan_id, &mut result);
        Ok(result)
    }
}

/// Query one ASGS layer for the polygon containing the point. `Ok(None)` is a
/// genuine miss (a 200 with no feature covering the point); `Err` is a real ABS
/// outage (transport failure or non-2xx, incl. the WAF's 403). The caller
/// tolerates a partial failure but surfaces a total one.
async fn query_layer(
    ctx: &ModuleContext,
    geom: &str,
    spec: &LayerSpec,
) -> Result<Option<(String, String, Option<String>)>> {
    let url = format!(
        "{BASE}/{}/MapServer/0/query?geometry={geom}&geometryType=esriGeometryPoint\
         &inSR=4326&spatialRel=esriSpatialRelIntersects&outFields=*&returnGeometry=false&f=json",
        spec.path
    );
    // The ABS WAF 403s a request with no User-Agent — present the browser UA the
    // sibling AU registry scrapers use.
    let resp = ctx
        .http
        .get(&url)
        .header("User-Agent", UA_BROWSER)
        .send_tagged(SRC)
        .await?;
    if !resp.status().is_success() {
        return Err(crate::util::http::http_status_error(SRC, resp).await);
    }
    let body = read_text(SRC, resp).await?;
    Ok(parse_feature(&body, spec.name_field, spec.code_field))
}

/// Extract `(name, code, state)` from a layer-query response's first feature.
/// Pure — unit-tested against fixtures.
fn parse_feature(
    body: &str,
    name_field: &str,
    code_field: &str,
) -> Option<(String, String, Option<String>)> {
    let resp: QueryResp = serde_json::from_str(body).ok()?;
    let attrs = resp.features.into_iter().next()?.attributes;
    let name = attr_str(&attrs, name_field)?;
    let code = attr_str(&attrs, code_field).unwrap_or_default();
    let state = attr_str(&attrs, "state_name_2021");
    Some((name, code, state))
}

/// Read an attribute as a string, accepting both JSON string and number values.
fn attr_str(m: &Map<String, Value>, k: &str) -> Option<String> {
    match m.get(k)? {
        Value::String(s) => (!s.is_empty()).then(|| s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Build entities from the resolved layers (aligned with [`LAYERS`]): one
/// `Other` region entity per hit, and the seed coordinate enriched with the
/// full administrative roll-up. Pure — unit-tested against fixtures.
fn assemble(
    coord: &str,
    resolved: &[Option<(String, String, Option<String>)>],
    scan_id: &str,
    result: &mut ModuleResult,
) {
    let mut roll_up = Evidence::new(SRC, "Australian ASGS geography (ABS, point-in-polygon)")
        .with_attr("source", "abs-asgs-2021")
        .with_attr("coordinates", coord);
    let mut state: Option<String> = None;
    let mut any = false;

    for (spec, res) in LAYERS.iter().zip(resolved.iter()) {
        let Some((name, code, st)) = res else {
            continue;
        };
        any = true;
        if state.is_none() {
            state = st.clone();
        }
        roll_up = roll_up.with_attr(spec.attr_key, name);

        let mut e = Entity::new(
            EntityKind::Other(spec.kind.to_string()),
            name,
            spec.conf,
            scan_id,
        );
        e.tag("au");
        e.tag("asgs");
        e.tag(spec.kind);
        e.add_evidence(
            Evidence::new(SRC, format!("ASGS {}: {name}", spec.label))
                .with_attr("asgs_code", code)
                .with_attr("layer", spec.path)
                .with_attr("coordinates", coord),
        );
        result.push(e);
    }

    if !any {
        return;
    }
    if let Some(s) = &state {
        roll_up = roll_up.with_attr("au_state", s);
    }
    // Enrich the seed coordinate (GREATEST-merge folds this onto the existing
    // Coordinates entity, only ever adding tags/evidence).
    let mut coord_e = Entity::new(EntityKind::Coordinates, coord, 0.85, scan_id);
    coord_e.tag("au");
    coord_e.tag("geoint");
    coord_e.tag("asgs");
    // `coord_state()` (core::correlator::rules::geo) prefers an `au-state:XX`
    // tag over its own coarse rectangular-bbox fallback — without this tag the
    // exact ABS point-in-polygon state answer above is discarded and AU-056/
    // AU-085 jurisdiction cross-checks silently re-derive a less precise one.
    if let Some(code) = state
        .as_deref()
        .and_then(crate::util::address_au::state_code)
    {
        coord_e.tag(format!("au-state:{code}"));
        coord_e.tag("country:AU");
    }
    coord_e.add_evidence(roll_up);
    result.push(coord_e);
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
