//! Australian socio-economic profile for a coordinate — ABS SEIFA + area
//! population. Free, no API key.
//!
//! The ABS Socio-Economic Indexes for Areas (SEIFA) rank every Australian area
//! by relative advantage and disadvantage from the Census. This module resolves
//! a coordinate against the ABS's public SEIFA ArcGIS service (point-in-polygon,
//! no key) to attach the containing SA2's profile:
//!
//! * **IRSD** — Index of Relative Socio-economic **Disadvantage** (the headline
//!   measure),
//! * **IRSAD** — Advantage **and** Disadvantage,
//! * **IER** — Economic Resources,
//! * **IEO** — Education and Occupation,
//!
//! each as a score, a national quintile (1 = most disadvantaged … 5 = least),
//! and a national percentile — plus the area's **usual resident population**.
//! This turns a bare coordinate (e.g. the one [`crate::modules::geocode`]
//! resolves from an address) into the socio-economic context of where someone
//! lives or works — applicable to essentially every Australian address and a
//! dimension the keyed OSINT stacks don't surface. It complements
//! [`crate::modules::au_geo`] (administrative geography) on the same input. A
//! coordinate outside Australia is skipped before any request. The indexes are
//! the 2016 release (the latest the ABS serves on this endpoint); relative
//! standing is slow-moving. No mock: queried live from the ABS's own service.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::core::{confidence, 
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::geo::parse_coords;
use crate::util::http::{RequestBuilderExt, UA_BROWSER, read_text, urlencode};

const SRC: &str = "au_seifa";
/// ABS SEIFA 2016 ArcGIS service, SA2 layer (id 2) — carries all four indexes.
const URL: &str = "https://geo.abs.gov.au/arcgis/rest/services/SEIFA2016/IRSD/MapServer/2/query";

/// The four SEIFA index field stems (IRSD = disadvantage, IRSAD = advantage &
/// disadvantage, IER = economic resources, IEO = education & occupation).
const INDEXES: &[&str] = &["IRSD", "IRSAD", "IER", "IEO"];

pub struct AuSeifa;

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
impl Module for AuSeifa {
    fn name(&self) -> &'static str {
        "au_seifa"
    }

    fn description(&self) -> &'static str {
        "Australian socio-economic profiling — geolocates a coordinate to its SEIFA disadvantage/advantage indexes and area population via ABS"
    }

    fn priority(&self) -> u8 {
        69
    }

    fn accepts(&self, t: &Target) -> bool {
        // Kind-only; the AU bounding-box gate is applied in process().
        matches!(t.kind, TargetKind::Coordinates)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        // Also emits `Other("au-population")` and `Other("au-seifa-disadvantage")`,
        // which cannot live in a `const` slice; the enriched pivot is the
        // Coordinates seed.
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let Ok((lat, lon)) = parse_coords(&target.value) else {
            return Ok(result);
        };
        // Australia (mainland + Tasmania) bounding box — skip non-AU points.
        if !(-44.0..=-9.5).contains(&lat) || !(112.0..=154.5).contains(&lon) {
            return Ok(result);
        }

        let geom = urlencode(&format!("{lon},{lat}"));
        let url = format!(
            "{URL}?geometry={geom}&geometryType=esriGeometryPoint&inSR=4326\
             &spatialRel=esriSpatialRelIntersects&outFields=*&returnGeometry=false&f=json"
        );
        let Some(attrs) = fetch_attrs(ctx, &url).await? else {
            return Ok(result);
        };
        assemble(&target.value, &attrs, &ctx.scan_id, &mut result);
        Ok(result)
    }
}

/// Fetch the SA2 SEIFA feature's attributes for the point. `Ok(None)` is a
/// genuine miss — a 200 response whose feature set does not cover the point
/// (e.g. an offshore coordinate). `Err` is a real ABS outage: a transport
/// failure, a non-2xx (the WAF answers a UA-less or throttled request with
/// 403), or a malformed body. Collapsing the two — as the previous
/// `.ok()?`/`return None` chain did — reported an ABS outage as "this point has
/// no SEIFA coverage," the honest-failure defect class.
async fn fetch_attrs(ctx: &ModuleContext, url: &str) -> Result<Option<Map<String, Value>>> {
    // The ABS WAF 403s a request with no User-Agent (cf. the AU registry scrapers).
    let resp = ctx
        .http
        .get(url)
        .header("User-Agent", UA_BROWSER)
        .send_tagged(SRC)
        .await?;
    if !resp.status().is_success() {
        return Err(crate::util::http::http_status_error(SRC, resp).await);
    }
    let body = read_text(SRC, resp).await?;
    let parsed: QueryResp = serde_json::from_str(&body)
        .map_err(|e| crate::core::error::Error::module(SRC, e.to_string()))?;
    Ok(parsed.features.into_iter().next().map(|f| f.attributes))
}

/// Build entities from the SA2 SEIFA attributes: the coordinate enriched with
/// the full profile, plus the population and headline-disadvantage pivots.
/// Pure — unit-tested against a fixture.
fn assemble(coord: &str, attrs: &Map<String, Value>, scan_id: &str, result: &mut ModuleResult) {
    // No SA2 name → the point has no SEIFA coverage (e.g. offshore).
    let Some(sa2_name) = attr_str(attrs, "SA2_NAME_2016") else {
        return;
    };
    let population = attr_i64(attrs, "SA2_URP_2016");

    let mut ev = Evidence::new(
        SRC,
        format!("ABS SEIFA 2016 socio-economic profile for {sa2_name}"),
    )
    .with_attr("coordinates", coord)
    .with_attr("seifa_sa2", &sa2_name)
    .with_attr("seifa_year", "2016");
    if let Some(code) = attr_str(attrs, "SA2_MAINCODE_2016") {
        ev = ev.with_attr("seifa_sa2_code", &code);
    }
    if let Some(p) = population {
        ev = ev.with_attr("population", p.to_string());
    }

    let mut irsd_quintile = None;
    for &stem in INDEXES {
        let lower = stem.to_ascii_lowercase();
        if let Some(s) = attr_i64(attrs, &format!("SA2_{stem}_SCORE_2016")) {
            ev = ev.with_attr(format!("seifa_{lower}_score"), s.to_string());
        }
        if let Some(q) = attr_i64(attrs, &format!("SA2_{stem}_QUINTILE_2016")) {
            ev = ev.with_attr(format!("seifa_{lower}_quintile"), q.to_string());
            if stem == "IRSD" {
                irsd_quintile = Some(q);
            }
        }
        if let Some(p) = attr_i64(attrs, &format!("SA2_{stem}_PER_AUS_2016")) {
            ev = ev.with_attr(format!("seifa_{lower}_pct_aus"), p.to_string());
        }
    }

    // Enrich the seed coordinate with the full profile (GREATEST-merge folds it
    // onto the existing Coordinates entity).
    let mut coord_e = Entity::new(EntityKind::Coordinates, coord, confidence::HIGH_PLUSPLUS_PLUS, scan_id);
    coord_e.tag("au");
    coord_e.tag("seifa");
    coord_e.tag("socioeconomic");
    coord_e.add_evidence(ev);
    result.push(coord_e);

    // Population — a clean, broadly-useful discrete figure.
    if let Some(p) = population {
        let mut pe = Entity::new(
            EntityKind::Other("au-population".into()),
            p.to_string(),
            confidence::HIGH_PLUSPLUS_PLUS,
            scan_id,
        );
        pe.tag("au");
        pe.tag("seifa");
        pe.tag("demographic");
        pe.add_evidence(
            Evidence::new(
                SRC,
                format!("Usual resident population of {sa2_name} (ABS 2016)"),
            )
            .with_attr("sa2", &sa2_name)
            .with_attr("population", p.to_string())
            .with_attr("coordinates", coord),
        );
        result.push(pe);
    }

    // Headline socio-economic disadvantage (IRSD quintile), as a descriptive pivot.
    if let Some(q) = irsd_quintile {
        let desc = format!("IRSD quintile {q} of 5");
        let mut de = Entity::new(
            EntityKind::Other("au-seifa-disadvantage".into()),
            &desc,
            confidence::HIGH_PLUSPLUS_PLUS,
            scan_id,
        );
        de.tag("au");
        de.tag("seifa");
        de.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "SEIFA disadvantage (IRSD) for {sa2_name}: quintile {q}/5 (1 = most disadvantaged)"
                ),
            )
            .with_attr("irsd_quintile", q.to_string())
            .with_attr("sa2", &sa2_name)
            .with_attr("coordinates", coord),
        );
        result.push(de);
    }
}

/// Read an attribute as a string (JSON string or number).
fn attr_str(m: &Map<String, Value>, k: &str) -> Option<String> {
    match m.get(k)? {
        Value::String(s) => (!s.is_empty()).then(|| s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Read an attribute as an integer (`null`/absent → `None`).
fn attr_i64(m: &Map<String, Value>, k: &str) -> Option<i64> {
    m.get(k)?.as_i64()
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
