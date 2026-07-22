//! Wikidata geo — a coordinate → its nearby Wikidata entities.
//!
//! Endpoint: `GET https://query.wikidata.org/sparql` (a `wikibase:around` query)
//! Auth:     None (free, public SPARQL endpoint).
//!
//! Given a `Coordinates` target, runs a `wikibase:around` SPARQL query for
//! entities within a radius, each with its QID, English label, own coordinates,
//! and distance. Complements [`super::wiki_geosearch`] (Wikipedia *articles*)
//! with Wikidata's structured *entities* — the same place is often modelled in
//! both, but Wikidata reaches items that have no Wikipedia article, and its QID
//! is a stable cross-source join key. Turns a raw lat/lon into named,
//! machine-linkable nearby places (GEOINT context).
//!
//! Termux aarch64 / no-root: a single keyless HTTPS GET through the shared
//! client; no new deps.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "wikidata_geo";
/// Search radius in kilometres (`wikibase:radius` unit). 1 km keeps results
/// tightly relevant to the point.
const RADIUS_KM: &str = "1";
/// Entities requested / kept.
const LIMIT: u32 = 12;

pub struct WikidataGeo;

#[derive(Deserialize)]
struct SparqlResp {
    #[serde(default)]
    results: SparqlResults,
}

#[derive(Deserialize, Default)]
struct SparqlResults {
    #[serde(default)]
    bindings: Vec<Binding>,
}

#[derive(Deserialize)]
struct Binding {
    #[serde(default)]
    place: Option<Cell>,
    #[serde(rename = "placeLabel", default)]
    place_label: Option<Cell>,
    #[serde(default)]
    location: Option<Cell>,
    #[serde(default)]
    dist: Option<Cell>,
}

#[derive(Deserialize)]
struct Cell {
    #[serde(default)]
    value: String,
}

/// Parse a WKT point literal `Point(<lon> <lat>)` into `(lat, lon)`. Wikidata
/// emits longitude FIRST (GeoSPARQL/WKT order), so the two are swapped on the way
/// out to HSE's canonical `lat,lon`. `None` on any malformed literal. Pure.
fn parse_wkt_point(wkt: &str) -> Option<(f64, f64)> {
    let inner = wkt.trim().strip_prefix("Point(")?.strip_suffix(')')?;
    let mut it = inner.split_whitespace();
    let lon: f64 = it.next()?.parse().ok()?;
    let lat: f64 = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None; // more than two components ⇒ not a plain point
    }
    Some((lat, lon))
}

/// The bare QID (`Q2154104`) from a Wikidata entity URI. `None` if `uri` isn't
/// an entity URI. Pure.
fn qid_from_uri(uri: &str) -> Option<&str> {
    let q = uri.rsplit('/').next()?;
    (q.starts_with('Q') && q[1..].chars().all(|c| c.is_ascii_digit()) && q.len() > 1).then_some(q)
}

/// Build the entities for a SPARQL response. **Pure** (no network): one
/// `Coordinates` entity per binding that has a valid location + QID, tagged
/// `wikidata` + `geoint` + `nearby-place`, carrying the label, QID, distance, and
/// the entity URL as evidence. `query_coord` is echoed for provenance.
fn build_entities(query_coord: &str, bindings: &[Binding], scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    for b in bindings {
        let Some((lat, lon)) = b.location.as_ref().and_then(|c| parse_wkt_point(&c.value)) else {
            continue;
        };
        let Some(qid) = b.place.as_ref().and_then(|c| qid_from_uri(&c.value)) else {
            continue;
        };
        // The label service falls back to the QID string when an item has no
        // English label; treat that as "unlabelled" rather than a real name.
        let label = b
            .place_label
            .as_ref()
            .map(|c| c.value.as_str())
            .filter(|l| !l.is_empty() && *l != qid);

        let place_coord = format!("{lat:.6},{lon:.6}");
        let mut e = Entity::new(
            EntityKind::Coordinates,
            &place_coord,
            confidence::MEDIUM_HIGH,
            scan_id,
        );
        e.tag("wikidata");
        e.tag("geoint");
        e.tag("nearby-place");
        e.tag(format!("wikidata:{qid}"));
        crate::util::geo::tag_au_state(&mut e, lat, lon);

        let summary = label.map_or_else(
            || format!("Wikidata entity {qid} near {query_coord}"),
            |l| format!("Wikidata place '{l}' ({qid}) near {query_coord}"),
        );
        let mut ev = Evidence::new(SRC, summary)
            .with_attr("qid", qid)
            .with_attr("url", format!("https://www.wikidata.org/entity/{qid}"));
        if let Some(l) = label {
            ev = ev.with_attr("label", l);
        }
        if let Some(d) = b.dist.as_ref() {
            // `dist` is in km; surface metres to match wiki_geosearch's units.
            if let Ok(km) = d.value.parse::<f64>() {
                ev = ev.with_attr("distance_m", format!("{:.0}", km * 1000.0));
            }
        }
        e.add_evidence(ev);
        out.push(e);
    }
    out
}

#[async_trait]
impl Module for WikidataGeo {
    fn name(&self) -> &'static str {
        "wikidata_geo"
    }

    fn description(&self) -> &'static str {
        "Wikidata geo — resolves coordinates to nearby Wikidata entities (QID, label, coords) for GEOINT context"
    }

    fn priority(&self) -> u8 {
        15
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Coordinates)
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn max_timeout_ms(&self) -> u64 {
        // The public SPARQL endpoint can be slow / queued under load; give the
        // query real headroom (it self-limits to LIMIT rows within RADIUS_KM).
        20_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let (lat, lon) = crate::util::geo::parse_coords(&target.value)?;

        // WKT centre is `Point(<lon> <lat>)`. The label service resolves
        // ?placeLabel to the English name; ORDER BY ?dist keeps the nearest first.
        let query = format!(
            "SELECT ?place ?placeLabel ?location ?dist WHERE {{ \
             SERVICE wikibase:around {{ ?place wdt:P625 ?location. \
             bd:serviceParam wikibase:center \"Point({lon} {lat})\"^^geo:wktLiteral. \
             bd:serviceParam wikibase:radius \"{RADIUS_KM}\". \
             bd:serviceParam wikibase:distance ?dist. }} \
             SERVICE wikibase:label {{ bd:serviceParam wikibase:language \"en\". }} }} \
             ORDER BY ?dist LIMIT {LIMIT}"
        );
        let url = format!(
            "https://query.wikidata.org/sparql?format=json&query={}",
            crate::util::http::urlencode(&query)
        );

        // Shared `fetch_json` (curl/OpenSSL fallback + circuit breaker + the
        // client's descriptive User-Agent the WDQS policy expects).
        let resp: SparqlResp = crate::util::http::fetch_json(&ctx.http, SRC, &url).await?;

        let mut result = ModuleResult::new();
        for e in build_entities(&target.value, &resp.results.bindings, &ctx.scan_id) {
            result.push(e);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
