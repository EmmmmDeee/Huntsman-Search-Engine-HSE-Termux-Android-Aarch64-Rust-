//! Wikipedia GeoSearch — a coordinate → its nearby named places.
//!
//! Endpoint: `GET https://en.wikipedia.org/w/api.php?action=query&list=geosearch`
//! Auth:     None (free, public MediaWiki API).
//!
//! Given a `Coordinates` target, returns the Wikipedia articles for places
//! within a radius — each with its title, own coordinates, and distance from the
//! query point. This turns a raw lat/lon (from `exif_geo`, `ip_geo`, the
//! snippet-coordinate extractor, or any geocode) into named, human-meaningful
//! nearby landmarks: the GEOINT context that says *where* a point actually is.
//! Complements `overpass` (which returns physical infrastructure nodes) with
//! named, encyclopaedic places.
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

const SRC: &str = "wiki_geosearch";
/// Search radius (metres). The MediaWiki GeoSearch max is 10 000 m; 1 km keeps
/// results tightly relevant to the point rather than the whole suburb.
const RADIUS_M: u32 = 1_000;
/// Places requested / kept — enough to characterise the locale without flooding
/// the graph with distant, weakly-related articles.
const LIMIT: u32 = 10;

pub struct WikiGeoSearch;

#[derive(Deserialize)]
struct GeoResp {
    #[serde(default)]
    query: Option<GeoQuery>,
}

#[derive(Deserialize)]
struct GeoQuery {
    #[serde(default)]
    geosearch: Vec<GeoPlace>,
}

#[derive(Deserialize)]
struct GeoPlace {
    #[serde(default)]
    pageid: Option<u64>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    lat: Option<f64>,
    #[serde(default)]
    lon: Option<f64>,
    /// Distance from the query point in metres (MediaWiki computes it).
    #[serde(default)]
    dist: Option<f64>,
}

/// Build the entities for a GeoSearch response. **Pure** (no network): one
/// `Coordinates` entity per located nearby place (its own lat/lon), tagged
/// `wikipedia` + `geoint` + `nearby-place`, carrying the article title, pageid,
/// distance, and a stable article URL as evidence. `query_coord` is the point we
/// searched around, echoed into each finding's evidence for provenance.
fn build_entities(query_coord: &str, places: &[GeoPlace], scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    for p in places {
        let (Some(lat), Some(lon)) = (p.lat, p.lon) else {
            continue;
        };
        let title = match p.title.as_deref().filter(|t| !t.trim().is_empty()) {
            Some(t) => t,
            None => continue,
        };
        let place_coord = format!("{lat:.6},{lon:.6}");
        let mut e = Entity::new(
            EntityKind::Coordinates,
            &place_coord,
            confidence::MEDIUM_HIGH,
            scan_id,
        );
        e.tag("wikipedia");
        e.tag("geoint");
        e.tag("nearby-place");
        crate::util::geo::tag_au_state(&mut e, lat, lon);

        let mut ev = Evidence::new(SRC, format!("Wikipedia place '{title}' near {query_coord}"))
            .with_attr("title", title);
        if let Some(dist) = p.dist {
            ev = ev.with_attr("distance_m", format!("{dist:.0}"));
        }
        if let Some(pid) = p.pageid {
            ev = ev
                .with_attr("pageid", pid.to_string())
                // Stable, redirect-proof article URL via the numeric page id.
                .with_attr("url", format!("https://en.wikipedia.org/?curid={pid}"));
        }
        e.add_evidence(ev);
        out.push(e);
    }
    out
}

#[async_trait]
impl Module for WikiGeoSearch {
    fn name(&self) -> &'static str {
        "wiki_geosearch"
    }

    fn description(&self) -> &'static str {
        "Wikipedia GeoSearch — resolves coordinates to nearby named places (articles, landmarks) for GEOINT context"
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
        15_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let (lat, lon) = crate::util::geo::parse_coords(&target.value)?;

        // `gscoord=lat|lon` (the `|` percent-encoded); the primary-article
        // GeoSearch list within RADIUS_M, up to LIMIT results, as JSON.
        let url = format!(
            "https://en.wikipedia.org/w/api.php?action=query&list=geosearch\
             &gscoord={lat}%7C{lon}&gsradius={RADIUS_M}&gslimit={LIMIT}&format=json"
        );

        // Shared `fetch_json` (curl/OpenSSL fallback + circuit breaker + the
        // client's descriptive User-Agent Wikimedia's API policy expects).
        let resp: GeoResp = crate::util::http::fetch_json(&ctx.http, SRC, &url).await?;
        let places = resp.query.map(|q| q.geosearch).unwrap_or_default();

        let mut result = ModuleResult::new();
        for e in build_entities(&target.value, &places, &ctx.scan_id) {
            result.push(e);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
