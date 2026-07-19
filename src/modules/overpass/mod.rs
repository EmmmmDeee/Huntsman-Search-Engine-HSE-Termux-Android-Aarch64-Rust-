//! Overpass API — extract physical infrastructure from OpenStreetMap.
//!
//! Endpoint: `POST https://overpass-api.de/api/interpreter`
//! Auth:     None (free, public).
//!
//! Given a Coordinates target, queries for nearby infrastructure nodes
//! (cell towers, substations, surveillance cameras) within a 500m radius.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{confidence, 
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "overpass";

pub struct Overpass;

#[derive(Deserialize)]
struct OverpassResp {
    #[serde(default)]
    elements: Vec<OsmElement>,
}

#[derive(Deserialize)]
struct OsmElement {
    /// `node` | `way` | `relation`. Surfaced on each node's evidence + tag so an
    /// area-mapped facility (a substation drawn as a `way`) is distinguishable
    /// from a point (a `node` mast).
    #[serde(default, rename = "type")]
    osm_type: Option<String>,
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    lat: Option<f64>,
    #[serde(default)]
    lon: Option<f64>,
    /// Centroid Overpass emits for `way`/`relation` elements under `out center;`
    /// — those have no own lat/lon. Lets area-mapped infrastructure be located.
    #[serde(default)]
    center: Option<Center>,
    #[serde(default)]
    tags: Option<std::collections::HashMap<String, String>>,
}

#[derive(Deserialize)]
struct Center {
    #[serde(default)]
    lat: Option<f64>,
    #[serde(default)]
    lon: Option<f64>,
}

impl OsmElement {
    /// Located coordinates: a `node`'s own `lat`/`lon`, else a `way`/`relation`
    /// centroid (`center`). `None` when the element carries neither.
    fn coords(&self) -> Option<(f64, f64)> {
        if let (Some(lat), Some(lon)) = (self.lat, self.lon) {
            return Some((lat, lon));
        }
        let c = self.center.as_ref()?;
        Some((c.lat?, c.lon?))
    }
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

    let mut summary = Entity::new(EntityKind::Coordinates, coord, confidence::HIGH_PLUS, scan_id);
    summary.tag("overpass");
    summary.tag("geoint");
    // Attempt to parse the query coordinates for state tagging.
    if let Ok((slat, slon)) = crate::util::geo::parse_coords(coord)
        && let Some(state) = crate::util::geo::au_state_for_coords(slat, slon)
    {
        summary.tag(format!("au-state:{state}"));
        summary.tag("country:AU");
    }
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

    // Category breakdown over EVERY discovered node, not just the emitted subset:
    // the summary's `node_count` reports the true total, so the breakdown must
    // agree with it. Counting inside the `take(MAX_NODES)` loop below would report
    // a distribution over only the first MAX_NODES while `node_count` showed the
    // full total — a self-contradictory aggregate for a dense (>MAX_NODES) query.
    let mut categories: std::collections::BTreeMap<&str, u32> = std::collections::BTreeMap::new();
    for elem in elements {
        if let Some(tags) = &elem.tags {
            *categories.entry(classify_element(tags)).or_default() += 1;
        }
    }

    // Emit one Coordinates entity per LOCATED node, bounded at MAX_NODES to avoid
    // flooding the graph near a dense coordinate. The full node count and the
    // complete category breakdown are already surfaced on the summary above, so
    // this bound loses no aggregate information — only the individual far-node
    // points beyond the cap.
    for elem in elements.iter().take(MAX_NODES) {
        let Some(tags) = &elem.tags else {
            continue;
        };
        let category = classify_element(tags);
        if let Some((nlat, nlon)) = elem.coords()
            && crate::util::geo::is_valid_coords(nlat, nlon)
        {
            let node_coords = format!("{nlat:.6},{nlon:.6}");
            let mut ce = Entity::new(EntityKind::Coordinates, &node_coords, confidence::MEDIUM_HIGH, scan_id);
            ce.tag("overpass");
            ce.tag("geoint");
            ce.tag(format!("infra:{category}"));
            if let Some(ty) = elem.osm_type.as_deref().filter(|s| !s.is_empty()) {
                ce.tag(format!("osm:{ty}"));
            }
            crate::util::geo::tag_au_state(&mut ce, nlat, nlon);
            let mut ev = Evidence::new(SRC, format!("OSM {category} near {coord}"))
                .with_attr("category", category);
            if let Some(ty) = elem.osm_type.as_deref().filter(|s| !s.is_empty()) {
                ev = ev.with_attr("osm_type", ty);
            }
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
        "OpenStreetMap infrastructure probe — enumerates cell towers, substations, and cameras near coordinates"
    }
    fn priority(&self) -> u8 {
        15
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Coordinates)
    }
    fn max_timeout_ms(&self) -> u64 {
        // The query itself is server-documented [timeout:25] (up to 25s of
        // Overpass-side execution). A 429 retry (see `process`) can now
        // mean a second full query execution after a short bounded sleep —
        // budget for two worst-case query executions plus the sleep and
        // headroom, not just one.
        58_000
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

        // `nwr` (node/way/relation) + `out center;` so AREA-mapped infrastructure
        // — substations, police/fire stations are commonly drawn as ways, not
        // points — is found too, each with a centroid. `out body;`/`node` alone
        // silently missed all of it.
        let query = format!(
            r#"[out:json][timeout:25];
(
  nwr["man_made"="mast"](around:500,{lat},{lon});
  nwr["man_made"="tower"]["tower:type"="communication"](around:500,{lat},{lon});
  nwr["man_made"="surveillance"](around:500,{lat},{lon});
  nwr["power"="substation"](around:500,{lat},{lon});
  nwr["amenity"="police"](around:500,{lat},{lon});
  nwr["amenity"="fire_station"](around:500,{lat},{lon});
);
out center;"#
        );

        let mut resp = ctx
            .http
            .post("https://overpass-api.de/api/interpreter")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!("data={}", crate::util::http::urlencode(&query)))
            .send_tagged(SRC)
            .await?;

        // A 429 here used to degrade straight to Ok(empty) — indistinguishable
        // from "nothing found nearby" — with no retry, no backoff, and no
        // circuit-breaker engagement (this module calls send_tagged directly
        // rather than the shared fetch_json_inner/fetch_keyed_json helpers
        // every rate-limit-aware module routes through). Honour a real
        // server Retry-After (kept short — Overpass is a shared public
        // resource and this query is server-documented as expensive, so this
        // retries once, not aggressively) before giving up; a second 429 is
        // now a real, surfaced error instead of a silent empty success.
        if resp.status().as_u16() == 429 {
            let delay = crate::util::http::retry_after_secs(resp.headers(), 2, 4);
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            resp = ctx
                .http
                .post("https://overpass-api.de/api/interpreter")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(format!("data={}", crate::util::http::urlencode(&query)))
                .send_tagged(SRC)
                .await?;
        }

        let status = resp.status();
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
    include!("tests.rs");
}
