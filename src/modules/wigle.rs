//! WiGLE WiFi network search by geographic point. Key-gated.
//!
//! Endpoint: `GET https://api.wigle.net/api/v2/network/search`
//! Auth:     HTTP Basic — `HUNTSMAN_WIGLE_USER` (API name) + `HUNTSMAN_WIGLE_TOKEN`.
//!
//! Accepts a `Coordinates` target (`"lat,lon"`). WiGLE wants a bounding
//! box; we expand the point to ±0.001° (~111 m at the equator) — large
//! enough to catch the immediate neighbourhood, small enough not to
//! burn the lookup quota on a noisy match.
//!
//! Per project invariants, we never store the raw observation list
//! (which can include personal MAC addresses observed in scans). We
//! summarise: total networks found + the top encryption types + the
//! highest-quality (lowest-trilateration-error) SSID, if any.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

const USER_ENV: &str = "HUNTSMAN_WIGLE_USER";
const TOKEN_ENV: &str = "HUNTSMAN_WIGLE_TOKEN";

#[derive(Deserialize)]
struct Resp {
    #[serde(default)]
    success: Option<bool>,
    #[serde(default, rename = "resultCount")]
    result_count: Option<u64>,
    #[serde(default, rename = "totalResults")]
    total_results: Option<u64>,
    #[serde(default)]
    results: Vec<Network>,
}

#[derive(Deserialize)]
struct Network {
    #[serde(default)]
    encryption: Option<String>,
    #[serde(default)]
    lastupdt: Option<String>,
}

pub struct Wigle;

#[async_trait]
impl Module for Wigle {
    fn name(&self) -> &'static str {
        "wigle"
    }
    fn description(&self) -> &'static str {
        "WiGLE wireless network geolocation database"
    }
    fn priority(&self) -> u8 {
        70
    }

    fn description(&self) -> &'static str {
        "WiGLE geographic WiFi-network search by GPS coordinates. Key-gated; aggregate counts + encryption types only."
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Coordinates)
    }
    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let user = ctx.key(USER_ENV)?;
        let token = ctx.key(TOKEN_ENV)?;

        let (lat, lon) = match target.value.split_once(',') {
            Some((a, b)) => {
                let lat: f64 = a.trim().parse().map_err(|_| {
                    Error::module("wigle", "coordinates lat is not a number".to_string())
                })?;
                let lon: f64 = b.trim().parse().map_err(|_| {
                    Error::module("wigle", "coordinates lon is not a number".to_string())
                })?;
                (lat, lon)
            }
            None => {
                return Err(Error::module(
                    "wigle",
                    "coordinates target must be 'lat,lon'".to_string(),
                ));
            }
        };
        // Small bounding box around the requested point.
        const D: f64 = 0.001;
        let url = format!(
            "https://api.wigle.net/api/v2/network/search?latrange1={lat_lo:.6}&latrange2={lat_hi:.6}&longrange1={lon_lo:.6}&longrange2={lon_hi:.6}&onlymine=false",
            lat_lo = lat - D,
            lat_hi = lat + D,
            lon_lo = lon - D,
            lon_hi = lon + D,
        );

        let resp = ctx
            .http
            .get(&url)
            .basic_auth(user, Some(token))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module("wigle", e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Error::module(
                "wigle",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }
        let body: Resp = resp
            .json()
            .await
            .map_err(|e| Error::module("wigle", e.to_string()))?;

        if body.success != Some(true) {
            return Ok(ModuleResult::new());
        }
        let total = body
            .total_results
            .or(body.result_count)
            .unwrap_or(body.results.len() as u64);
        if total == 0 {
            return Ok(ModuleResult::new());
        }

        let mut entity = Entity::new(EntityKind::Coordinates, &target.value, 0.85, &ctx.scan_id);
        entity.tag("wigle");
        entity.tag("wifi-observed");

        // Aggregate encryption types.
        let enc_types: Vec<String> = body
            .results
            .iter()
            .filter_map(|n| n.encryption.clone())
            .collect();
        let top_encryption = crate::util::freq::top_n(enc_types.iter().map(String::as_str), 5);

        let most_recent = body
            .results
            .iter()
            .filter_map(|n| n.lastupdt.as_deref())
            .max();

        let mut ev = Evidence::new(
            "wigle",
            format!(
                "WiGLE: {total} WiFi network(s) within ±{D}° of {}",
                target.value
            ),
        )
        .with_attr("total", total.to_string())
        .with_attr("returned", body.results.len().to_string())
        .with_attr("bbox_half_size_deg", D.to_string());
        if !top_encryption.is_empty() {
            ev = ev.with_attr("top_encryption", top_encryption);
        }
        if let Some(t) = most_recent {
            ev = ev.with_attr("most_recent_observation", t);
        }
        entity.add_evidence(ev);
        let mut result = ModuleResult::new();
        result.push(entity);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_only_coordinates() {
        let m = Wigle;
        assert!(m.accepts(&Target::new(TargetKind::Coordinates, "0,0")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
    }
    #[test]
    fn cost_is_key_gated() {
        assert!(matches!(Wigle.cost(), ModuleCost::KeyGated));
    }
}
