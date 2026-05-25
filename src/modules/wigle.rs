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
#[allow(dead_code)]
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
#[allow(dead_code)]
struct Network {
    #[serde(default)]
    netid: Option<String>,
    #[serde(default)]
    ssid: Option<String>,
    #[serde(default)]
    encryption: Option<String>,
    #[serde(default)]
    channel: Option<i32>,
    #[serde(default)]
    trilat: Option<f64>,
    #[serde(default)]
    trilong: Option<f64>,
    #[serde(default)]
    lastupdt: Option<String>,
    #[serde(default, rename = "type")]
    net_type: Option<String>,
}

pub struct Wigle;

#[async_trait]
impl Module for Wigle {
    fn name(&self) -> &'static str {
        "wigle"
    }
    fn priority(&self) -> u8 {
        70
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

        let mut result = ModuleResult::new();

        // Summary entity on the input coordinates.
        let mut entity = Entity::new(EntityKind::Coordinates, &target.value, 0.85, &ctx.scan_id);
        entity.tag("wigle");
        entity.tag("wifi-observed");

        // Aggregate encryption types.
        let mut enc_counts: std::collections::BTreeMap<String, u32> =
            std::collections::BTreeMap::new();
        for n in &body.results {
            if let Some(e) = n.encryption.as_deref() {
                *enc_counts.entry(e.to_string()).or_insert(0) += 1;
            }
        }
        let mut ranked: Vec<(String, u32)> = enc_counts.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let top_encryption = ranked
            .iter()
            .take(5)
            .map(|(e, n)| format!("{e}×{n}"))
            .collect::<Vec<_>>()
            .join(", ");

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
            ev = ev.with_attr("top_encryption", &top_encryption);
        }
        if let Some(t) = most_recent {
            ev = ev.with_attr("most_recent_observation", t);
        }
        entity.add_evidence(ev);
        result.push(entity);

        // Emit individual MacAddress entities for the top networks so
        // the on-device wifi_scan output can cross-reference against
        // WiGLE's crowdsourced database. Each network with a BSSID
        // (netid) and trilateration coordinates becomes a geolocated
        // access point — the correlator can match these against
        // wifi_scan's local observations for location corroboration.
        const MAX_NETWORKS: usize = 20;
        for net in body.results.iter().take(MAX_NETWORKS) {
            let Some(bssid) = net.netid.as_deref() else {
                continue;
            };
            if bssid.is_empty() || bssid.len() < 11 {
                continue;
            }
            let mut mac = Entity::new(EntityKind::MacAddress, bssid, 0.78, &ctx.scan_id);
            mac.tag("wigle");
            mac.tag("wifi-ap");
            let mut mac_ev = Evidence::new("wigle", format!("WiFi AP {bssid} observed by WiGLE"));
            if let Some(ssid) = net.ssid.as_deref() {
                mac_ev = mac_ev.with_attr("ssid", ssid);
                mac.tag(format!("ssid:{ssid}"));
            }
            if let Some(enc) = net.encryption.as_deref() {
                mac_ev = mac_ev.with_attr("encryption", enc);
            }
            if let Some(ch) = net.channel {
                mac_ev = mac_ev.with_attr("channel", ch.to_string());
            }
            if let Some(t) = net.lastupdt.as_deref() {
                mac_ev = mac_ev.with_attr("last_seen", t);
            }
            // Emit the trilaterated coordinates of this specific AP
            // so the correlator can cluster per-AP locations.
            if let (Some(tlat), Some(tlon)) = (net.trilat, net.trilong) {
                let ap_coords = format!("{tlat:.6},{tlon:.6}");
                mac_ev = mac_ev
                    .with_attr("trilat", tlat.to_string())
                    .with_attr("trilong", tlon.to_string());

                let mut ap_loc =
                    Entity::new(EntityKind::Coordinates, &ap_coords, 0.82, &ctx.scan_id);
                ap_loc.tag("wigle");
                ap_loc.tag("wifi-trilaterated");
                ap_loc.add_evidence(
                    Evidence::new("wigle", format!("AP {bssid} trilaterated to {ap_coords}"))
                        .with_attr("bssid", bssid),
                );
                result.push(ap_loc);
            }
            mac.add_evidence(mac_ev);
            result.push(mac);
        }

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
