//! WiGLE BSSID geolocation — resolve a WiFi MAC address to coordinates.
//!
//! Endpoint: `GET https://api.wigle.net/api/v2/network/search?netid={bssid}`
//! Auth:     HTTP Basic — `HUNTSMAN_WIGLE_USER` + `HUNTSMAN_WIGLE_TOKEN`.
//!
//! Accepts a `MacAddress` target (BSSID from wifi_scan or wigle nearby
//! search). Resolves the access point to its trilaterated coordinates
//! so on-device WiFi observations produce precise geolocation:
//!
//!   wifi_scan → MacAddress → wigle_bssid → Coordinates → nominatim
//!
//! This is the key link for Termux GEOINT: the phone sees nearby APs
//! via `termux-wifi-scaninfo`, and WiGLE's crowdsourced database turns
//! those BSSIDs into lat/lng.

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
    #[serde(default, rename = "totalResults")]
    total_results: Option<u64>,
    #[serde(default)]
    results: Vec<Network>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct Network {
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
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region: Option<String>,
}

pub struct WigleBssid;

#[async_trait]
impl Module for WigleBssid {
    fn name(&self) -> &'static str {
        "wigle_bssid"
    }
    fn priority(&self) -> u8 {
        72
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::MacAddress)
    }
    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let user = ctx.key(USER_ENV)?;
        let token = ctx.key(TOKEN_ENV)?;

        let Some(bssid) = target.trimmed() else {
            return Ok(ModuleResult::new());
        };
        if bssid.len() < 11 {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://api.wigle.net/api/v2/network/search?netid={}",
            crate::util::http::urlencode(bssid)
        );
        let resp = ctx
            .http
            .get(&url)
            .basic_auth(user, Some(token))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module("wigle_bssid", e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::module(
                "wigle_bssid",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let body: Resp = resp
            .json()
            .await
            .map_err(|e| Error::module("wigle_bssid", e.to_string()))?;

        if body.success != Some(true) || body.results.is_empty() {
            return Ok(ModuleResult::new());
        }

        let net = &body.results[0];
        let (Some(lat), Some(lon)) = (net.trilat, net.trilong) else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();

        let coord_value = format!("{lat:.6},{lon:.6}");
        let mut coords = Entity::new(EntityKind::Coordinates, &coord_value, 0.88, &ctx.scan_id);
        coords.tag("geoint");
        coords.tag("wigle");
        coords.tag("wifi-trilaterated");
        coords.tag("bssid-located");

        let mut ev = Evidence::new(
            "wigle_bssid",
            format!("BSSID {bssid} geolocated to {coord_value} via WiGLE"),
        )
        .with_attr("bssid", bssid)
        .with_attr("lat", lat.to_string())
        .with_attr("lon", lon.to_string());

        if let Some(ssid) = net.ssid.as_deref() {
            ev = ev.with_attr("ssid", ssid);
        }
        if let Some(enc) = net.encryption.as_deref() {
            ev = ev.with_attr("encryption", enc);
        }
        if let Some(ch) = net.channel {
            ev = ev.with_attr("channel", ch.to_string());
        }
        if let Some(c) = net.country.as_deref() {
            ev = ev.with_attr("country", c);
            coords.tag_country(c);
        }
        if let Some(c) = net.city.as_deref() {
            ev = ev.with_attr("city", c);
        }
        if let Some(r) = net.region.as_deref() {
            ev = ev.with_attr("region", r);
        }
        if let Some(t) = net.lastupdt.as_deref() {
            ev = ev.with_attr("last_seen", t);
        }

        coords.add_evidence(ev);
        result.push(coords);

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_mac_address() {
        assert!(WigleBssid.accepts(&Target::new(TargetKind::MacAddress, "aa:bb:cc:dd:ee:ff")));
        assert!(!WigleBssid.accepts(&Target::new(TargetKind::Coordinates, "0,0")));
    }
    #[test]
    fn cost_is_key_gated() {
        assert!(matches!(WigleBssid.cost(), ModuleCost::KeyGated));
    }
}
