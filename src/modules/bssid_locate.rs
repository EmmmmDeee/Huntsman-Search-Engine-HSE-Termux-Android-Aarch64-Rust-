//! WiFi BSSID geolocation — resolves nearby access-point BSSIDs to GPS
//! coordinates via the WiGLE network detail API.
//!
//! Passive module that runs `termux-wifi-scaninfo`, selects the strongest
//! BSSIDs by signal (top 5 to conserve API quota), and queries WiGLE's
//! `network/detail` endpoint for each. Produces Coordinates entities with
//! per-AP accuracy — typically 10–50m in urban areas.
//!
//! Complements `wifi_scan` (which only records MACs) and `wigle` (which
//! searches by bounding box around known coordinates). This module works
//! in the opposite direction: BSSID → coordinates, enabling geolocation
//! when no prior coordinate fix exists.
//!
//! Auth: HTTP Basic — same `HUNTSMAN_WIGLE_USER` / `HUNTSMAN_WIGLE_TOKEN`
//! as the `wigle` module (with hardcoded fallback).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::Target,
};
use crate::util::http::error_snippet;
use crate::util::termux::termux_cmd;

const USER_ENV: &str = "HUNTSMAN_WIGLE_USER";
const TOKEN_ENV: &str = "HUNTSMAN_WIGLE_TOKEN";
const HARDCODED_USER: &str = "AID4493a33e2df9d07ab9666a27c8aead17";
const HARDCODED_TOKEN: &str = "1aedb7ad0171ff3d6be5a844cca5d977";

const MAX_BSSIDS: usize = 5;

#[derive(Deserialize)]
struct Ap {
    bssid: String,
    ssid: Option<String>,
    rssi: Option<i64>,
}

#[derive(Deserialize)]
struct DetailResp {
    #[serde(default)]
    success: Option<bool>,
    #[serde(default)]
    results: Vec<DetailNetwork>,
}

#[derive(Deserialize)]
struct DetailNetwork {
    #[serde(default)]
    trilat: Option<f64>,
    #[serde(default)]
    trilong: Option<f64>,
    #[serde(default)]
    ssid: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    postalcode: Option<String>,
    #[serde(default)]
    lastupdt: Option<String>,
    #[serde(default)]
    encryption: Option<String>,
}

pub struct BssidLocate;

#[async_trait]
impl Module for BssidLocate {
    fn name(&self) -> &'static str {
        "bssid_locate"
    }

    fn description(&self) -> &'static str {
        "WiFi BSSID to GPS coordinates via WiGLE network detail API"
    }

    fn priority(&self) -> u8 {
        63
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, _t: &Target) -> bool {
        true
    }

    fn max_timeout_ms(&self) -> u64 {
        20_000
    }

    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let user = ctx.key_opt(USER_ENV).unwrap_or(HARDCODED_USER);
        let token = ctx.key_opt(TOKEN_ENV).unwrap_or(HARDCODED_TOKEN);

        let Some(stdout) = termux_cmd("termux-wifi-scaninfo", &[], 5000).await else {
            return Ok(ModuleResult::new());
        };

        let mut aps: Vec<Ap> = match serde_json::from_slice(&stdout) {
            Ok(v) => v,
            Err(_) => return Ok(ModuleResult::new()),
        };

        if aps.is_empty() {
            return Ok(ModuleResult::new());
        }

        // Sort by signal strength (strongest first) and take top N
        aps.sort_by_key(|a| std::cmp::Reverse(a.rssi.unwrap_or(-100)));
        aps.truncate(MAX_BSSIDS);

        let mut result = ModuleResult::new();

        for ap in &aps {
            if ctx.cancel.is_cancelled() {
                break;
            }

            if ap.bssid.len() < 12 {
                continue;
            }

            if let Ok(Some(detail)) = query_wigle_detail(&ctx.http, user, token, &ap.bssid).await {
                if let (Some(lat), Some(lon)) = (detail.trilat, detail.trilong) {
                    if lat == 0.0 && lon == 0.0 {
                        continue;
                    }

                    let coords = format!("{lat:.6},{lon:.6}");
                    let ssid = detail
                        .ssid
                        .as_deref()
                        .or(ap.ssid.as_deref())
                        .unwrap_or("<hidden>");

                    let mut e =
                        Entity::new(EntityKind::Coordinates, &coords, 0.80, &ctx.scan_id);
                    e.tag("geoint");
                    e.tag("wifi-ap");
                    e.tag("bssid-located");

                    let mut ev = Evidence::new(
                        "bssid_locate",
                        format!("BSSID {} ({ssid}) → {coords}", ap.bssid),
                    )
                    .with_attr("bssid", &ap.bssid)
                    .with_attr("ssid", ssid)
                    .with_attr("latitude", lat.to_string())
                    .with_attr("longitude", lon.to_string())
                    .with_attr("source", "WiGLE");

                    if let Some(rssi) = ap.rssi {
                        ev = ev.with_attr("rssi_dbm", rssi.to_string());
                    }
                    if let Some(c) = detail.city.as_deref() {
                        ev = ev.with_attr("city", c);
                    }
                    if let Some(r) = detail.region.as_deref() {
                        ev = ev.with_attr("region", r);
                    }
                    if let Some(c) = detail.country.as_deref() {
                        ev = ev.with_attr("country", c);
                    }
                    if let Some(p) = detail.postalcode.as_deref() {
                        ev = ev.with_attr("postcode", p);
                    }
                    if let Some(t) = detail.lastupdt.as_deref() {
                        ev = ev.with_attr("last_updated", t);
                    }
                    if let Some(enc) = detail.encryption.as_deref() {
                        ev = ev.with_attr("encryption", enc);
                    }

                    e.add_evidence(ev);
                    result.push(e);

                    // Also emit an Address entity if we have city + country
                    let addr_parts: Vec<&str> = [
                        detail.city.as_deref(),
                        detail.region.as_deref(),
                        detail.country.as_deref(),
                    ]
                    .iter()
                    .filter_map(|p| *p)
                    .filter(|p| !p.is_empty())
                    .collect();

                    if addr_parts.len() >= 2 {
                        let mut addr_str = addr_parts.join(", ");
                        if let Some(p) = detail.postalcode.as_deref() {
                            if !p.is_empty() {
                                addr_str = format!("{addr_str} {p}");
                            }
                        }
                        let mut addr =
                            Entity::new(EntityKind::Address, &addr_str, 0.60, &ctx.scan_id);
                        addr.tag("geoint");
                        addr.tag("bssid-derived");
                        addr.add_evidence(
                            Evidence::new(
                                "bssid_locate",
                                format!("Address from BSSID {} location", ap.bssid),
                            )
                            .with_attr("bssid", &ap.bssid),
                        );
                        result.push(addr);
                    }
                }
            }
        }

        Ok(result)
    }
}

async fn query_wigle_detail(
    http: &reqwest::Client,
    user: &str,
    token: &str,
    bssid: &str,
) -> Result<Option<DetailNetwork>> {
    let encoded = crate::util::http::urlencode(bssid);
    let url = format!(
        "https://api.wigle.net/api/v2/network/detail?netid={encoded}&type=wifi"
    );

    let resp = http
        .get(&url)
        .basic_auth(user, Some(token))
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| Error::module("bssid_locate", e.to_string()))?;

    let status = resp.status();
    if status.as_u16() == 404 {
        return Ok(None);
    }
    if status.as_u16() == 401 || status.as_u16() == 403 {
        return Err(Error::module(
            "bssid_locate",
            format!("WiGLE auth failed (HTTP {status}): check HUNTSMAN_WIGLE_USER/TOKEN"),
        ));
    }
    if !status.is_success() {
        return Err(Error::module(
            "bssid_locate",
            format!("WiGLE HTTP {status}: {}", error_snippet(resp).await),
        ));
    }

    let body: DetailResp = resp
        .json()
        .await
        .map_err(|e| Error::module("bssid_locate", e.to_string()))?;

    if body.success != Some(true) {
        return Ok(None);
    }

    Ok(body.results.into_iter().next())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    #[test]
    fn is_passive() {
        assert!(BssidLocate.is_passive());
    }

    #[test]
    fn accepts_any_target() {
        assert!(BssidLocate.accepts(&Target::new(TargetKind::Domain, "x")));
    }

    #[test]
    fn cost_is_key_gated() {
        assert!(matches!(BssidLocate.cost(), ModuleCost::KeyGated));
    }

    #[test]
    fn module_name_and_priority() {
        assert_eq!(BssidLocate.name(), "bssid_locate");
        assert_eq!(BssidLocate.priority(), 63);
    }

    #[test]
    fn detail_resp_deserializes() {
        let json = r#"{
            "success": true,
            "results": [{
                "trilat": -27.4766,
                "trilong": 153.0166,
                "ssid": "TestNet",
                "city": "Brisbane",
                "region": "Queensland",
                "country": "AU",
                "postalcode": "4000",
                "lastupdt": "2024-12-01",
                "encryption": "wpa2"
            }]
        }"#;
        let r: DetailResp = serde_json::from_str(json).unwrap();
        assert_eq!(r.success, Some(true));
        assert_eq!(r.results.len(), 1);
        let net = &r.results[0];
        assert!((net.trilat.unwrap() - (-27.4766)).abs() < 0.001);
        assert_eq!(net.city.as_deref(), Some("Brisbane"));
    }

    #[test]
    fn detail_resp_handles_empty() {
        let json = r#"{"success": true, "results": []}"#;
        let r: DetailResp = serde_json::from_str(json).unwrap();
        assert!(r.results.is_empty());
    }

    #[test]
    fn detail_resp_handles_failure() {
        let json = r#"{"success": false}"#;
        let r: DetailResp = serde_json::from_str(json).unwrap();
        assert_eq!(r.success, Some(false));
    }
}
