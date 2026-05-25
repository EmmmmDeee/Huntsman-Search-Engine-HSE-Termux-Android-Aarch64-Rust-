//! ip2location.io — alternative IP geolocation with threat intelligence.
//! Free tier: 30k lookups/month with API key, 500/day without.
//!
//! Endpoint: `GET https://api.ip2location.io/?ip={ip}&key={key}&format=json`
//! Auth:     optional query-string `key={HUNTSMAN_IP2LOCATION_KEY}`.
//!
//! Returns city, region, country, lat/lon, zip, timezone, ISP, domain,
//! AS number, usage type, and threat indicators (is_proxy, is_vpn,
//! is_tor, is_datacenter). Complements ip_geo and ipinfo with a third
//! independent geolocation source for the AU-014 multi-source cluster.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

#[derive(Deserialize)]
#[allow(dead_code)]
struct Resp {
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    country_name: Option<String>,
    #[serde(default)]
    region_name: Option<String>,
    #[serde(default)]
    city_name: Option<String>,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    zip_code: Option<String>,
    #[serde(default)]
    time_zone: Option<String>,
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default, rename = "as")]
    as_number: Option<String>,
    #[serde(default)]
    as_name: Option<String>,
    #[serde(default)]
    is_proxy: Option<bool>,
    #[serde(default)]
    proxy_type: Option<String>,
    #[serde(default)]
    usage_type: Option<String>,
}

pub struct Ip2Location;

#[async_trait]
impl Module for Ip2Location {
    fn name(&self) -> &'static str {
        "ip2location"
    }
    fn priority(&self) -> u8 {
        84
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let ip = target.value.trim();
        if ip.is_empty() {
            return Ok(ModuleResult::new());
        }

        let key_param = ctx
            .key_opt("HUNTSMAN_IP2LOCATION_KEY")
            .map(|k| format!("&key={k}"))
            .unwrap_or_default();
        let url = format!("https://api.ip2location.io/?ip={ip}&format=json{key_param}");

        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module("ip2location", e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::module(
                "ip2location",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let body: Resp = resp
            .json()
            .await
            .map_err(|e| Error::module("ip2location", e.to_string()))?;

        let mut result = ModuleResult::new();

        let mut entity = Entity::new(EntityKind::IpAddress, ip, 0.84, &ctx.scan_id);
        entity.tag("ip2location");

        if let Some(cc) = body.country_code.as_deref() {
            entity.tag(format!("country:{}", cc.to_uppercase()));
        }
        if body.is_proxy == Some(true) {
            entity.tag("proxy");
            if let Some(pt) = body.proxy_type.as_deref() {
                match pt {
                    "VPN" => entity.tag("vpn"),
                    "TOR" => entity.tag("tor"),
                    "DCH" => entity.tag("datacenter"),
                    _ => {}
                }
            }
        }

        let mut ev = Evidence::new(
            "ip2location",
            format!("ip2location.io geolocation for {ip}"),
        );
        if let Some(v) = body.country_name.as_deref() {
            ev = ev.with_attr("country", v);
        }
        if let Some(v) = body.region_name.as_deref() {
            ev = ev.with_attr("region", v);
        }
        if let Some(v) = body.city_name.as_deref() {
            ev = ev.with_attr("city", v);
        }
        if let Some(v) = body.isp.as_deref() {
            ev = ev.with_attr("isp", v);
        }
        if let Some(v) = body.as_name.as_deref() {
            ev = ev.with_attr("as_name", v);
        }
        if let Some(v) = body.usage_type.as_deref() {
            ev = ev.with_attr("usage_type", v);
        }
        if let Some(v) = body.time_zone.as_deref() {
            ev = ev.with_attr("timezone", v);
        }
        entity.add_evidence(ev);
        result.push(entity);

        if let (Some(lat), Some(lon)) = (body.latitude, body.longitude)
            && (lat.abs() > 0.001 || lon.abs() > 0.001)
        {
            let coord_value = format!("{lat},{lon}");
            let mut coords = Entity::new(EntityKind::Coordinates, &coord_value, 0.70, &ctx.scan_id);
            coords.tag("geoint");
            coords.tag("ip2location");
            coords.add_evidence(
                Evidence::new(
                    "ip2location",
                    format!("IP {ip} geolocated to {coord_value}"),
                )
                .with_attr("ip", ip)
                .with_attr("source", "ip2location.io"),
            );
            result.push(coords);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_ip() {
        assert!(Ip2Location.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
        assert!(!Ip2Location.accepts(&Target::new(TargetKind::Domain, "x")));
    }
}
