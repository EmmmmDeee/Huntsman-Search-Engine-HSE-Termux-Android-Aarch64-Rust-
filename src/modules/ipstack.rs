//! ipstack — IP geolocation with security flags. Free tier: 100 req/mo.
//!
//! Endpoint: `GET https://api.ipstack.com/{ip}?access_key={key}`
//! Auth:     query-string `access_key={HUNTSMAN_IPSTACK_KEY}`.
//!
//! Fourth independent IP geolocation source (complements ip_geo, ipinfo,
//! ip2location). Returns city/region/country/lat/lon + security module
//! with proxy/crawler/tor flags. The AU-014 geo-cluster correlator rule
//! fires when 2+ independent sources agree on coordinates.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

const KEY_ENV: &str = "HUNTSMAN_IPSTACK_KEY";

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
    city: Option<String>,
    #[serde(default)]
    zip: Option<String>,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    security: Option<Security>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct Security {
    #[serde(default)]
    is_proxy: Option<bool>,
    #[serde(default)]
    is_crawler: Option<bool>,
    #[serde(default)]
    is_tor: Option<bool>,
    #[serde(default)]
    threat_level: Option<String>,
}

pub struct IpStack;

#[async_trait]
impl Module for IpStack {
    fn name(&self) -> &'static str {
        "ipstack"
    }
    fn priority(&self) -> u8 {
        82
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = ctx.key(KEY_ENV)?;
        let Some(ip) = target.trimmed() else {
            return Ok(ModuleResult::new());
        };

        let url = format!("https://api.ipstack.com/{ip}?access_key={key}");
        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module("ipstack", e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Error::module(
                "ipstack",
                format!("HTTP {}: {}", resp.status(), error_snippet(resp).await),
            ));
        }

        let body: Resp = resp
            .json()
            .await
            .map_err(|e| Error::module("ipstack", e.to_string()))?;

        let mut result = ModuleResult::new();
        let mut entity = Entity::new(EntityKind::IpAddress, ip, 0.83, &ctx.scan_id);
        entity.tag("ipstack");

        if let Some(cc) = body.country_code.as_deref() {
            entity.tag_country(cc);
        }
        if let Some(sec) = &body.security {
            if sec.is_proxy == Some(true) {
                entity.tag("proxy");
            }
            if sec.is_crawler == Some(true) {
                entity.tag("crawler");
            }
            if sec.is_tor == Some(true) {
                entity.tag("tor");
            }
            if let Some(tl) = sec.threat_level.as_deref()
                && tl == "high"
            {
                entity.tag("high-risk");
            }
        }

        let ev = Evidence::new("ipstack", format!("ipstack geolocation for {ip}"))
            .opt_attr("country", body.country_name.as_deref())
            .opt_attr("region", body.region_name.as_deref())
            .opt_attr("city", body.city.as_deref())
            .opt_attr("zip", body.zip.as_deref());
        entity.add_evidence(ev);
        result.push(entity);

        if let (Some(lat), Some(lon)) = (body.latitude, body.longitude)
            && (lat.abs() > 0.001 || lon.abs() > 0.001)
        {
            let cv = format!("{lat},{lon}");
            let mut coords = Entity::new(EntityKind::Coordinates, &cv, 0.76, &ctx.scan_id);
            coords.tag("geoint");
            coords.tag("ipstack");
            coords.add_evidence(
                Evidence::new("ipstack", format!("IP {ip} geolocated to {cv}"))
                    .with_attr("ip", ip)
                    .with_attr("source", "ipstack"),
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
        assert!(IpStack.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!IpStack.accepts(&Target::new(TargetKind::Domain, "x")));
    }
    #[test]
    fn cost_key_gated() {
        assert!(matches!(IpStack.cost(), ModuleCost::KeyGated));
    }
}
