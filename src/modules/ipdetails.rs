//! IPDetails.io — free IP geolocation + threat intelligence.
//! No API key, no rate limits, no signup. Sub-10ms response times.
//!
//! Endpoint: `GET https://ipdetails.io/ip/{ip}`
//!
//! Returns country, city, region, lat/lon, ASN, ISP, WHOIS org,
//! and threat flags (is_tor, is_proxy, is_datacenter, is_vpn).
//! Sixth independent IP geolocation source — feeds the AU-014
//! multi-source geo-cluster correlator rule.

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
    country: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    asn: Option<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    is_tor: Option<bool>,
    #[serde(default)]
    is_proxy: Option<bool>,
    #[serde(default)]
    is_datacenter: Option<bool>,
    #[serde(default)]
    is_vpn: Option<bool>,
}

pub struct IpDetails;

#[async_trait]
impl Module for IpDetails {
    fn name(&self) -> &'static str {
        "ipdetails"
    }
    fn priority(&self) -> u8 {
        80
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }
    fn max_timeout_ms(&self) -> u64 {
        6_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(ip) = target.trimmed() else {
            return Ok(ModuleResult::new());
        };

        let url = format!("https://ipdetails.io/ip/{ip}");
        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module("ipdetails", e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Error::module(
                "ipdetails",
                format!("HTTP {}: {}", resp.status(), error_snippet(resp).await),
            ));
        }

        let body: Resp = resp
            .json()
            .await
            .map_err(|e| Error::module("ipdetails", e.to_string()))?;

        let mut result = ModuleResult::new();
        let mut entity = Entity::new(EntityKind::IpAddress, ip, 0.82, &ctx.scan_id);
        entity.tag("ipdetails");

        if let Some(cc) = body.country_code.as_deref() {
            entity.tag_country(cc);
        }
        if body.is_tor == Some(true) {
            entity.tag("tor");
        }
        if body.is_proxy == Some(true) {
            entity.tag("proxy");
        }
        if body.is_vpn == Some(true) {
            entity.tag("vpn");
        }
        if body.is_datacenter == Some(true) {
            entity.tag("datacenter");
        }

        let ev = Evidence::new("ipdetails", format!("ipdetails.io for {ip}"))
            .opt_attr("country", body.country.as_deref())
            .opt_attr("region", body.region.as_deref())
            .opt_attr("city", body.city.as_deref())
            .opt_attr("asn", body.asn.as_deref())
            .opt_attr("org", body.org.as_deref())
            .opt_attr("isp", body.isp.as_deref());
        entity.add_evidence(ev);
        result.push(entity);

        if let (Some(lat), Some(lon)) = (body.latitude, body.longitude)
            && (lat.abs() > 0.001 || lon.abs() > 0.001)
        {
            let cv = format!("{lat},{lon}");
            let mut coords = Entity::new(EntityKind::Coordinates, &cv, 0.76, &ctx.scan_id);
            coords.tag("geoint");
            coords.tag("ipdetails");
            coords.add_evidence(
                Evidence::new("ipdetails", format!("IP {ip} → {cv}"))
                    .with_attr("ip", ip)
                    .with_attr("source", "ipdetails.io"),
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
        assert!(IpDetails.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!IpDetails.accepts(&Target::new(TargetKind::Domain, "x")));
    }
}
