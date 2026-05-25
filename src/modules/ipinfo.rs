//! ipinfo.io — IP geolocation + ASN + company enrichment. Free tier
//! allows 50k lookups/month without a key; keyed access removes limits.
//!
//! Endpoint: `GET https://ipinfo.io/{ip}/json`
//! Auth:     optional `Authorization: Bearer {HUNTSMAN_IPINFO_KEY}`.
//!
//! Complements the existing `ip_geo` module (ip-api.com) with richer
//! data: company name, privacy flags (VPN/proxy/Tor/relay), ASN, and
//! a hostname field. Fills the SpiderFoot `sfp_ipinfo` gap.

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
    hostname: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    loc: Option<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    postal: Option<String>,
    #[serde(default)]
    timezone: Option<String>,
    #[serde(default)]
    bogon: Option<bool>,
    #[serde(default)]
    privacy: Option<Privacy>,
    #[serde(default)]
    company: Option<Company>,
}

#[derive(Deserialize)]
struct Privacy {
    #[serde(default)]
    vpn: Option<bool>,
    #[serde(default)]
    proxy: Option<bool>,
    #[serde(default)]
    tor: Option<bool>,
    #[serde(default)]
    relay: Option<bool>,
    #[serde(default)]
    hosting: Option<bool>,
}

#[derive(Deserialize)]
struct Company {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "type")]
    company_type: Option<String>,
}

pub struct IpInfo;

#[async_trait]
impl Module for IpInfo {
    fn name(&self) -> &'static str {
        "ipinfo"
    }
    fn priority(&self) -> u8 {
        88
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

        let url = format!("https://ipinfo.io/{ip}/json");
        let mut req = ctx.http.get(&url).header("Accept", "application/json");
        if let Some(key) = ctx.key_opt("HUNTSMAN_IPINFO_KEY") {
            req = req.bearer_auth(key);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| Error::module("ipinfo", e.to_string()))?;

        let status = resp.status();
        if status.as_u16() == 429 {
            return Err(Error::module("ipinfo", "rate limited"));
        }
        if !status.is_success() {
            return Err(Error::module(
                "ipinfo",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let body: Resp = resp
            .json()
            .await
            .map_err(|e| Error::module("ipinfo", e.to_string()))?;

        if body.bogon == Some(true) {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();

        let mut entity = Entity::new(EntityKind::IpAddress, ip, 0.88, &ctx.scan_id);
        entity.tag("ipinfo");

        if let Some(c) = body.country.as_deref() {
            entity.tag(format!("country:{}", c.to_uppercase()));
        }

        if let Some(priv_data) = &body.privacy {
            if priv_data.vpn == Some(true) {
                entity.tag("vpn");
            }
            if priv_data.proxy == Some(true) {
                entity.tag("proxy");
            }
            if priv_data.tor == Some(true) {
                entity.tag("tor");
            }
            if priv_data.relay == Some(true) {
                entity.tag("relay");
            }
            if priv_data.hosting == Some(true) {
                entity.tag("hosting");
            }
        }

        let mut ev = Evidence::new("ipinfo", format!("ipinfo.io enrichment for {ip}"));
        if let Some(v) = body.hostname.as_deref() {
            ev = ev.with_attr("hostname", v);
        }
        if let Some(v) = body.city.as_deref() {
            ev = ev.with_attr("city", v);
        }
        if let Some(v) = body.region.as_deref() {
            ev = ev.with_attr("region", v);
        }
        if let Some(v) = body.country.as_deref() {
            ev = ev.with_attr("country", v);
        }
        if let Some(v) = body.org.as_deref() {
            ev = ev.with_attr("org", v);
        }
        if let Some(v) = body.postal.as_deref() {
            ev = ev.with_attr("postal", v);
        }
        if let Some(v) = body.timezone.as_deref() {
            ev = ev.with_attr("timezone", v);
        }
        if let Some(c) = &body.company {
            if let Some(n) = c.name.as_deref() {
                ev = ev.with_attr("company", n);
            }
            if let Some(t) = c.company_type.as_deref() {
                ev = ev.with_attr("company_type", t);
            }
        }
        entity.add_evidence(ev);
        result.push(entity);

        // Emit Coordinates entity if loc is present.
        if let Some(loc) = body.loc.as_deref()
            && loc.contains(',')
        {
            let mut coords = Entity::new(EntityKind::Coordinates, loc, 0.72, &ctx.scan_id);
            coords.tag("geoint");
            coords.tag("ipinfo");
            coords.add_evidence(
                Evidence::new("ipinfo", format!("IP {ip} geolocated to {loc}"))
                    .with_attr("ip", ip)
                    .with_attr("source", "ipinfo.io"),
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
    fn accepts_ip_only() {
        let m = IpInfo;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }
}
