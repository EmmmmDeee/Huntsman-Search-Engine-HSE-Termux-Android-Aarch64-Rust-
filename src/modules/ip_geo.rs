//! ip-api.com IP geolocation. Free tier (HTTP only), 45 req/min limit.
//!
//! Yields a Coordinates entity (when lat/lon present) and an Organisation
//! entity (when org/ASN present).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json;

const SRC: &str = "ip_geo";

pub struct IpGeo;

#[derive(Deserialize)]
struct IpApiResp {
    status: String,
    country: Option<String>,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    #[serde(rename = "regionName")]
    region_name: Option<String>,
    city: Option<String>,
    zip: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    timezone: Option<String>,
    isp: Option<String>,
    org: Option<String>,
    #[serde(rename = "as")]
    asn: Option<String>,
    #[serde(default)]
    mobile: Option<bool>,
    #[serde(default)]
    proxy: Option<bool>,
    #[serde(default)]
    hosting: Option<bool>,
}

#[async_trait]
impl Module for IpGeo {
    fn name(&self) -> &'static str {
        "ip_geo"
    }

    fn description(&self) -> &'static str {
        "IP geolocation, ISP, proxy and hosting detection"
    }

    fn priority(&self) -> u8 {
        28
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // ip-api.com free tier is HTTP only — HTTPS requires paid plan.
        let url = format!(
            "http://ip-api.com/json/{}?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting",
            target.value
        );

        // ip-api.com free tier rate-limits at 45 req/min and returns
        // HTTP 429 with a JSON body when exceeded. `fetch_json` surfaces
        // the body as a `module_error`, keeping rate-limit conditions
        // visible (previous silent-empty behaviour hid them).
        let data: IpApiResp = fetch_json(&ctx.http, SRC, &url).await?;

        if data.status != "success" {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();

        if let (Some(lat), Some(lon)) = (data.lat, data.lon) {
            let coords = format!("{lat:.6},{lon:.6}");
            // Confidence scaled by IP type: hosting/proxy locations are
            // datacenter-level (low geo value), mobile IPs are cell-tower-level.
            let base_conf = if data.hosting == Some(true) || data.proxy == Some(true) {
                0.45
            } else if data.mobile == Some(true) {
                0.60
            } else {
                0.70
            };
            let mut e = Entity::new(EntityKind::Coordinates, &coords, base_conf, &ctx.scan_id);
            e.tag("geoint");
            if let Some(cc) = data.country_code.as_deref() {
                e.tag(format!("country:{}", cc.to_uppercase()));
            }
            if data.proxy == Some(true) {
                e.tag("proxy");
            }
            if data.hosting == Some(true) {
                e.tag("hosting");
            }
            if data.mobile == Some(true) {
                e.tag("mobile");
            }
            let mut ev = Evidence::new(SRC, format!("IP geolocation for {}", target.value))
                .with_attr("country", data.country.as_deref().unwrap_or("-"))
                .with_attr("region", data.region_name.as_deref().unwrap_or("-"))
                .with_attr("city", data.city.as_deref().unwrap_or("-"))
                .with_attr("latitude", lat.to_string())
                .with_attr("longitude", lon.to_string())
                .with_attr("source", "ip-api.com");
            if let Some(cc) = data.country_code.as_deref() {
                ev = ev.with_attr("country_code", cc);
            }
            if let Some(z) = data.zip.as_deref() {
                ev = ev.with_attr("zip", z);
            }
            if let Some(tz) = data.timezone.as_deref() {
                ev = ev.with_attr("timezone", tz);
            }
            if let Some(isp) = data.isp.as_deref() {
                ev = ev.with_attr("isp", isp);
            }
            if let Some(asn) = data.asn.as_deref() {
                ev = ev.with_attr("asn", asn);
            }
            if let Some(v) = data.proxy {
                ev = ev.with_attr("is_proxy", v.to_string());
            }
            if let Some(v) = data.hosting {
                ev = ev.with_attr("is_hosting", v.to_string());
            }
            if let Some(v) = data.mobile {
                ev = ev.with_attr("is_mobile", v.to_string());
            }
            e.add_evidence(ev);
            result.push(e);
        }

        // Emit Address entity from city/region/country
        let city = data.city.as_deref().unwrap_or("");
        let region = data.region_name.as_deref().unwrap_or("");
        let country = data.country.as_deref().unwrap_or("");
        if !city.is_empty() && !country.is_empty() {
            let addr = if !region.is_empty() {
                format!("{city}, {region}, {country}")
            } else {
                format!("{city}, {country}")
            };
            let mut ae = Entity::new(EntityKind::Address, &addr, 0.65, &ctx.scan_id);
            ae.tag("geoint");
            ae.add_evidence(Evidence::new(
                SRC,
                format!("IP address for {}", target.value),
            ));
            result.push(ae);
        }

        // Emit ASN entity
        if let Some(asn) = &data.asn
            && !asn.is_empty()
        {
            let mut ae = Entity::new(EntityKind::Asn, asn, 0.80, &ctx.scan_id);
            ae.add_evidence(Evidence::new(SRC, format!("ASN for {}", target.value)));
            result.push(ae);
        }

        // Emit reverse DNS domain if present in ISP name
        if let Some(org) = &data.org {
            let mut e = Entity::new(EntityKind::Organisation, org, 0.65, &ctx.scan_id);
            let mut ev = Evidence::new(SRC, format!("IP org for {}", target.value))
                .with_attr("asn", data.asn.as_deref().unwrap_or("-"));
            if let Some(isp) = data.isp.as_deref() {
                ev = ev.with_attr("isp", isp);
            }
            if let Some(cc) = data.country_code.as_deref() {
                ev = ev.with_attr("country_code", cc);
            }
            e.add_evidence(ev);
            result.push(e);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ip_only() {
        let m = IpGeo;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "x")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
    }
}
