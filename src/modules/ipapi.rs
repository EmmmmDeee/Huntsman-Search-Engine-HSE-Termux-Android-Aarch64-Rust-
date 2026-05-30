//! ip-api.com — free IP geolocation with ISP/ASN/proxy detection.
//!
//! Endpoint: `GET http://ip-api.com/json/{ip}?fields=66846719`
//! Auth: None — 45 requests/minute, no key required.
//!
//! Returns city/region/country, lat/lon, ISP, ASN, org, mobile/proxy/
//! hosting flags, reverse DNS, and timezone. The numeric `fields` bitmask
//! requests all available fields.
//!
//! Note: free tier requires HTTP (not HTTPS). HTTPS is paid only.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};

const SRC: &str = "ipapi";
const FIELDS: u64 = 66846719;

#[derive(Deserialize)]
#[allow(dead_code)]
struct IpApiResp {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(rename = "countryCode", default)]
    country_code: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(rename = "regionName", default)]
    region_name: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    zip: Option<String>,
    #[serde(default)]
    lat: Option<f64>,
    #[serde(default)]
    lon: Option<f64>,
    #[serde(default)]
    timezone: Option<String>,
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(rename = "as", default)]
    asn: Option<String>,
    #[serde(rename = "asname", default)]
    as_name: Option<String>,
    #[serde(default)]
    reverse: Option<String>,
    #[serde(default)]
    mobile: Option<bool>,
    #[serde(default)]
    proxy: Option<bool>,
    #[serde(default)]
    hosting: Option<bool>,
    #[serde(default)]
    district: Option<String>,
}

pub struct IpApi;

#[async_trait]
impl Module for IpApi {
    fn name(&self) -> &'static str {
        "ipapi"
    }

    fn description(&self) -> &'static str {
        "Free IP geolocation via ip-api.com (city, ISP, ASN, proxy detection)"
    }

    fn priority(&self) -> u8 {
        26
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Address,
            EntityKind::Asn,
            EntityKind::Coordinates,
            EntityKind::Domain,
            EntityKind::Organisation,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // ip-api.com free tier is IPv4-only — the universal dispatcher
        // gate allows public IPv6 through, so this module needs its own
        // IPv6 rejection on top.
        if crate::util::preflight::should_skip_external_ipv4(&target.value) {
            return Ok(ModuleResult::new());
        }
        let ip = target.value.trim();

        let url = format!("http://ip-api.com/json/{ip}?fields={FIELDS}");

        let resp = ctx
            .http
            .get(&url)
            .timeout(std::time::Duration::from_millis(self.max_timeout_ms()))
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Error::module(SRC, format!("HTTP {}", resp.status())));
        }

        let data: IpApiResp = resp
            .json()
            .await
            .map_err(|e| Error::module(SRC, format!("JSON: {e}")))?;

        if data.status.as_deref() != Some("success") {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();

        let city = data.city.as_deref().unwrap_or("");
        let region = data.region_name.as_deref().unwrap_or("");
        let country = data.country.as_deref().unwrap_or("");
        let isp = data.isp.as_deref().unwrap_or("");

        let mut ev = Evidence::new(SRC, format!("IP geolocation: {city}, {region}, {country}"))
            .with_attr("ip", ip);
        if !city.is_empty() {
            ev = ev.with_attr("city", city);
        }
        if !region.is_empty() {
            ev = ev.with_attr("region", region);
        }
        if !country.is_empty() {
            ev = ev.with_attr("country", country);
        }
        if !isp.is_empty() {
            ev = ev.with_attr("isp", isp);
        }
        if let Some(asn) = &data.asn {
            ev = ev.with_attr("asn", asn);
        }
        if let Some(org) = &data.org {
            ev = ev.with_attr("org", org);
        }
        if let Some(tz) = &data.timezone {
            ev = ev.with_attr("timezone", tz);
        }

        if let (Some(lat), Some(lon)) = (data.lat, data.lon)
            && lat.abs() > 0.01
            && lon.abs() > 0.01
        {
            let coords = format!("{lat:.4},{lon:.4}");
            // Confidence recalibrated 0.70 → 0.60 — see ip_geo.rs for
            // rationale (single-source free IP geo overstates
            // residential precision; corroboration boost lifts the
            // real value at the merge step).
            let mut ce = Entity::new(EntityKind::Coordinates, &coords, 0.60, &ctx.scan_id);
            ce.tag(tags::GEOINT);
            if data.mobile == Some(true) {
                ce.tag("mobile");
            }
            if data.proxy == Some(true) {
                ce.tag(tags::PROXY);
            }
            if data.hosting == Some(true) {
                ce.tag("hosting");
            }
            ce.add_evidence(ev.clone());
            result.push(ce);
        }

        if !city.is_empty() {
            let addr = if !region.is_empty() && !country.is_empty() {
                format!("{city}, {region}, {country}")
            } else if !country.is_empty() {
                format!("{city}, {country}")
            } else {
                city.to_string()
            };
            let mut ae = Entity::new(EntityKind::Address, &addr, 0.65, &ctx.scan_id);
            ae.tag(tags::GEOINT);
            ae.add_evidence(ev.clone());
            result.push(ae);
        }

        if let Some(asn) = &data.asn {
            let mut ae = Entity::new(EntityKind::Asn, asn, 0.80, &ctx.scan_id);
            ae.add_evidence(ev.clone());
            result.push(ae);
        }

        if let Some(org) = &data.org
            && !org.is_empty()
            && org.len() >= 3
        {
            let mut oe = Entity::new(EntityKind::Organisation, org, 0.60, &ctx.scan_id);
            oe.add_evidence(ev.clone());
            result.push(oe);
        }

        if let Some(rev) = &data.reverse
            && !rev.is_empty()
            && rev.contains('.')
        {
            let mut de = Entity::new(EntityKind::Domain, rev, 0.65, &ctx.scan_id);
            de.tag(tags::PTR);
            de.add_evidence(ev);
            result.push(de);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ip_only() {
        let m = IpApi;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }

    #[test]
    fn cost_is_free() {
        assert!(matches!(
            IpApi.cost(),
            crate::core::module::ModuleCost::Free
        ));
    }

    #[test]
    fn description_non_empty() {
        assert!(!IpApi.description().is_empty());
    }

    #[test]
    fn rejects_ipv6() {
        let t = Target::new(TargetKind::IpAddress, "2001:db8::1");
        let m = IpApi;
        assert!(m.accepts(&t));
    }

    #[test]
    fn deser_full() {
        let json = r#"{"status":"success","country":"Australia","countryCode":"AU","region":"NSW","regionName":"New South Wales","city":"Sydney","zip":"1001","lat":-33.8688,"lon":151.209,"timezone":"Australia/Sydney","isp":"Telstra","org":"Telstra Corp","as":"AS1221 Telstra","asname":"ASN-TELSTRA","reverse":"","mobile":true,"proxy":false,"hosting":false}"#;
        let data: IpApiResp = serde_json::from_str(json).unwrap();
        assert_eq!(data.city.as_deref(), Some("Sydney"));
        assert_eq!(data.mobile, Some(true));
        assert_eq!(data.proxy, Some(false));
    }
}
