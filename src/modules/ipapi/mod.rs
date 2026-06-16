//! ipwho.is — free IP geolocation over **HTTPS** (no key).
//!
//! Endpoint: `GET https://ipwho.is/{ip}`
//! Auth: None — generous free quota, HTTPS, no key required.
//!
//! Returns city/region/country, lat/lon, and the connection's ISP / org / ASN.
//! Chosen over the (HTTP-only free tier) ip-api.com so the subject's IP is not
//! geolocated in cleartext from the device, and so this module is a genuinely
//! INDEPENDENT geo source from [`crate::modules::ip_geo`] — which keeps
//! ip-api.com for its proxy/hosting/mobile flags. With two distinct providers
//! the correlator's "two sources agree on location" is real corroboration, not
//! the same provider counted twice.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "ipapi";

#[derive(Deserialize)]
struct IpWhoResp {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    connection: Option<Connection>,
    #[serde(default)]
    timezone: Option<Timezone>,
}

#[derive(Deserialize, Default)]
struct Connection {
    #[serde(default)]
    asn: Option<u64>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    isp: Option<String>,
}

#[derive(Deserialize, Default)]
struct Timezone {
    #[serde(default)]
    id: Option<String>,
}

pub struct IpApi;

#[async_trait]
impl Module for IpApi {
    fn name(&self) -> &'static str {
        "ipapi"
    }

    fn description(&self) -> &'static str {
        "Free IP geolocation via ipwho.is (HTTPS; city, ISP, ASN, org)"
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

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Passive IP geolocation API — same surface as ip2location, ipinfo, etc.
        // Maps IPs to physical location (T1591.001) and identifies the ISP/AS
        // operator as an Organisation (T1591.002); T1596.005 (Scan Databases) does
        // not describe a passive geolocation lookup.
        &["T1590.005", "T1591.001", "T1591.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Coordinates,
            EntityKind::Address,
            EntityKind::Asn,
            EntityKind::Organisation,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // IPv4-only gate retained for parity with ip_geo; also skips private /
        // reserved space. (ipwho.is does resolve IPv6 — enabling it is a separate
        // change that must also teach `is_cdn_edge_ip` about v6 edge ranges.)
        if crate::util::preflight::should_skip_external_ipv4(&target.value) {
            return Ok(ModuleResult::new());
        }
        let ip = target.value.trim();

        let url = format!("https://ipwho.is/{ip}");

        let resp = ctx
            .http
            .get(&url)
            .timeout(std::time::Duration::from_millis(self.max_timeout_ms()))
            .send_tagged(SRC)
            .await?;

        if !resp.status().is_success() {
            return Err(Error::module(SRC, format!("HTTP {}", resp.status())));
        }

        let data: IpWhoResp = resp
            .json()
            .await
            .map_err(|e| Error::module(SRC, format!("JSON: {e}")))?;

        // ipwho.is signals lookup failure (private/reserved IP, quota) with
        // `success:false` rather than an HTTP error — treat it as no-data.
        if !data.success {
            return Ok(ModuleResult::new());
        }

        // A CDN/anycast edge IP geolocates to whichever datacenter answered, not
        // to the subject — skip it (the same guard ip_geo applies).
        if crate::core::validation::is_cdn_edge_ip(ip) {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();

        let conn = data.connection.unwrap_or_default();
        let city = data.city.as_deref().unwrap_or("");
        let region = data.region.as_deref().unwrap_or("");
        let country = data.country.as_deref().unwrap_or("");
        let isp = conn.isp.as_deref().unwrap_or("");
        let asn = conn.asn.map(|n| format!("AS{n}"));
        let tz = data.timezone.and_then(|t| t.id);

        let ev = [
            ("city", (!city.is_empty()).then(|| city.to_string())),
            ("region", (!region.is_empty()).then(|| region.to_string())),
            (
                "country",
                (!country.is_empty()).then(|| country.to_string()),
            ),
            ("isp", (!isp.is_empty()).then(|| isp.to_string())),
            ("asn", asn.clone()),
            ("org", conn.org.clone()),
            ("timezone", tz),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|v| (key, v)))
        .fold(
            Evidence::new(SRC, format!("IP geolocation: {city}, {region}, {country}"))
                .with_attr("ip", ip),
            |ev, (key, v)| ev.with_attr(key, v),
        );

        // Coordinates — `coarse_provider_coords` gates implausible / null-island
        // fixes (the same shared validator every coarse IP-geo provider uses).
        if let (Some(lat), Some(lon)) = (data.latitude, data.longitude)
            && let Some(mut ce) =
                crate::util::geo::coarse_provider_coords(lat, lon, 0.60, &ctx.scan_id)
        {
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

        if let Some(asn) = &asn {
            let mut ae = Entity::new(EntityKind::Asn, asn, 0.80, &ctx.scan_id);
            ae.add_evidence(ev.clone());
            result.push(ae);
        }

        if let Some(org) = conn.org.as_deref().filter(|o| o.len() >= 3) {
            let mut oe = Entity::new(EntityKind::Organisation, org, 0.60, &ctx.scan_id);
            oe.add_evidence(ev);
            result.push(oe);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
