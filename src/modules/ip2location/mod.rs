//! ip2location.io — free IP geolocation with postcode precision (no key, 1K/day).
//!
//! Endpoint: `GET https://api.ip2location.io/?ip={ip}`
//! Auth: None for basic tier (1,000/day free, 50K/month with free signup).
//!
//! Returns country, region, city, postcode, lat/lon, timezone, ASN, ISP,
//! and proxy detection. Often more precise than ip-api.com (returns suburb-
//! level city names like "Gatton" instead of "Sydney").

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

const SRC: &str = "ip2location";

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
    zip_code: Option<String>,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    time_zone: Option<String>,
    #[serde(default)]
    asn: Option<String>,
    #[serde(default, rename = "as")]
    as_name: Option<String>,
    #[serde(default)]
    is_proxy: Option<bool>,
}

pub struct Ip2Location;

#[async_trait]
impl Module for Ip2Location {
    fn name(&self) -> &'static str {
        "ip2location"
    }
    fn description(&self) -> &'static str {
        "Suburb-precision IP geolocation via ip2location.io (free, 1K/day)"
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
        // Infrastructure default (T1590.005 + T1596.005) covers IP address info
        // but misses the physical location (T1591.001) and ISP/AS organisation
        // (T1591.002) this module emits; T1596.005 (Scan Databases) is for
        // Shodan-style scan engines, not a geolocation lookup service. Override
        // with the precise surface.
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
        // ip2location.io free tier is IPv4-only — universal dispatcher
        // gate lets public IPv6 through, so reject it here.
        if crate::util::preflight::should_skip_external_ipv4(&target.value) {
            return Ok(ModuleResult::new());
        }
        let ip = target.value.trim();

        let url = format!("https://api.ip2location.io/?ip={ip}");
        let resp = ctx
            .http
            .get(&url)
            .timeout(std::time::Duration::from_secs(6))
            .send_tagged(SRC)
            .await?;

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let data: Resp = resp
            .json()
            .await
            .map_err(|e| Error::module(SRC, format!("JSON: {e}")))?;

        let mut result = ModuleResult::new();

        // A CDN/anycast edge IP geolocates to the answering datacenter, not the
        // subject — skip its Coordinates/Address so they can't pollute
        // identity-location correlation, consistent with the ip_geo rule. The
        // ASN/network entities below still describe the infrastructure itself.
        let skip_geo = crate::core::validation::is_cdn_edge_ip(ip);
        if skip_geo {
            tracing::debug!(
                module = SRC,
                %ip,
                "skipping IP-geo Coordinates/Address — CDN/anycast edge IP, location is datacenter not subject"
            );
        }

        let city = data.city_name.as_deref().unwrap_or("");
        let region = data.region_name.as_deref().unwrap_or("");
        let country = data.country_name.as_deref().unwrap_or("");
        let zip = data.zip_code.as_deref().unwrap_or("");

        // Confidence recalibrated 0.72 → 0.62 — see ip_geo.rs. The ip2location
        // commercial DB is marginally better than the freemium competitors so it
        // stays slightly above ipinfo.
        if let (Some(lat), Some(lon)) = (data.latitude, data.longitude)
            && !skip_geo
            && let Some(mut ce) =
                crate::util::geo::coarse_provider_coords(lat, lon, 0.62, &ctx.scan_id)
        {
            ce.tag("ip2location");
            if data.is_proxy == Some(true) {
                ce.tag(tags::PROXY);
            }
            if let Some(state) = crate::util::geo::au_state_for_coords(lat, lon) {
                ce.tag(format!("au-state:{state}"));
                ce.tag("country:AU");
            }
            let ev = [
                ("city", (!city.is_empty()).then_some(city)),
                ("region", (!region.is_empty()).then_some(region)),
                ("country", (!country.is_empty()).then_some(country)),
                ("postcode", (!zip.is_empty()).then_some(zip)),
            ]
            .into_iter()
            .filter_map(|(key, value)| value.map(|v| (key, v)))
            .fold(
                Evidence::new(
                    SRC,
                    format!("IP geolocation for {ip}: {city}, {region}, {country}"),
                )
                .with_attr("ip", ip),
                |ev, (key, v)| ev.with_attr(key, v),
            );
            ce.add_evidence(ev);
            result.push(ce);
        }

        if !skip_geo && !city.is_empty() && !country.is_empty() {
            let addr = if !region.is_empty() && !zip.is_empty() {
                format!("{city}, {region} {zip}, {country}")
            } else if !region.is_empty() {
                format!("{city}, {region}, {country}")
            } else {
                format!("{city}, {country}")
            };
            let mut ae = Entity::new(EntityKind::Address, &addr, 0.68, &ctx.scan_id);
            ae.tag("ip2location");
            ae.tag(tags::GEOINT);
            ae.add_evidence(Evidence::new(SRC, format!("Address for {ip}")));
            result.push(ae);
        }

        if let Some(asn) = &data.asn
            && !asn.is_empty()
        {
            let asn_str = format!("AS{asn}");
            let mut ae = Entity::new(EntityKind::Asn, &asn_str, 0.80, &ctx.scan_id);
            ae.tag("ip2location");
            ae.add_evidence(Evidence::new(SRC, format!("ASN for {ip}")));
            result.push(ae);
        }

        if let Some(as_name) = &data.as_name
            && !as_name.is_empty()
        {
            let mut oe = Entity::new(EntityKind::Organisation, as_name, 0.65, &ctx.scan_id);
            oe.tag("ip2location");
            oe.add_evidence(Evidence::new(SRC, format!("ISP for {ip}")));
            result.push(oe);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
