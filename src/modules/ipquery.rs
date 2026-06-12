//! IPQuery.io — free IP risk assessment + geolocation (no key, unlimited).
//!
//! Endpoint: `GET https://api.ipquery.io/{ip}`
//! Auth: None. Completely free with no rate limit published.
//!
//! Returns ISP/ASN/org, city/state/country/coordinates, and risk flags
//! (mobile, VPN, Tor, proxy, datacenter) with a 0-100 risk score.

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

const SRC: &str = "ipquery";

#[derive(Deserialize)]
struct Resp {
    #[serde(default)]
    isp: Option<IspBlock>,
    #[serde(default)]
    location: Option<LocationBlock>,
    #[serde(default)]
    risk: Option<RiskBlock>,
}

#[derive(Deserialize)]
struct IspBlock {
    #[serde(default)]
    asn: Option<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    isp: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct LocationBlock {
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    timezone: Option<String>,
}

#[derive(Deserialize)]
struct RiskBlock {
    #[serde(default)]
    is_mobile: Option<bool>,
    #[serde(default)]
    is_vpn: Option<bool>,
    #[serde(default)]
    is_tor: Option<bool>,
    #[serde(default)]
    is_proxy: Option<bool>,
    #[serde(default)]
    is_datacenter: Option<bool>,
    #[serde(default)]
    risk_score: Option<u32>,
}

pub struct IpQuery;

#[async_trait]
impl Module for IpQuery {
    fn name(&self) -> &'static str {
        "ipquery"
    }
    fn description(&self) -> &'static str {
        "Free IP risk assessment + geolocation via ipquery.io (no key, unlimited)"
    }
    fn priority(&self) -> u8 {
        27
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
            EntityKind::Coordinates,
            EntityKind::Address,
            EntityKind::Asn,
            EntityKind::Organisation,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // ipquery.io is IPv4-only — universal dispatcher gate lets
        // public IPv6 through, so reject it here.
        if crate::util::preflight::should_skip_external_ipv4(&target.value) {
            return Ok(ModuleResult::new());
        }
        let ip = target.value.trim();

        let url = format!("https://api.ipquery.io/{ip}");
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

        let risk = data.risk.as_ref();
        let risk_score = risk.and_then(|r| r.risk_score).unwrap_or(0);

        let mut ip_entity = target.to_entity(0.80, &ctx.scan_id);
        ip_entity.tag("ipquery");
        if risk.and_then(|r| r.is_vpn) == Some(true) {
            ip_entity.tag(tags::VPN);
        }
        if risk.and_then(|r| r.is_tor) == Some(true) {
            ip_entity.tag(tags::TOR_EXIT);
        }
        if risk.and_then(|r| r.is_proxy) == Some(true) {
            ip_entity.tag(tags::PROXY);
        }
        if risk.and_then(|r| r.is_mobile) == Some(true) {
            ip_entity.tag("mobile");
        }
        if risk.and_then(|r| r.is_datacenter) == Some(true) {
            ip_entity.tag("hosting");
        }
        if risk_score >= 70 {
            ip_entity.tag("high-risk");
        }

        let mut ev = Evidence::new(SRC, format!("IPQuery risk assessment for {ip}"))
            .with_attr("risk_score", risk_score.to_string());
        if let Some(isp) = data.isp.as_ref() {
            if let Some(v) = isp.isp.as_deref() {
                ev = ev.with_attr("isp", v);
            }
            if let Some(v) = isp.org.as_deref() {
                ev = ev.with_attr("org", v);
            }
            if let Some(v) = isp.asn.as_deref() {
                ev = ev.with_attr("asn", v);
            }
        }
        ip_entity.add_evidence(ev);
        result.push(ip_entity);

        // A CDN/anycast edge IP geolocates to the answering datacenter, not the
        // subject — its city/coords are pure infrastructure. Skip the geo
        // (Coordinates/Address) entities so they can't pollute identity-location
        // correlation, consistent with the ip_geo/ipinfo rule. The IP, ASN and
        // ISP-org entities above are still emitted (they describe the
        // infrastructure itself, not a claimed subject location).
        let skip_geo = crate::core::validation::is_cdn_edge_ip(ip);
        if skip_geo {
            tracing::debug!(
                module = SRC,
                %ip,
                "skipping IP-geo Coordinates/Address — CDN/anycast edge IP, location is datacenter not subject"
            );
        }
        if let Some(loc) = data.location.as_ref().filter(|_| !skip_geo) {
            // Confidence recalibrated 0.68 → 0.58 — see ip_geo.rs.
            if let (Some(lat), Some(lon)) = (loc.latitude, loc.longitude)
                && let Some(mut ce) =
                    crate::util::geo::coarse_provider_coords(lat, lon, 0.58, &ctx.scan_id)
            {
                ce.tag("ipquery");
                if let Some(state) = crate::util::geo::au_state_for_coords(lat, lon) {
                    ce.tag(format!("au-state:{state}"));
                    ce.tag("country:AU");
                }
                ce.add_evidence(Evidence::new(SRC, format!("Geolocation for {ip}")));
                result.push(ce);
            }
            let city = loc.city.as_deref().unwrap_or("");
            let state = loc.state.as_deref().unwrap_or("");
            let country = loc.country.as_deref().unwrap_or("");
            if !city.is_empty() && !country.is_empty() {
                let addr = if !state.is_empty() {
                    format!("{city}, {state}, {country}")
                } else {
                    format!("{city}, {country}")
                };
                let mut ae = Entity::new(EntityKind::Address, &addr, 0.62, &ctx.scan_id);
                ae.tag("ipquery");
                ae.add_evidence(Evidence::new(SRC, format!("Address for {ip}")));
                result.push(ae);
            }
        }

        if let Some(isp) = &data.isp {
            if let Some(asn) = isp.asn.as_deref()
                && !asn.is_empty()
            {
                let mut ae = Entity::new(EntityKind::Asn, asn, 0.80, &ctx.scan_id);
                ae.tag("ipquery");
                ae.add_evidence(Evidence::new(SRC, format!("ASN for {ip}")));
                result.push(ae);
            }
            if let Some(org) = isp.org.as_deref()
                && !org.is_empty()
            {
                let mut oe = Entity::new(EntityKind::Organisation, org, 0.65, &ctx.scan_id);
                oe.tag("ipquery");
                oe.add_evidence(Evidence::new(SRC, format!("ISP org for {ip}")));
                result.push(oe);
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ip_only() {
        assert!(IpQuery.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
        assert!(!IpQuery.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }

    #[test]
    fn cost_is_free() {
        assert!(matches!(
            IpQuery.cost(),
            crate::core::module::ModuleCost::Free
        ));
    }

    #[test]
    fn deser() {
        let j = r#"{"ip":"8.8.8.8","isp":{"asn":"AS15169","org":"Google LLC","isp":"Google LLC"},"location":{"country":"United States","country_code":"US","city":"Mountain View","state":"California","latitude":37.41,"longitude":-122.11},"risk":{"is_mobile":false,"is_vpn":false,"is_tor":false,"is_proxy":false,"is_datacenter":true,"risk_score":0}}"#;
        let r: Resp = serde_json::from_str(j).unwrap();
        assert_eq!(r.risk.unwrap().risk_score, Some(0));
        assert_eq!(r.location.unwrap().city.as_deref(), Some("Mountain View"));
    }
}
