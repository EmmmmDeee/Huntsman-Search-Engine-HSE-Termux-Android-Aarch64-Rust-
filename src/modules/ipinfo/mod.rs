//! ipinfo.io — free IP intelligence (no key for basic queries).
//!
//! Endpoint: `GET https://ipinfo.io/{ip}/json`
//! Auth: None for basic tier (50K/month).
//!
//! Returns city, region, country, org, ASN, hostname, timezone, postal.
//! Richer than ip-api.com for organisation + hostname data.

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

const SRC: &str = "ipinfo";

#[derive(Deserialize)]
#[allow(dead_code)]
struct IpInfoResp {
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
}

/// Map an ipinfo.io record to its entities. **Pure** (no network/IO): yields up
/// to five — `Coordinates` from a real (non-null-island) `loc`, an `Address` from
/// city/region/country, an `Organisation` plus the leading `Asn` parsed out of
/// the `org` string (`"AS15169 Google LLC"`), and the PTR `Domain` from a
/// dotted `hostname`. Each is independent; absent/blank fields are skipped.
fn build_entities(ip: &str, data: &IpInfoResp, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();

    // Shared trust gate: an IP whose geolocation is infrastructure (a
    // CDN/anycast edge) is not the subject's, so skip its findings rather than
    // pollute identity-location correlation.
    if let Some(reason) = crate::core::validation::untrusted_ip_geo_reason(ip) {
        tracing::debug!(
            module = SRC,
            %ip,
            reason,
            "skipping IP-geo — location is the infrastructure, not the subject"
        );
        return out;
    }

    if let Some(loc) = &data.loc {
        let mut parts = loc.split(',');
        if let (Some(lat_s), Some(lon_s)) = (parts.next(), parts.next())
            && let (Ok(lat), Ok(lon)) = (lat_s.trim().parse::<f64>(), lon_s.trim().parse::<f64>())
            // Confidence recalibrated 0.68 → 0.58 — see ip_geo.rs.
            && let Some(mut ce) = crate::util::geo::coarse_provider_coords(lat, lon, 0.58, scan_id)
        {
            ce.tag("ipinfo");
            if let Some(state) = crate::util::geo::au_state_for_coords(lat, lon) {
                ce.tag(format!("au-state:{state}"));
                ce.tag("country:AU");
            }
            let ev = [
                ("city", data.city.as_deref()),
                ("region", data.region.as_deref()),
                ("country", data.country.as_deref()),
            ]
            .into_iter()
            .filter_map(|(key, value)| value.map(|v| (key, v)))
            .fold(
                Evidence::new(SRC, format!("IP geo for {ip}")),
                |ev, (key, v)| ev.with_attr(key, v),
            );
            ce.add_evidence(ev);
            out.push(ce);
        }
    }

    let city = data.city.as_deref().unwrap_or("");
    let region = data.region.as_deref().unwrap_or("");
    let country = data.country.as_deref().unwrap_or("");
    if !city.is_empty() {
        let addr = if !region.is_empty() {
            format!("{city}, {region}, {country}")
        } else {
            format!("{city}, {country}")
        };
        let mut ae = Entity::new(EntityKind::Address, &addr, 0.60, scan_id);
        ae.tag("ipinfo");
        ae.add_evidence(Evidence::new(SRC, format!("Address for {ip}")));
        out.push(ae);
    }

    if let Some(org) = &data.org
        && !org.is_empty()
    {
        let mut oe = Entity::new(EntityKind::Organisation, org, 0.65, scan_id);
        oe.tag("ipinfo");
        oe.add_evidence(Evidence::new(SRC, format!("Org for {ip}")));
        out.push(oe);
        if let Some(asn) = org.split_whitespace().next()
            && asn.starts_with("AS")
        {
            let mut ae = Entity::new(EntityKind::Asn, asn, 0.80, scan_id);
            ae.tag("ipinfo");
            ae.add_evidence(Evidence::new(SRC, format!("ASN for {ip}")));
            out.push(ae);
        }
    }

    if let Some(hostname) = &data.hostname
        && !hostname.is_empty()
        && hostname.contains('.')
    {
        let mut de = Entity::new(EntityKind::Domain, hostname, 0.70, scan_id);
        de.tag("ipinfo");
        de.tag(tags::PTR);
        de.add_evidence(Evidence::new(SRC, format!("Hostname for {ip}")));
        out.push(de);
    }

    out
}

pub struct IpInfo;

#[async_trait]
impl Module for IpInfo {
    fn name(&self) -> &'static str {
        "ipinfo"
    }
    fn description(&self) -> &'static str {
        "IP intelligence via ipinfo.io (free, 50K/month, no key)"
    }
    fn priority(&self) -> u8 {
        25
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
        // Infrastructure default (T1590.005 + T1596.005) covers IP info but
        // ipinfo.io is a passive geolocation API, not a scan database (T1596.005).
        // It maps IPs to physical coordinates + address (T1591.001) and identifies
        // the ISP/ASN operator as an Organisation (T1591.002).
        &["T1590.005", "T1591.001", "T1591.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Coordinates,
            EntityKind::Address,
            EntityKind::Asn,
            EntityKind::Organisation,
            EntityKind::Domain,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let ip = target.value.trim();

        let url = format!("https://ipinfo.io/{ip}/json");
        let resp = ctx
            .http
            .get(&url)
            .timeout(std::time::Duration::from_secs(6))
            .send_tagged(SRC)
            .await?;

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let data: IpInfoResp = resp
            .json()
            .await
            .map_err(|e| Error::module(SRC, format!("JSON: {e}")))?;

        let mut result = ModuleResult::new();
        result.entities = build_entities(ip, &data, &ctx.scan_id);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
