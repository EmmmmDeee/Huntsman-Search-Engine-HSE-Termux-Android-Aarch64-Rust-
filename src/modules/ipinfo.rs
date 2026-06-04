//! ipinfo.io — free IP intelligence (no key for basic queries).
//!
//! Endpoint: GET https://ipinfo.io/{ip}/json
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

const SRC: &str = "ipinfo";

/// Trimmed, non-empty view of an optional string field.
fn nonempty(o: &Option<String>) -> Option<&str> {
    o.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

#[derive(Deserialize)]
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
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let data: IpInfoResp = resp
            .json()
            .await
            .map_err(|e| Error::module(SRC, format!("JSON: {e}")))?;

        let mut result = ModuleResult::new();
        for e in build_entities(ip, &data, &ctx.scan_id) {
            result.push(e);
        }
        Ok(result)
    }
}

/// Map an ipinfo.io record to its geo/network entities. **Pure** (no IO) so the
/// multi-entity construction is unit-tested. Recovers the previously-discarded
/// `postal` and `timezone` (surfaced on the coordinate/address evidence — the
/// fields the geo-precision diagnostic reports on) and the echoed `ip` (a
/// mismatch against the queried IP flags `ip-mismatch`, so a record for another
/// host can't pose as this one's).
fn build_entities(ip: &str, data: &IpInfoResp, scan_id: &str) -> Vec<Entity> {
    let mut result: Vec<Entity> = Vec::new();
    let mismatch = nonempty(&data.ip).is_some_and(|echoed| echoed != ip);

    if let Some(loc) = &data.loc {
        let parts: Vec<&str> = loc.split(',').collect();
        if let (Some(lat_s), Some(lon_s)) = (parts.first(), parts.get(1))
            && let (Ok(lat), Ok(lon)) = (lat_s.trim().parse::<f64>(), lon_s.trim().parse::<f64>())
            && lat.abs() > 0.01
            && lon.abs() > 0.01
        {
            let coords = format!("{lat:.4},{lon:.4}");
            // Confidence recalibrated 0.68 → 0.58 — see ip_geo.rs.
            let mut ce = Entity::new(EntityKind::Coordinates, &coords, 0.58, scan_id);
            ce.tag(tags::GEOINT);
            ce.tag("ipinfo");
            if mismatch {
                ce.tag("ip-mismatch");
            }
            let mut ev = Evidence::new(SRC, format!("IP geo for {ip}"));
            if let Some(c) = &data.city {
                ev = ev.with_attr("city", c);
            }
            if let Some(r) = &data.region {
                ev = ev.with_attr("region", r);
            }
            if let Some(co) = &data.country {
                ev = ev.with_attr("country", co);
            }
            // Recovered: postal + timezone (precision signals the old code dropped).
            if let Some(p) = nonempty(&data.postal) {
                ev = ev.with_attr("postal", p);
            }
            if let Some(tz) = nonempty(&data.timezone) {
                ev = ev.with_attr("timezone", tz);
            }
            if mismatch && let Some(echoed) = nonempty(&data.ip) {
                ev = ev.with_attr("queried_ip", echoed);
            }
            ce.add_evidence(ev);
            result.push(ce);
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
        let mut ev = Evidence::new(SRC, format!("Address for {ip}"));
        if let Some(p) = nonempty(&data.postal) {
            ev = ev.with_attr("postal", p);
        }
        ae.add_evidence(ev);
        result.push(ae);
    }

    if let Some(org) = &data.org
        && !org.is_empty()
    {
        let mut oe = Entity::new(EntityKind::Organisation, org, 0.65, scan_id);
        oe.tag("ipinfo");
        oe.add_evidence(Evidence::new(SRC, format!("Org for {ip}")));
        result.push(oe);
        if let Some(asn) = org.split_whitespace().next()
            && asn.starts_with("AS")
        {
            let mut ae = Entity::new(EntityKind::Asn, asn, 0.80, scan_id);
            ae.tag("ipinfo");
            ae.add_evidence(Evidence::new(SRC, format!("ASN for {ip}")));
            result.push(ae);
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
        result.push(de);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_ip_only() {
        assert!(IpInfo.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
        assert!(!IpInfo.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }
    #[test]
    fn cost_is_free() {
        assert!(matches!(
            IpInfo.cost(),
            crate::core::module::ModuleCost::Free
        ));
    }
    #[test]
    fn deser() {
        let j = r#"{"ip":"8.8.8.8","hostname":"dns.google","city":"Mountain View","region":"California","country":"US","loc":"37.4056,-122.0775","org":"AS15169 Google LLC","postal":"94043","timezone":"America/Los_Angeles"}"#;
        let r: IpInfoResp = serde_json::from_str(j).unwrap();
        assert_eq!(r.city.as_deref(), Some("Mountain View"));
        assert_eq!(r.org.as_deref(), Some("AS15169 Google LLC"));
    }

    fn resp(json: &str) -> IpInfoResp {
        serde_json::from_str(json).unwrap()
    }

    fn of_kind(v: &[Entity], k: EntityKind) -> Option<&Entity> {
        v.iter().find(|e| e.kind == k)
    }

    #[test]
    fn build_entities_full_record_emits_all_kinds_and_recovers_postal_timezone() {
        let d = resp(
            r#"{"ip":"8.8.8.8","hostname":"dns.google","city":"Mountain View",
                "region":"California","country":"US","loc":"37.4056,-122.0775",
                "org":"AS15169 Google LLC","postal":"94043","timezone":"America/Los_Angeles"}"#,
        );
        let v = build_entities("8.8.8.8", &d, "s");
        // Coordinates, Address, Organisation, Asn, Domain (PTR) all produced.
        let coords = of_kind(&v, EntityKind::Coordinates).unwrap();
        assert!(!coords.has_tag("ip-mismatch"));
        let ca = &coords.evidence[0].attributes;
        // Previously-discarded precision fields are now surfaced.
        assert_eq!(ca.get("postal").map(String::as_str), Some("94043"));
        assert_eq!(
            ca.get("timezone").map(String::as_str),
            Some("America/Los_Angeles")
        );
        let addr = of_kind(&v, EntityKind::Address).unwrap();
        assert_eq!(
            addr.evidence[0]
                .attributes
                .get("postal")
                .map(String::as_str),
            Some("94043")
        );
        assert_eq!(of_kind(&v, EntityKind::Asn).unwrap().value, "AS15169");
        assert_eq!(of_kind(&v, EntityKind::Domain).unwrap().value, "dns.google");
        assert!(of_kind(&v, EntityKind::Organisation).is_some());
    }

    #[test]
    fn build_entities_flags_echoed_ip_mismatch() {
        // ipinfo echoed a different IP than queried → geo is for another host.
        let d = resp(r#"{"ip":"9.9.9.9","city":"X","country":"US","loc":"1.5,2.5"}"#);
        let v = build_entities("1.1.1.1", &d, "s");
        let coords = of_kind(&v, EntityKind::Coordinates).unwrap();
        assert!(coords.has_tag("ip-mismatch"));
        assert_eq!(
            coords.evidence[0]
                .attributes
                .get("queried_ip")
                .map(String::as_str),
            Some("9.9.9.9")
        );
    }

    #[test]
    fn build_entities_skips_null_island_and_empty() {
        // 0,0 coordinates are rejected; an empty record yields nothing.
        let d = resp(r#"{"ip":"8.8.8.8","loc":"0,0"}"#);
        assert!(of_kind(&build_entities("8.8.8.8", &d, "s"), EntityKind::Coordinates).is_none());
        assert!(build_entities("8.8.8.8", &resp(r#"{"ip":"8.8.8.8"}"#), "s").is_empty());
    }
}
