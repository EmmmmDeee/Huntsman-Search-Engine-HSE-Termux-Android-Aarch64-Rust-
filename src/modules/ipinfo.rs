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

    // A CDN/anycast edge IP geolocates to the answering datacenter, not the
    // subject — its city/coords/org are pure infrastructure. Skip them so they
    // can't pollute identity-location correlation (see ip_geo.rs for the rule).
    if crate::core::validation::is_cdn_edge_ip(ip) {
        tracing::debug!(
            module = SRC,
            %ip,
            "skipping IP-geo — CDN/anycast edge IP, location is datacenter not subject"
        );
        return out;
    }

    if let Some(loc) = &data.loc {
        let mut parts = loc.split(',');
        if let (Some(lat_s), Some(lon_s)) = (parts.next(), parts.next())
            && let (Ok(lat), Ok(lon)) = (lat_s.trim().parse::<f64>(), lon_s.trim().parse::<f64>())
            && crate::util::geo::is_plausible_provider_coord(lat, lon)
        {
            let coords = format!("{lat:.4},{lon:.4}");
            // Confidence recalibrated 0.68 → 0.58 — see ip_geo.rs.
            let mut ce = Entity::new(EntityKind::Coordinates, &coords, 0.58, scan_id);
            ce.tag(tags::GEOINT);
            ce.tag("ipinfo");
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
        result.entities = build_entities(ip, &data, &ctx.scan_id);
        Ok(result)
    }
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

    fn data(json: &str) -> IpInfoResp {
        serde_json::from_str(json).unwrap()
    }

    fn one(ents: &[Entity], kind: EntityKind) -> Option<&Entity> {
        ents.iter().find(|e| e.kind == kind)
    }

    #[test]
    fn full_record_yields_all_five_entities() {
        let d = data(
            r#"{"ip":"8.8.8.8","hostname":"dns.google","city":"Mountain View",
                "region":"California","country":"US","loc":"37.4056,-122.0775",
                "org":"AS15169 Google LLC"}"#,
        );
        let ents = build_entities("8.8.8.8", &d, "s");
        assert_eq!(ents.len(), 5);

        let coords = one(&ents, EntityKind::Coordinates).unwrap();
        // Entity::new normalises Coordinates to 6-decimal lat,lon.
        assert_eq!(coords.value, "37.405600,-122.077500");
        assert!(coords.has_tag(tags::GEOINT) && coords.has_tag("ipinfo"));
        assert_eq!(
            coords.evidence[0]
                .attributes
                .get("city")
                .map(String::as_str),
            Some("Mountain View")
        );

        assert_eq!(
            one(&ents, EntityKind::Address).unwrap().value,
            "Mountain View, California, US"
        );
        assert_eq!(
            one(&ents, EntityKind::Organisation).unwrap().value,
            "AS15169 Google LLC"
        );
        let asn = one(&ents, EntityKind::Asn).unwrap();
        assert_eq!(asn.value, "AS15169");
        assert!((asn.confidence - 0.80).abs() < 1e-9);
        let dom = one(&ents, EntityKind::Domain).unwrap();
        assert_eq!(dom.value, "dns.google");
        assert!(dom.has_tag(tags::PTR));
    }

    #[test]
    fn cdn_edge_ip_yields_no_entities() {
        // A Cloudflare anycast edge IP (104.16.0.0/13) geolocates to whichever
        // datacenter answered — never the subject. ipinfo drops the whole record
        // (the city/coords/org all describe infrastructure) rather than seed a
        // false subject location into identity-location correlation.
        let d = data(
            r#"{"ip":"104.16.1.1","hostname":"edge.cloudflare.example",
                "city":"San Francisco","region":"California","country":"US",
                "loc":"37.7749,-122.4194","org":"AS13335 Cloudflare, Inc."}"#,
        );
        let ents = build_entities("104.16.1.1", &d, "s");
        assert!(ents.is_empty(), "CDN-edge IP must yield no entities, got {ents:?}");
        // Sanity: the same record on a non-CDN IP DOES produce entities.
        assert!(!build_entities("8.8.8.8", &d, "s").is_empty());
    }

    #[test]
    fn null_island_loc_is_dropped() {
        // 0,0 (and sub-threshold magnitudes) is a placeholder, not a location.
        let ents = build_entities("1.2.3.4", &data(r#"{"loc":"0,0"}"#), "s");
        assert!(one(&ents, EntityKind::Coordinates).is_none());
        let ents = build_entities("1.2.3.4", &data(r#"{"loc":"0.001,0.001"}"#), "s");
        assert!(one(&ents, EntityKind::Coordinates).is_none());
    }

    #[test]
    fn address_omits_region_when_absent() {
        let ents = build_entities("1.2.3.4", &data(r#"{"city":"Sydney","country":"AU"}"#), "s");
        assert_eq!(one(&ents, EntityKind::Address).unwrap().value, "Sydney, AU");
    }

    #[test]
    fn org_without_as_prefix_yields_no_asn() {
        let ents = build_entities("1.2.3.4", &data(r#"{"org":"Cloudflare Inc"}"#), "s");
        assert!(one(&ents, EntityKind::Organisation).is_some());
        assert!(one(&ents, EntityKind::Asn).is_none());
    }

    #[test]
    fn dotless_hostname_is_not_a_domain() {
        let ents = build_entities("1.2.3.4", &data(r#"{"hostname":"localhost"}"#), "s");
        assert!(one(&ents, EntityKind::Domain).is_none());
    }
}
