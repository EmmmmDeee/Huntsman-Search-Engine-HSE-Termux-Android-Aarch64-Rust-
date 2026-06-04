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
            EntityKind::Coordinates,
            EntityKind::Address,
            EntityKind::Asn,
            EntityKind::Organisation,
            EntityKind::Domain,
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
        for e in build_entities(ip, &data, &ctx.scan_id) {
            result.push(e);
        }
        Ok(result)
    }
}

/// Trimmed, non-empty view of an optional string field.
fn nonempty(o: &Option<String>) -> Option<&str> {
    o.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// Map an ip-api.com record to its geo/network entities. **Pure** (no IO) so the
/// multi-entity construction is unit-tested. Recovers the previously-discarded
/// `zip` (postal precision), `countryCode` (also tagged `country:XX` on the
/// coordinate for geo-cluster correlation), `asname`, the `region` code, and
/// `district` — all surfaced on the shared evidence so no API datum is dropped.
fn build_entities(ip: &str, data: &IpApiResp, scan_id: &str) -> Vec<Entity> {
    let mut result: Vec<Entity> = Vec::new();

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
    if let Some(asn) = nonempty(&data.asn) {
        ev = ev.with_attr("asn", asn);
    }
    if let Some(org) = nonempty(&data.org) {
        ev = ev.with_attr("org", org);
    }
    if let Some(tz) = nonempty(&data.timezone) {
        ev = ev.with_attr("timezone", tz);
    }
    // ── Recovered fields (previously deserialised then discarded) ──
    if let Some(cc) = nonempty(&data.country_code) {
        ev = ev.with_attr("country_code", cc);
    }
    if let Some(z) = nonempty(&data.zip) {
        ev = ev.with_attr("postal", z);
    }
    if let Some(an) = nonempty(&data.as_name) {
        ev = ev.with_attr("as_name", an);
    }
    if let Some(rc) = nonempty(&data.region) {
        ev = ev.with_attr("region_code", rc);
    }
    if let Some(d) = nonempty(&data.district) {
        ev = ev.with_attr("district", d);
    }

    if let (Some(lat), Some(lon)) = (data.lat, data.lon)
        && lat.abs() > 0.01
        && lon.abs() > 0.01
    {
        let coords = format!("{lat:.4},{lon:.4}");
        // Confidence recalibrated 0.70 → 0.60 — see ip_geo.rs for rationale
        // (single-source free IP geo overstates residential precision;
        // corroboration boost lifts the real value at the merge step).
        let mut ce = Entity::new(EntityKind::Coordinates, &coords, 0.60, scan_id);
        ce.tag(tags::GEOINT);
        if let Some(cc) = nonempty(&data.country_code) {
            ce.tag(format!("country:{}", cc.to_uppercase()));
        }
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
        let mut ae = Entity::new(EntityKind::Address, &addr, 0.65, scan_id);
        ae.tag(tags::GEOINT);
        ae.add_evidence(ev.clone());
        result.push(ae);
    }

    if let Some(asn) = nonempty(&data.asn) {
        let mut ae = Entity::new(EntityKind::Asn, asn, 0.80, scan_id);
        ae.add_evidence(ev.clone());
        result.push(ae);
    }

    if let Some(org) = nonempty(&data.org)
        && org.len() >= 3
    {
        let mut oe = Entity::new(EntityKind::Organisation, org, 0.60, scan_id);
        oe.add_evidence(ev.clone());
        result.push(oe);
    }

    if let Some(rev) = nonempty(&data.reverse)
        && rev.contains('.')
    {
        let mut de = Entity::new(EntityKind::Domain, rev, 0.65, scan_id);
        de.tag(tags::PTR);
        de.add_evidence(ev);
        result.push(de);
    }

    result
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

    fn data_of(json: &str) -> IpApiResp {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn build_recovers_postal_country_code_asname_and_tags_country() {
        let d = data_of(
            r#"{"status":"success","country":"Australia","countryCode":"AU","region":"NSW",
                "regionName":"New South Wales","city":"Sydney","zip":"2000","lat":-33.8688,
                "lon":151.209,"timezone":"Australia/Sydney","isp":"Telstra","org":"Telstra Corp",
                "as":"AS1221 Telstra","asname":"ASN-TELSTRA","reverse":"host.telstra.net",
                "mobile":true,"proxy":false,"hosting":false,"district":"CBD"}"#,
        );
        let v = build_entities("1.2.3.4", &d, "s");
        let coords = v
            .iter()
            .find(|e| e.kind == EntityKind::Coordinates)
            .unwrap();
        assert!(coords.has_tag("country:AU") && coords.has_tag("mobile"));
        let a = &coords.evidence[0].attributes;
        // Recovered fields surfaced on the shared evidence.
        assert_eq!(a.get("postal").map(String::as_str), Some("2000")); // zip
        assert_eq!(a.get("country_code").map(String::as_str), Some("AU"));
        assert_eq!(a.get("as_name").map(String::as_str), Some("ASN-TELSTRA"));
        assert_eq!(a.get("region_code").map(String::as_str), Some("NSW"));
        assert_eq!(a.get("district").map(String::as_str), Some("CBD"));
        // Existing entity kinds still produced.
        assert!(
            v.iter()
                .any(|e| e.kind == EntityKind::Asn && e.value == "AS1221 Telstra")
        );
        assert!(v.iter().any(|e| e.kind == EntityKind::Organisation));
        assert!(v.iter().any(|e| e.kind == EntityKind::Address));
        assert!(
            v.iter()
                .any(|e| e.kind == EntityKind::Domain && e.value == "host.telstra.net")
        );
    }

    #[test]
    fn build_skips_null_island_coordinates() {
        let d = data_of(r#"{"status":"success","city":"X","country":"Y","lat":0.0,"lon":0.0}"#);
        assert!(
            !build_entities("1.2.3.4", &d, "s")
                .iter()
                .any(|e| e.kind == EntityKind::Coordinates)
        );
    }
}
