//! ipwho.is IP geolocation — free, HTTPS, no API key.
//!
//! Second-source geo module alongside `ip_geo` (ip-api.com, HTTP-only).
//! Having two independent geo sources on the same IP lets the AU-014
//! geolocation-cluster correlation rule fire, corroborating the location.
//!
//! Endpoint: `GET https://ipwho.is/{ip}`
//! Returns JSON with lat, lon, country, city, region, ISP, ASN, timezone.
//! No rate limit documented; we keep requests reasonable via the engine's
//! per-module timeout and inter-module throttle.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::geo::is_plausible_provider_coord;
use crate::util::http::fetch_json;

const SRC: &str = "ip_whois_geo";

pub struct IpWhois;

#[derive(Deserialize)]
struct Resp {
    #[serde(default)]
    success: Option<bool>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    postal: Option<String>,
    #[serde(default)]
    timezone_id: Option<String>,
    #[serde(default)]
    connection: Option<Connection>,
}

#[derive(Deserialize)]
struct Connection {
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default, rename = "asn")]
    asn_num: Option<u64>,
}

/// Map a decoded ipwho.is record to its entities. **Pure** (no network/IO), so
/// the geo → Coordinates/Address/Organisation/Asn mapping is unit-testable
/// directly off JSON fixtures.
///
/// Gates internally (both moved here from the transport shell so they are
/// tested): a `success:false` lookup yields an empty `Vec`, and a CDN/anycast
/// edge IP — [`crate::core::validation::is_cdn_edge_ip`] — is skipped (its geo
/// is the datacenter's, not the subject's).
///
/// Coordinates are gated by the coarse-provider
/// [`crate::util::geo::is_plausible_provider_coord`] (null-island band /
/// out-of-range / non-finite rejected) and formatted to 6 dp; an `AU`
/// country-code with an in-box fix also gets an `au-state:` tag. Blank scalar
/// fields are kept out of evidence and a blank country code adds no `country:`
/// tag.
fn build_entities(data: &Resp, ip: &str, scan_id: &str) -> Vec<Entity> {
    if data.success == Some(false) {
        return Vec::new();
    }

    // CDN/anycast edge IP → datacenter location, not the subject. Skip (see
    // ip_geo.rs); prevents false identity-location correlations.
    if crate::core::validation::is_cdn_edge_ip(ip) {
        return Vec::new();
    }

    let mut result = Vec::new();

    if let (Some(lat), Some(lon)) = (data.latitude, data.longitude) {
        // Coarse-provider validator: ipwho.is is an IP-geolocation API, so
        // alongside Null Island / out-of-range / non-finite it also emits a
        // sub-degree jitter band around (0,0) as its "no fix" placeholder.
        // Gate on the same is_plausible_provider_coord the other IP/WiFi-geo
        // sources use (ip_geo/ipinfo/ipapi/ip2location/ipquery/wigle) so a
        // 0.005,0.005 placeholder can't become a high-confidence false fix
        // that poisons the geo-cluster correlator.
        if !is_plausible_provider_coord(lat, lon) {
            return result;
        }

        let coords = format!("{lat:.6},{lon:.6}");
        // Confidence recalibrated 0.68 → 0.55 — WHOIS-based geo is
        // particularly coarse (registrar address, not host
        // location) so this provider should rank below the
        // residential-DB-backed IP-geo modules.
        let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.55, scan_id);
        e.tag("geoint");
        if let Some(cc) = data.country_code.as_deref().filter(|c| !c.is_empty()) {
            e.tag(format!("country:{}", cc.to_uppercase()));
        }
        if data.country_code.as_deref() == Some("AU")
            && let Some(state) = crate::util::geo::au_state_for_coords(lat, lon)
        {
            e.tag(format!("au-state:{state}"));
        }

        let conn = data.connection.as_ref();
        let ev = [
            ("country", data.country.as_deref()),
            ("country_code", data.country_code.as_deref()),
            ("region", data.region.as_deref()),
            ("city", data.city.as_deref()),
            ("postal", data.postal.as_deref()),
            ("timezone", data.timezone_id.as_deref()),
            ("isp", conn.and_then(|c| c.isp.as_deref())),
        ]
        .into_iter()
        .filter_map(|(key, value)| {
            value
                .filter(|s| !s.is_empty())
                .map(|v| (key, v.to_string()))
        })
        .chain(
            conn.and_then(|c| c.asn_num)
                .map(|a| ("asn", format!("AS{a}"))),
        )
        .chain(
            conn.and_then(|c| c.org.as_deref())
                .filter(|s| !s.is_empty())
                .map(|o| ("org", o.to_string())),
        )
        .fold(
            Evidence::new(SRC, format!("IP geolocation for {ip}"))
                .with_attr("latitude", lat.to_string())
                .with_attr("longitude", lon.to_string())
                .with_attr("source", "ipwho.is"),
            |ev, (key, v)| ev.with_attr(key, v),
        );

        e.add_evidence(ev);
        result.push(e);

        // Synthesize an Address entity from the city/region/country
        // so expansion can chain into forward_geocode without an
        // extra API call.
        let parts: Vec<&str> = [
            data.city.as_deref(),
            data.region.as_deref(),
            data.country.as_deref(),
        ]
        .iter()
        .filter_map(|p| *p)
        .filter(|p| !p.is_empty())
        .collect();

        if parts.len() >= 2 {
            let addr_str = parts.join(", ");
            let mut addr = Entity::new(EntityKind::Address, &addr_str, 0.50, scan_id);
            addr.tag("geoint");
            addr.tag("derived");
            addr.add_evidence(
                Evidence::new(
                    "ip_whois_geo",
                    format!("Address derived from IP geo for {ip}"),
                )
                .with_attr("source", "ipwho.is"),
            );
            result.push(addr);
        }
    }

    if let Some(conn) = &data.connection
        && let Some(org) = &conn.org
        && !org.is_empty()
    {
        let mut e = Entity::new(EntityKind::Organisation, org, 0.60, scan_id);
        let ev = [
            ("asn", conn.asn_num.map(|a| format!("AS{a}"))),
            (
                "isp",
                conn.isp
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .map(String::from),
            ),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|v| (key, v)))
        .fold(
            Evidence::new(SRC, format!("IP org for {ip}")),
            |ev, (key, v)| ev.with_attr(key, v),
        );
        e.add_evidence(ev);
        result.push(e);
    }

    if let Some(conn) = &data.connection
        && let Some(asn) = conn.asn_num
    {
        let asn_str = format!("AS{asn}");
        let mut ae = Entity::new(EntityKind::Asn, &asn_str, 0.80, scan_id);
        ae.tag("ip-whois");
        ae.add_evidence(Evidence::new(SRC, format!("ASN for {ip}")));
        result.push(ae);
    }

    result
}

#[async_trait]
impl Module for IpWhois {
    fn name(&self) -> &'static str {
        "ip_whois_geo"
    }

    fn description(&self) -> &'static str {
        "HTTPS IP geolocation via ipwho.is (second source for geo-cluster correlation)"
    }

    fn priority(&self) -> u8 {
        27
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
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

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Infrastructure default (T1590.005 + T1596.005): T1590.005 is correct
        // for the ASN/IP block, but T1596.005 (Scan Databases like Shodan) does
        // not describe a passive geolocation API. Additionally the module maps
        // IPs to physical locations (T1591.001) and identifies the ISP/operator
        // as an Organisation (T1591.002) — both absent from the default.
        &["T1590.005", "T1591.001", "T1591.002"]
    }

    fn max_timeout_ms(&self) -> u64 {
        // Single network request with no per-request timeout; the 3s default
        // would kill a slow-but-connected response as a spurious "timeout".
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let url = format!("https://ipwho.is/{}", target.value);
        let data: Resp = fetch_json(&ctx.http, SRC, &url).await?;

        let mut result = ModuleResult::new();
        result.entities = build_entities(&data, &target.value, &ctx.scan_id);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
