//! ip-api.com IP geolocation. Free tier (HTTP only), 45 req/min limit.
//!
//! Yields a Coordinates entity (when lat/lon present) and an Organisation
//! entity (when org/ASN present).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
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

/// Map a decoded ip-api.com record to its entities. **Pure** (no network/IO),
/// so the geo → Coordinates/Address/Asn/Organisation mapping is unit-testable
/// directly off JSON fixtures.
///
/// Gates internally (both moved here from the transport shell so they are
/// tested): a non-`"success"` status yields an empty `Vec`, and a CDN/anycast
/// edge IP — [`crate::core::validation::is_cdn_edge_ip`] — is skipped (its geo
/// is the answering datacenter's, not the subject's).
///
/// Confidence is scaled by IP type (hosting/proxy/mobile); coordinates pass the
/// shared [`crate::util::geo::coarse_provider_coords`] gate (4-dp `geoint`
/// entity, `country:`/`au-state:` tags); the Address is suppressed for a
/// datacenter/proxy IP; blank scalar fields are kept out of evidence.
fn build_entities(data: &IpApiResp, ip: &str, scan_id: &str) -> Vec<Entity> {
    if data.status != "success" {
        return Vec::new();
    }

    // A CDN/anycast edge IP (Cloudflare, Fastly, …) geolocates to whichever
    // datacenter answered the query — Montreal, Toronto, San Francisco — NOT
    // to the subject. Emitting those as Coordinates/Address PII produced the
    // false "geolocation convergence" and "email + physical location" hits in
    // a real scan of an Australian subject. Skip geo for edge IPs entirely.
    if crate::core::validation::is_cdn_edge_ip(ip) {
        tracing::debug!(
            module = SRC,
            ip = %ip,
            "skipping IP-geo — CDN/anycast edge IP, location is datacenter not subject"
        );
        return Vec::new();
    }

    let mut result = Vec::new();

    // Confidence scaled by IP type: hosting/proxy locations are
    // datacenter-level (low geo value), mobile IPs are cell-tower-level.
    // Recalibrated downward from the old confidence::LOW_MEDIUM / confidence::MEDIUM_PLUS / confidence::HIGH_PLUS trio — free
    // IP-geo providers routinely miss residential geolocation by 30–80 km
    // even for "fixed" connections, which the prior confidence overstated;
    // a single overstated IP-geo hit was outranking a corroborated WiGLE
    // WiFi fix at confidence::HIGH_PLUSPLUS_PLUS.
    let geo_conf = if data.hosting == Some(true) || data.proxy == Some(true) {
        0.35
    } else if data.mobile == Some(true) {
        confidence::MEDIUM
    } else {
        confidence::MEDIUM_PLUS
    };
    // `coarse_provider_coords` returns None for an implausible fix, so this
    // `if` is false in exactly the same cases the old `is_plausible_provider_coord`
    // guard made it false — the `else if` below (lat/lon present but rejected)
    // still fires identically.
    if let (Some(lat), Some(lon)) = (data.lat, data.lon)
        && let Some(mut e) = crate::util::geo::coarse_provider_coords(lat, lon, geo_conf, scan_id)
    {
        if let Some(cc) = data.country_code.as_deref() {
            e.tag(format!("country:{}", cc.to_uppercase()));
        }
        if data.country_code.as_deref() == Some("AU")
            && let Some(state) = crate::util::geo::au_state_for_coords(lat, lon)
        {
            e.tag(format!("au-state:{state}"));
        }
        crate::util::geo::tag_flags(
            &mut e,
            &[
                (data.proxy, "proxy"),
                (data.hosting, "hosting"),
                (data.mobile, "mobile"),
            ],
        );
        let ev = [
            (
                "country_code",
                data.country_code.as_deref().filter(|s| !s.is_empty()),
            ),
            ("zip", data.zip.as_deref().filter(|s| !s.is_empty())),
            (
                "timezone",
                data.timezone.as_deref().filter(|s| !s.is_empty()),
            ),
            ("isp", data.isp.as_deref().filter(|s| !s.is_empty())),
            ("asn", data.asn.as_deref().filter(|s| !s.is_empty())),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|v| (key, v.to_string())))
        .chain(
            [
                ("is_proxy", data.proxy),
                ("is_hosting", data.hosting),
                ("is_mobile", data.mobile),
            ]
            .into_iter()
            .filter_map(|(key, value)| value.map(|v| (key, v.to_string()))),
        )
        .fold(
            Evidence::new(SRC, format!("IP geolocation for {ip}"))
                // The originating IP, recorded explicitly so a finalise pass can
                // robustly tie this coordinate back to its source IpAddress (e.g.
                // to recognise a person's breach login IP) without parsing the
                // summary string.
                .with_attr("ip", ip)
                .with_attr("country", data.country.as_deref().unwrap_or("-"))
                .with_attr("region", data.region_name.as_deref().unwrap_or("-"))
                .with_attr("city", data.city.as_deref().unwrap_or("-"))
                .with_attr("latitude", lat.to_string())
                .with_attr("longitude", lon.to_string())
                .with_attr("source", "ip-api.com"),
            |ev, (key, v)| ev.with_attr(key, v),
        );
        e.add_evidence(ev);
        result.push(e);
    } else if data.lat.is_some() || data.lon.is_some() {
        // ip-api returned coordinates but they failed the plausibility
        // gate (Null Island / sentinel "no-fix" bands). Previously dropped
        // silently — now logged so a missing geo fix is never a black box.
        tracing::debug!(
            module = SRC,
            ip = %ip,
            lat = ?data.lat,
            lon = ?data.lon,
            "dropped IP-geo coordinate — failed is_plausible_provider_coord (likely Null Island / no-fix sentinel)"
        );
    }

    // Emit Address entity from city/region/country — but NOT for a
    // hosting/datacenter or proxy IP: that "address" is the server's, never
    // the subject's, and at confidence::HIGH it outweighed genuine residential signals
    // and seeded false identity-location correlations.
    let is_datacenter = data.hosting == Some(true) || data.proxy == Some(true);
    let city = data.city.as_deref().unwrap_or("");
    let region = data.region_name.as_deref().unwrap_or("");
    let country = data.country.as_deref().unwrap_or("");
    if !is_datacenter && !city.is_empty() && !country.is_empty() {
        let addr = crate::util::geo::compose_address(city, region, country);
        let mut ae = Entity::new(EntityKind::Address, &addr, confidence::HIGH, scan_id);
        ae.tag("geoint");
        ae.add_evidence(Evidence::new(SRC, format!("IP address for {ip}")));
        result.push(ae);
    }

    // Emit ASN entity
    if let Some(asn) = &data.asn
        && !asn.is_empty()
    {
        result.push(crate::util::geo::ip_asn_entity(asn, SRC, ip, scan_id));
    }

    // Emit reverse DNS domain if present in ISP name
    if let Some(org) = &data.org {
        let mut e = Entity::new(EntityKind::Organisation, org, confidence::HIGH, scan_id);
        let ev = [
            ("isp", data.isp.as_deref().filter(|s| !s.is_empty())),
            (
                "country_code",
                data.country_code.as_deref().filter(|s| !s.is_empty()),
            ),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|v| (key, v)))
        .fold(
            Evidence::new(SRC, format!("IP org for {ip}"))
                .with_attr("asn", data.asn.as_deref().unwrap_or("-")),
            |ev, (key, v)| ev.with_attr(key, v),
        );
        e.add_evidence(ev);
        result.push(e);
    }

    result
}

#[async_trait]
impl Module for IpGeo {
    fn name(&self) -> &'static str {
        "ip_geo"
    }

    fn description(&self) -> &'static str {
        "IP geolocation recon — geolocates an IP and fingerprints ISP, proxy, and hosting infrastructure"
    }

    fn priority(&self) -> u8 {
        28
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
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
        // The Geo default (T1591.001 Physical Locations) covers the coordinates
        // and address entities but misses the ASN block (T1590.005 IP Addresses)
        // and ISP/AS name mapped to an Organisation (T1591.002 Business
        // Relationships). Declare all three explicitly.
        &["T1590.005", "T1591.001", "T1591.002"]
    }

    fn max_timeout_ms(&self) -> u64 {
        // Single network request with no per-request timeout; the 3s default
        // would kill a slow-but-connected response as a spurious "timeout".
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // ip-api.com free tier is IPv4-only — universal dispatcher gate
        // lets public IPv6 through, so reject it here.
        if crate::util::preflight::should_skip_external_ipv4(&target.value) {
            return Ok(ModuleResult::new());
        }
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

        let mut result = ModuleResult::new();
        result.entities = build_entities(&data, &target.value, &ctx.scan_id);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
