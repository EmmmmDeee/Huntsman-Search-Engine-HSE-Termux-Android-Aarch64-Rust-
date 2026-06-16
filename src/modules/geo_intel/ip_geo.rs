//! IP geolocation via free public APIs (ipapi.co, freeipapi.com).

use std::collections::HashSet;

use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{ModuleContext, ModuleResult},
    scan::Target,
};
use crate::util::geo::is_valid_coords;
use crate::util::http::fetch_json;

use super::SRC;

// ─── ipapi.co response ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub(super) struct IpApiCoResp {
    #[serde(default)]
    pub(super) city: Option<String>,
    #[serde(default)]
    pub(super) region: Option<String>,
    #[serde(default)]
    pub(super) country_name: Option<String>,
    #[serde(default)]
    pub(super) country_code: Option<String>,
    #[serde(default)]
    pub(super) postal: Option<String>,
    #[serde(default)]
    pub(super) latitude: Option<f64>,
    #[serde(default)]
    pub(super) longitude: Option<f64>,
    #[serde(default)]
    pub(super) timezone: Option<String>,
    #[serde(default)]
    pub(super) org: Option<String>,
    #[serde(default)]
    pub(super) asn: Option<String>,
    #[serde(default)]
    pub(super) error: Option<bool>,
}

// ─── freeipapi.com response ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub(super) struct FreeIpApiResp {
    #[serde(default)]
    pub(super) latitude: Option<f64>,
    #[serde(default)]
    pub(super) longitude: Option<f64>,
    #[serde(default, rename = "countryName")]
    pub(super) country_name: Option<String>,
    #[serde(default, rename = "countryCode")]
    pub(super) country_code: Option<String>,
    #[serde(default, rename = "cityName")]
    pub(super) city_name: Option<String>,
    #[serde(default, rename = "regionName")]
    pub(super) region_name: Option<String>,
    #[serde(default, rename = "zipCode")]
    pub(super) zip_code: Option<String>,
    #[serde(default, rename = "timeZone")]
    pub(super) timezone: Option<String>,
    #[serde(default, rename = "isProxy")]
    pub(super) is_proxy: Option<bool>,
}

// ─── IP geolocation: additional free sources ────────────────────────────────

pub(super) async fn process_ip(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let mut result = ModuleResult::new();
    let mut seen_coords = HashSet::new();
    let ip = target.value.as_str();

    // Shared trust gate: a CDN/anycast edge IP's geo is the answering
    // datacenter, not the subject — suppress its coordinates entirely (the same
    // rule ipinfo/ip2location/ipquery apply). Single source in core::validation.
    let geo_untrusted = crate::core::validation::untrusted_ip_geo_reason(ip);
    if let Some(reason) = geo_untrusted {
        tracing::debug!(
            module = SRC,
            %ip,
            reason,
            "skipping IP-geo coordinates — location is the infrastructure, not the subject"
        );
    }
    let untrusted = geo_untrusted.is_some();

    // Source 1: ipapi.co (free, HTTPS, 1000/day)
    if !ctx.cancel.is_cancelled()
        && let Ok(data) =
            fetch_json::<IpApiCoResp>(&ctx.http, SRC, &format!("https://ipapi.co/{ip}/json/")).await
        && let Some(e) = build_ipapico_entity(&data, ip, untrusted, &ctx.scan_id)
        && seen_coords.insert(e.value.clone())
    {
        result.push(e);
    }

    // Source 2: freeipapi.com (free, HTTPS, no limit documented)
    if !ctx.cancel.is_cancelled()
        && let Ok(data) = fetch_json::<FreeIpApiResp>(
            &ctx.http,
            SRC,
            &format!("https://freeipapi.com/api/json/{ip}"),
        )
        .await
        && let Some(e) = build_freeipapi_entity(&data, ip, untrusted, &ctx.scan_id)
        && seen_coords.insert(e.value.clone())
    {
        result.push(e);
    }

    Ok(result)
}

/// Tag a coordinate entity with `geoint`, its ISO country, and (for AU) the
/// derived state. Shared by both source builders.
fn tag_country(e: &mut Entity, country_code: Option<&str>, lat: f64, lon: f64) {
    e.tag("geoint");
    if let Some(cc) = country_code {
        e.tag(format!("country:{}", cc.to_uppercase()));
        if cc.eq_ignore_ascii_case("AU")
            && let Some(state) = crate::util::geo::au_state_for_coords(lat, lon)
        {
            e.tag(format!("au-state:{state}"));
        }
    }
}

/// Build the ipapi.co `Coordinates` entity. **Pure.** `None` when the API
/// errored, the coordinates are absent/invalid, or `geo_untrusted` (the IP's
/// location is infrastructure, not the subject).
pub(super) fn build_ipapico_entity(
    data: &IpApiCoResp,
    ip: &str,
    geo_untrusted: bool,
    scan_id: &str,
) -> Option<Entity> {
    if data.error == Some(true) || geo_untrusted {
        return None;
    }
    let (lat, lon) = (data.latitude?, data.longitude?);
    if !is_valid_coords(lat, lon) {
        return None;
    }
    let coords = format!("{lat:.6},{lon:.6}");
    let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.68, scan_id);
    tag_country(&mut e, data.country_code.as_deref(), lat, lon);

    let ev = [
        ("city", data.city.as_deref()),
        ("region", data.region.as_deref()),
        ("country", data.country_name.as_deref()),
        ("country_iso", data.country_code.as_deref()),
        ("postal", data.postal.as_deref()),
        ("timezone", data.timezone.as_deref()),
        ("org", data.org.as_deref()),
        ("asn", data.asn.as_deref()),
    ]
    .into_iter()
    .filter_map(|(k, v)| v.map(|val| (k, val)))
    .fold(
        Evidence::new(SRC, format!("IP geo for {ip} via ipapi.co"))
            .with_attr("latitude", lat.to_string())
            .with_attr("longitude", lon.to_string())
            .with_attr("source", "ipapi.co"),
        |ev, (k, val)| ev.with_attr(k, val),
    );
    e.add_evidence(ev);
    Some(e)
}

/// Build the freeipapi.com `Coordinates` entity. **Pure.** `None` when the
/// coordinates are absent/invalid, `geo_untrusted`, or the IP is flagged a
/// proxy (an anonymiser exit's location is not the subject's).
pub(super) fn build_freeipapi_entity(
    data: &FreeIpApiResp,
    ip: &str,
    geo_untrusted: bool,
    scan_id: &str,
) -> Option<Entity> {
    if geo_untrusted || data.is_proxy == Some(true) {
        return None;
    }
    let (lat, lon) = (data.latitude?, data.longitude?);
    if !is_valid_coords(lat, lon) {
        return None;
    }
    let coords = format!("{lat:.6},{lon:.6}");
    let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.62, scan_id);
    tag_country(&mut e, data.country_code.as_deref(), lat, lon);

    let ev = [
        ("city", data.city_name.as_deref()),
        ("region", data.region_name.as_deref()),
        ("country", data.country_name.as_deref()),
        ("country_iso", data.country_code.as_deref()),
        ("postal", data.zip_code.as_deref()),
        ("timezone", data.timezone.as_deref()),
    ]
    .into_iter()
    .filter_map(|(k, v)| v.map(|val| (k, val)))
    .fold(
        Evidence::new(SRC, format!("IP geo for {ip} via freeipapi.com"))
            .with_attr("latitude", lat.to_string())
            .with_attr("longitude", lon.to_string())
            .with_attr("source", "freeipapi.com"),
        |ev, (k, val)| ev.with_attr(k, val),
    );
    e.add_evidence(ev);
    Some(e)
}
