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
    #[allow(dead_code)]
    pub(super) ip: Option<String>,
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
    #[serde(default, rename = "ipAddress")]
    #[allow(dead_code)]
    pub(super) ip_address: Option<String>,
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

    // Source 1: ipapi.co (free, HTTPS, 1000/day)
    if !ctx.cancel.is_cancelled()
        && let Ok(data) = fetch_json::<IpApiCoResp>(
            &ctx.http,
            SRC,
            &format!("https://ipapi.co/{}/json/", target.value),
        )
        .await
        && data.error != Some(true)
        && let (Some(lat), Some(lon)) = (data.latitude, data.longitude)
        && is_valid_coords(lat, lon)
    {
        let coords = format!("{lat:.6},{lon:.6}");
        if seen_coords.insert(coords.clone()) {
            let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.68, &ctx.scan_id);
            e.tag("geoint");
            if let Some(cc) = data.country_code.as_deref() {
                e.tag(format!("country:{}", cc.to_uppercase()));
            }
            if data.country_code.as_deref() == Some("AU")
                && let Some(state) = crate::util::geo::au_state_for_coords(lat, lon)
            {
                e.tag(format!("au-state:{state}"));
            }

            // Fold the present optional fields into the evidence in one pass.
            let ev = [
                ("city", data.city.as_deref()),
                ("region", data.region.as_deref()),
                ("country", data.country_name.as_deref()),
                ("postal", data.postal.as_deref()),
                ("timezone", data.timezone.as_deref()),
                ("org", data.org.as_deref()),
                ("asn", data.asn.as_deref()),
            ]
            .into_iter()
            .filter_map(|(k, v)| v.map(|val| (k, val)))
            .fold(
                Evidence::new(SRC, format!("IP geo for {} via ipapi.co", target.value))
                    .with_attr("latitude", lat.to_string())
                    .with_attr("longitude", lon.to_string())
                    .with_attr("source", "ipapi.co"),
                |ev, (k, val)| ev.with_attr(k, val),
            );

            e.add_evidence(ev);
            result.push(e);
        }
    }

    // Source 2: freeipapi.com (free, HTTPS, no limit documented)
    if !ctx.cancel.is_cancelled()
        && let Ok(data) = fetch_json::<FreeIpApiResp>(
            &ctx.http,
            SRC,
            &format!("https://freeipapi.com/api/json/{}", target.value),
        )
        .await
        && let (Some(lat), Some(lon)) = (data.latitude, data.longitude)
        && is_valid_coords(lat, lon)
    {
        let coords = format!("{lat:.6},{lon:.6}");
        if seen_coords.insert(coords.clone()) {
            let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.62, &ctx.scan_id);
            e.tag("geoint");
            if let Some(cc) = data.country_code.as_deref() {
                e.tag(format!("country:{}", cc.to_uppercase()));
            }
            if data.country_code.as_deref() == Some("AU")
                && let Some(state) = crate::util::geo::au_state_for_coords(lat, lon)
            {
                e.tag(format!("au-state:{state}"));
            }
            if data.is_proxy == Some(true) {
                e.tag("proxy");
            }

            // Fold the present optional string fields in one pass; is_proxy is a
            // bool, attached separately below.
            let mut ev = [
                ("city", data.city_name.as_deref()),
                ("region", data.region_name.as_deref()),
                ("country", data.country_name.as_deref()),
                ("postal", data.zip_code.as_deref()),
                ("timezone", data.timezone.as_deref()),
            ]
            .into_iter()
            .filter_map(|(k, v)| v.map(|val| (k, val)))
            .fold(
                Evidence::new(
                    SRC,
                    format!("IP geo for {} via freeipapi.com", target.value),
                )
                .with_attr("latitude", lat.to_string())
                .with_attr("longitude", lon.to_string())
                .with_attr("source", "freeipapi.com"),
                |ev, (k, val)| ev.with_attr(k, val),
            );
            if let Some(v) = data.is_proxy {
                ev = ev.with_attr("is_proxy", v.to_string());
            }

            e.add_evidence(ev);
            result.push(e);
        }
    }

    Ok(result)
}
