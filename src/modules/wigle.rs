//! WiGLE WiFi network search by geographic point. Key-gated.
//!
//! Endpoint: `GET https://api.wigle.net/api/v2/network/search`
//! Auth:     HTTP Basic — `HUNTSMAN_WIGLE_USER` (API name) + `HUNTSMAN_WIGLE_TOKEN`.
//!
//! Accepts a `Coordinates` target (`"lat,lon"`). WiGLE wants a bounding
//! box; we use an adaptive strategy: start at ±0.002° (~220m), widen to
//! ±0.01° (~1.1km) only if the tight box returns zero results. This
//! preserves API quota while ensuring populated areas get results.
//!
//! Intelligence extracted per API call:
//! - Coordinates entity (corroborated by WiFi observation data)
//! - Address entity from city/region/country fields (free geolocation)
//! - SSID-derived intelligence (names, business identifiers)
//! - WiFi density and encryption breakdown (neighbourhood profiling)
//! - MacAddress entities for device/AP correlation (top 5 only)

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

const USER_ENV: &str = "HUNTSMAN_WIGLE_USER";
const TOKEN_ENV: &str = "HUNTSMAN_WIGLE_TOKEN";
const HARDCODED_USER: &str = "AID4493a33e2df9d07ab9666a27c8aead17";
const HARDCODED_TOKEN: &str = "1aedb7ad0171ff3d6be5a844cca5d977";

#[derive(Deserialize)]
struct Resp {
    #[serde(default)]
    success: Option<bool>,
    #[serde(default, rename = "resultCount")]
    result_count: Option<u64>,
    #[serde(default, rename = "totalResults")]
    total_results: Option<u64>,
    #[serde(default)]
    results: Vec<Network>,
}

#[derive(Deserialize)]
struct Network {
    #[serde(default)]
    ssid: Option<String>,
    #[serde(default)]
    netid: Option<String>,
    #[serde(default)]
    encryption: Option<String>,
    #[serde(default)]
    lastupdt: Option<String>,
    #[serde(default)]
    trilat: Option<f64>,
    #[serde(default)]
    trilong: Option<f64>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    postalcode: Option<String>,
}

const SRC: &str = "wigle";

pub struct Wigle;

#[async_trait]
impl Module for Wigle {
    fn name(&self) -> &'static str {
        "wigle"
    }
    fn description(&self) -> &'static str {
        "WiGLE wireless network geolocation database"
    }
    fn priority(&self) -> u8 {
        18
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Coordinates | TargetKind::MacAddress)
    }
    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let user = ctx.key_opt(USER_ENV).unwrap_or(HARDCODED_USER);
        let token = ctx.key_opt(TOKEN_ENV).unwrap_or(HARDCODED_TOKEN);

        // MacAddress target: BSSID detail lookup → coordinates
        if target.kind == TargetKind::MacAddress {
            return self.bssid_lookup(user, token, &target.value, ctx).await;
        }

        let (lat, lon) = crate::util::geo::parse_coords(&target.value)?;

        // Adaptive bounding box: try tight first, widen if empty.
        // This saves API quota in dense areas while still finding
        // results in sparse ones.
        let body = {
            let tight = fetch_wigle(&ctx.http, user, token, lat, lon, 0.002).await?;
            if tight.success == Some(true)
                && tight.total_results.or(tight.result_count).unwrap_or(0) > 0
            {
                tight
            } else {
                fetch_wigle(&ctx.http, user, token, lat, lon, 0.01).await?
            }
        };

        if body.success != Some(true) {
            return Ok(ModuleResult::new());
        }
        let total = body
            .total_results
            .or(body.result_count)
            .unwrap_or(body.results.len() as u64);
        if total == 0 {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();

        // ── Primary: Coordinates entity with WiFi corroboration ─────
        let mut coords_entity =
            Entity::new(EntityKind::Coordinates, &target.value, 0.85, &ctx.scan_id);
        coords_entity.tag("wigle");
        coords_entity.tag("wifi-observed");

        let enc_types: Vec<String> = body
            .results
            .iter()
            .filter_map(|n| n.encryption.clone())
            .collect();
        let top_encryption = crate::util::freq::top_n(enc_types.iter().map(String::as_str), 5);

        let most_recent = body
            .results
            .iter()
            .filter_map(|n| n.lastupdt.as_deref())
            .max()
            .map(String::from);

        let mut ev = Evidence::new(
            "wigle",
            format!("WiGLE: {total} WiFi network(s) near {}", target.value),
        )
        .with_attr("total", total.to_string())
        .with_attr("returned", body.results.len().to_string());
        if !top_encryption.is_empty() {
            ev = ev.with_attr("top_encryption", top_encryption);
        }
        if let Some(ref t) = most_recent {
            ev = ev.with_attr("most_recent_observation", t);
        }

        // WiFi density classification — intelligence value
        let density = if total >= 50 {
            "dense-urban"
        } else if total >= 10 {
            "suburban"
        } else if total >= 2 {
            "sparse"
        } else {
            "isolated"
        };
        ev = ev.with_attr("density", density);
        coords_entity.tag(format!("wifi-density:{density}"));

        coords_entity.add_evidence(ev);
        result.push(coords_entity);

        // ── Address from WiGLE city/region/country (free geo!) ──────
        // Use the most common city/region/country across results for
        // consensus-based location.
        let cities: Vec<&str> = body
            .results
            .iter()
            .filter_map(|n| n.city.as_deref())
            .filter(|c| !c.is_empty())
            .collect();
        let regions: Vec<&str> = body
            .results
            .iter()
            .filter_map(|n| n.region.as_deref())
            .filter(|r| !r.is_empty())
            .collect();
        let countries: Vec<&str> = body
            .results
            .iter()
            .filter_map(|n| n.country.as_deref())
            .filter(|c| !c.is_empty() && *c != "US" && *c != "AU" && c.len() > 2)
            .collect();
        let postcodes: Vec<&str> = body
            .results
            .iter()
            .filter_map(|n| n.postalcode.as_deref())
            .filter(|p| !p.is_empty())
            .collect();

        let top_city = mode(&cities);
        let top_region = mode(&regions);
        let top_country = mode_or(&countries, || {
            body.results
                .iter()
                .find_map(|n| n.country.as_deref())
                .unwrap_or("")
        });
        let top_postcode = mode(&postcodes);

        let addr_parts: Vec<&str> = [top_city, top_region, top_country]
            .iter()
            .copied()
            .filter(|s| !s.is_empty())
            .collect();

        if addr_parts.len() >= 2 {
            let mut addr_str = addr_parts.join(", ");
            if !top_postcode.is_empty() {
                addr_str = format!("{addr_str} {top_postcode}");
            }
            let mut addr = Entity::new(EntityKind::Address, &addr_str, 0.65, &ctx.scan_id);
            addr.tag("wigle");
            addr.tag("wifi-derived");
            addr.add_evidence(
                Evidence::new(
                    "wigle",
                    format!("Address from WiFi AP consensus near {}", target.value),
                )
                .with_attr("networks_sampled", total.to_string())
                .with_attr("city", top_city)
                .with_attr("region", top_region)
                .with_attr("country", top_country),
            );
            if !top_postcode.is_empty() {
                addr.tag(format!("postcode:{top_postcode}"));
            }
            result.push(addr);
        }

        // ── SSID intelligence: extract names and business identifiers ──
        let mut ssid_names: Vec<String> = Vec::new();
        for net in &body.results {
            if let Some(ref ssid) = net.ssid {
                let ssid = ssid.trim();
                if ssid.is_empty() || ssid.len() < 4 || ssid.starts_with("DIRECT-") {
                    continue;
                }
                // Skip generic SSIDs
                let lower = ssid.to_lowercase();
                if GENERIC_SSIDS.iter().any(|g| lower.contains(g)) {
                    continue;
                }
                // SSIDs with separators that look like names: "Smith-Family"
                if ssid.contains('-') || ssid.contains('_') || ssid.contains(' ') {
                    let parts: Vec<&str> = ssid.split(['-', '_', ' ']).collect();
                    if parts.len() >= 2
                        && parts[0].len() >= 3
                        && parts[0].starts_with(|c: char| c.is_ascii_uppercase())
                    {
                        ssid_names.push(ssid.to_string());
                    }
                }
            }
        }
        ssid_names.sort();
        ssid_names.dedup();

        if !ssid_names.is_empty() {
            let top_ssids: Vec<&str> = ssid_names.iter().take(10).map(String::as_str).collect();
            let mut ssid_ev = Evidence::new(
                "wigle",
                format!(
                    "{} named WiFi network(s) near {}",
                    top_ssids.len(),
                    target.value
                ),
            )
            .with_attr("named_ssids", top_ssids.join(", "));
            if let Some(ref t) = most_recent {
                ssid_ev = ssid_ev.with_attr("most_recent", t);
            }
            // Attach to the coordinates entity's evidence
            if let Some(first) = result.entities.first_mut() {
                first.add_evidence(ssid_ev);
            }
        }

        // ── Top MAC addresses (AP BSSIDs) for device correlation ────
        // Only emit the 5 most precise (lowest trilat variance).
        let mut macs: Vec<(&str, f64)> = body
            .results
            .iter()
            .filter_map(|n| {
                let mac = n.netid.as_deref()?;
                let nlat = n.trilat.unwrap_or(lat);
                let nlon = n.trilong.unwrap_or(lon);
                let dlat = nlat - lat;
                let dlon = nlon - lon;
                let dist = (dlat * dlat + dlon * dlon).sqrt();
                Some((mac, dist))
            })
            .collect();
        macs.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        macs.dedup_by_key(|m| m.0);

        for (mac, _) in macs.iter().take(5) {
            if mac.len() >= 12 {
                let mut e = Entity::new(EntityKind::MacAddress, *mac, 0.60, &ctx.scan_id);
                e.tag("wigle");
                e.tag("wifi-ap");
                e.add_evidence(
                    Evidence::new(SRC, format!("WiFi AP near {}", target.value))
                        .with_attr("coordinates", &target.value),
                );
                result.push(e);
            }
        }

        Ok(result)
    }
}

async fn fetch_wigle(
    http: &reqwest::Client,
    user: &str,
    token: &str,
    lat: f64,
    lon: f64,
    d: f64,
) -> Result<Resp> {
    let url = format!(
        "https://api.wigle.net/api/v2/network/search?\
         latrange1={lat_lo:.6}&latrange2={lat_hi:.6}\
         &longrange1={lon_lo:.6}&longrange2={lon_hi:.6}\
         &onlymine=false&freenet=false&paynet=false\
         &resultsPerPage=100",
        lat_lo = lat - d,
        lat_hi = lat + d,
        lon_lo = lon - d,
        lon_hi = lon + d,
    );

    let resp = http
        .get(&url)
        .basic_auth(user, Some(token))
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| Error::module("wigle", e.to_string()))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(Error::module(
            "wigle",
            format!("HTTP {status}: {}", error_snippet(resp).await),
        ));
    }

    resp.json()
        .await
        .map_err(|e| Error::module("wigle", e.to_string()))
}

impl Wigle {
    async fn bssid_lookup(
        &self,
        user: &str,
        token: &str,
        bssid: &str,
        ctx: &ModuleContext,
    ) -> Result<ModuleResult> {
        let encoded = crate::util::http::urlencode(bssid);
        let url = format!("https://api.wigle.net/api/v2/network/detail?netid={encoded}&type=wifi");

        let resp = ctx
            .http
            .get(&url)
            .basic_auth(user, Some(token))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module("wigle", e.to_string()))?;

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        #[derive(Deserialize)]
        struct DetailResp {
            #[serde(default)]
            success: Option<bool>,
            #[serde(default)]
            results: Vec<Network>,
        }

        let body: DetailResp = resp
            .json()
            .await
            .map_err(|e| Error::module("wigle", e.to_string()))?;

        if body.success != Some(true) {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();

        if let Some(net) = body.results.first()
            && let Some(lat) = net.trilat
            && let Some(lon) = net.trilong
        {
            let coords_str = format!("{lat:.6},{lon:.6}");

            // Emit precise coordinates from BSSID triangulation
            if lat.abs() > 0.0001 || lon.abs() > 0.0001 {
                let mut e = Entity::new(EntityKind::Coordinates, &coords_str, 0.80, &ctx.scan_id);
                e.tag("geoint");
                e.tag("wigle");
                e.tag("bssid-located");
                e.add_evidence(
                    Evidence::new(SRC, format!("WiGLE BSSID {bssid} → coordinates"))
                        .with_attr("bssid", bssid)
                        .with_attr("latitude", lat.to_string())
                        .with_attr("longitude", lon.to_string()),
                );
                if let Some(ref ssid) = net.ssid {
                    e.tag(format!("ssid:{ssid}"));
                }
                result.push(e);
            }

            // Emit address from city/region/country
            let parts: Vec<&str> = [
                net.city.as_deref(),
                net.region.as_deref(),
                net.country.as_deref(),
            ]
            .iter()
            .filter_map(|p| *p)
            .filter(|p| !p.is_empty())
            .collect();

            if parts.len() >= 2 {
                let addr_str = parts.join(", ");
                let mut addr = Entity::new(EntityKind::Address, &addr_str, 0.72, &ctx.scan_id);
                addr.tag("wigle");
                addr.tag("bssid-located");
                addr.add_evidence(
                    Evidence::new(SRC, format!("WiGLE BSSID lookup for {bssid}"))
                        .with_attr("bssid", bssid)
                        .with_attr("coordinates", &coords_str),
                );
                result.push(addr);
            }

            // Emit SSID-derived intelligence from the BSSID's network name
            if let Some(ref ssid) = net.ssid {
                let ssid = ssid.trim();
                if ssid.len() >= 4 && !ssid.starts_with("DIRECT-") {
                    let lower = ssid.to_lowercase();
                    if !GENERIC_SSIDS.iter().any(|g| lower.contains(g)) {
                        let ssid_parts: Vec<&str> = ssid.split(['-', '_', ' ']).collect();
                        if ssid_parts.len() >= 2
                            && ssid_parts[0].len() >= 3
                            && ssid_parts[0].starts_with(|c: char| c.is_ascii_uppercase())
                        {
                            let mut name_entity =
                                Entity::new(EntityKind::Organisation, ssid, 0.35, &ctx.scan_id);
                            name_entity.tag("wigle");
                            name_entity.tag("ssid-derived");
                            name_entity.add_evidence(
                                Evidence::new(SRC, format!("SSID name from BSSID {bssid}"))
                                    .with_attr("ssid", ssid)
                                    .with_attr("coordinates", &coords_str),
                            );
                            result.push(name_entity);
                        }
                    }
                }
            }
        } else if let Some(net) = body.results.first() {
            // Fallback: no trilong but have city/region/country
            let parts: Vec<&str> = [
                net.city.as_deref(),
                net.region.as_deref(),
                net.country.as_deref(),
            ]
            .iter()
            .filter_map(|p| *p)
            .filter(|p| !p.is_empty())
            .collect();

            if parts.len() >= 2 {
                let addr_str = parts.join(", ");
                let mut addr = Entity::new(EntityKind::Address, &addr_str, 0.55, &ctx.scan_id);
                addr.tag("wigle");
                addr.tag("bssid-located");
                addr.add_evidence(
                    Evidence::new(SRC, format!("WiGLE BSSID {bssid} (city/region only)"))
                        .with_attr("bssid", bssid),
                );
                result.push(addr);
            }
        }

        Ok(result)
    }
}

/// Statistical mode: most common value in a slice.
fn mode<'a>(items: &[&'a str]) -> &'a str {
    if items.is_empty() {
        return "";
    }
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for &item in items {
        *counts.entry(item).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by_key(|&(_, count)| count)
        .map_or("", |(val, _)| val)
}

fn mode_or<'a>(items: &[&'a str], fallback: impl FnOnce() -> &'a str) -> &'a str {
    let m = mode(items);
    if m.is_empty() { fallback() } else { m }
}

const GENERIC_SSIDS: &[&str] = &[
    "linksys", "netgear", "default", "dlink", "tp-link", "tplink", "asus", "xfinity", "spectrum",
    "att", "optimum", "cox", "telstra", "optus", "vodafone", "nbn", "iinet", "eduroam", "guest",
    "free", "public", "open", "android", "iphone", "galaxy", "pixel", "setup", "config", "admin",
    "test", "hidden", "unknown", "unnamed",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::geo::parse_coords;

    #[test]
    fn accepts_coordinates_and_mac_address() {
        let m = Wigle;
        assert!(m.accepts(&Target::new(TargetKind::Coordinates, "0,0")));
        assert!(m.accepts(&Target::new(TargetKind::MacAddress, "AA:BB:CC:DD:EE:FF")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
    }

    #[test]
    fn cost_is_key_gated() {
        assert!(matches!(Wigle.cost(), ModuleCost::KeyGated));
    }

    #[test]
    fn parse_coords_valid() {
        let (lat, lon) = parse_coords("-27.4766,153.0166").unwrap();
        assert!((lat - (-27.4766)).abs() < 0.001);
        assert!((lon - 153.0166).abs() < 0.001);
    }

    #[test]
    fn parse_coords_invalid() {
        assert!(parse_coords("not-coords").is_err());
        assert!(parse_coords("").is_err());
    }

    #[test]
    fn mode_finds_most_common() {
        assert_eq!(mode(&["a", "b", "a", "c", "a"]), "a");
        assert_eq!(mode(&["x"]), "x");
        assert_eq!(mode(&[]), "");
    }

    #[test]
    fn generic_ssid_filter() {
        let lower = "telstra-home-123".to_lowercase();
        assert!(GENERIC_SSIDS.iter().any(|g| lower.contains(g)));
        let lower2 = "smith-family".to_lowercase();
        assert!(!GENERIC_SSIDS.iter().any(|g| lower2.contains(g)));
    }

    #[test]
    fn resp_deserializes_with_full_fields() {
        let json = r#"{
            "success": true,
            "totalResults": 42,
            "results": [{
                "ssid": "Smith-Family-5G",
                "netid": "AA:BB:CC:DD:EE:FF",
                "encryption": "wpa2",
                "channel": 36,
                "lastupdt": "2024-06-15",
                "trilat": -27.4766,
                "trilong": 153.0166,
                "city": "Nundah",
                "region": "Queensland",
                "country": "AU",
                "postalcode": "4012",
                "type": "infra"
            }]
        }"#;
        let r: Resp = serde_json::from_str(json).unwrap();
        assert_eq!(r.success, Some(true));
        assert_eq!(r.total_results, Some(42));
        let net = &r.results[0];
        assert_eq!(net.ssid.as_deref(), Some("Smith-Family-5G"));
        assert_eq!(net.trilat, Some(-27.4766));
        assert_eq!(net.trilong, Some(153.0166));
        assert_eq!(net.city.as_deref(), Some("Nundah"));
        assert_eq!(net.region.as_deref(), Some("Queensland"));
        assert_eq!(net.postalcode.as_deref(), Some("4012"));
        assert_eq!(net.netid.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
    }
}
