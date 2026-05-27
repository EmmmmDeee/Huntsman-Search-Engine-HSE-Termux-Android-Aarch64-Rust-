//! Geolocation intelligence fusion — multi-source geo enrichment pipeline.
//!
//! # Geolocation Pathway Priority Matrix
//!
//! **P1 — Direct Physical (0.80–0.95 confidence)**
//!   GPS fix, cell tower triangulation, WiFi BSSID location
//!   Modules: gps_fix, cell_locate, bssid_locate
//!
//! **P2 — IP-Based (0.60–0.75 confidence)**
//!   ip-api.com, ipwho.is, ipapi.co, freeipapi.com, OathNet ip-info
//!   Modules: ip_geo, ip_whois_geo, THIS MODULE (additional sources)
//!
//! **P3 — Breach-Derived (0.35–0.65 confidence)**
//!   OathNet breach location fields (country, city, state, address)
//!   OathNet stealer/victim device IPs → IP geo chain
//!   Modules: oathnet_pro (extracts IPs/addresses), THIS MODULE (batch geo)
//!
//! **P4 — Inferred (0.15–0.35 confidence)**
//!   Phone prefix → country, timezone → region, ASN HQ
//!   Modules: phone_intl, THIS MODULE
//!
//! # Strategy
//!
//! For IP targets: queries additional free geo APIs (ipapi.co, freeipapi.com)
//! that aren't covered by ip_geo or ip_whois_geo, providing a third and
//! fourth independent source for AU-014 geo-cluster correlation.
//!
//! For identity targets (Email, Username, Phone, Domain): runs a geo-focused
//! OathNet Pro enrichment pass that extracts location fields from breach
//! data and converts them to Coordinates/Address entities. Assembles
//! high-confidence seeds from free sources first, then batch-queries
//! OathNet Pro for enrichment.
//!
//! Free APIs used:
//!   - ipapi.co — 1000 req/day, HTTPS, no key required
//!   - freeipapi.com — unlimited, HTTPS, no key required
//!   - OathNet ip-info — included with OathNet Pro key
//!
//! Phone prefix geolocation:
//!   - ITU E.164 country code → country centroid (offline, coarse)

use std::collections::HashSet;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json;
use crate::util::oathnet::{self, paths, val_str};

const SRC: &str = "geo_intel";

pub struct GeoIntel;

// ─── ipapi.co response ─────────────────────────────────────────────────────

#[derive(Deserialize)]
#[allow(dead_code)]
struct IpApiCoResp {
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    country_name: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    postal: Option<String>,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    timezone: Option<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    asn: Option<String>,
    #[serde(default)]
    error: Option<bool>,
}

// ─── freeipapi.com response ─────────────────────────────────────────────────

#[derive(Deserialize)]
#[allow(dead_code)]
struct FreeIpApiResp {
    #[serde(default, rename = "ipAddress")]
    ip_address: Option<String>,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default, rename = "countryName")]
    country_name: Option<String>,
    #[serde(default, rename = "countryCode")]
    country_code: Option<String>,
    #[serde(default, rename = "cityName")]
    city_name: Option<String>,
    #[serde(default, rename = "regionName")]
    region_name: Option<String>,
    #[serde(default, rename = "zipCode")]
    zip_code: Option<String>,
    #[serde(default, rename = "timeZone")]
    timezone: Option<String>,
    #[serde(default, rename = "isProxy")]
    is_proxy: Option<bool>,
}

#[async_trait]
impl Module for GeoIntel {
    fn name(&self) -> &'static str {
        "geo_intel"
    }

    fn description(&self) -> &'static str {
        "Multi-source geolocation fusion: free APIs + OathNet Pro batch enrichment"
    }

    fn priority(&self) -> u8 {
        22
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::IpAddress
                | TargetKind::Email
                | TargetKind::Username
                | TargetKind::Phone
                | TargetKind::Domain
                | TargetKind::Url
                | TargetKind::FullName
                | TargetKind::Organisation
        )
    }

    fn max_timeout_ms(&self) -> u64 {
        25_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        match target.kind {
            TargetKind::IpAddress => process_ip(target, ctx).await,
            TargetKind::Email
            | TargetKind::Username
            | TargetKind::Domain
            | TargetKind::FullName
            | TargetKind::Organisation => process_identity(target, ctx).await,
            TargetKind::Phone => process_phone(target, ctx).await,
            TargetKind::Url => {
                // Extract domain from URL and run the domain identity path
                if let Some(host) = target.value.split("//").nth(1) {
                    let domain = host.split('/').next().unwrap_or(host);
                    let domain_target = Target::new(TargetKind::Domain, domain);
                    process_identity(&domain_target, ctx).await
                } else {
                    Ok(ModuleResult::new())
                }
            }
            _ => Ok(ModuleResult::new()),
        }
    }
}

// ─── IP geolocation: additional free sources ────────────────────────────────

async fn process_ip(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let mut result = ModuleResult::new();
    let mut seen_coords = HashSet::new();

    // Source 1: ipapi.co (free, HTTPS, 1000/day)
    if !ctx.cancel.is_cancelled()
        && let Ok(data) = fetch_json::<IpApiCoResp>(
            &ctx.http,
            "geo_intel",
            &format!("https://ipapi.co/{}/json/", target.value),
        )
        .await
        && data.error != Some(true)
        && let (Some(lat), Some(lon)) = (data.latitude, data.longitude)
        && !(lat == 0.0 && lon == 0.0)
    {
        let coords = format!("{lat:.6},{lon:.6}");
        if seen_coords.insert(coords.clone()) {
            let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.68, &ctx.scan_id);
            e.tag("geoint");
            if let Some(cc) = data.country_code.as_deref() {
                e.tag(format!("country:{}", cc.to_uppercase()));
            }

            let mut ev = Evidence::new(
                "geo_intel",
                format!("IP geo for {} via ipapi.co", target.value),
            )
            .with_attr("latitude", lat.to_string())
            .with_attr("longitude", lon.to_string())
            .with_attr("source", "ipapi.co");

            if let Some(c) = data.city.as_deref() {
                ev = ev.with_attr("city", c);
            }
            if let Some(r) = data.region.as_deref() {
                ev = ev.with_attr("region", r);
            }
            if let Some(c) = data.country_name.as_deref() {
                ev = ev.with_attr("country", c);
            }
            if let Some(p) = data.postal.as_deref() {
                ev = ev.with_attr("postal", p);
            }
            if let Some(tz) = data.timezone.as_deref() {
                ev = ev.with_attr("timezone", tz);
            }
            if let Some(org) = data.org.as_deref() {
                ev = ev.with_attr("org", org);
            }
            if let Some(asn) = data.asn.as_deref() {
                ev = ev.with_attr("asn", asn);
            }

            e.add_evidence(ev);
            result.push(e);
        }
    }

    // Source 2: freeipapi.com (free, HTTPS, no limit documented)
    if !ctx.cancel.is_cancelled()
        && let Ok(data) = fetch_json::<FreeIpApiResp>(
            &ctx.http,
            "geo_intel",
            &format!("https://freeipapi.com/api/json/{}", target.value),
        )
        .await
        && let (Some(lat), Some(lon)) = (data.latitude, data.longitude)
        && !(lat == 0.0 && lon == 0.0)
    {
        let coords = format!("{lat:.6},{lon:.6}");
        if seen_coords.insert(coords.clone()) {
            let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.62, &ctx.scan_id);
            e.tag("geoint");
            if let Some(cc) = data.country_code.as_deref() {
                e.tag(format!("country:{}", cc.to_uppercase()));
            }
            if data.is_proxy == Some(true) {
                e.tag("proxy");
            }

            let mut ev = Evidence::new(
                "geo_intel",
                format!("IP geo for {} via freeipapi.com", target.value),
            )
            .with_attr("latitude", lat.to_string())
            .with_attr("longitude", lon.to_string())
            .with_attr("source", "freeipapi.com");

            if let Some(c) = data.city_name.as_deref() {
                ev = ev.with_attr("city", c);
            }
            if let Some(r) = data.region_name.as_deref() {
                ev = ev.with_attr("region", r);
            }
            if let Some(c) = data.country_name.as_deref() {
                ev = ev.with_attr("country", c);
            }
            if let Some(z) = data.zip_code.as_deref() {
                ev = ev.with_attr("postal", z);
            }
            if let Some(tz) = data.timezone.as_deref() {
                ev = ev.with_attr("timezone", tz);
            }
            if let Some(v) = data.is_proxy {
                ev = ev.with_attr("is_proxy", v.to_string());
            }

            e.add_evidence(ev);
            result.push(e);
        }
    }

    Ok(result)
}

// ─── Identity geo enrichment: OathNet Pro batch queries ─────────────────────

async fn process_identity(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let oathnet_key = ctx.key_opt(oathnet::KEY_ENV);
    if oathnet_key.is_none() {
        return Ok(ModuleResult::new());
    }
    let key = oathnet::resolve_key(oathnet_key);

    let mut result = ModuleResult::new();
    let mut seen = HashSet::new();

    let field = match target.kind {
        TargetKind::Email => "email",
        TargetKind::Username => "username",
        TargetKind::Domain => "domain",
        TargetKind::FullName => "full_name",
        TargetKind::Organisation => "domain",
        _ => return Ok(result),
    };

    // Phase 1: Geo-focused breach search — extract location fields
    let items = match oathnet::search(key, paths::BREACH, field, &target.value, 50).await {
        Ok(items) => items,
        Err(_) => return Ok(result),
    };

    if items.is_empty() {
        return Ok(result);
    }

    // Phase 2: Aggregate all location mentions across breach records
    let mut location_seeds: Vec<LocationSeed> = Vec::new();
    let mut ip_seeds: Vec<String> = Vec::new();

    for item in &items {
        // Extract explicit location fields
        let country = val_str(item, "country");
        let city = val_str(item, "city");
        let state = val_str(item, "state");
        let postal = val_str(item, "postal_code");
        let address = val_str(item, "address_street");
        let location = val_str(item, "location");
        let timezone = val_str(item, "timezone");

        if city.is_some() || country.is_some() || location.is_some() {
            location_seeds.push(LocationSeed {
                country: country.clone(),
                city: city.clone(),
                state: state.clone(),
                postal: postal.clone(),
                address,
                location,
                timezone: timezone.clone(),
                source: val_str(item, "dbname").unwrap_or_else(|| "unknown".to_string()),
            });
        }

        // Extract IPs for recursive geo lookup
        if let Some(ip) = val_str(item, "ip")
            && ip.len() >= 7
            && ip_seeds.len() < 10
            && !ip_seeds.contains(&ip)
        {
            ip_seeds.push(ip);
        }
    }

    // Phase 3: Build location frequency map and find consensus
    let consensus = compute_location_consensus(&location_seeds);

    // Emit Address entity from breach location consensus
    if let Some(ref con) = consensus {
        let addr_str = &con.address_str;
        if addr_str.len() >= 4 && seen.insert(format!("@addr:{}", addr_str.to_lowercase())) {
            let confidence = 0.35 + (0.10 * (con.source_count as f64).min(4.0));
            let mut e = Entity::new(EntityKind::Address, addr_str, confidence, &ctx.scan_id);
            e.tag("geoint");
            e.tag("breach-derived");
            e.tag("geo-consensus");
            if let Some(cc) = &con.country_code {
                e.tag(format!("country:{cc}"));
            }
            e.add_evidence(
                Evidence::new(
                    "geo_intel",
                    format!(
                        "Breach location consensus from {} source(s) for {}",
                        con.source_count, target.value
                    ),
                )
                .with_attr("city", con.city.as_deref().unwrap_or("-"))
                .with_attr("country", con.country.as_deref().unwrap_or("-"))
                .with_attr("sources", con.source_count.to_string())
                .with_attr("method", "breach-frequency-consensus"),
            );
            result.push(e);
        }
    }

    // Phase 4: Geo-locate discovered IPs via free APIs
    if !ctx.cancel.is_cancelled() {
        for ip in ip_seeds.iter().take(5) {
            if ctx.cancel.is_cancelled() {
                break;
            }
            if seen.insert(format!("@ip-geo:{ip}"))
                && let Some((lat, lon, ev_attrs)) = quick_ip_geo(&ctx.http, ip).await
            {
                let coords = format!("{lat:.6},{lon:.6}");
                if seen.insert(format!("@coords:{coords}")) {
                    let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.55, &ctx.scan_id);
                    e.tag("geoint");
                    e.tag("breach-ip");
                    e.tag("geolocation-lead");

                    let mut ev = Evidence::new(
                        "geo_intel",
                        format!("Breach IP {ip} geo for {}", target.value),
                    )
                    .with_attr("ip", ip)
                    .with_attr("latitude", lat.to_string())
                    .with_attr("longitude", lon.to_string());

                    for (k, v) in &ev_attrs {
                        ev = ev.with_attr(k, v);
                    }

                    e.add_evidence(ev);
                    result.push(e);
                }
            }
        }
    }

    // Phase 5: OathNet IP info enrichment for high-confidence IPs
    if !ctx.cancel.is_cancelled() {
        for ip in ip_seeds.iter().take(3) {
            if ctx.cancel.is_cancelled() {
                break;
            }
            if let Ok(info) = oathnet::osint(key, paths::IP_INFO, "ip", ip).await {
                extract_oathnet_ip_geo(
                    &info,
                    ip,
                    &target.value,
                    &ctx.scan_id,
                    &mut seen,
                    &mut result,
                );
            }
        }
    }

    // Phase 6: Stealer device IP extraction for recursive geo
    if !ctx.cancel.is_cancelled()
        && let Ok(victim_items) =
            oathnet::search(key, paths::VICTIMS, field, &target.value, 10).await
    {
        for item in &victim_items {
            if let Some(ips) = item.get("device_ips").and_then(|v| v.as_array()) {
                for ip_val in ips.iter().take(3) {
                    if let Some(ip) = ip_val.as_str()
                        && ip.parse::<std::net::IpAddr>().is_ok()
                        && seen.insert(format!("@victim-ip:{ip}"))
                    {
                        let mut e = Entity::new(EntityKind::IpAddress, ip, 0.50, &ctx.scan_id);
                        e.tag("geolocation-lead");
                        e.tag("victim-device");
                        e.add_evidence(Evidence::new(
                            "geo_intel",
                            format!("Device IP from victim data for {}", target.value),
                        ));
                        result.push(e);
                    }
                }
            }
        }
    }

    // Phase 7: Timezone inference from breach data
    if !ctx.cancel.is_cancelled() {
        let timezones: Vec<&str> = location_seeds
            .iter()
            .filter_map(|s| s.timezone.as_deref())
            .collect();
        if !timezones.is_empty()
            && let Some(tz) = mode(&timezones)
            && let Some((lat, lon, region)) = timezone_to_coordinates(tz)
        {
            let coords = format!("{lat:.4},{lon:.4}");
            if seen.insert(format!("@tz-geo:{coords}")) {
                let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.52, &ctx.scan_id);
                e.tag("geoint");
                e.tag("timezone-inferred");
                e.tag("coarse");
                e.add_evidence(
                    Evidence::new(
                        "geo_intel",
                        format!("Timezone {tz} → {region} for {}", target.value),
                    )
                    .with_attr("timezone", tz)
                    .with_attr("region", region)
                    .with_attr("method", "timezone-centroid"),
                );
                result.push(e);
            }
        }
    }

    Ok(result)
}

// ─── Phone number geolocation ───────────────────────────────────────────────

async fn process_phone(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let mut result = ModuleResult::new();
    let mut seen = HashSet::new();

    // Extract country from E.164 phone prefix
    let phone = target.value.trim().trim_start_matches('+');
    if let Some((country, cc, lat, lon)) = phone_prefix_to_country(phone) {
        let coords = format!("{lat:.4},{lon:.4}");
        if seen.insert(format!("@phone-geo:{coords}")) {
            let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.52, &ctx.scan_id);
            e.tag("geoint");
            e.tag("phone-prefix");
            e.tag("coarse");
            e.tag(format!("country:{cc}"));
            e.add_evidence(
                Evidence::new(
                    "geo_intel",
                    format!("Phone prefix → {country} for {}", target.value),
                )
                .with_attr("country", country)
                .with_attr("country_code", cc)
                .with_attr("method", "e164-prefix"),
            );
            result.push(e);
        }
    }

    // OathNet Pro breach search for phone geo data (only with explicit key)
    let oathnet_key = ctx.key_opt(oathnet::KEY_ENV);
    if !ctx.cancel.is_cancelled() && oathnet_key.is_some() {
        let key = oathnet::resolve_key(oathnet_key);
        if let Ok(items) = oathnet::search(key, paths::BREACH, "phone", &target.value, 20).await {
            let mut location_seeds = Vec::new();
            let mut ip_seeds = Vec::new();

            for item in &items {
                let country = val_str(item, "country");
                let city = val_str(item, "city");
                let state = val_str(item, "state");

                if city.is_some() || country.is_some() {
                    location_seeds.push(LocationSeed {
                        country: country.clone(),
                        city: city.clone(),
                        state: state.clone(),
                        postal: val_str(item, "postal_code"),
                        address: val_str(item, "address_street"),
                        location: val_str(item, "location"),
                        timezone: val_str(item, "timezone"),
                        source: val_str(item, "dbname").unwrap_or_else(|| "unknown".to_string()),
                    });
                }

                if let Some(ip) = val_str(item, "ip")
                    && ip.len() >= 7
                    && ip_seeds.len() < 5
                    && !ip_seeds.contains(&ip)
                {
                    ip_seeds.push(ip);
                }
            }

            if let Some(con) = compute_location_consensus(&location_seeds)
                && seen.insert(format!("@phone-addr:{}", con.address_str.to_lowercase()))
            {
                let confidence = 0.35 + (0.10 * (con.source_count as f64).min(4.0));
                let mut e = Entity::new(
                    EntityKind::Address,
                    &con.address_str,
                    confidence,
                    &ctx.scan_id,
                );
                e.tag("geoint");
                e.tag("breach-derived");
                e.add_evidence(
                    Evidence::new(
                        "geo_intel",
                        format!("Phone breach location from {} source(s)", con.source_count),
                    )
                    .with_attr("city", con.city.as_deref().unwrap_or("-"))
                    .with_attr("country", con.country.as_deref().unwrap_or("-")),
                );
                result.push(e);
            }

            // Geo-locate discovered IPs
            for ip in ip_seeds.iter().take(3) {
                if ctx.cancel.is_cancelled() {
                    break;
                }
                if seen.insert(format!("@ip-geo:{ip}"))
                    && let Some((lat, lon, ev_attrs)) = quick_ip_geo(&ctx.http, ip).await
                {
                    let coords = format!("{lat:.6},{lon:.6}");
                    if seen.insert(format!("@coords:{coords}")) {
                        let mut e =
                            Entity::new(EntityKind::Coordinates, &coords, 0.50, &ctx.scan_id);
                        e.tag("geoint");
                        e.tag("breach-ip");
                        let mut ev = Evidence::new(SRC, format!("Phone breach IP {ip} → {coords}"))
                            .with_attr("ip", ip);
                        for (k, v) in &ev_attrs {
                            ev = ev.with_attr(k, v);
                        }
                        e.add_evidence(ev);
                        result.push(e);
                    }
                }
            }
        }
    }

    Ok(result)
}

// ─── Quick IP geo via freeipapi.com (no key, no rate limit) ─────────────────

async fn quick_ip_geo(
    http: &reqwest::Client,
    ip: &str,
) -> Option<(f64, f64, Vec<(String, String)>)> {
    let url = format!("https://freeipapi.com/api/json/{ip}");
    let data: FreeIpApiResp = fetch_json(http, "geo_intel", &url).await.ok()?;

    let lat = data.latitude?;
    let lon = data.longitude?;
    if lat == 0.0 && lon == 0.0 {
        return None;
    }

    let mut attrs = Vec::new();
    attrs.push(("source".to_string(), "freeipapi.com".to_string()));
    if let Some(c) = data.city_name {
        attrs.push(("city".to_string(), c));
    }
    if let Some(r) = data.region_name {
        attrs.push(("region".to_string(), r));
    }
    if let Some(c) = data.country_name {
        attrs.push(("country".to_string(), c));
    }

    Some((lat, lon, attrs))
}

// ─── OathNet IP info geo extraction ─────────────────────────────────────────

fn extract_oathnet_ip_geo(
    data: &Value,
    ip: &str,
    target_value: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let lat = data.get("lat").and_then(serde_json::Value::as_f64);
    let lon = data.get("lon").and_then(serde_json::Value::as_f64);

    if let (Some(lat), Some(lon)) = (lat, lon) {
        if lat == 0.0 && lon == 0.0 {
            return;
        }
        let coords = format!("{lat:.6},{lon:.6}");
        if !seen.insert(format!("@oathnet-geo:{coords}")) {
            return;
        }

        let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.60, scan_id);
        e.tag("geoint");
        e.tag("oathnet-pro");
        e.tag("breach-ip");

        let mut ev = Evidence::new(
            "geo_intel",
            format!("OathNet IP info: {ip} → {coords} for {target_value}"),
        )
        .with_attr("ip", ip)
        .with_attr("source", "OathNet ip-info");

        for (field, attr) in [
            ("city", "city"),
            ("regionName", "region"),
            ("country", "country"),
            ("countryCode", "country_code"),
            ("isp", "isp"),
            ("org", "org"),
            ("timezone", "timezone"),
        ] {
            if let Some(v) = data.get(field).and_then(|v| v.as_str()) {
                ev = ev.with_attr(attr, v);
            }
        }

        e.add_evidence(ev);
        result.push(e);
    }
}

// ─── Location consensus engine ──────────────────────────────────────────────

#[allow(dead_code)]
struct LocationSeed {
    country: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal: Option<String>,
    address: Option<String>,
    location: Option<String>,
    timezone: Option<String>,
    source: String,
}

#[allow(dead_code)]
struct LocationConsensus {
    city: Option<String>,
    state: Option<String>,
    country: Option<String>,
    country_code: Option<String>,
    address_str: String,
    source_count: usize,
}

fn compute_location_consensus(seeds: &[LocationSeed]) -> Option<LocationConsensus> {
    if seeds.is_empty() {
        return None;
    }

    let countries: Vec<&str> = seeds
        .iter()
        .filter_map(|s| s.country.as_deref())
        .filter(|c| !c.is_empty())
        .collect();
    let cities: Vec<&str> = seeds
        .iter()
        .filter_map(|s| s.city.as_deref())
        .filter(|c| !c.is_empty())
        .collect();
    let states: Vec<&str> = seeds
        .iter()
        .filter_map(|s| s.state.as_deref())
        .filter(|s| !s.is_empty())
        .collect();

    let top_country = mode(&countries).map(String::from);
    let top_city = mode(&cities).map(String::from);
    let top_state = mode(&states).map(String::from);

    if top_country.is_none() && top_city.is_none() {
        return None;
    }

    let unique_sources: HashSet<&str> = seeds.iter().map(|s| s.source.as_str()).collect();

    let addr_parts: Vec<&str> = [
        top_city.as_deref(),
        top_state.as_deref(),
        top_country.as_deref(),
    ]
    .iter()
    .filter_map(|p| *p)
    .filter(|p| !p.is_empty())
    .collect();

    let address_str = addr_parts.join(", ");

    let country_code = top_country.as_deref().and_then(country_name_to_code);

    Some(LocationConsensus {
        city: top_city,
        state: top_state,
        country: top_country,
        country_code: country_code.map(String::from),
        address_str,
        source_count: unique_sources.len(),
    })
}

fn mode<'a>(items: &[&'a str]) -> Option<&'a str> {
    if items.is_empty() {
        return None;
    }
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for &item in items {
        *counts.entry(item).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(b.0)))
        .map(|(val, _)| val)
}

// ─── Phone prefix → country ────────────────────────────────────────────────

fn phone_prefix_to_country(phone: &str) -> Option<(&'static str, &'static str, f64, f64)> {
    if !phone.is_ascii() {
        return None;
    }
    for len in [3, 2, 1] {
        if phone.len() >= len {
            let prefix = &phone[..len];
            if !prefix.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            if let Some(result) = match prefix {
                // 1-digit
                "1" => Some(("United States/Canada", "US", 39.8283, -98.5795)),
                "7" => Some(("Russia", "RU", 61.5240, 105.3188)),
                // 2-digit
                "20" => Some(("Egypt", "EG", 26.8206, 30.8025)),
                "27" => Some(("South Africa", "ZA", -30.5595, 22.9375)),
                "30" => Some(("Greece", "GR", 39.0742, 21.8243)),
                "31" => Some(("Netherlands", "NL", 52.1326, 5.2913)),
                "32" => Some(("Belgium", "BE", 50.5039, 4.4699)),
                "33" => Some(("France", "FR", 46.6034, 1.8883)),
                "34" => Some(("Spain", "ES", 40.4637, -3.7492)),
                "36" => Some(("Hungary", "HU", 47.1625, 19.5033)),
                "39" => Some(("Italy", "IT", 41.8719, 12.5674)),
                "40" => Some(("Romania", "RO", 45.9432, 24.9668)),
                "41" => Some(("Switzerland", "CH", 46.8182, 8.2275)),
                "43" => Some(("Austria", "AT", 47.5162, 14.5501)),
                "44" => Some(("United Kingdom", "GB", 55.3781, -3.4360)),
                "45" => Some(("Denmark", "DK", 56.2639, 9.5018)),
                "46" => Some(("Sweden", "SE", 60.1282, 18.6435)),
                "47" => Some(("Norway", "NO", 60.4720, 8.4689)),
                "48" => Some(("Poland", "PL", 51.9194, 19.1451)),
                "49" => Some(("Germany", "DE", 51.1657, 10.4515)),
                "51" => Some(("Peru", "PE", -9.1900, -75.0152)),
                "52" => Some(("Mexico", "MX", 23.6345, -102.5528)),
                "53" => Some(("Cuba", "CU", 21.5218, -77.7812)),
                "54" => Some(("Argentina", "AR", -38.4161, -63.6167)),
                "55" => Some(("Brazil", "BR", -14.2350, -51.9253)),
                "56" => Some(("Chile", "CL", -35.6751, -71.5430)),
                "57" => Some(("Colombia", "CO", 4.5709, -74.2973)),
                "58" => Some(("Venezuela", "VE", 6.4238, -66.5897)),
                "60" => Some(("Malaysia", "MY", 4.2105, 101.9758)),
                "61" => Some(("Australia", "AU", -25.2744, 133.7751)),
                "62" => Some(("Indonesia", "ID", -0.7893, 113.9213)),
                "63" => Some(("Philippines", "PH", 12.8797, 121.7740)),
                "64" => Some(("New Zealand", "NZ", -41.2865, 174.7762)),
                "65" => Some(("Singapore", "SG", 1.3521, 103.8198)),
                "66" => Some(("Thailand", "TH", 15.8700, 100.9925)),
                "81" => Some(("Japan", "JP", 36.2048, 138.2529)),
                "82" => Some(("South Korea", "KR", 35.9078, 127.7669)),
                "84" => Some(("Vietnam", "VN", 14.0583, 108.2772)),
                "86" => Some(("China", "CN", 35.8617, 104.1954)),
                "90" => Some(("Turkey", "TR", 38.9637, 35.2433)),
                "91" => Some(("India", "IN", 20.5937, 78.9629)),
                "92" => Some(("Pakistan", "PK", 30.3753, 69.3451)),
                "93" => Some(("Afghanistan", "AF", 33.9391, 67.7100)),
                "94" => Some(("Sri Lanka", "LK", 7.8731, 80.7718)),
                "95" => Some(("Myanmar", "MM", 21.9162, 95.9560)),
                "98" => Some(("Iran", "IR", 32.4279, 53.6880)),
                // 3-digit
                "212" => Some(("Morocco", "MA", 31.7917, -7.0926)),
                "213" => Some(("Algeria", "DZ", 28.0339, 1.6596)),
                "216" => Some(("Tunisia", "TN", 33.8869, 9.5375)),
                "218" => Some(("Libya", "LY", 26.3351, 17.2283)),
                "220" => Some(("Gambia", "GM", 13.4432, -15.3101)),
                "234" => Some(("Nigeria", "NG", 9.0820, 8.6753)),
                "254" => Some(("Kenya", "KE", -0.0236, 37.9062)),
                "255" => Some(("Tanzania", "TZ", -6.3690, 34.8888)),
                "256" => Some(("Uganda", "UG", 1.3733, 32.2903)),
                "351" => Some(("Portugal", "PT", 39.3999, -8.2245)),
                "353" => Some(("Ireland", "IE", 53.4129, -8.2439)),
                "354" => Some(("Iceland", "IS", 64.9631, -19.0208)),
                "358" => Some(("Finland", "FI", 61.9241, 25.7482)),
                "380" => Some(("Ukraine", "UA", 48.3794, 31.1656)),
                "852" => Some(("Hong Kong", "HK", 22.3193, 114.1694)),
                "853" => Some(("Macau", "MO", 22.1987, 113.5439)),
                "855" => Some(("Cambodia", "KH", 12.5657, 104.9910)),
                "856" => Some(("Laos", "LA", 19.8563, 102.4955)),
                "880" => Some(("Bangladesh", "BD", 23.6850, 90.3563)),
                "886" => Some(("Taiwan", "TW", 23.6978, 120.9605)),
                "960" => Some(("Maldives", "MV", 3.2028, 73.2207)),
                "961" => Some(("Lebanon", "LB", 33.8547, 35.8623)),
                "962" => Some(("Jordan", "JO", 30.5852, 36.2384)),
                "963" => Some(("Syria", "SY", 34.8021, 38.9968)),
                "964" => Some(("Iraq", "IQ", 33.2232, 43.6793)),
                "965" => Some(("Kuwait", "KW", 29.3117, 47.4818)),
                "966" => Some(("Saudi Arabia", "SA", 23.8859, 45.0792)),
                "971" => Some(("UAE", "AE", 23.4241, 53.8478)),
                "972" => Some(("Israel", "IL", 31.0461, 34.8516)),
                _ => None,
            } {
                return Some(result);
            }
        }
    }
    None
}

// ─── Timezone → coordinates ─────────────────────────────────────────────────

fn timezone_to_coordinates(tz: &str) -> Option<(f64, f64, &'static str)> {
    let tz_lower = tz.to_lowercase();
    match tz_lower.as_str() {
        // Americas
        "america/new_york" | "us/eastern" | "est" | "edt" => {
            Some((40.7128, -74.0060, "US Eastern"))
        }
        "america/chicago" | "us/central" | "cst" | "cdt" => Some((41.8781, -87.6298, "US Central")),
        "america/denver" | "us/mountain" | "mst" | "mdt" => {
            Some((39.7392, -104.9903, "US Mountain"))
        }
        "america/los_angeles" | "us/pacific" | "pst" | "pdt" => {
            Some((34.0522, -118.2437, "US Pacific"))
        }
        "america/toronto" => Some((43.6532, -79.3832, "Eastern Canada")),
        "america/vancouver" => Some((49.2827, -123.1207, "Western Canada")),
        "america/sao_paulo" | "brazil/east" => Some((-23.5505, -46.6333, "Brazil")),
        "america/buenos_aires" | "america/argentina/buenos_aires" => {
            Some((-34.6037, -58.3816, "Argentina"))
        }
        "america/mexico_city" => Some((19.4326, -99.1332, "Mexico")),
        "america/bogota" => Some((4.7110, -74.0721, "Colombia")),
        "america/lima" => Some((-12.0464, -77.0428, "Peru")),
        "america/santiago" => Some((-33.4489, -70.6693, "Chile")),
        // Europe
        "europe/london" | "gmt" | "bst" => Some((51.5074, -0.1278, "London/UK")),
        "europe/paris" | "cet" | "cest" => Some((48.8566, 2.3522, "Paris/France")),
        "europe/berlin" => Some((52.5200, 13.4050, "Berlin/Germany")),
        "europe/rome" => Some((41.9028, 12.4964, "Rome/Italy")),
        "europe/madrid" => Some((40.4168, -3.7038, "Madrid/Spain")),
        "europe/amsterdam" => Some((52.3676, 4.9041, "Amsterdam/Netherlands")),
        "europe/brussels" => Some((50.8503, 4.3517, "Brussels/Belgium")),
        "europe/zurich" => Some((47.3769, 8.5417, "Zurich/Switzerland")),
        "europe/vienna" => Some((48.2082, 16.3738, "Vienna/Austria")),
        "europe/stockholm" => Some((59.3293, 18.0686, "Stockholm/Sweden")),
        "europe/oslo" => Some((59.9139, 10.7522, "Oslo/Norway")),
        "europe/helsinki" => Some((60.1699, 24.9384, "Helsinki/Finland")),
        "europe/copenhagen" => Some((55.6761, 12.5683, "Copenhagen/Denmark")),
        "europe/warsaw" => Some((52.2297, 21.0122, "Warsaw/Poland")),
        "europe/bucharest" => Some((44.4268, 26.1025, "Bucharest/Romania")),
        "europe/prague" => Some((50.0755, 14.4378, "Prague/Czech Republic")),
        "europe/athens" => Some((37.9838, 23.7275, "Athens/Greece")),
        "europe/lisbon" => Some((38.7223, -9.1393, "Lisbon/Portugal")),
        "europe/dublin" => Some((53.3498, -6.2603, "Dublin/Ireland")),
        "europe/moscow" | "msk" => Some((55.7558, 37.6173, "Moscow/Russia")),
        "europe/istanbul" => Some((41.0082, 28.9784, "Istanbul/Turkey")),
        "europe/kyiv" | "europe/kiev" => Some((50.4504, 30.5234, "Kyiv/Ukraine")),
        // Asia/Pacific
        "asia/tokyo" | "jst" => Some((35.6762, 139.6503, "Tokyo/Japan")),
        "asia/seoul" | "kst" => Some((37.5665, 126.9780, "Seoul/South Korea")),
        "asia/shanghai" | "asia/hong_kong" | "hkt" => Some((31.2304, 121.4737, "Shanghai/China")),
        "asia/kolkata" | "asia/calcutta" | "ist" => Some((28.6139, 77.2090, "Delhi/India")),
        "asia/singapore" | "sgt" => Some((1.3521, 103.8198, "Singapore")),
        "asia/bangkok" | "ict" => Some((13.7563, 100.5018, "Bangkok/Thailand")),
        "asia/jakarta" | "wib" => Some((-6.2088, 106.8456, "Jakarta/Indonesia")),
        "asia/manila" | "pht" => Some((14.5995, 120.9842, "Manila/Philippines")),
        "asia/ho_chi_minh" | "asia/saigon" => Some((10.8231, 106.6297, "Vietnam")),
        "asia/kuala_lumpur" | "myt" => Some((3.1390, 101.6869, "Kuala Lumpur/Malaysia")),
        "asia/dubai" | "gst" => Some((25.2048, 55.2708, "Dubai/UAE")),
        "asia/riyadh" => Some((24.7136, 46.6753, "Riyadh/Saudi Arabia")),
        "asia/tehran" | "irst" => Some((35.6892, 51.3890, "Tehran/Iran")),
        "asia/jerusalem" | "asia/tel_aviv" => Some((31.7683, 35.2137, "Jerusalem/Israel")),
        // Oceania
        "australia/sydney" | "aest" | "aedt" => Some((-33.8688, 151.2093, "Sydney/Australia")),
        "australia/melbourne" => Some((-37.8136, 144.9631, "Melbourne/Australia")),
        "australia/brisbane" => Some((-27.4698, 153.0251, "Brisbane/Australia")),
        "australia/perth" | "awst" => Some((-31.9505, 115.8605, "Perth/Australia")),
        "pacific/auckland" | "nzst" | "nzdt" => Some((-36.8485, 174.7633, "Auckland/New Zealand")),
        // Africa
        "africa/cairo" | "eet" => Some((30.0444, 31.2357, "Cairo/Egypt")),
        "africa/johannesburg" | "sast" => Some((-26.2041, 28.0473, "Johannesburg/South Africa")),
        "africa/nairobi" | "eat" => Some((-1.2921, 36.8219, "Nairobi/Kenya")),
        "africa/lagos" | "wat" => Some((6.5244, 3.3792, "Lagos/Nigeria")),
        "africa/casablanca" => Some((33.5731, -7.5898, "Casablanca/Morocco")),
        _ => None,
    }
}

// ─── Country name → code ────────────────────────────────────────────────────

fn country_name_to_code(name: &str) -> Option<&'static str> {
    let lower = name.to_lowercase();
    match lower.as_str() {
        "united states" | "us" | "usa" => Some("US"),
        "united kingdom" | "uk" | "gb" | "great britain" => Some("GB"),
        "australia" | "au" => Some("AU"),
        "canada" | "ca" => Some("CA"),
        "germany" | "de" | "deutschland" => Some("DE"),
        "france" | "fr" => Some("FR"),
        "italy" | "it" | "italia" => Some("IT"),
        "spain" | "es" | "españa" => Some("ES"),
        "japan" | "jp" => Some("JP"),
        "south korea" | "kr" | "korea" => Some("KR"),
        "china" | "cn" => Some("CN"),
        "india" | "in" => Some("IN"),
        "brazil" | "br" | "brasil" => Some("BR"),
        "russia" | "ru" => Some("RU"),
        "netherlands" | "nl" => Some("NL"),
        "switzerland" | "ch" => Some("CH"),
        "sweden" | "se" => Some("SE"),
        "norway" | "no" => Some("NO"),
        "new zealand" | "nz" => Some("NZ"),
        "singapore" | "sg" => Some("SG"),
        "indonesia" | "id" => Some("ID"),
        "mexico" | "mx" => Some("MX"),
        "argentina" | "ar" => Some("AR"),
        "south africa" | "za" => Some("ZA"),
        "turkey" | "tr" | "türkiye" => Some("TR"),
        "poland" | "pl" => Some("PL"),
        "ukraine" | "ua" => Some("UA"),
        "israel" | "il" => Some("IL"),
        "egypt" | "eg" => Some("EG"),
        "nigeria" | "ng" => Some("NG"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    #[test]
    fn accepts_geo_relevant_targets() {
        let m = GeoIntel;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y")));
        assert!(m.accepts(&Target::new(TargetKind::Username, "alice")));
        assert!(m.accepts(&Target::new(TargetKind::Phone, "+61400000000")));
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://example.com")));
        assert!(m.accepts(&Target::new(TargetKind::FullName, "John Doe")));
        assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Corp")));
    }

    #[test]
    fn rejects_non_geo_targets() {
        let m = GeoIntel;
        assert!(!m.accepts(&Target::new(TargetKind::Coordinates, "0,0")));
        assert!(!m.accepts(&Target::new(TargetKind::Address, "Brisbane")));
    }

    #[test]
    fn module_name_and_priority() {
        assert_eq!(GeoIntel.name(), "geo_intel");
        assert_eq!(GeoIntel.priority(), 22);
    }

    #[test]
    fn cost_is_key_gated() {
        assert!(matches!(GeoIntel.cost(), ModuleCost::KeyGated));
    }

    #[test]
    fn phone_prefix_au() {
        let (country, cc, lat, lon) = phone_prefix_to_country("61400000000").unwrap();
        assert_eq!(cc, "AU");
        assert!(country.contains("Australia"));
        assert!(lat < 0.0);
        assert!(lon > 100.0);
    }

    #[test]
    fn phone_prefix_us() {
        let (_, cc, _, _) = phone_prefix_to_country("12025551234").unwrap();
        assert_eq!(cc, "US");
    }

    #[test]
    fn phone_prefix_uk() {
        let (_, cc, _, _) = phone_prefix_to_country("447911123456").unwrap();
        assert_eq!(cc, "GB");
    }

    #[test]
    fn phone_prefix_3digit() {
        let (_, cc, _, _) = phone_prefix_to_country("971501234567").unwrap();
        assert_eq!(cc, "AE");
    }

    #[test]
    fn phone_prefix_unknown() {
        assert!(phone_prefix_to_country("000").is_none());
    }

    #[test]
    fn timezone_nyc() {
        let (lat, lon, region) = timezone_to_coordinates("America/New_York").unwrap();
        assert!((lat - 40.7128).abs() < 0.01);
        assert!((lon - (-74.0060)).abs() < 0.01);
        assert!(region.contains("Eastern"));
    }

    #[test]
    fn timezone_sydney() {
        let (lat, _, region) = timezone_to_coordinates("Australia/Sydney").unwrap();
        assert!(lat < 0.0);
        assert!(region.contains("Sydney"));
    }

    #[test]
    fn timezone_unknown() {
        assert!(timezone_to_coordinates("Unknown/Zone").is_none());
    }

    #[test]
    fn consensus_single_source() {
        let seeds = vec![LocationSeed {
            country: Some("Australia".into()),
            city: Some("Brisbane".into()),
            state: Some("QLD".into()),
            postal: None,
            address: None,
            location: None,
            timezone: None,
            source: "linkedin".into(),
        }];
        let con = compute_location_consensus(&seeds).unwrap();
        assert_eq!(con.city.as_deref(), Some("Brisbane"));
        assert_eq!(con.country.as_deref(), Some("Australia"));
        assert_eq!(con.source_count, 1);
        assert!(con.address_str.contains("Brisbane"));
    }

    #[test]
    fn consensus_multiple_sources() {
        let seeds = vec![
            LocationSeed {
                country: Some("US".into()),
                city: Some("New York".into()),
                state: None,
                postal: None,
                address: None,
                location: None,
                timezone: None,
                source: "linkedin".into(),
            },
            LocationSeed {
                country: Some("US".into()),
                city: Some("New York".into()),
                state: None,
                postal: None,
                address: None,
                location: None,
                timezone: None,
                source: "adobe".into(),
            },
            LocationSeed {
                country: Some("US".into()),
                city: Some("Los Angeles".into()),
                state: None,
                postal: None,
                address: None,
                location: None,
                timezone: None,
                source: "myspace".into(),
            },
        ];
        let con = compute_location_consensus(&seeds).unwrap();
        assert_eq!(con.city.as_deref(), Some("New York"));
        assert_eq!(con.country.as_deref(), Some("US"));
        assert_eq!(con.source_count, 3);
    }

    #[test]
    fn consensus_empty() {
        assert!(compute_location_consensus(&[]).is_none());
    }

    #[test]
    fn country_name_to_code_works() {
        assert_eq!(country_name_to_code("Australia"), Some("AU"));
        assert_eq!(country_name_to_code("united states"), Some("US"));
        assert_eq!(country_name_to_code("United Kingdom"), Some("GB"));
        assert_eq!(country_name_to_code("Unknown Country"), None);
    }

    #[test]
    fn mode_finds_most_common() {
        assert_eq!(mode(&["a", "b", "a", "c", "a"]), Some("a"));
        assert_eq!(mode(&["x"]), Some("x"));
        assert_eq!(mode(&[]), None);
    }

    #[test]
    fn ipapico_resp_deserializes() {
        let json = r#"{
            "ip": "1.1.1.1",
            "city": "South Brisbane",
            "region": "Queensland",
            "country_name": "Australia",
            "country_code": "AU",
            "postal": "4101",
            "latitude": -27.4766,
            "longitude": 153.0166,
            "timezone": "Australia/Brisbane",
            "org": "APNIC",
            "asn": "AS13335"
        }"#;
        let r: IpApiCoResp = serde_json::from_str(json).unwrap();
        assert!((r.latitude.unwrap() - (-27.4766)).abs() < 0.001);
        assert_eq!(r.country_code.as_deref(), Some("AU"));
        assert_eq!(r.error, None);
    }

    #[test]
    fn freeipapi_resp_deserializes() {
        let json = r#"{
            "ipAddress": "1.1.1.1",
            "latitude": -27.4766,
            "longitude": 153.0166,
            "countryName": "Australia",
            "countryCode": "AU",
            "cityName": "South Brisbane",
            "regionName": "Queensland",
            "zipCode": "4101",
            "timeZone": "+10:00",
            "isProxy": false
        }"#;
        let r: FreeIpApiResp = serde_json::from_str(json).unwrap();
        assert!((r.latitude.unwrap() - (-27.4766)).abs() < 0.001);
        assert_eq!(r.country_code.as_deref(), Some("AU"));
        assert_eq!(r.is_proxy, Some(false));
    }
}
