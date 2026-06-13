//! Geolocation intelligence — free-API IP geo and E.164 phone prefix lookup.
//!
//! For IP targets: queries free geo APIs (ipapi.co, freeipapi.com) that aren't
//! covered by ip_geo or ip_whois_geo, providing a third and fourth independent
//! source for AU-014 geo-cluster correlation.
//!
//! For Phone targets: derives a coarse country-centroid coordinate from the
//! ITU E.164 country prefix (offline, no API call).
//!
//! Free APIs used:
//!   - ipapi.co     — 1000 req/day, HTTPS, no key required
//!   - freeipapi.com — unlimited, HTTPS, no key required

use std::collections::HashSet;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::geo::is_valid_coords;
use crate::util::http::fetch_json;

const SRC: &str = "geo_intel";

pub struct GeoIntel;

// ─── ipapi.co response ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct IpApiCoResp {
    #[serde(default)]
    #[allow(dead_code)]
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
struct FreeIpApiResp {
    #[serde(default, rename = "ipAddress")]
    #[allow(dead_code)]
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
        "Free-API IP geolocation (ipapi.co, freeipapi.com) and E.164 phone prefix lookup"
    }

    fn priority(&self) -> u8 {
        22
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress | TargetKind::Phone)
    }

    fn max_timeout_ms(&self) -> u64 {
        25_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        match target.kind {
            TargetKind::IpAddress => process_ip(target, ctx).await,
            TargetKind::Phone => process_phone_prefix_only(target, ctx).await,
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

// ─── Phone number geolocation (free — E.164 prefix only) ────────────────────

async fn process_phone_prefix_only(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let mut result = ModuleResult::new();
    let mut seen = HashSet::new();

    // Country geolocation requires an EXPLICIT international form ('+' or the
    // '00' prefix) — shared with `phone_intl` so both agree on what counts as
    // international. Without it the leading digits are ambiguous: a US national
    // number ("202-555-0100") begins with an area code that the bare-prefix
    // scan would otherwise read as a country code ("20" → Egypt) and emit a
    // wrong-country coordinate. National/ambiguous → no coarse geo.
    let Some(phone) = crate::modules::phone_intl::international_digits(&target.value) else {
        return Ok(result);
    };
    if let Some((country, cc, lat, lon)) = phone_prefix_to_country(&phone) {
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
                    format!("Phone prefix -> {country} for {}", target.value),
                )
                .with_attr("country", country)
                .with_attr("country_code", cc)
                .with_attr("method", "e164-prefix"),
            );
            result.push(e);
        }
    }

    Ok(result)
}

// ─── Phone prefix -> country ────────────────────────────────────────────────

fn phone_prefix_to_country(phone: &str) -> Option<(&'static str, &'static str, f64, f64)> {
    if !phone.is_ascii() {
        return None;
    }
    // Caribbean NANP territories share country code +1 but use a 4-digit dialling
    // prefix (1242 Bahamas, 1876 Jamaica, …). The `[3, 2, 1]` scan below can only
    // see up to `1` and would geolocate every one of them to the US centroid —
    // an actively misleading wrong-country fix. `phone_intl` is the source of
    // truth for these 4-digit codes: if it identifies a non-US/CA NANP territory,
    // return `None` (honest "no precise location") rather than a wrong "US".
    if phone.starts_with('1')
        && let Some((prefix, iso, _)) = crate::modules::phone_intl::match_country(phone)
        && prefix.len() == 4
        && iso != "US"
        && iso != "CA"
    {
        return None;
    }
    [3usize, 2, 1].into_iter().find_map(|len| {
        if phone.len() < len {
            return None;
        }
        let prefix = &phone[..len];
        if !prefix.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        match prefix {
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
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    #[test]
    fn accepts_ip_and_phone() {
        let m = GeoIntel;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(m.accepts(&Target::new(TargetKind::Phone, "+61400000000")));
    }

    #[test]
    fn rejects_non_ip_phone_targets() {
        let m = GeoIntel;
        assert!(!m.accepts(&Target::new(TargetKind::Coordinates, "0,0")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Username, "alice")));
        assert!(!m.accepts(&Target::new(TargetKind::FullName, "Alice Bob")));
    }

    #[test]
    fn module_name_and_priority() {
        assert_eq!(GeoIntel.name(), "geo_intel");
        assert_eq!(GeoIntel.priority(), 22);
    }

    #[test]
    fn cost_is_free() {
        assert!(matches!(GeoIntel.cost(), ModuleCost::Free));
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
    fn caribbean_nanp_is_not_geolocated_to_the_us() {
        // Regression: a +1 number with a 4-digit Caribbean dialling prefix used to
        // fall through the 3-digit scan to `1` → US centroid. It must now return
        // None (no precise location) rather than an actively-wrong US fix.
        assert!(phone_prefix_to_country("12424567890").is_none()); // Bahamas (1242)
        assert!(phone_prefix_to_country("18764567890").is_none()); // Jamaica (1876)
        // A genuine US/Canada +1 number is unaffected.
        assert_eq!(phone_prefix_to_country("14165551234").unwrap().1, "US"); // Toronto (NANP)
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

    fn offline_ctx() -> ModuleContext {
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        ModuleContext {
            scan_id: "t".into(),
            bus,
            http: crate::util::http::build_client(),
            keys: std::collections::HashMap::default(),
            cancel: crate::core::cancel::CancelHandle::new(),
            proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
        }
    }

    #[tokio::test]
    async fn national_number_without_marker_yields_no_coordinate() {
        // Regression: a US national number ("202-555-0100") has no '+'/'00'
        // marker. The old code stripped a (absent) '+' and matched "20" → Egypt,
        // emitting Cairo coordinates. It must now emit nothing.
        let ctx = offline_ctx();
        let t = Target::new(TargetKind::Phone, "202-555-0100");
        let out = process_phone_prefix_only(&t, &ctx).await.unwrap();
        assert!(
            out.entities.is_empty(),
            "national number must not produce a (wrong-country) coordinate: {:?}",
            out.entities
        );

        // An explicit E.164 number still geolocates (here Egypt, correctly).
        let t = Target::new(TargetKind::Phone, "+20 100 000 0000");
        let out = process_phone_prefix_only(&t, &ctx).await.unwrap();
        assert_eq!(out.entities.len(), 1);
        assert!(out.entities[0].has_tag("country:EG"));
    }

    #[test]
    fn ip_geo_uses_shared_coord_validator() {
        // geo_intel now gates both IP sources on util::geo::is_valid_coords,
        // so out-of-range / Null-Island fixes from a hostile or buggy API are
        // rejected rather than becoming high-confidence Coordinates entities.
        assert!(is_valid_coords(-27.4766, 153.0166));
        assert!(!is_valid_coords(0.0, 0.0));
        assert!(!is_valid_coords(999.0, 10.0));
        assert!(!is_valid_coords(10.0, f64::NAN));
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
