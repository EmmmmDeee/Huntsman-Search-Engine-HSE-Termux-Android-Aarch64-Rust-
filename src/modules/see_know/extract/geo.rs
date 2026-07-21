//! Geo-entity extraction from SeekNow records.
//!
//! Parses lat/lon coordinate fields and emits the Coordinates lead. Reaches
//! the parent extractor's helpers and imports via `use super::*`.

use super::*;
use crate::core::confidence;

/// Geo-conscious extraction — surface coordinates, timezones, and
/// location-bearing fields from any SeekNow endpoint response so the
/// downstream geocode/overpass/wigle modules can converge.
/// First-present-of-`keys` coordinate value, accepting either a JSON number or
/// a numeric string (some SeekNow endpoints serialise lat/lon as strings).
/// Preserves the original semantics: pick the first present key, then read it as
/// an f64 or, failing that, parse its string form.
pub(super) fn parse_coord(item: &Value, keys: &[&str]) -> Option<f64> {
    let v = keys.iter().find_map(|k| item.get(*k))?;
    v.as_f64().or_else(|| v.as_str()?.parse().ok())
}

pub(in crate::modules::see_know) fn extract_geo_entities(
    item: &Value,
    endpoint: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    // Direct coordinate fields — some endpoints (ip_info, phone_info)
    // return lat/lon pairs directly, as a JSON number or a numeric string.
    let lat = parse_coord(item, &["latitude", "lat"]);
    let lon = parse_coord(item, &["longitude", "lon", "lng"]);
    // Shared validator: finite + in-range + not-Null-Island. Breach/OSINT
    // aggregators commonly carry 0,0 as a null-location value in records,
    // which the prior range-only check admitted as a false Coordinates entity.
    if let (Some(la), Some(lo)) = (lat, lon)
        && is_valid_coords(la, lo)
    {
        let coord_val = format!("{la:.5},{lo:.5}");
        if seen.insert(format!("@coord:{coord_val}")) {
            let mut e = Entity::new(
                EntityKind::Coordinates,
                &coord_val,
                confidence::VERY_HIGH,
                scan_id,
            );
            e.tag("see-know");
            e.tag(format!("via:{endpoint}"));
            e.add_evidence(
                Evidence::new(SRC, format!("Coordinates from SeekNow /{endpoint}"))
                    .with_attr("lat", la.to_string())
                    .with_attr("lon", lo.to_string()),
            );
            result.push(e);
        }
    }

    // Location string fields — profile bios often contain "Sydney, NSW"-
    // style city/region strings that geocode can resolve.
    for field in ["location", "city_state", "region", "place", "hometown"] {
        if let Some(loc) = val_str(item, field)
            && loc.len() >= 3
            && seen.insert(format!("@loc:{}", loc.to_lowercase()))
        {
            let mut e = Entity::new(EntityKind::Address, &loc, confidence::MEDIUM_HIGH, scan_id);
            e.tag("see-know");
            e.tag(format!("via:{endpoint}"));
            e.tag("geo-hint");
            e.add_evidence(
                Evidence::new(SRC, format!("Location hint from {endpoint}.{field}"))
                    .with_attr("raw_field", field),
            );
            result.push(e);
        }
    }

    // Timezone — feeds the breach_timezone correlator for chronolocation.
    if let Some(tz) = val_str(item, "timezone").or_else(|| val_str(item, "tz"))
        && tz.len() >= 3
        && seen.insert(format!("@tz:{}", tz.to_lowercase()))
    {
        // Timezones don't have their own EntityKind; surface as evidence
        // on a low-confidence Address so the correlator can join.
        let mut e = Entity::new(
            EntityKind::Address,
            format!("tz:{tz}"),
            confidence::LOW,
            scan_id,
        );
        e.tag("see-know");
        e.tag("timezone");
        e.tag(format!("via:{endpoint}"));
        e.add_evidence(
            Evidence::new(SRC, format!("Timezone from {endpoint}")).with_attr("timezone", &tz),
        );
        result.push(e);
    }

    // ASN / ISP / Organisation — only emit when endpoint is ip_info.
    if endpoint == "ip_info" {
        if let Some(asn) = val_str(item, "asn")
            && seen.insert(format!("@asn:{asn}"))
        {
            let mut e = Entity::new(EntityKind::Asn, &asn, confidence::VERY_HIGH, scan_id);
            e.tag("see-know");
            e.add_evidence(Evidence::new(SRC, "ASN from SeekNow /network/ip"));
            result.push(e);
        }
        if let Some(org) = val_str(item, "org")
            .or_else(|| val_str(item, "isp"))
            .or_else(|| val_str(item, "company"))
            && seen.insert(format!("@org:{}", org.to_lowercase()))
        {
            let mut e = Entity::new(EntityKind::Organisation, &org, confidence::HIGH, scan_id);
            e.tag("see-know");
            e.add_evidence(Evidence::new(SRC, "Organisation from SeekNow /network/ip"));
            result.push(e);
        }
    }

    // WHOIS registrant address (Domain target via /whois endpoint).
    if endpoint == "whois" {
        let parts: Vec<String> = [
            "registrant_street",
            "registrant_city",
            "registrant_state",
            "registrant_postal",
            "registrant_country",
        ]
        .iter()
        .filter_map(|f| val_str(item, f))
        .collect();
        if parts.len() >= 2 {
            let addr = parts.join(", ");
            if seen.insert(format!("@whois-addr:{}", addr.to_lowercase())) {
                let mut e = Entity::new(EntityKind::Address, &addr, confidence::HIGH_PLUS, scan_id);
                e.tag("see-know");
                e.tag("whois-registrant");
                e.add_evidence(Evidence::new(SRC, "Domain WHOIS registrant address"));
                result.push(e);
            }
        }
    }
}
