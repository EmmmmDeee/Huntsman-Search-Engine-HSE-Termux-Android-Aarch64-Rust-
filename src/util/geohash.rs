//! Geospatial enrichment helpers — geohash, address normalisation,
//! timezone inference, all offline (no API calls, no deps).
//!
//! These functions feed the geo-precision pipeline: every Coordinates
//! entity gets a geohash and timezone attached as evidence; every
//! Address entity gets parsed into structured components so downstream
//! geocode/overpass can resolve it more reliably.

/// Standard geohash base-32 alphabet (no a/i/l/o to avoid confusion).
const BASE32: &[u8; 32] = b"0123456789bcdefghjkmnpqrstuvwxyz";

/// Compute the geohash for a (lat, lon) pair at the given precision.
///
/// Precision 7 = ±76m on the equator (suburb-level). 8 = ±19m (block).
/// 9 = ±2.4m (building). The default 7 matches HSE's coordinate
/// confidence — anything tighter is false precision.
pub fn geohash(lat: f64, lon: f64, precision: u8) -> String {
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return String::new();
    }
    let precision = precision.clamp(1, 12) as usize;
    let mut out = String::with_capacity(precision);
    let mut lat_range = (-90.0_f64, 90.0_f64);
    let mut lon_range = (-180.0_f64, 180.0_f64);
    let mut even = true;
    let mut bit: u8 = 0;
    let mut idx: u8 = 0;
    while out.len() < precision {
        let mid = if even {
            (lon_range.0 + lon_range.1) / 2.0
        } else {
            (lat_range.0 + lat_range.1) / 2.0
        };
        let val = if even { lon } else { lat };
        if val >= mid {
            idx = (idx << 1) | 1;
            if even {
                lon_range.0 = mid;
            } else {
                lat_range.0 = mid;
            }
        } else {
            idx <<= 1;
            if even {
                lon_range.1 = mid;
            } else {
                lat_range.1 = mid;
            }
        }
        even = !even;
        bit += 1;
        if bit == 5 {
            out.push(BASE32[idx as usize] as char);
            bit = 0;
            idx = 0;
        }
    }
    out
}

/// Parse "lat,lon" strings (as produced by HSE Coordinates entities)
/// into a (f64, f64) tuple. Tolerates whitespace, trailing characters.
pub fn parse_coords(s: &str) -> Option<(f64, f64)> {
    let (lat_s, lon_s) = s.split_once(',')?;
    let lat: f64 = lat_s.trim().parse().ok()?;
    let lon: f64 = lon_s.trim().parse().ok()?;
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }
    Some((lat, lon))
}

/// Coarse timezone inference from coordinates via 15° longitude bands.
/// Returns IANA-style "Etc/GMT±N" identifier — accurate to within
/// 1-2 hours for any inland location. Refines for Australia (UTC+8/9.5/10),
/// US (Pacific/Mountain/Central/Eastern), and Europe (CET/EET).
pub fn timezone_for(lat: f64, lon: f64) -> &'static str {
    // Australia tight bands (more precise than longitude/15)
    if (-44.0..=-10.0).contains(&lat) {
        if lon > 140.0 {
            return "Australia/Sydney"; // UTC+10/+11 (Eastern: NSW, VIC, QLD, TAS)
        }
        if lon > 130.0 {
            return "Australia/Adelaide"; // UTC+9:30/+10:30 (SA, NT central)
        }
        if lon > 110.0 {
            return "Australia/Perth"; // UTC+8 (WA)
        }
    }
    // CONUS
    if (24.0..=49.0).contains(&lat) && (-125.0..=-66.0).contains(&lon) {
        if lon < -114.0 {
            return "America/Los_Angeles";
        }
        if lon < -102.0 {
            return "America/Denver";
        }
        if lon < -87.0 {
            return "America/Chicago";
        }
        return "America/New_York";
    }
    // UK + Western Europe
    if (35.0..=60.0).contains(&lat) {
        if (-12.0..=2.0).contains(&lon) {
            return "Europe/London";
        }
        if (2.0..=20.0).contains(&lon) {
            return "Europe/Paris"; // CET
        }
        if (20.0..=30.0).contains(&lon) {
            return "Europe/Helsinki"; // EET
        }
    }
    // Generic fallback: 15° bands
    let offset = (lon / 15.0).round() as i32;
    match offset {
        -12 => "Etc/GMT+12",
        -11 => "Etc/GMT+11",
        -10 => "Pacific/Honolulu",
        -9 => "Etc/GMT+9",
        -8 => "America/Los_Angeles",
        -7 => "America/Denver",
        -6 => "America/Chicago",
        -5 => "America/New_York",
        -4 => "Atlantic/Bermuda",
        -3 => "America/Argentina/Buenos_Aires",
        -2 => "Etc/GMT+2",
        -1 => "Atlantic/Azores",
        0 => "Etc/UTC",
        1 => "Europe/Paris",
        2 => "Europe/Helsinki",
        3 => "Europe/Moscow",
        4 => "Asia/Dubai",
        5 => "Asia/Karachi",
        6 => "Asia/Dhaka",
        7 => "Asia/Bangkok",
        8 => "Asia/Singapore",
        9 => "Asia/Tokyo",
        10 => "Australia/Sydney",
        11 => "Pacific/Noumea",
        12 => "Pacific/Auckland",
        _ => "Etc/UTC",
    }
}

/// Parsed components of a free-form address string.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AddressComponents {
    pub street: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
    pub iso_country: Option<String>,
}

/// Two-letter ISO country code lookup by name. Covers the ~30
/// countries most likely to appear in OSINT breach data.
fn iso_for(country: &str) -> Option<&'static str> {
    let l = country.trim().to_lowercase();
    Some(match l.as_str() {
        "united states" | "usa" | "us" | "united states of america" => "US",
        "australia" | "au" => "AU",
        "united kingdom" | "uk" | "great britain" | "england" | "gb" => "GB",
        "canada" | "ca" => "CA",
        "germany" | "de" | "deutschland" => "DE",
        "france" | "fr" => "FR",
        "netherlands" | "nl" | "holland" => "NL",
        "spain" | "es" => "ES",
        "italy" | "it" => "IT",
        "japan" | "jp" => "JP",
        "china" | "cn" => "CN",
        "india" | "in" => "IN",
        "brazil" | "br" => "BR",
        "russia" | "ru" => "RU",
        "ireland" | "ie" => "IE",
        "new zealand" | "nz" => "NZ",
        "singapore" | "sg" => "SG",
        "south africa" | "za" => "ZA",
        "mexico" | "mx" => "MX",
        "south korea" | "kr" | "korea" => "KR",
        "switzerland" | "ch" => "CH",
        "sweden" | "se" => "SE",
        "norway" | "no" => "NO",
        "denmark" | "dk" => "DK",
        "finland" | "fi" => "FI",
        "poland" | "pl" => "PL",
        "belgium" | "be" => "BE",
        "austria" | "at" => "AT",
        "portugal" | "pt" => "PT",
        _ => return None,
    })
}

/// Australian state-name normaliser.
fn au_state_norm(s: &str) -> Option<&'static str> {
    let l = s.trim().to_lowercase();
    Some(match l.as_str() {
        "nsw" | "new south wales" => "NSW",
        "vic" | "victoria" => "VIC",
        "qld" | "queensland" => "QLD",
        "wa" | "western australia" => "WA",
        "sa" | "south australia" => "SA",
        "tas" | "tasmania" => "TAS",
        "act" | "australian capital territory" => "ACT",
        "nt" | "northern territory" => "NT",
        _ => return None,
    })
}

/// Parse a comma-separated address into structured components.
///
/// Handles common formats:
///   "Sydney, NSW, Australia"      → city=Sydney, state=NSW, country=Australia
///   "10 Smith St, Melbourne, VIC" → street=..., city=..., state=...
///   "SA, VIC"                     → state list (no city/country)
///   "Brisbane, QLD 4000"          → city + state + postal
pub fn parse_address(input: &str) -> AddressComponents {
    let mut out = AddressComponents::default();
    let parts: Vec<&str> = input
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if parts.is_empty() {
        return out;
    }

    // Country: last part if it matches a known ISO name.
    if let Some(last) = parts.last()
        && let Some(iso) = iso_for(last)
    {
        out.country = Some((*last).to_string());
        out.iso_country = Some(iso.to_string());
    }

    // Scan every part for state codes and postal patterns. A part like
    // "QLD 4000" carries both — split on space and try each token.
    for part in &parts {
        for token in part.split_whitespace() {
            // Australian state code
            if out.state.is_none()
                && let Some(s) = au_state_norm(token)
            {
                out.state = Some(s.to_string());
                if out.iso_country.is_none() {
                    out.iso_country = Some("AU".to_string());
                    out.country = Some("Australia".to_string());
                }
            }
            // Postal code (bare digits, 4-10 chars)
            if out.postal_code.is_none()
                && token.chars().all(|c| c.is_ascii_digit())
                && (4..=10).contains(&token.len())
            {
                out.postal_code = Some(token.to_string());
            }
        }
    }

    // Street detection BEFORE city: if parts.len() ≥ 3 and the first
    // part starts with a digit, it's a street address.
    let mut city_skip = 0usize;
    if parts.len() >= 3 && parts[0].chars().next().map(|c| c.is_ascii_digit()) == Some(true) {
        out.street = Some(parts[0].to_string());
        city_skip = 1;
    }

    // City: first non-classified part after any street.
    for part in parts.iter().skip(city_skip) {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        if out.country.as_deref() == Some(p) {
            continue;
        }
        // "QLD 4000"-style parts: skip if the entire part is a state token,
        // a postal, or "state postal" combination.
        let first_token = p.split_whitespace().next().unwrap_or("");
        if au_state_norm(first_token).is_some() {
            continue;
        }
        if iso_for(p).is_some() {
            continue;
        }
        if p.chars().all(|c| c.is_ascii_digit() || c.is_whitespace()) {
            continue;
        }
        // First valid candidate wins.
        out.city = Some(p.to_string());
        break;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geohash_sydney_opera_house() {
        // Famous coords: -33.8568° S, 151.2153° E → r3gx2f7 prefix
        let h = geohash(-33.8568, 151.2153, 7);
        assert!(h.starts_with("r3gx2"), "got {h}");
        assert_eq!(h.len(), 7);
    }

    #[test]
    fn geohash_invalid_coords_returns_empty() {
        assert!(geohash(91.0, 0.0, 7).is_empty());
        assert!(geohash(0.0, 200.0, 7).is_empty());
    }

    #[test]
    fn parse_coords_handles_typical_format() {
        assert_eq!(
            parse_coords("-33.8568,151.2153"),
            Some((-33.8568, 151.2153))
        );
        assert_eq!(parse_coords("38.83, -104.82"), Some((38.83, -104.82)));
    }

    #[test]
    fn parse_coords_rejects_invalid() {
        assert!(parse_coords("not-coords").is_none());
        assert!(parse_coords("91,0").is_none());
        assert!(parse_coords("0,181").is_none());
    }

    #[test]
    fn timezone_australia_specific() {
        assert_eq!(timezone_for(-33.86, 151.21), "Australia/Sydney");
        assert_eq!(timezone_for(-31.95, 115.86), "Australia/Perth");
        assert_eq!(timezone_for(-34.93, 138.60), "Australia/Adelaide");
    }

    #[test]
    fn timezone_us_specific() {
        assert_eq!(timezone_for(40.71, -74.00), "America/New_York");
        assert_eq!(timezone_for(37.77, -122.41), "America/Los_Angeles");
    }

    #[test]
    fn parse_address_aus_full() {
        let a = parse_address("Sydney, NSW, Australia");
        assert_eq!(a.city.as_deref(), Some("Sydney"));
        assert_eq!(a.state.as_deref(), Some("NSW"));
        assert_eq!(a.country.as_deref(), Some("Australia"));
        assert_eq!(a.iso_country.as_deref(), Some("AU"));
    }

    #[test]
    fn parse_address_with_street() {
        let a = parse_address("10 Smith St, Melbourne, VIC, Australia");
        assert_eq!(a.street.as_deref(), Some("10 Smith St"));
        assert_eq!(a.city.as_deref(), Some("Melbourne"));
        assert_eq!(a.state.as_deref(), Some("VIC"));
        assert_eq!(a.iso_country.as_deref(), Some("AU"));
    }

    #[test]
    fn parse_address_state_only() {
        let a = parse_address("SA, VIC");
        // First-classified-state wins
        assert_eq!(a.state.as_deref(), Some("SA"));
        // Country inferred from AU state code
        assert_eq!(a.iso_country.as_deref(), Some("AU"));
    }

    #[test]
    fn parse_address_postal_code() {
        let a = parse_address("Brisbane, QLD 4000");
        assert_eq!(a.city.as_deref(), Some("Brisbane"));
        assert_eq!(a.state.as_deref(), Some("QLD"));
        assert_eq!(a.postal_code.as_deref(), Some("4000"));
    }
}
