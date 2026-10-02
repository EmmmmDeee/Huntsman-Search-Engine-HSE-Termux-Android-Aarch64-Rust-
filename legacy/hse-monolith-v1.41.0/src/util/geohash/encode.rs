/// Standard geohash base-32 alphabet (no a/i/l/o to avoid confusion).
const BASE32: &[u8; 32] = b"0123456789bcdefghjkmnpqrstuvwxyz";

/// Compute the geohash for a (lat, lon) pair at the given precision.
///
/// Precision 7 = ±76m on the equator (suburb-level). 8 = ±19m (block).
/// 9 = ±2.4m (building). The default 7 matches HSE's coordinate
/// confidence — anything tighter is false precision.
///
/// # Guarantees
/// - On valid coordinates, returns a string of exactly `precision.clamp(1, 12)`
///   base-32 characters (the standard `0-9 b-z` minus `a i l o` alphabet).
/// - Out-of-range `lat`/`lon` yield an empty string — never a panic.
///
/// ```
/// use huntsman_search_engine::util::geohash::geohash;
///
/// // Canonical reference point (Wikipedia) → its known geohash.
/// assert_eq!(geohash(57.64911, 10.40744, 11), "u4pruydqqvj");
/// assert_eq!(geohash(57.64911, 10.40744, 5), "u4pru"); // shorter precision = prefix
/// // Out-of-range latitude → empty, no panic.
/// assert_eq!(geohash(91.0, 0.0, 7), "");
/// ```
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

/// Parse a `"lat,lon"` string (as produced by HSE `Coordinates` entities) into a
/// `(f64, f64)` pair.
///
/// # Guarantees
/// - Returns `Some((lat, lon))` only when `s` is two comma-separated numbers with
///   `lat ∈ [-90, 90]` and `lon ∈ [-180, 180]`; surrounding whitespace on each
///   component is trimmed.
/// - Returns `None` for any other shape, a non-numeric component, or an
///   out-of-range value — never panics.
///
/// ```
/// use huntsman_search_engine::util::geohash::parse_coords;
///
/// assert_eq!(parse_coords(" -27.47 , 153.02 "), Some((-27.47, 153.02)));
/// assert_eq!(parse_coords("91.0,0.0"), None); // latitude out of range
/// assert_eq!(parse_coords("153.02"), None);   // not a pair
/// assert_eq!(parse_coords("a,b"), None);      // not numeric
/// ```
pub fn parse_coords(s: &str) -> Option<(f64, f64)> {
    let (lat_s, lon_s) = s.split_once(',')?;
    let lat: f64 = lat_s.trim().parse().ok()?;
    let lon: f64 = lon_s.trim().parse().ok()?;
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }
    Some((lat, lon))
}
