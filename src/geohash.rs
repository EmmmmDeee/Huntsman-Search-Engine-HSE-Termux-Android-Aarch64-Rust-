#![allow(clippy::cast_precision_loss)]

//! Geohash encode/decode plus the monolith's missing pure place helpers.

use crate::error::Error;

pub use crate::place::{
    AddressComponents, GEO_OUTLIER_KM, country_name_for_iso, is_bare_country, parse_address,
    reverse_country_iso, timezone_for,
};

const BASE32: &[u8; 32] = b"0123456789bcdefghjkmnpqrstuvwxyz";
const EARTH_KM: f64 = 6_371.0;
const MAX_PRECISION_U8: u8 = 12;

/// 12 characters are 60 bits, 30 per axis: the most an `f64` splits without loss.
pub const MAX_PRECISION: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Cell {
    pub lat_min: f64,
    pub lat_max: f64,
    pub lon_min: f64,
    pub lon_max: f64,
}

impl Cell {
    #[must_use]
    pub fn center(&self) -> (f64, f64) {
        (
            f64::midpoint(self.lat_min, self.lat_max),
            f64::midpoint(self.lon_min, self.lon_max),
        )
    }

    #[must_use]
    pub fn contains(&self, lat: f64, lon: f64) -> bool {
        (self.lat_min..=self.lat_max).contains(&lat) && (self.lon_min..=self.lon_max).contains(&lon)
    }
}

/// Encode a coordinate at `precision` characters (1..=12).
///
/// # Errors
/// `Error::Invalid` for a non-finite or out-of-range coordinate, or a precision
/// outside 1..=12.
pub fn encode(lat: f64, lon: f64, precision: usize) -> Result<String, Error> {
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return Err(Error::Invalid("coordinate out of range".into()));
    }
    if !(1..=MAX_PRECISION).contains(&precision) {
        return Err(Error::Invalid(format!(
            "geohash precision must be 1..={MAX_PRECISION}"
        )));
    }
    let (mut lat_lo, mut lat_hi) = (-90.0_f64, 90.0_f64);
    let (mut lon_lo, mut lon_hi) = (-180.0_f64, 180.0_f64);
    let mut out = String::with_capacity(precision);
    let mut even = true;
    for _ in 0..precision {
        let mut idx = 0usize;
        for _ in 0..5 {
            let (lo, hi, value) = if even {
                (&mut lon_lo, &mut lon_hi, lon)
            } else {
                (&mut lat_lo, &mut lat_hi, lat)
            };
            let mid = f64::midpoint(*lo, *hi);
            idx <<= 1;
            if value >= mid {
                idx |= 1;
                *lo = mid;
            } else {
                *hi = mid;
            }
            even = !even;
        }
        out.push(char::from(BASE32[idx]));
    }
    Ok(out)
}

/// Legacy-compatible wrapper: invalid input yields `""` and precision is clamped.
#[must_use]
pub fn geohash(lat: f64, lon: f64, precision: u8) -> String {
    encode(lat, lon, usize::from(precision.clamp(1, MAX_PRECISION_U8))).unwrap_or_default()
}

/// The cell named by `hash`. Lowercase only: `a`, `i`, `l`, `o` are not in the alphabet.
///
/// # Errors
/// `Error::Invalid` for an empty, over-long, or non-alphabet hash.
pub fn decode(hash: &str) -> Result<Cell, Error> {
    if hash.is_empty() || hash.len() > MAX_PRECISION {
        return Err(Error::Invalid(format!(
            "geohash length must be 1..={MAX_PRECISION}"
        )));
    }
    let mut cell = Cell {
        lat_min: -90.0,
        lat_max: 90.0,
        lon_min: -180.0,
        lon_max: 180.0,
    };
    let mut even = true;
    for byte in hash.bytes() {
        let idx = BASE32
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or_else(|| {
                Error::Invalid(format!("not a geohash character: {:?}", char::from(byte)))
            })?;
        for bit in (0..5).rev() {
            let (lo, hi) = if even {
                (&mut cell.lon_min, &mut cell.lon_max)
            } else {
                (&mut cell.lat_min, &mut cell.lat_max)
            };
            let mid = f64::midpoint(*lo, *hi);
            if (idx >> bit) & 1 == 1 {
                *lo = mid;
            } else {
                *hi = mid;
            }
            even = !even;
        }
    }
    Ok(cell)
}

/// Parse a `lat,lon` pair with range checks.
#[must_use]
pub fn parse_coords(value: &str) -> Option<(f64, f64)> {
    let (lat_raw, lon_raw) = value.split_once(',')?;
    let lat = lat_raw.trim().parse::<f64>().ok()?;
    let lon = lon_raw.trim().parse::<f64>().ok()?;
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }
    Some((lat, lon))
}

/// Great-circle distance in kilometres.
#[must_use]
pub fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlon / 2.0).sin().powi(2);
    2.0 * EARTH_KM * a.sqrt().atan2((1.0 - a).max(0.0).sqrt())
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn canonical_reference_vectors() {
        assert_eq!(encode(57.64911, 10.40744, 11).unwrap(), "u4pruydqqvj");
        assert_eq!(encode(57.64911, 10.40744, 5).unwrap(), "u4pru");
        assert_eq!(encode(42.605, -5.603, 5).unwrap(), "ezs42");
        assert_eq!(encode(0.0, 0.0, 1).unwrap(), "s");
        assert_eq!(encode(-27.4698, 153.0251, 6).unwrap(), "r7hgdp");
    }

    #[test]
    fn legacy_wrapper_keeps_old_totality_contract() {
        let hash = geohash(-33.8568, 151.2153, 7);
        assert!(hash.starts_with("r3gx2"), "{hash}");
        assert_eq!(hash.len(), 7);
        assert_eq!(geohash(91.0, 0.0, 7), "");
        assert_eq!(geohash(0.0, 200.0, 7), "");
        assert_eq!(geohash(0.0, 0.0, 0).len(), 1);
        assert_eq!(geohash(0.0, 0.0, 20).len(), MAX_PRECISION);
    }

    #[test]
    fn unusable_input_is_an_error_not_a_clamp() {
        assert!(encode(91.0, 0.0, 7).is_err());
        assert!(encode(0.0, 180.5, 7).is_err());
        assert!(encode(f64::NAN, 0.0, 7).is_err());
        assert!(encode(0.0, f64::INFINITY, 7).is_err());
        assert!(encode(0.0, 0.0, 0).is_err());
        assert!(encode(0.0, 0.0, 13).is_err());
        for bad in ["", "a", "u4pruydqqvjxx", "U4PRU", "u4 ru", "é"] {
            assert!(decode(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn extreme_corners_encode_and_stay_inside_their_cell() {
        for (lat, lon) in [
            (90.0, 180.0),
            (-90.0, -180.0),
            (90.0, -180.0),
            (-90.0, 180.0),
            (-0.0, -0.0),
        ] {
            for precision in 1..=MAX_PRECISION {
                let hash = encode(lat, lon, precision).unwrap();
                assert_eq!(hash.len(), precision);
                assert!(
                    decode(&hash).unwrap().contains(lat, lon),
                    "{lat},{lon} {hash}"
                );
            }
        }
    }

    #[test]
    fn every_hash_round_trips_through_its_own_cell_center() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for _ in 0..2000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let len = 1 + usize::try_from((state >> 40) % 12).unwrap();
            let hash: String = (0..len)
                .map(|index| {
                    let value = usize::try_from((state >> (index * 5 % 59)) % 32).unwrap();
                    char::from(BASE32[value])
                })
                .collect();
            let (lat, lon) = decode(&hash).unwrap().center();
            assert_eq!(encode(lat, lon, len).unwrap(), hash);
        }
    }

    #[test]
    fn prefix_property_and_cell_nesting_hold() {
        let (lat, lon) = (-33.8688, 151.2093);
        let full = encode(lat, lon, MAX_PRECISION).unwrap();
        let mut outer = decode(&full[..1]).unwrap();
        for precision in 1..=MAX_PRECISION {
            assert_eq!(encode(lat, lon, precision).unwrap(), &full[..precision]);
            let cell = decode(&full[..precision]).unwrap();
            assert!(cell.contains(lat, lon));
            assert!(
                cell.lat_min >= outer.lat_min
                    && cell.lat_max <= outer.lat_max
                    && cell.lon_min >= outer.lon_min
                    && cell.lon_max <= outer.lon_max
            );
            outer = cell;
        }
    }

    #[test]
    fn parse_coords_and_haversine_cover_legacy_helpers() {
        assert_eq!(parse_coords(" -27.47 , 153.02 "), Some((-27.47, 153.02)));
        assert_eq!(parse_coords("91.0,0.0"), None);
        assert_eq!(parse_coords("153.02"), None);
        assert_eq!(parse_coords("a,b"), None);
        let distance = haversine_km(-33.87, 151.21, -37.81, 144.96);
        assert!((distance - 714.0).abs() < 15.0, "{distance}");
        assert_eq!(haversine_km(10.0, 20.0, 10.0, 20.0), 0.0);
        let half = std::f64::consts::PI * EARTH_KM;
        let antipode = haversine_km(-87.5, 0.0, 87.5, 180.0);
        assert!(antipode.is_finite());
        assert!((antipode - half).abs() < 1.0);
    }

    #[test]
    fn haversine_is_a_bounded_symmetric_metric() {
        let max_km = std::f64::consts::PI * EARTH_KM + 1e-6;
        let mut state = 0x5dee_ce66d_u64;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            (state >> 11) as f64 / (1u64 << 53) as f64
        };
        for _ in 0..50_000 {
            let lat1 = next() * 180.0 - 90.0;
            let lon1 = next() * 360.0 - 180.0;
            let lat2 = next() * 180.0 - 90.0;
            let lon2 = next() * 360.0 - 180.0;
            let d = haversine_km(lat1, lon1, lat2, lon2);
            assert!(d.is_finite() && d >= 0.0);
            assert!(d <= max_km);
            assert_eq!(d, haversine_km(lat2, lon2, lat1, lon1));
            assert_eq!(haversine_km(lat1, lon1, lat1, lon1), 0.0);
        }
    }
}
