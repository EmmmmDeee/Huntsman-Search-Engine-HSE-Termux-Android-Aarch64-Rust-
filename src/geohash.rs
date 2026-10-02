//! Geohash encode and decode. Rebuilt from the monolith's `util::geohash::encode`.
//! Pure, no I/O.
//!
//! The monolith clamped precision silently (0 became 1, 99 became 12) and had no
//! decoder, so nothing could prove an encoding round-trips. Here an unusable
//! precision is an error and `decode` returns the cell the hash names. A geohash
//! names a cell, not a point: precision 7 is roughly 150 m by 150 m.

use crate::error::Error;

const BASE32: &[u8; 32] = b"0123456789bcdefghjkmnpqrstuvwxyz";

/// 12 characters are 60 bits, 30 per axis: the most an `f64` splits without loss.
pub const MAX_PRECISION: usize = 12;

/// The cell a geohash names. Edges are inclusive on the low side.
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
            let (lo, hi, v) = if even {
                (&mut lon_lo, &mut lon_hi, lon)
            } else {
                (&mut lat_lo, &mut lat_hi, lat)
            };
            let mid = f64::midpoint(*lo, *hi);
            idx <<= 1;
            if v >= mid {
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
    for b in hash.bytes() {
        let idx = BASE32.iter().position(|&c| c == b).ok_or_else(|| {
            Error::Invalid(format!("not a geohash character: {:?}", char::from(b)))
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

#[cfg(test)]
#[allow(clippy::float_cmp)] // exact 0.0/1.0 sentinels are the contract under test
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
    fn unusable_input_is_an_error_not_a_clamp() {
        assert!(encode(91.0, 0.0, 7).is_err());
        assert!(encode(0.0, 180.5, 7).is_err());
        assert!(encode(f64::NAN, 0.0, 7).is_err());
        assert!(encode(0.0, f64::INFINITY, 7).is_err());
        assert!(encode(0.0, 0.0, 0).is_err());
        assert!(encode(0.0, 0.0, 13).is_err());
        for bad in ["", "a", "u4pruydqqvjxx", "U4PRU", "u4 ru", "é"] {
            assert!(decode(bad).is_err(), "{bad:?}");
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
            for p in 1..=MAX_PRECISION {
                let h = encode(lat, lon, p).unwrap();
                assert_eq!(h.len(), p);
                assert!(decode(&h).unwrap().contains(lat, lon), "{lat},{lon} {h}");
            }
        }
    }

    #[test]
    fn every_hash_round_trips_through_its_own_cell_centre() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for _ in 0..2000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let len = 1 + usize::try_from((state >> 40) % 12).unwrap();
            let hash: String = (0..len)
                .map(|i| {
                    let v = usize::try_from((state >> (i * 5 % 59)) % 32).unwrap();
                    char::from(BASE32[v])
                })
                .collect();
            let (lat, lon) = decode(&hash).unwrap().center();
            assert_eq!(encode(lat, lon, len).unwrap(), hash);
        }
    }

    #[test]
    fn a_point_is_inside_the_cell_of_every_prefix_and_cells_nest() {
        let (lat, lon) = (-33.8688, 151.2093);
        let full = encode(lat, lon, MAX_PRECISION).unwrap();
        let mut outer = decode(&full[..1]).unwrap();
        for p in 1..=MAX_PRECISION {
            assert_eq!(encode(lat, lon, p).unwrap(), &full[..p], "prefix property");
            let cell = decode(&full[..p]).unwrap();
            assert!(cell.contains(lat, lon));
            assert!(
                cell.lat_min >= outer.lat_min
                    && cell.lat_max <= outer.lat_max
                    && cell.lon_min >= outer.lon_min
                    && cell.lon_max <= outer.lon_max,
                "cells must nest at {p}"
            );
            outer = cell;
        }
    }

    #[test]
    fn cell_size_halves_per_bit() {
        let c = decode("s").unwrap();
        assert!((c.lon_max - c.lon_min - 45.0).abs() < 1e-12);
        assert!((c.lat_max - c.lat_min - 45.0).abs() < 1e-12);
        let c7 = decode("r7hgdqz").unwrap();
        assert!(c7.lat_max - c7.lat_min < 0.002 && c7.lon_max - c7.lon_min < 0.002);
    }
}
