//! GEOINT on operator-supplied fixes plus rebuilt legacy geo support.

use crate::error::Error;

pub use crate::geo;
pub use crate::geometry;
pub use crate::oui;
pub use crate::postcode_au;
pub use crate::radar;
pub use crate::rf;

#[derive(Debug, Clone, PartialEq)]
pub struct Fix {
    pub id: String,
    pub lat: f64,
    pub lon: f64,
    pub at_unix: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CoLocation {
    pub left: String,
    pub right: String,
    pub meters: f64,
    pub delta_secs: u64,
}

/// Parse `LAT,LON` in decimal degrees. NaN, infinities, and out-of-range values are refused.
///
/// # Errors
/// `Error::Invalid` when the pair is malformed or out of range.
pub fn parse_latlon(raw: &str) -> Result<(f64, f64), Error> {
    crate::geohash::parse_coords(raw)
        .ok_or_else(|| Error::Invalid("coordinate out of range".into()))
}

/// Great-circle metres on the sphere of [`crate::geohash::EARTH_RADIUS_KM`].
#[must_use]
pub fn haversine_m(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    crate::geohash::haversine_km(lat1, lon1, lat2, lon2) * 1000.0
}

/// Correlate only geographically valid fixes. `Fix` is public, so callers may
/// bypass `parse_latlon`; malformed coordinates must never produce an attribution.
#[must_use]
pub fn colocated(fixes: &[Fix], radius_m: f64, window_secs: u64) -> Vec<CoLocation> {
    let valid: Vec<&Fix> = fixes
        .iter()
        .filter(|fix| {
            (-90.0..=90.0).contains(&fix.lat) && (-180.0..=180.0).contains(&fix.lon)
        })
        .collect();
    let mut out = Vec::new();
    for i in 0..valid.len() {
        for j in (i + 1)..valid.len() {
            let meters = haversine_m(valid[i].lat, valid[i].lon, valid[j].lat, valid[j].lon);
            let delta = valid[i].at_unix.abs_diff(valid[j].at_unix);
            if meters <= radius_m && delta <= window_secs {
                out.push(CoLocation {
                    left: valid[i].id.clone(),
                    right: valid[j].id.clone(),
                    meters,
                    delta_secs: delta,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brisbane_sydney_band() {
        let (blat, blon) = parse_latlon("-27.4698,153.0251").unwrap();
        let (slat, slon) = parse_latlon("-33.8688,151.2093").unwrap();
        let meters = haversine_m(blat, blon, slat, slon);
        assert!(meters > 700_000.0 && meters < 760_000.0, "{meters}");
    }

    #[test]
    fn outside_radius_or_window_is_not_colocation() {
        let fixes = vec![
            Fix {
                id: "a".into(),
                lat: -27.47,
                lon: 153.02,
                at_unix: 1_000,
            },
            Fix {
                id: "b".into(),
                lat: -27.47,
                lon: 153.03,
                at_unix: 1_100,
            },
            Fix {
                id: "c".into(),
                lat: -33.87,
                lon: 151.21,
                at_unix: 1_050,
            },
        ];
        let near = colocated(&fixes, 2_000.0, 200);
        assert!(near.iter().any(|fix| fix.left == "a" && fix.right == "b"));
        assert!(near.iter().all(|fix| fix.left != "c" && fix.right != "c"));
        let pairs = colocated(&fixes, 2_000.0, 10);
        assert!(pairs.is_empty(), "{pairs:?}");
    }

    #[test]
    fn antipodes_are_half_circumference_not_nan() {
        let half = std::f64::consts::PI * crate::geohash::EARTH_RADIUS_KM * 1_000.0;
        for (lat, lon) in [
            (-59.811_333_000_000_005, -55.338_965),
            (20.542_294, -6.566_629_000_000_006),
            (0.0, 0.0),
        ] {
            let other = if lon > 0.0 { lon - 180.0 } else { lon + 180.0 };
            let meters = haversine_m(lat, lon, -lat, other);
            assert!((meters - half).abs() < 1.0, "{lat},{lon}: {meters}");
        }
    }

    #[test]
    fn extreme_timestamps_do_not_overflow() {
        let fixes = vec![
            Fix {
                id: "a".into(),
                lat: 0.0,
                lon: 0.0,
                at_unix: i64::MIN,
            },
            Fix {
                id: "b".into(),
                lat: 0.0,
                lon: 0.0,
                at_unix: i64::MAX,
            },
        ];
        let pairs = colocated(&fixes, 1.0, u64::MAX - 1);
        assert!(pairs.is_empty(), "{pairs:?}");
        assert_eq!(colocated(&fixes, 1.0, u64::MAX).len(), 1);
    }

    #[test]
    fn rejects_invalid_public_fixes_before_spatial_correlation() {
        let fix = |id: &str, lat: f64, lon: f64| Fix {
            id: id.into(),
            lat,
            lon,
            at_unix: 100,
        };
        let fixes = [
            fix("valid-a", 0.0, 0.0),
            fix("invalid-lat-a", 95.0, 0.0),
            fix("invalid-lat-b", 95.0, 0.0),
            fix("invalid-lon-a", 0.0, 181.0),
            fix("invalid-lon-b", 0.0, 181.0),
            fix("nan", f64::NAN, 0.0),
            fix("infinity", 0.0, f64::INFINITY),
            fix("valid-b", 0.0, 0.0),
        ];
        let pairs = colocated(&fixes, 1.0, 0);
        assert_eq!(pairs.len(), 1, "{pairs:?}");
        assert_eq!(pairs[0].left, "valid-a");
        assert_eq!(pairs[0].right, "valid-b");
        assert_eq!(pairs[0].meters, 0.0);

        let boundaries = [fix("south-a", -90.0, -180.0), fix("south-b", -90.0, -180.0)];
        assert_eq!(colocated(&boundaries, 0.0, 0).len(), 1);
    }

    #[test]
    fn rejects_out_of_range() {
        assert!(parse_latlon("91,0").is_err());
    }
}
