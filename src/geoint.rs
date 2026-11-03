//! GEOINT on operator-supplied coordinates: `LAT,LON` parsing and great-circle metres.

use crate::error::Error;

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

/// Initial great-circle bearing in degrees clockwise from true north.
///
/// Returns `None` for invalid coordinates, a starting point exactly at a
/// geographic pole, or coincident/antipodal points where a unique direction
/// cannot be established. This is a spherical
/// bearing, not a magnetic heading or a road-routing direction.
#[must_use]
pub fn initial_bearing_deg(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> Option<f64> {
    if !valid_coordinate(lat1, lon1) || !valid_coordinate(lat2, lon2) {
        return None;
    }
    // True north is undefined exactly at a geographic pole: changing the
    // arbitrary longitude label must not change a supposedly unique bearing.
    if lat1.abs() >= 90.0 {
        return None;
    }
    let phi1 = lat1.to_radians();
    let phi2 = lat2.to_radians();
    // Normalize to the shortest signed longitude arc without rem_euclid:
    // negative sub-microscopic deltas must not lose precision by rounding
    // through approximately 360 degrees.
    let mut delta_deg = lon2 - lon1;
    if delta_deg > 180.0 {
        delta_deg -= 360.0;
    } else if delta_deg < -180.0 {
        delta_deg += 360.0;
    }
    // Exactly coincident and antipodal endpoints have no unique initial
    // bearing. A fixed absolute threshold on x/y incorrectly discards
    // distinct, representable near-neighbour points.
    if ((lat1 - lat2).abs() == 0.0 && delta_deg.abs() == 0.0)
        || ((lat1 + lat2).abs() == 0.0 && delta_deg.abs().total_cmp(&180.0).is_eq())
    {
        return None;
    }
    let delta = delta_deg.to_radians();
    let y = delta.sin() * phi2.cos();
    let x = phi1.cos() * phi2.sin() - phi1.sin() * phi2.cos() * delta.cos();
    if y == 0.0 && x == 0.0 {
        return None;
    }
    Some(y.atan2(x).to_degrees().rem_euclid(360.0))
}

/// Strict WGS84 latitude/longitude domain check, shared by GEOINT callers.
#[must_use]
pub fn valid_coordinate(lat: f64, lon: f64) -> bool {
    lat.is_finite()
        && lon.is_finite()
        && (-90.0..=90.0).contains(&lat)
        && (-180.0..=180.0).contains(&lon)
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
    fn rejects_out_of_range() {
        assert!(parse_latlon("91,0").is_err());
    }
    #[test]
    fn bearings_are_normalized_and_cross_the_date_line() {
        let east = initial_bearing_deg(0.0, 179.0, 0.0, -179.0).unwrap();
        let west = initial_bearing_deg(0.0, -179.0, 0.0, 179.0).unwrap();
        assert!((east - 90.0).abs() < 1e-9, "{east}");
        assert!((west - 270.0).abs() < 1e-9, "{west}");
        assert!((initial_bearing_deg(0.0, 0.0, 90.0, 0.0).unwrap()).abs() < 1e-9);
    }

    #[test]
    fn bearing_refuses_undefined_or_invalid_geometry() {
        assert_eq!(initial_bearing_deg(0.0, 0.0, 0.0, 0.0), None);
        assert_eq!(initial_bearing_deg(0.0, 0.0, 0.0, 180.0), None);
        assert_eq!(initial_bearing_deg(f64::NAN, 0.0, 1.0, 1.0), None);
        assert_eq!(initial_bearing_deg(91.0, 0.0, 1.0, 1.0), None);
        assert!(!valid_coordinate(0.0, f64::INFINITY));
        assert!(valid_coordinate(-90.0, 180.0));
    }

    #[test]
    fn north_and_south_poles_have_no_unique_initial_compass_bearing() {
        assert_eq!(initial_bearing_deg(90.0, 0.0, 80.0, 90.0), None);
        assert_eq!(initial_bearing_deg(90.0, 120.0, 80.0, 90.0), None);
        assert_eq!(initial_bearing_deg(-90.0, 0.0, -80.0, 90.0), None);
        assert!(initial_bearing_deg(89.999, 0.0, 80.0, 90.0).is_some());
        assert!(initial_bearing_deg(0.0, 0.0, 90.0, 0.0).is_some());
    }

    #[test]
    fn equivalent_antimeridian_longitudes_are_coincident() {
        assert_eq!(initial_bearing_deg(0.0, -180.0, 0.0, 180.0), None);
        assert_eq!(initial_bearing_deg(10.0, -180.0, 10.0, 180.0), None);
    }

    #[test]
    fn distinct_nearby_points_keep_defined_signed_bearings() {
        // Distinct representable longitudes must not be silently collapsed
        // by a fixed trigonometric magnitude threshold or wrap rounding.
        let tiny = 1e-13;
        let east = initial_bearing_deg(0.0, 0.0, 0.0, tiny).unwrap();
        let west = initial_bearing_deg(0.0, 0.0, 0.0, -tiny).unwrap();
        let north = initial_bearing_deg(0.0, 0.0, tiny, 0.0).unwrap();
        assert!((east - 90.0).abs() < 1e-9, "{east}");
        assert!((west - 270.0).abs() < 1e-9, "{west}");
        assert!(north.abs() < 1e-9, "{north}");
        assert_eq!(initial_bearing_deg(0.0, 0.0, 0.0, 0.0), None);
        assert_eq!(initial_bearing_deg(0.0, 0.0, 0.0, 180.0), None);
    }

    #[test]
    fn bearing_handles_both_longitude_wrap_directions() {
        let east = initial_bearing_deg(0.0, 170.0, 0.0, -170.0).unwrap();
        let west = initial_bearing_deg(0.0, -170.0, 0.0, 170.0).unwrap();
        assert!((east - 90.0).abs() < 1e-9, "{east}");
        assert!((west - 270.0).abs() < 1e-9, "{west}");
    }
}
