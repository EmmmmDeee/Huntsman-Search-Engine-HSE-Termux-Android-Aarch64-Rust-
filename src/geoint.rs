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
}
