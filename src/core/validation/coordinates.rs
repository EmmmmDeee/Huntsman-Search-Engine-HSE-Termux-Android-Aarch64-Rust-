use super::report::ValidationReport;

/// Validate that `(lat, lon)` lie inside the Earth's coordinate bounds
/// and are not the Null Island origin (0.0, 0.0) which is almost
/// always a parser failure rather than a real location.
pub fn validate_coordinates(lat: f64, lon: f64) -> ValidationReport {
    if !lat.is_finite() || !lon.is_finite() {
        return ValidationReport::fail("coord.non_finite", "lat or lon is NaN/Inf");
    }
    if !(-90.0..=90.0).contains(&lat) {
        return ValidationReport::fail(
            "coord.lat_oob",
            format!("latitude {lat} outside [-90, 90]"),
        );
    }
    if !(-180.0..=180.0).contains(&lon) {
        return ValidationReport::fail(
            "coord.lon_oob",
            format!("longitude {lon} outside [-180, 180]"),
        );
    }
    if lat == 0.0 && lon == 0.0 {
        return ValidationReport::fail("coord.null_island", "(0.0, 0.0) is null-island");
    }
    ValidationReport::ok()
}
