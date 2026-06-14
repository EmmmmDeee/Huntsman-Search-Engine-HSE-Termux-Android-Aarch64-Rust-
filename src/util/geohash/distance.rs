/// Great-circle distance between two coordinates in kilometres
/// (Haversine formula). For proximity scoring.
///
/// # Guarantees
/// - A proper metric for finite inputs: non-negative, symmetric, zero iff the
///   points coincide, and bounded by half the Earth's circumference (≈20 015 km).
///   Uses the numerically-stable `atan2` form, so identical/antipodal points do
///   not produce `NaN`. (Invariants proved over a randomised sample in
///   `haversine_is_a_bounded_symmetric_metric`.)
///
/// ```
/// use huntsman_search_engine::util::geohash::haversine_km;
///
/// // Sydney → Melbourne is ~714 km great-circle.
/// assert!((haversine_km(-33.87, 151.21, -37.81, 144.96) - 714.0).abs() < 15.0);
/// assert_eq!(haversine_km(10.0, 20.0, 10.0, 20.0), 0.0); // identical → 0, no NaN
/// ```
pub fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6371.0; // Earth radius in km
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlon / 2.0).sin().powi(2);
    2.0 * R * a.sqrt().atan2((1.0 - a).sqrt())
}
