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
/// // Near-antipodal FP edge: `a` rounds a ULP above 1.0; must stay finite.
/// assert!(haversine_km(-87.5, 0.0, 87.5, 180.0).is_finite());
/// ```
pub fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6371.0; // Earth radius in km
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlon / 2.0).sin().powi(2);
    // `a` is mathematically in [0, 1], but at a near-antipodal pair floating-point
    // rounding can push it ~1 ULP above 1.0 (e.g. (-87.5, 0, 87.5, 180) yields
    // a = 1.0000000000000002), making `(1.0 - a).sqrt()` = `sqrt(-2.2e-16)` = NaN
    // — which would poison every downstream distance comparison. Clamp the
    // radicand to ≥ 0 so the result is the correct antipodal distance (R·π), never
    // NaN. A no-op for every non-edge input (where a < 1).
    2.0 * R * a.sqrt().atan2((1.0 - a).max(0.0).sqrt())
}
