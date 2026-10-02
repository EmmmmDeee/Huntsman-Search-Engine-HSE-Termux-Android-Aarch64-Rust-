//! Geometric median estimators: [`geometric_median`], [`weighted_geometric_median`],
//! [`median_distance_km`], and [`weighted_centroid`].

use super::footprint::lon_scale;
use crate::util::geohash::haversine_km;

/// The **geometric median** (Weber point) of observed coordinates — the location
/// that minimises the *sum* of great-circle distances to every sighting (the L1
/// facility-location optimum), found with **Weiszfeld's algorithm**.
///
/// This is the most outlier-robust single-point location estimate available: a
/// plain centroid (L2) or a Chebyshev centre (L∞, the min-enclosing-circle
/// centre) is dragged toward a lone faraway sighting — a trip, a VPN exit, a
/// planted address — whereas the geometric median has a breakdown point of 0.5
/// (up to half the points can be arbitrarily corrupted before it moves far). For
/// "where does this person actually live", it is the estimator to trust.
///
/// Deterministic: initialised at the centroid and iterated a fixed bounded number
/// of times (no randomness); when an iterate lands on a data point — Weiszfeld's
/// singularity — it snaps to that point, which is the median in that case. Fitted
/// in planar (lon, lat) degree space, consistent with the other geometry helpers.
///
/// ```
/// use huntsman_search_engine::util::geometry::geometric_median;
///
/// // Three tight points plus a far outlier: the median stays with the cluster.
/// let pts = [(0.0, 0.0), (0.0, 0.01), (0.01, 0.0), (10.0, 10.0)];
/// let m = geometric_median(&pts).expect("should succeed");
/// assert!(m.0.abs() < 1.0 && m.1.abs() < 1.0, "robust to the outlier: {m:?}");
/// ```
pub fn geometric_median(points: &[(f64, f64)]) -> Option<(f64, f64)> {
    // The unweighted Weber point is the uniform-weight special case.
    let wp: Vec<((f64, f64), f64)> = points.iter().map(|&p| (p, 1.0)).collect();
    weighted_geometric_median(&wp)
}

/// The **confidence-weighted geometric median**: the location minimising
/// `Σ wᵢ·‖x − pᵢ‖` over confidence-weighted sightings, via weighted Weiszfeld.
///
/// This combines the two properties a single location estimate should have but
/// the others each lack one of: it is **outlier-robust** like the unweighted
/// median (breakdown point 0.5 — a lone trip/VPN/planted point can't drag it
/// off the base), *and* it is **confidence-aware** like the weighted centroid (a
/// GPS-exact photo pulls harder than a coarse IP-geo guess). It is the estimator
/// to trust for "where does this person actually live".
///
/// Weights are clamped non-negative; zero-weight sightings drop out of the
/// objective. If every weight is zero the points are weighted uniformly so a
/// degenerate confidence set still yields the (unweighted) Weber point rather
/// than nothing. Deterministic: initialised at the weighted centroid, iterated a
/// fixed bounded number of times, snapping to a data point at Weiszfeld's
/// singularity. Returns `None` only for an empty input.
pub fn weighted_geometric_median(weighted: &[((f64, f64), f64)]) -> Option<(f64, f64)> {
    if weighted.is_empty() {
        return None;
    }
    // Convert to (x = lon, y = lat). If no weight is positive, weight uniformly.
    let any_pos = weighted.iter().any(|&(_, w)| w > 0.0);
    // Reference latitude for the equirectangular correction: the (weighted) mean
    // latitude of the contributing points. Longitude is scaled by `cos(lat_ref)`
    // throughout so Weiszfeld minimises approximate true ground distance, not
    // anisotropic degree distance; the result's longitude is unscaled at the end.
    let lat_ref = {
        let (mut slat, mut sw) = (0.0_f64, 0.0_f64);
        for &((lat, _), w) in weighted {
            let w = if any_pos { w.max(0.0) } else { 1.0 };
            slat += w * lat;
            sw += w;
        }
        if sw > 0.0 { slat / sw } else { 0.0 }
    };
    let s = lon_scale(lat_ref);
    // Work in (x = lon·s, y = lat): an isotropic planar frame.
    let pts: Vec<((f64, f64), f64)> = weighted
        .iter()
        .map(|&((lat, lon), w)| ((lon * s, lat), if any_pos { w.max(0.0) } else { 1.0 }))
        .filter(|&(_, w)| w > 0.0)
        .collect();
    if pts.len() == 1 {
        let ((x, y), _) = pts[0];
        return Some((y, x / s));
    }
    // Initialise at the weighted centroid.
    let sw: f64 = pts.iter().map(|&(_, w)| w).sum();
    let init = pts
        .iter()
        .fold((0.0, 0.0), |a, &((px, py), w)| (a.0 + w * px, a.1 + w * py));
    let mut x = (init.0 / sw, init.1 / sw);

    const MAX_ITERS: usize = 128;
    const CONVERGED: f64 = 1e-10; // degrees
    const ON_POINT: f64 = 1e-12;
    for _ in 0..MAX_ITERS {
        let mut num = (0.0_f64, 0.0_f64);
        let mut den = 0.0_f64;
        let mut snapped: Option<(f64, f64)> = None;
        for &((px, py), w) in &pts {
            let d = ((x.0 - px).powi(2) + (x.1 - py).powi(2)).sqrt();
            if d < ON_POINT {
                snapped = Some((px, py));
                break;
            }
            let f = w / d; // weight ÷ distance
            num.0 += px * f;
            num.1 += py * f;
            den += f;
        }
        if let Some(p) = snapped {
            x = p;
            break;
        }
        let next = (num.0 / den, num.1 / den);
        let moved = ((next.0 - x.0).powi(2) + (next.1 - x.1).powi(2)).sqrt();
        x = next;
        if moved < CONVERGED {
            break;
        }
    }
    Some((x.1, x.0 / s)) // back to (lat, lon): unscale the longitude axis
}

/// The **median** great-circle distance (km) from `center` to `points` — a
/// robust radius of spread to pair with the [`geometric_median`].
///
/// Where a min-enclosing-circle radius is the *worst-case* distance (set by the
/// single farthest sighting, so a lone trip or VPN exit inflates it), the median
/// distance has the same 0.5 breakdown point as the geometric median itself:
/// half the points could be arbitrarily far without moving it. Reporting the
/// robust location with a robust radius keeps the uncertainty honest — `± this`
/// is where the subject actually is, not where their farthest outlier was.
/// Returns `0.0` for an empty input.
pub fn median_distance_km(center: (f64, f64), points: &[(f64, f64)]) -> f64 {
    if points.is_empty() {
        return 0.0;
    }
    let mut d: Vec<f64> = points
        .iter()
        .map(|&(lat, lon)| haversine_km(center.0, center.1, lat, lon))
        .collect();
    d.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = d.len();
    if n % 2 == 1 {
        d[n / 2]
    } else {
        // Even count: mean of the two central order statistics.
        (d[n / 2 - 1] + d[n / 2]) / 2.0
    }
}

/// Confidence-weighted centroid of observed coordinates — the **convex
/// combination** `Σ wᵢ·pᵢ / Σ wᵢ` of the points `pᵢ` by non-negative weights
/// `wᵢ` (each sighting's `c_effective`). Because the weights are non-negative and
/// normalised, the result provably lies inside the convex hull of the points (a
/// convex combination never escapes the hull), so it is always a valid interior
/// location estimate — but, unlike the plain hull centroid, it is pulled toward
/// the *high-confidence* sightings rather than treating a shaky IP-geo guess and
/// a GPS-exact photo as equals.
///
/// Returns `None` for an empty input. If every weight is zero (or negative,
/// which is clamped away), it degrades to the unweighted mean so a degenerate
/// confidence set still yields a centre rather than a divide-by-zero.
///
/// ```
/// use huntsman_search_engine::util::geometry::weighted_centroid;
///
/// // A high-confidence point and a low-confidence one: the centre sits much
/// // closer to the trusted sighting than a plain average (0.5) would.
/// let c = weighted_centroid(&[((0.0, 0.0), 0.9), ((0.0, 1.0), 0.1)]).expect("should succeed");
/// assert!(c.1 < 0.2, "weighted toward the high-confidence point");
/// ```
pub fn weighted_centroid(points: &[((f64, f64), f64)]) -> Option<(f64, f64)> {
    if points.is_empty() {
        return None;
    }
    let mut sw = 0.0_f64;
    let mut slat = 0.0_f64;
    let mut slon = 0.0_f64;
    for &((lat, lon), w) in points {
        let w = w.max(0.0);
        sw += w;
        slat += w * lat;
        slon += w * lon;
    }
    if sw <= 0.0 {
        // All weights zero → fall back to the unweighted mean.
        let n = points.len() as f64;
        let lat = points.iter().map(|&((la, _), _)| la).sum::<f64>() / n;
        let lon = points.iter().map(|&((_, lo), _)| lo).sum::<f64>() / n;
        return Some((lat, lon));
    }
    Some((slat / sw, slon / sw))
}
