//! Consolidated location estimate: [`LocationFix`] and [`location_fix`].

use super::circle::{EnclosingCircle, min_enclosing_circle};
use super::footprint::{GeoFootprint, geo_footprint};
use super::median::{median_distance_km, weighted_centroid, weighted_geometric_median};

/// Test whether point `p = (lat, lon)` lies inside (or on the boundary of) the
/// convex polygon `hull`, whose vertices are in counter-clockwise order — the
/// form [`geo_footprint`] returns. The check is whether `p` is left-of-or-on
/// every directed edge (all cross products ≥ 0 in (lon, lat) space). A hull of
/// fewer than three vertices bounds no area, so the result is `false`.
///
/// Use: decide whether a *candidate* location — a geocoded breach address, a
/// claimed home — is consistent with a subject's established area of operation,
/// without any distance threshold to tune; the polygon itself is the boundary.
///
/// ```
/// use huntsman_search_engine::util::geometry::point_in_convex_hull;
///
/// let square = [(0.0, 0.0), (0.0, 1.0), (1.0, 1.0), (1.0, 0.0)];
/// assert!(point_in_convex_hull(&square, (0.5, 0.5)));   // interior
/// assert!(point_in_convex_hull(&square, (0.0, 0.5)));   // on an edge
/// assert!(!point_in_convex_hull(&square, (2.0, 0.5)));  // outside
/// ```
pub fn point_in_convex_hull(hull: &[(f64, f64)], p: (f64, f64)) -> bool {
    if hull.len() < 3 {
        return false;
    }
    // Cross product of edge a→b with a→p, in (x=lon, y=lat) space — same
    // orientation as `convex_hull_latlon` (CCW ⇒ ≥ 0 on the interior side).
    let cross = |a: (f64, f64), b: (f64, f64)| -> f64 {
        (b.1 - a.1) * (p.0 - a.0) - (b.0 - a.0) * (p.1 - a.1)
    };
    // Tiny negative slack so a point numerically on an edge counts as inside.
    const EPS: f64 = -1e-12;
    let n = hull.len();
    (0..n).all(|i| cross(hull[i], hull[(i + 1) % n]) >= EPS)
}

/// A consolidated location estimate from a set of confidence-weighted sightings:
/// every convex estimator this module offers, computed once with consistent
/// fallbacks. Bundling them keeps the orchestration (which estimator, which
/// fallback) in one tested place rather than scattered across a caller.
#[derive(Debug, Clone, PartialEq)]
pub struct LocationFix {
    /// The convex hull, centroid, and diameter of the sightings.
    pub footprint: GeoFootprint,
    /// Confidence-weighted convex combination (pulled toward trusted sightings).
    pub weighted_centroid: (f64, f64),
    /// The **headline** estimate: the confidence-weighted geometric median
    /// (L1, outlier-robust *and* confidence-aware).
    pub geometric_median: (f64, f64),
    /// Robust uncertainty around the median — the median distance to the
    /// sightings (same 0.5 breakdown point as the median).
    pub median_radius_km: f64,
    /// The minimum enclosing circle: Chebyshev centre + worst-case radius.
    pub enclosing: EnclosingCircle,
}

impl LocationFix {
    /// A one-line, operator-facing rendering of the location estimates: the
    /// headline robust+confidence-weighted geometric median with its robust
    /// radius, then the worst-case Chebyshev bounding circle. The rendering lives
    /// with the data so every consumer (a correlation description, a future
    /// export or API field) describes the fix identically.
    pub fn location_summary(&self) -> String {
        format!(
            "best location fix (confidence-weighted geometric median, outlier-robust): \
             {:.4},{:.4} ± {:.1} km (robust); bounding circle (Chebyshev centre): \
             {:.4},{:.4} ± {:.1} km",
            self.geometric_median.0,
            self.geometric_median.1,
            self.median_radius_km,
            self.enclosing.center.0,
            self.enclosing.center.1,
            self.enclosing.radius_km,
        )
    }
}

/// Compute the full [`LocationFix`] for confidence-weighted `(point, weight)`
/// sightings, or `None` when they don't bound an area (fewer than three distinct
/// non-collinear points — see [`geo_footprint`]).
///
/// This is the single entry point a caller needs for "where is the subject":
/// it runs the weighted centroid, the geometric median, its robust radius, and
/// the enclosing circle, applying the same deterministic fallbacks throughout (a
/// degenerate estimator falls back to the hull centroid / half-diameter) so the
/// result is always fully populated once a footprint exists.
pub fn location_fix(weighted_points: &[((f64, f64), f64)]) -> Option<LocationFix> {
    let points: Vec<(f64, f64)> = weighted_points.iter().map(|&(p, _)| p).collect();
    let footprint = geo_footprint(&points)?;
    let weighted_centroid = weighted_centroid(weighted_points).unwrap_or(footprint.centroid);
    let geometric_median = weighted_geometric_median(weighted_points).unwrap_or(weighted_centroid);
    let median_radius_km = median_distance_km(geometric_median, &points);
    let enclosing = min_enclosing_circle(&points).unwrap_or(EnclosingCircle {
        center: footprint.centroid,
        radius_km: footprint.diameter_km / 2.0,
    });
    Some(LocationFix {
        footprint,
        weighted_centroid,
        geometric_median,
        median_radius_km,
        enclosing,
    })
}
