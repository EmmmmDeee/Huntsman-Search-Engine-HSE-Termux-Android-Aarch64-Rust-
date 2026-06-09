//! Planar computational geometry over `(lat, lon)` coordinates.
//!
//! The convex location-estimation toolkit, split out of [`super::geohash`] so the
//! geospatial-*encoding* concerns (geohash, timezone, address parsing) and the
//! convex-*geometry* estimators each live in one focused module:
//!
//!   * [`geo_footprint`] — convex hull (Andrew's monotone chain) + centroid + diameter
//!   * [`min_enclosing_circle`] — Welzl's 1-centre (Chebyshev / L∞)
//!   * [`geometric_median`] — Weiszfeld's algorithm (Weber point / L1, robust)
//!   * [`weighted_centroid`] — confidence-weighted convex combination
//!   * [`point_in_convex_hull`] — hull-membership test
//!
//! The hull and circle are fitted in planar (lon, lat) degree space — exact for
//! the bounding question at city/region scale — while every *distance* is the
//! true great-circle kilometre via the spherical [`super::geohash::haversine_km`].
//! All functions are pure, deterministic, and dependency-free.

use super::geohash::haversine_km;

/// The convex geographic footprint of a set of observed coordinates: the hull
/// polygon that bounds every point, the area's centroid (the single best
/// point-estimate of the subject's base), and its diameter (the greatest
/// great-circle span across the points, in km).
#[derive(Debug, Clone, PartialEq)]
pub struct GeoFootprint {
    /// Convex-hull vertices in counter-clockwise order as `(lat, lon)`. For one
    /// or two distinct points the "hull" is just those points.
    pub hull: Vec<(f64, f64)>,
    /// Mean of the hull vertices, `(lat, lon)` — the area's centre of mass.
    pub centroid: (f64, f64),
    /// Greatest great-circle distance between any two input points, in km.
    pub diameter_km: f64,
}

impl GeoFootprint {
    /// A footprint is *tight* when every point lies within a single metropolitan
    /// span (diameter ≤ 25 km). A tight cluster of independent geo sources is a
    /// strong fix on a residence/base; a wide one describes a travel pattern.
    pub fn is_tight(&self) -> bool {
        self.diameter_km <= 25.0
    }
}

/// Compute the [`GeoFootprint`] of a set of `(lat, lon)` points: the convex hull
/// (via Andrew's monotone-chain algorithm), the centroid of the hull, and the
/// great-circle diameter. Returns `None` for fewer than three *distinct* points
/// (a hull needs three non-collinear vertices to bound an area; with one or two
/// distinct points there is no polygon to report).
///
/// The hull is computed in planar (lon, lat) degree space. At the city/region
/// scales OSINT geolocation operates over, the planar hull and the spherical
/// hull share the same vertex set, so this stays dependency-free and exact for
/// the bounding question; the *diameter* is measured with the spherical
/// [`haversine_km`] so the reported span is true great-circle kilometres.
///
/// ```
/// use huntsman_search_engine::util::geometry::geo_footprint;
///
/// // A tight cluster of three independent sightings around one suburb.
/// let pts = [(-33.870, 151.210), (-33.872, 151.215), (-33.868, 151.208)];
/// let fp = geo_footprint(&pts).expect("three points bound an area");
/// assert!(fp.is_tight(), "a few-hundred-metre spread is a tight fix");
/// ```
pub fn geo_footprint(points: &[(f64, f64)]) -> Option<GeoFootprint> {
    // Deduplicate identical coordinates first; the hull and the distinct-count
    // guard must both see unique points.
    let mut pts: Vec<(f64, f64)> = Vec::with_capacity(points.len());
    for &p in points {
        if !pts.contains(&p) {
            pts.push(p);
        }
    }
    if pts.len() < 3 {
        return None;
    }
    let hull = convex_hull_latlon(&pts);
    if hull.len() < 3 {
        // All points collinear — no bounded area.
        return None;
    }
    let n = hull.len() as f64;
    let centroid = (
        hull.iter().map(|p| p.0).sum::<f64>() / n,
        hull.iter().map(|p| p.1).sum::<f64>() / n,
    );
    // Diameter: greatest pairwise great-circle distance. The point count is
    // bounded (a scan holds tens of coordinates), so the O(n²) scan is trivial.
    let mut diameter_km = 0.0_f64;
    for i in 0..pts.len() {
        for j in (i + 1)..pts.len() {
            let d = haversine_km(pts[i].0, pts[i].1, pts[j].0, pts[j].1);
            if d > diameter_km {
                diameter_km = d;
            }
        }
    }
    Some(GeoFootprint {
        hull,
        centroid,
        diameter_km,
    })
}

/// Andrew's monotone-chain convex hull over `(lat, lon)` points, returned
/// counter-clockwise. Treats `lon` as x and `lat` as y. Collinear points on a
/// hull edge are excluded (strict turns only), so a degenerate all-collinear
/// input yields fewer than three vertices and the caller reports "no area".
fn convex_hull_latlon(points: &[(f64, f64)]) -> Vec<(f64, f64)> {
    let mut pts: Vec<(f64, f64)> = points.to_vec();
    // Sort by lon (x) then lat (y). Total order via partial_cmp is safe: scan
    // coordinates are finite (parse_coords range-validates, no NaN).
    pts.sort_by(|a, b| {
        a.1.partial_cmp(&b.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
    });

    // 2D cross product of OA×OB for points O, A, B. >0 ⇒ counter-clockwise turn.
    let cross = |o: (f64, f64), a: (f64, f64), b: (f64, f64)| -> f64 {
        (a.1 - o.1) * (b.0 - o.0) - (a.0 - o.0) * (b.1 - o.1)
    };

    let mut lower: Vec<(f64, f64)> = Vec::new();
    for &p in &pts {
        while lower.len() >= 2 && cross(lower[lower.len() - 2], lower[lower.len() - 1], p) <= 0.0 {
            lower.pop();
        }
        lower.push(p);
    }
    let mut upper: Vec<(f64, f64)> = Vec::new();
    for &p in pts.iter().rev() {
        while upper.len() >= 2 && cross(upper[upper.len() - 2], upper[upper.len() - 1], p) <= 0.0 {
            upper.pop();
        }
        upper.push(p);
    }
    // Concatenate, dropping each chain's last point (it's the first of the other).
    lower.pop();
    upper.pop();
    lower.extend(upper);
    lower
}

/// The smallest circle enclosing a set of observed coordinates: its centre — the
/// **Chebyshev centre**, the point that minimises the *worst-case* distance to
/// any sighting — and the radius (km) to the farthest one.
///
/// This is a more robust single-point location estimate than a hull centroid:
/// the centroid is the mean of hull *vertices* and drifts toward whichever side
/// has more vertices, whereas the min-enclosing-circle centre is fixed by the
/// extreme points alone and answers "the one place that is never far from any
/// sighting" — exactly the location an investigator wants, with `radius_km` as
/// the honest uncertainty around it.
#[derive(Debug, Clone, PartialEq)]
pub struct EnclosingCircle {
    /// Circle centre as `(lat, lon)`.
    pub center: (f64, f64),
    /// Great-circle distance from the centre to the farthest input point, km.
    pub radius_km: f64,
}

/// Compute the [`EnclosingCircle`] of a set of `(lat, lon)` points via Welzl's
/// algorithm (the incremental, move-to-front formulation). Returns `None` for an
/// empty input.
///
/// Deterministic: unlike the textbook randomised Welzl, points are processed in
/// their given order. The minimum enclosing circle is *unique*, so the result is
/// order-independent regardless; with the bounded coordinate counts a scan holds
/// (tens), the non-randomised worst case is irrelevant. The circle is fitted in
/// planar (lon, lat) degree space — at city/region scale that shares the optimum
/// with the spherical problem — while `radius_km` is measured with the spherical
/// [`haversine_km`] so the reported uncertainty is true kilometres.
///
/// ```
/// use huntsman_search_engine::util::geometry::min_enclosing_circle;
///
/// // Three points spanning a small triangle; the centre sits between them.
/// let c = min_enclosing_circle(&[(0.0, 0.0), (0.0, 0.2), (0.2, 0.1)]).unwrap();
/// assert!(c.radius_km > 0.0 && c.radius_km < 30.0);
/// ```
pub fn min_enclosing_circle(points: &[(f64, f64)]) -> Option<EnclosingCircle> {
    // Planar disk in (x=lon, y=lat) degree space.
    #[derive(Clone, Copy)]
    struct Disk {
        x: f64,
        y: f64,
        r: f64,
    }
    // Numerical slack so a point exactly on the boundary counts as inside.
    const EPS: f64 = 1e-12;
    let dist = |ax: f64, ay: f64, bx: f64, by: f64| ((ax - bx).powi(2) + (ay - by).powi(2)).sqrt();
    let in_disk = |d: &Disk, x: f64, y: f64| dist(d.x, d.y, x, y) <= d.r + EPS;
    // Circle through two points: the diameter circle.
    let from2 = |a: (f64, f64), b: (f64, f64)| Disk {
        x: (a.0 + b.0) / 2.0,
        y: (a.1 + b.1) / 2.0,
        r: dist(a.0, a.1, b.0, b.1) / 2.0,
    };
    // Circumscribed circle of three points; `None` if (near-)collinear.
    let from3 = |a: (f64, f64), b: (f64, f64), c: (f64, f64)| -> Option<Disk> {
        let d = 2.0 * (a.0 * (b.1 - c.1) + b.0 * (c.1 - a.1) + c.0 * (a.1 - b.1));
        if d.abs() < 1e-15 {
            return None;
        }
        let (a2, b2, c2) = (
            a.0 * a.0 + a.1 * a.1,
            b.0 * b.0 + b.1 * b.1,
            c.0 * c.0 + c.1 * c.1,
        );
        let ux = (a2 * (b.1 - c.1) + b2 * (c.1 - a.1) + c2 * (a.1 - b.1)) / d;
        let uy = (a2 * (c.0 - b.0) + b2 * (a.0 - c.0) + c2 * (b.0 - a.0)) / d;
        Some(Disk {
            x: ux,
            y: uy,
            r: dist(ux, uy, a.0, a.1),
        })
    };

    // Points in (x=lon, y=lat) order. Deduplicate so collinear/coincident inputs
    // don't stall the incremental passes.
    let mut p: Vec<(f64, f64)> = Vec::with_capacity(points.len());
    for &(lat, lon) in points {
        let q = (lon, lat);
        if !p.contains(&q) {
            p.push(q);
        }
    }
    let first = *p.first()?;
    // Incremental Welzl: maintain the MEC of p[0..=i], rebuilding when p[i] falls
    // outside, using one then two boundary points.
    let mut d = Disk {
        x: first.0,
        y: first.1,
        r: 0.0,
    };
    for i in 1..p.len() {
        if in_disk(&d, p[i].0, p[i].1) {
            continue;
        }
        d = Disk {
            x: p[i].0,
            y: p[i].1,
            r: 0.0,
        };
        for j in 0..i {
            if in_disk(&d, p[j].0, p[j].1) {
                continue;
            }
            d = from2(p[i], p[j]);
            for k in 0..j {
                if in_disk(&d, p[k].0, p[k].1) {
                    continue;
                }
                if let Some(d3) = from3(p[i], p[j], p[k]) {
                    d = d3;
                }
            }
        }
    }
    // Report the centre as (lat, lon) and the radius as the true great-circle
    // distance to the farthest original point.
    let center = (d.y, d.x);
    let radius_km = points
        .iter()
        .map(|&(lat, lon)| haversine_km(center.0, center.1, lat, lon))
        .fold(0.0_f64, f64::max);
    Some(EnclosingCircle { center, radius_km })
}

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
/// let m = geometric_median(&pts).unwrap();
/// assert!(m.0.abs() < 1.0 && m.1.abs() < 1.0, "robust to the outlier: {m:?}");
/// ```
pub fn geometric_median(points: &[(f64, f64)]) -> Option<(f64, f64)> {
    if points.is_empty() {
        return None;
    }
    if points.len() == 1 {
        return Some(points[0]);
    }
    // Work in (x = lon, y = lat).
    let pts: Vec<(f64, f64)> = points.iter().map(|&(lat, lon)| (lon, lat)).collect();
    let n = pts.len() as f64;
    let mut x = pts.iter().fold((0.0, 0.0), |a, p| (a.0 + p.0, a.1 + p.1));
    x = (x.0 / n, x.1 / n);

    const MAX_ITERS: usize = 128;
    const CONVERGED: f64 = 1e-10; // degrees
    const ON_POINT: f64 = 1e-12;
    for _ in 0..MAX_ITERS {
        let mut num = (0.0_f64, 0.0_f64);
        let mut den = 0.0_f64;
        let mut snapped: Option<(f64, f64)> = None;
        for &p in &pts {
            let d = ((x.0 - p.0).powi(2) + (x.1 - p.1).powi(2)).sqrt();
            if d < ON_POINT {
                snapped = Some(p);
                break;
            }
            let w = 1.0 / d;
            num.0 += p.0 * w;
            num.1 += p.1 * w;
            den += w;
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
    Some((x.1, x.0)) // back to (lat, lon)
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
/// let c = weighted_centroid(&[((0.0, 0.0), 0.9), ((0.0, 1.0), 0.1)]).unwrap();
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
    /// The **headline** estimate: the geometric median (L1, outlier-robust).
    pub geometric_median: (f64, f64),
    /// Robust uncertainty around the median — the median distance to the
    /// sightings (same 0.5 breakdown point as the median).
    pub median_radius_km: f64,
    /// The minimum enclosing circle: Chebyshev centre + worst-case radius.
    pub enclosing: EnclosingCircle,
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
    let geometric_median = geometric_median(&points).unwrap_or(weighted_centroid);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn footprint_needs_three_distinct_noncollinear_points() {
        // Fewer than three distinct points: no bounded area.
        assert!(geo_footprint(&[]).is_none());
        assert!(geo_footprint(&[(0.0, 0.0)]).is_none());
        assert!(geo_footprint(&[(0.0, 0.0), (1.0, 1.0)]).is_none());
        // Duplicates collapse — three records of two places is still two points.
        assert!(geo_footprint(&[(0.0, 0.0), (0.0, 0.0), (1.0, 1.0)]).is_none());
        // Three collinear points bound no area.
        assert!(geo_footprint(&[(0.0, 0.0), (1.0, 1.0), (2.0, 2.0)]).is_none());
    }

    #[test]
    fn footprint_hull_centroid_and_diameter() {
        // A unit square (plus an interior point that must NOT become a vertex).
        let pts = [
            (0.0, 0.0),
            (0.0, 1.0),
            (1.0, 1.0),
            (1.0, 0.0),
            (0.5, 0.5), // interior — excluded from the hull
        ];
        let fp = geo_footprint(&pts).expect("square has an area");
        assert_eq!(fp.hull.len(), 4, "interior point must not be a hull vertex");
        // Centroid of the four corners is the square's centre.
        assert!((fp.centroid.0 - 0.5).abs() < 1e-9 && (fp.centroid.1 - 0.5).abs() < 1e-9);
        // Diameter is a diagonal of the square (~157 km at the equator), strictly
        // greater than a side (~111 km).
        assert!(
            fp.diameter_km > 111.0 && fp.diameter_km < 160.0,
            "{}",
            fp.diameter_km
        );
        assert!(!fp.is_tight(), "a ~1° square is not a single-metro fix");
    }

    #[test]
    fn footprint_tight_cluster_is_a_location_fix() {
        // Three sightings within a few hundred metres of one suburb.
        let pts = [
            (-33.8700, 151.2100),
            (-33.8720, 151.2150),
            (-33.8680, 151.2080),
        ];
        let fp = geo_footprint(&pts).expect("three points bound an area");
        assert!(
            fp.is_tight(),
            "diameter {} should be <=25km",
            fp.diameter_km
        );
    }

    #[test]
    fn min_enclosing_circle_basics() {
        // Empty → None.
        assert!(min_enclosing_circle(&[]).is_none());
        // Single point → zero-radius circle centred on it.
        let c = min_enclosing_circle(&[(10.0, 20.0)]).unwrap();
        assert_eq!(c.center, (10.0, 20.0));
        assert_eq!(c.radius_km, 0.0);
    }

    #[test]
    fn min_enclosing_circle_covers_every_point_and_is_order_independent() {
        let pts = [
            (-33.8700, 151.2100),
            (-33.8800, 151.2300),
            (-33.8600, 151.2000),
            (-33.8750, 151.2200), // interior-ish
        ];
        let c = min_enclosing_circle(&pts).expect("non-empty");
        // Every input point lies within the circle (radius is the max distance,
        // so all are ≤ radius by construction — assert with a small slack).
        for &(lat, lon) in &pts {
            let d = haversine_km(c.center.0, c.center.1, lat, lon);
            assert!(
                d <= c.radius_km + 1e-6,
                "point {d}km outside r={}",
                c.radius_km
            );
        }
        // The minimum circle is unique → permuting the input gives the same
        // centre and radius (determinism the correlator relies on).
        let mut rev = pts;
        rev.reverse();
        let c2 = min_enclosing_circle(&rev).unwrap();
        assert!((c.center.0 - c2.center.0).abs() < 1e-9);
        assert!((c.center.1 - c2.center.1).abs() < 1e-9);
        assert!((c.radius_km - c2.radius_km).abs() < 1e-6);
    }

    #[test]
    fn min_enclosing_circle_chebyshev_beats_centroid_for_worst_case() {
        // Three points clustered tightly plus one outlier. The Chebyshev centre
        // minimises the worst-case distance, so its radius must be no larger than
        // the worst-case distance from the hull centroid.
        let pts = [
            (0.0, 0.0),
            (0.0, 0.01),
            (0.01, 0.0),
            (0.0, 0.5), // outlier
        ];
        let mec = min_enclosing_circle(&pts).unwrap();
        let fp = geo_footprint(&pts).unwrap();
        let centroid_worst = pts
            .iter()
            .map(|&(lat, lon)| haversine_km(fp.centroid.0, fp.centroid.1, lat, lon))
            .fold(0.0_f64, f64::max);
        assert!(
            mec.radius_km <= centroid_worst + 1e-6,
            "MEC radius {} must minimise worst-case vs centroid {}",
            mec.radius_km,
            centroid_worst
        );
    }

    #[test]
    fn geometric_median_basics_and_robustness() {
        // Empty → None; single → itself.
        assert!(geometric_median(&[]).is_none());
        assert_eq!(geometric_median(&[(12.0, 34.0)]), Some((12.0, 34.0)));

        // The defining property: robust to an outlier. Three tight points near
        // the origin plus one far outlier. The geometric median must stay with
        // the cluster, while the plain mean is dragged a quarter of the way to
        // the outlier.
        let pts = [(0.0, 0.0), (0.0, 0.02), (0.02, 0.0), (10.0, 10.0)];
        let med = geometric_median(&pts).unwrap();
        let mean = (
            pts.iter().map(|p| p.0).sum::<f64>() / 4.0,
            pts.iter().map(|p| p.1).sum::<f64>() / 4.0,
        );
        let dist0 = |q: (f64, f64)| haversine_km(0.0, 0.0, q.0, q.1);
        assert!(dist0(med) < 5.0, "median stays with the cluster: {med:?}");
        assert!(
            dist0(med) < dist0(mean),
            "median ({:.1}km) must beat the mean ({:.1}km) on outlier robustness",
            dist0(med),
            dist0(mean)
        );
    }

    #[test]
    fn median_distance_is_robust_to_an_outlier() {
        assert_eq!(median_distance_km((0.0, 0.0), &[]), 0.0);
        // Three sightings ~tight around a point, plus one far outlier. The MEDIAN
        // distance reflects the tight cluster, NOT the outlier — unlike a max
        // (enclosing-circle) radius, which the outlier would dominate.
        let center = (-33.8700, 151.2100);
        let pts = [
            (-33.8700, 151.2100),
            (-33.8720, 151.2150),
            (-33.8680, 151.2080),
            (-31.9520, 115.8570), // Perth, ~3300 km
        ];
        let med = median_distance_km(center, &pts);
        let max = pts
            .iter()
            .map(|&(la, lo)| haversine_km(center.0, center.1, la, lo))
            .fold(0.0_f64, f64::max);
        assert!(med < 5.0, "robust radius stays with the cluster: {med}km");
        assert!(
            max > 3000.0,
            "max radius is dominated by the outlier: {max}km"
        );
    }

    #[test]
    fn location_fix_bundles_every_estimator_consistently() {
        // Fewer than 3 distinct points → no area → None.
        assert!(location_fix(&[((0.0, 0.0), 1.0), ((1.0, 1.0), 1.0)]).is_none());

        // A tight suburb cluster: the bundle's fields agree with the standalone
        // estimators, proving location_fix just orchestrates them.
        let wp = [
            ((-33.8700, 151.2100), 0.9),
            ((-33.8720, 151.2150), 0.6),
            ((-33.8680, 151.2080), 0.7),
        ];
        let pts: Vec<(f64, f64)> = wp.iter().map(|&(p, _)| p).collect();
        let fix = location_fix(&wp).expect("three points bound an area");
        assert_eq!(fix.footprint, geo_footprint(&pts).unwrap());
        assert_eq!(fix.weighted_centroid, weighted_centroid(&wp).unwrap());
        assert_eq!(fix.geometric_median, geometric_median(&pts).unwrap());
        assert_eq!(
            fix.median_radius_km,
            median_distance_km(fix.geometric_median, &pts)
        );
        assert_eq!(fix.enclosing, min_enclosing_circle(&pts).unwrap());
    }

    #[test]
    fn geometric_median_minimises_total_distance() {
        // Against a small random sample, the Weiszfeld solution's summed distance
        // must be ≤ that of any input point (the optimum beats every vertex).
        let pts = [
            (-33.87, 151.21),
            (-33.80, 151.10),
            (-33.95, 151.20),
            (-33.70, 151.30),
            (-33.88, 151.00),
        ];
        let med = geometric_median(&pts).unwrap();
        let total = |q: (f64, f64)| {
            pts.iter()
                .map(|&p| haversine_km(q.0, q.1, p.0, p.1))
                .sum::<f64>()
        };
        let med_total = total(med);
        for &p in &pts {
            assert!(
                med_total <= total(p) + 1e-6,
                "median total {med_total} must be ≤ vertex total {}",
                total(p)
            );
        }
    }

    #[test]
    fn weighted_centroid_pulls_toward_confidence_and_stays_in_hull() {
        // Empty → None.
        assert!(weighted_centroid(&[]).is_none());
        // All-zero weights → unweighted mean (no divide-by-zero).
        let mean = weighted_centroid(&[((0.0, 0.0), 0.0), ((0.0, 2.0), 0.0)]).unwrap();
        assert!((mean.1 - 1.0).abs() < 1e-9);
        // A trusted point and a shaky one: the centre is pulled toward the
        // high-confidence sighting and remains a convex combination (inside the
        // segment, i.e. between the two longitudes).
        let c = weighted_centroid(&[((0.0, 0.0), 0.95), ((0.0, 1.0), 0.30)]).unwrap();
        assert!(c.1 > 0.0 && c.1 < 0.5, "pulled toward 0.0: {}", c.1);
    }

    #[test]
    fn point_in_convex_hull_uses_real_hull_orientation() {
        // Build the hull the same way the footprint does, then test membership —
        // proves the in-hull test agrees with the hull builder's CCW order.
        let pts = [(0.0, 0.0), (0.0, 1.0), (1.0, 1.0), (1.0, 0.0), (0.5, 0.5)];
        let fp = geo_footprint(&pts).unwrap();
        assert!(point_in_convex_hull(&fp.hull, (0.5, 0.5)), "interior point");
        assert!(
            point_in_convex_hull(&fp.hull, (0.0, 0.5)),
            "edge point counts inside"
        );
        assert!(
            !point_in_convex_hull(&fp.hull, (1.5, 0.5)),
            "point outside the square"
        );
        assert!(
            !point_in_convex_hull(&fp.hull, (-0.1, -0.1)),
            "point below-left"
        );
        // Degenerate hulls bound no area.
        assert!(!point_in_convex_hull(&[(0.0, 0.0), (1.0, 1.0)], (0.5, 0.5)));
    }
}
