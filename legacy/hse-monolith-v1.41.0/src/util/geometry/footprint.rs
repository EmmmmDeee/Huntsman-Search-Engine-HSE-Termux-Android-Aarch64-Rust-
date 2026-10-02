//! Convex-hull footprint: [`GeoFootprint`], [`geo_footprint`], and the private
//! helpers [`lon_scale`], [`polygon_centroid_latlon`], [`convex_hull_latlon`].

use crate::util::geohash::haversine_km;

/// Longitude-anisotropy scale at a reference latitude — the equirectangular
/// correction. A degree of longitude spans `cos(lat)` of a degree of latitude on
/// the ground (≈0.72 at 43°N, 0.5 at 60°N), so scaling longitude by this factor
/// before any *metric*-dependent planar geometry (the geometric median, the
/// enclosing circle) makes the planar distance approximate true ground distance
/// rather than raw degrees. Without it those estimators are biased away from the
/// equator. Clamped above zero so a near-polar reference can't collapse the axis.
///
/// Not needed for the convex hull (membership is invariant under any positive
/// axis scaling) nor the centroid (a mean factors the scale straight back out).
pub(super) fn lon_scale(lat_ref_deg: f64) -> f64 {
    lat_ref_deg.to_radians().cos().max(1e-6)
}

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
    let centroid = polygon_centroid_latlon(&hull);
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

/// Area centroid (centre of mass) of a convex polygon whose vertices are
/// `(lat, lon)` in CCW order — the documented `GeoFootprint::centroid`.
///
/// This is the **true polygon centroid** (the shoelace/area-weighted formula),
/// not the mean of the vertices. The two differ whenever the hull is
/// asymmetric: the vertex mean drifts toward whichever side carries more
/// vertices (the exact bias the [`EnclosingCircle`] rationale calls out), while
/// the area centroid is the honest centre of mass the field promises and is the
/// reference point the out-of-area guard (AU-053) measures from. Computed in
/// planar `(x = lon, y = lat)` space, consistent with the hull builder.
///
/// Falls back to the vertex mean only for a degenerate (near-zero-area) polygon,
/// which `geo_footprint` already excludes — a defensive guard against a
/// divide-by-near-zero, never reached on a real non-collinear hull.
///
/// [`EnclosingCircle`]: crate::util::geometry::EnclosingCircle
pub(super) fn polygon_centroid_latlon(hull: &[(f64, f64)]) -> (f64, f64) {
    let n = hull.len();
    // x = lon (.1), y = lat (.0).
    let mut area2 = 0.0_f64; // twice the signed area
    let mut cx = 0.0_f64;
    let mut cy = 0.0_f64;
    for i in 0..n {
        let (y0, x0) = hull[i];
        let (y1, x1) = hull[(i + 1) % n];
        let cross = x0 * y1 - x1 * y0;
        area2 += cross;
        cx += (x0 + x1) * cross;
        cy += (y0 + y1) * cross;
    }
    if area2.abs() < 1e-12 {
        // Degenerate area: fall back to the vertex mean (never reached for a
        // non-collinear hull, which is all geo_footprint passes in).
        let m = n as f64;
        return (
            hull.iter().map(|p| p.0).sum::<f64>() / m,
            hull.iter().map(|p| p.1).sum::<f64>() / m,
        );
    }
    let cx = cx / (3.0 * area2); // lon
    let cy = cy / (3.0 * area2); // lat
    (cy, cx) // back to (lat, lon)
}

/// Andrew's monotone-chain convex hull over `(lat, lon)` points, returned
/// counter-clockwise. Treats `lon` as x and `lat` as y. Collinear points on a
/// hull edge are excluded (strict turns only), so a degenerate all-collinear
/// input yields fewer than three vertices and the caller reports "no area".
pub(super) fn convex_hull_latlon(points: &[(f64, f64)]) -> Vec<(f64, f64)> {
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
