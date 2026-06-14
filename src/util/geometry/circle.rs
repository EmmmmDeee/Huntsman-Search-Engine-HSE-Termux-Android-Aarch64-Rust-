//! Minimum enclosing circle: [`EnclosingCircle`] and [`min_enclosing_circle`].

use super::footprint::lon_scale;
use crate::util::geohash::haversine_km;

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

    // Equirectangular correction: scale longitude by cos(mean-latitude) so the
    // disk is fitted in an isotropic frame (a degree of lon and a degree of lat
    // cover the same ground), removing the high-latitude bias. Unscaled at the
    // end. Points in (x=lon·s, y=lat) order, deduplicated so collinear/coincident
    // inputs don't stall the incremental passes.
    let lat_ref = points.iter().map(|&(lat, _)| lat).sum::<f64>() / points.len().max(1) as f64;
    let s = lon_scale(lat_ref);
    let mut p: Vec<(f64, f64)> = Vec::with_capacity(points.len());
    for &(lat, lon) in points {
        let q = (lon * s, lat);
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
    // Report the centre as (lat, lon) — unscaling the longitude axis — and the
    // radius as the true great-circle distance to the farthest original point.
    let center = (d.y, d.x / s);
    let radius_km = points
        .iter()
        .map(|&(lat, lon)| haversine_km(center.0, center.1, lat, lon))
        .fold(0.0_f64, f64::max);
    Some(EnclosingCircle { center, radius_km })
}
