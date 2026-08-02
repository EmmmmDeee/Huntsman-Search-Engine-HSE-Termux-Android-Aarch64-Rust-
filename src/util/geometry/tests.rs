//! Tests for the geometry submodules.

use super::circle::{EnclosingCircle, min_enclosing_circle};
use super::fix::{LocationFix, location_fix, point_in_convex_hull};
use super::footprint::{GeoFootprint, convex_hull_latlon, geo_footprint, polygon_centroid_latlon};
use super::median::{
    geometric_median, median_distance_km, weighted_centroid, weighted_geometric_median,
};
use crate::util::geohash::haversine_km;

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
fn footprint_centroid_is_the_polygon_area_centre_not_the_vertex_mean() {
    // An asymmetric trapezoid — all four points are hull vertices (no
    // interior point to collapse it to a triangle, where the two
    // definitions would coincide). A trapezoid's area centroid is pulled
    // toward its longer parallel edge, away from the vertex mean.
    //   (lat, lon): long bottom edge (lat 0), shorter top edge (lat 2).
    let pts = [
        (0.0, 0.0),
        (0.0, 4.0), // long bottom edge spans lon 0..4
        (2.0, 3.0),
        (2.0, 0.0), // top edge spans lon 0..3
    ];
    let fp = geo_footprint(&pts).expect("should succeed");
    assert_eq!(fp.hull.len(), 4, "all four points must be hull vertices");

    // Independent shoelace reference over the returned hull (x=lon, y=lat).
    let h = &fp.hull;
    let n = h.len();
    let (mut a2, mut cx, mut cy) = (0.0, 0.0, 0.0);
    for i in 0..n {
        let (y0, x0) = h[i];
        let (y1, x1) = h[(i + 1) % n];
        let cr = x0 * y1 - x1 * y0;
        a2 += cr;
        cx += (x0 + x1) * cr;
        cy += (y0 + y1) * cr;
    }
    let area_centroid = (cy / (3.0 * a2), cx / (3.0 * a2));
    assert!(
        (fp.centroid.0 - area_centroid.0).abs() < 1e-9
            && (fp.centroid.1 - area_centroid.1).abs() < 1e-9,
        "centroid must be the polygon area centroid: {:?} vs {:?}",
        fp.centroid,
        area_centroid
    );

    // And it must genuinely DIFFER from the naive vertex mean (else the test
    // proves nothing) — the area centroid sits farther right (toward the
    // open span), not dragged left by the three bunched vertices.
    let vm_lon = h.iter().map(|p| p.1).sum::<f64>() / n as f64;
    assert!(
        (fp.centroid.1 - vm_lon).abs() > 1e-3,
        "area centroid lon {} should differ from vertex-mean lon {}",
        fp.centroid.1,
        vm_lon
    );
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
    let c = min_enclosing_circle(&[(10.0, 20.0)]).expect("should succeed");
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
    let c2 = min_enclosing_circle(&rev).expect("should succeed");
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
    let mec = min_enclosing_circle(&pts).expect("should succeed");
    let fp = geo_footprint(&pts).expect("should succeed");
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
    let med = geometric_median(&pts).expect("should succeed");
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
fn weighted_geometric_median_reduces_to_unweighted_under_uniform_weights() {
    let pts = [(-33.87, 151.21), (-33.80, 151.10), (-33.95, 151.20)];
    let uniform: Vec<((f64, f64), f64)> = pts.iter().map(|&p| (p, 1.0)).collect();
    let w = weighted_geometric_median(&uniform).expect("should succeed");
    let u = geometric_median(&pts).expect("should succeed");
    assert!(
        (w.0 - u.0).abs() < 1e-9 && (w.1 - u.1).abs() < 1e-9,
        "{w:?} vs {u:?}"
    );
    // Empty → None; all-zero weights → falls back to uniform (not None).
    assert!(weighted_geometric_median(&[]).is_none());
    let zero: Vec<((f64, f64), f64)> = pts.iter().map(|&p| (p, 0.0)).collect();
    assert!(weighted_geometric_median(&zero).is_some());
}

#[test]
fn weighted_geometric_median_pulls_toward_high_confidence() {
    // Three sightings; weight the first heavily. The weighted Weber point must
    // sit closer to it than the unweighted median does — robust AND confidence-
    // aware at once.
    let a = (0.0, 0.0);
    let pts = [a, (0.0, 1.0), (0.8, 0.5)];
    let unweighted = geometric_median(&pts).expect("should succeed");
    let weighted = weighted_geometric_median(&[(a, 12.0), (pts[1], 1.0), (pts[2], 1.0)])
        .expect("should succeed");
    let d = |p: (f64, f64)| haversine_km(a.0, a.1, p.0, p.1);
    assert!(
        d(weighted) < d(unweighted),
        "confidence weight must pull the fix toward the trusted point: {} !< {}",
        d(weighted),
        d(unweighted)
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
fn location_fix_summary_describes_the_estimates() {
    let wp = [
        ((-33.8700, 151.2100), 0.9),
        ((-33.8720, 151.2150), 0.6),
        ((-33.8680, 151.2080), 0.7),
    ];
    let s = location_fix(&wp)
        .expect("should succeed")
        .location_summary();
    assert!(s.contains("geometric median"));
    assert!(s.contains("Chebyshev centre"));
    assert!(s.contains('±'));
    // Renders the median coordinate to 4 dp (the suburb is ~-33.87, 151.21).
    assert!(s.contains("-33.8") && s.contains("151.2"), "{s}");
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
    assert_eq!(fix.footprint, geo_footprint(&pts).expect("should succeed"));
    assert_eq!(
        fix.weighted_centroid,
        weighted_centroid(&wp).expect("should succeed")
    );
    assert_eq!(
        fix.geometric_median,
        weighted_geometric_median(&wp).expect("should succeed")
    );
    assert_eq!(
        fix.median_radius_km,
        median_distance_km(fix.geometric_median, &pts)
    );
    assert_eq!(
        fix.enclosing,
        min_enclosing_circle(&pts).expect("should succeed")
    );
}

#[test]
fn geometric_median_is_equirectangular_corrected_at_high_latitude() {
    // At 60°N a degree of longitude is half a degree of latitude on the
    // ground. The corrected median must beat the naive raw-degree median on
    // TRUE (haversine) total distance. We recompute the raw-degree median
    // here to prove the production code's correction actually helps.
    let pts = [
        (60.00, 10.00),
        (60.05, 10.80),
        (60.02, 9.20),
        (59.97, 10.40),
    ];
    let corrected = geometric_median(&pts).expect("should succeed");

    // Naive median: identical Weiszfeld but WITHOUT the cos(lat) scale.
    let naive = {
        let p: Vec<(f64, f64)> = pts.iter().map(|&(lat, lon)| (lon, lat)).collect();
        let n = p.len() as f64;
        let mut x = p.iter().fold((0.0, 0.0), |a, q| (a.0 + q.0, a.1 + q.1));
        x = (x.0 / n, x.1 / n);
        for _ in 0..128 {
            let mut num = (0.0, 0.0);
            let mut den = 0.0;
            for &q in &p {
                let d = ((x.0 - q.0).powi(2) + (x.1 - q.1).powi(2)).sqrt();
                if d < 1e-12 {
                    continue;
                }
                let f = 1.0 / d;
                num.0 += q.0 * f;
                num.1 += q.1 * f;
                den += f;
            }
            x = (num.0 / den, num.1 / den);
        }
        (x.1, x.0)
    };

    let total = |q: (f64, f64)| {
        pts.iter()
            .map(|&p| haversine_km(q.0, q.1, p.0, p.1))
            .sum::<f64>()
    };
    assert!(
        total(corrected) <= total(naive) + 1e-6,
        "equirectangular-corrected median ({:.4} km) must beat the naive one ({:.4} km)",
        total(corrected),
        total(naive)
    );
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
    let med = geometric_median(&pts).expect("should succeed");
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
    let mean = weighted_centroid(&[((0.0, 0.0), 0.0), ((0.0, 2.0), 0.0)]).expect("should succeed");
    assert!((mean.1 - 1.0).abs() < 1e-9);
    // A trusted point and a shaky one: the centre is pulled toward the
    // high-confidence sighting and remains a convex combination (inside the
    // segment, i.e. between the two longitudes).
    let c = weighted_centroid(&[((0.0, 0.0), 0.95), ((0.0, 1.0), 0.30)]).expect("should succeed");
    assert!(c.1 > 0.0 && c.1 < 0.5, "pulled toward 0.0: {}", c.1);
}

#[test]
fn point_in_convex_hull_uses_real_hull_orientation() {
    // Build the hull the same way the footprint does, then test membership —
    // proves the in-hull test agrees with the hull builder's CCW order.
    let pts = [(0.0, 0.0), (0.0, 1.0), (1.0, 1.0), (1.0, 0.0), (0.5, 0.5)];
    let fp = geo_footprint(&pts).expect("should succeed");
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

// ── Wolfram-verified ground truth for the location-fusion estimators ────────
//
// `geometric_median` and `min_enclosing_circle` are the project's two critical
// GEOINT location-fusion estimators, so their optima are pinned here to values
// computed INDEPENDENTLY in Wolfram Language — a different implementation and a
// different algorithm — over the *same* equirectangular frame the code uses
// (longitude scaled by cos(mean-latitude)):
//
//   median: FindArgMin[Total[EuclideanDistance[{x,y}, #] & /@ proj], {x,y}]
//   circle: BoundingRegion[proj, "MinDisk"]            (Chebyshev centre)
//
// each then unprojected back to (lat, lon). A refactor that drifted either
// estimator off its optimum would now have to disagree with Wolfram to pass.

/// Assert a `(lat, lon)` estimate agrees with Wolfram's optimum within `tol`
/// degrees on each axis.
fn assert_wolfram_latlon(got: (f64, f64), want: (f64, f64), tol: f64, what: &str) {
    assert!(
        (got.0 - want.0).abs() < tol && (got.1 - want.1).abs() < tol,
        "{what}: got {got:?}, Wolfram optimum {want:?} (tol +/-{tol})"
    );
}

#[test]
fn geometric_median_matches_wolfram_ground_truth() {
    // Tight cluster at the origin + a far outlier at (10,10): Wolfram's Weber
    // point stays in the cluster — the 0.5 breakdown point in action.
    let m = geometric_median(&[(0.0, 0.0), (0.0, 0.01), (0.01, 0.0), (10.0, 10.0)])
        .expect("should succeed");
    assert_wolfram_latlon(
        m,
        (0.005_000_000, 0.004_999_994),
        1e-5,
        "outlier-cluster median",
    );

    // Realistic: four Brisbane sightings + one Sydney outlier ~730 km away.
    // Wolfram's optimum stays on the Brisbane cluster, not between the two cities.
    let m = geometric_median(&[
        (-27.4700, 153.0250),
        (-27.4690, 153.0240),
        (-27.4710, 153.0260),
        (-27.4705, 153.0255),
        (-33.8688, 151.2093),
    ])
    .expect("should succeed");
    assert_wolfram_latlon(
        m,
        (-27.470_500_8, 153.025_496_9),
        1e-4,
        "brisbane-cluster median",
    );

    // Equilateral triangle: the Fermat point is the centroid (all angles 60deg).
    let m = geometric_median(&[(0.0, 0.0), (0.0, 1.0), (0.866_025_403_784_438_6, 0.5)])
        .expect("should succeed");
    assert_wolfram_latlon(
        m,
        (0.288_671_468, 0.499_999_995),
        1e-5,
        "equilateral Fermat median",
    );
}

#[test]
fn weighted_geometric_median_snaps_onto_a_dominant_high_confidence_point() {
    // The confidence-weighted Weber point is the PRODUCTION estimator. A
    // GPS-exact sighting (w=0.9) at the origin plus two coarse guesses (w=0.2) at
    // (0,0.1) and (0.1,0). Wolfram's optimum is exactly the origin: the resultant
    // pull of the two coarse points, ||0.2*(0,1) + 0.2*(1,0)|| = 0.283, is <= the
    // origin's weight 0.9, so the origin satisfies the weighted optimality
    // condition and the estimate sits ON the trusted sighting — exactly the
    // outlier/low-confidence rejection the weighting is meant to deliver.
    let m = weighted_geometric_median(&[((0.0, 0.0), 0.9), ((0.0, 0.1), 0.2), ((0.1, 0.0), 0.2)])
        .expect("should succeed");
    assert_wolfram_latlon(m, (0.0, 0.0), 1e-3, "dominant-confidence weighted median");
}

#[test]
fn min_enclosing_circle_matches_wolfram_min_disk() {
    // Chebyshev centres = Wolfram BoundingRegion[.., "MinDisk"], unprojected.
    let c = min_enclosing_circle(&[(0.0, 0.0), (0.0, 0.01), (0.01, 0.0), (10.0, 10.0)])
        .expect("should succeed");
    assert_wolfram_latlon(c.center, (5.0, 5.0), 1e-6, "outlier-cluster MEC centre");

    let c = min_enclosing_circle(&[
        (-27.4700, 153.0250),
        (-27.4690, 153.0240),
        (-27.4710, 153.0260),
        (-27.4705, 153.0255),
        (-33.8688, 151.2093),
    ])
    .expect("should succeed");
    assert_wolfram_latlon(
        c.center,
        (-30.668_900, 152.116_650),
        1e-5,
        "brisbane MEC centre",
    );

    let c = min_enclosing_circle(&[(0.0, 0.0), (0.0, 1.0), (0.866_025_403_784_438_6, 0.5)])
        .expect("should succeed");
    assert_wolfram_latlon(
        c.center,
        (0.288_678_799, 0.5),
        1e-6,
        "equilateral MEC centre",
    );
}

// Suppress unused-import warnings for items imported for potential future tests.
#[allow(unused_imports)]
use self::{
    EnclosingCircle as _, GeoFootprint as _, LocationFix as _, convex_hull_latlon as _,
    polygon_centroid_latlon as _,
};

// ── Property tests: estimators are total, finite, and geometrically sound ─────
//
// The geometry layer is the location-fix backbone yet (unlike `coords`, `entity`
// and `str_util`) carried no property coverage. These pin the two invariants a
// location estimator must never break: it never panics on a degenerate point set
// (empty / single / pair / duplicate / collinear), and it never emits a non-finite
// or out-of-hull coordinate — over the same finite, in-range domain `parse_coords`
// is already proven to produce.
mod prop {
    use proptest::prelude::*;

    use crate::util::geohash::haversine_km;
    use crate::util::geometry::{
        geo_footprint, geometric_median, location_fix, median_distance_km, min_enclosing_circle,
        point_in_convex_hull, weighted_centroid, weighted_geometric_median,
    };

    /// A finite, in-range sighting — the only domain these estimators ever see
    /// (entity `Coordinates` values come from `parse_coords`, which the
    /// `parse_is_total` / `parsed_values_are_always_in_range` properties pin to
    /// finite, in-range pairs).
    fn coord() -> impl Strategy<Value = (f64, f64)> {
        (-90.0f64..=90.0, -180.0f64..=180.0)
    }
    fn finite2((a, b): (f64, f64)) -> bool {
        a.is_finite() && b.is_finite()
    }

    proptest! {
        /// Totality + finiteness: no estimator panics on any finite point set —
        /// including the empty / single / pair / duplicate / collinear cases the
        /// `?`-guards short-circuit — and every numeric field it returns is finite,
        /// with every radius / diameter non-negative.
        #[test]
        fn estimators_are_total_and_finite(
            pts in prop::collection::vec(coord(), 0..=12),
            wpts in prop::collection::vec((coord(), 0.01f64..=1.0), 0..=12),
        ) {
            if let Some(c) = min_enclosing_circle(&pts) {
                prop_assert!(finite2(c.center));
                prop_assert!(c.radius_km.is_finite() && c.radius_km >= 0.0);
            }
            if let Some(f) = geo_footprint(&pts) {
                prop_assert!(finite2(f.centroid));
                prop_assert!(f.diameter_km.is_finite() && f.diameter_km >= 0.0);
                prop_assert!(f.hull.iter().all(|&v| finite2(v)));
            }
            if let Some(m) = geometric_median(&pts) {
                prop_assert!(finite2(m));
            }
            if let Some(m) = weighted_geometric_median(&wpts) {
                prop_assert!(finite2(m));
            }
            if let Some(c) = weighted_centroid(&wpts) {
                prop_assert!(finite2(c));
            }
            let r = median_distance_km(pts.first().copied().unwrap_or((0.0, 0.0)), &pts);
            prop_assert!(r.is_finite() && r >= 0.0);
            let _ = point_in_convex_hull(&pts, (0.0, 0.0)); // never panics
            if let Some(fix) = location_fix(&wpts) {
                prop_assert!(finite2(fix.weighted_centroid) && finite2(fix.geometric_median));
                prop_assert!(fix.median_radius_km.is_finite() && fix.median_radius_km >= 0.0);
                prop_assert!(fix.enclosing.radius_km.is_finite() && fix.enclosing.radius_km >= 0.0);
            }
        }

        /// The minimum enclosing circle truly encloses every input point: its
        /// reported radius is the greatest great-circle distance from the centre to
        /// any sighting, so none can fall outside it.
        #[test]
        fn mec_encloses_all_points(pts in prop::collection::vec(coord(), 1..=12)) {
            if let Some(c) = min_enclosing_circle(&pts) {
                for &(lat, lon) in &pts {
                    let d = haversine_km(c.center.0, c.center.1, lat, lon);
                    prop_assert!(
                        d <= c.radius_km + 1e-6,
                        "point {d:.6} km lies outside r={:.6} km",
                        c.radius_km
                    );
                }
            }
        }

        /// The confidence-weighted centroid is a convex combination of the
        /// sightings, so it can never escape their latitude/longitude bounding box.
        #[test]
        fn weighted_centroid_stays_in_bbox(
            wpts in prop::collection::vec((coord(), 0.01f64..=1.0), 1..=12),
        ) {
            if let Some((clat, clon)) = weighted_centroid(&wpts) {
                let mut mnla = f64::INFINITY;
                let mut mxla = f64::NEG_INFINITY;
                let mut mnlo = f64::INFINITY;
                let mut mxlo = f64::NEG_INFINITY;
                for &((la, lo), _) in &wpts {
                    mnla = mnla.min(la);
                    mxla = mxla.max(la);
                    mnlo = mnlo.min(lo);
                    mxlo = mxlo.max(lo);
                }
                prop_assert!(clat >= mnla - 1e-6 && clat <= mxla + 1e-6);
                prop_assert!(clon >= mnlo - 1e-6 && clon <= mxlo + 1e-6);
            }
        }
    }
}
