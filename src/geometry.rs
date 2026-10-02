#![allow(clippy::cast_precision_loss)]

//! Planar computational geometry over `(lat, lon)` coordinates. Rebuilt from the
//! monolith's `util::geometry`.

use crate::geohash::haversine_km;
use crate::union_find::UnionFind;

#[derive(Debug, Clone, PartialEq)]
pub struct GeoFootprint {
    pub hull: Vec<(f64, f64)>,
    pub centroid: (f64, f64),
    pub diameter_km: f64,
}

impl GeoFootprint {
    #[must_use]
    pub fn is_tight(&self) -> bool {
        self.diameter_km <= 25.0
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EnclosingCircle {
    pub center: (f64, f64),
    pub radius_km: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LocationFix {
    pub footprint: GeoFootprint,
    pub weighted_centroid: (f64, f64),
    pub geometric_median: (f64, f64),
    pub median_radius_km: f64,
    pub enclosing: EnclosingCircle,
}

impl LocationFix {
    #[must_use]
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

#[must_use]
pub fn geo_footprint(points: &[(f64, f64)]) -> Option<GeoFootprint> {
    let mut unique = Vec::with_capacity(points.len());
    for &point in points {
        if !unique.contains(&point) {
            unique.push(point);
        }
    }
    if unique.len() < 3 {
        return None;
    }
    let hull = convex_hull_latlon(&unique);
    if hull.len() < 3 {
        return None;
    }
    let centroid = polygon_centroid_latlon(&hull);
    let mut diameter_km = 0.0_f64;
    for i in 0..unique.len() {
        for j in (i + 1)..unique.len() {
            diameter_km = diameter_km.max(haversine_km(
                unique[i].0,
                unique[i].1,
                unique[j].0,
                unique[j].1,
            ));
        }
    }
    Some(GeoFootprint {
        hull,
        centroid,
        diameter_km,
    })
}

#[must_use]
pub fn min_enclosing_circle(points: &[(f64, f64)]) -> Option<EnclosingCircle> {
    #[derive(Clone, Copy)]
    struct Disk {
        x: f64,
        y: f64,
        r: f64,
    }

    const EPS: f64 = 1e-12;

    fn planar_distance(ax: f64, ay: f64, bx: f64, by: f64) -> f64 {
        ((ax - bx).powi(2) + (ay - by).powi(2)).sqrt()
    }

    fn in_disk(disk: &Disk, x: f64, y: f64) -> bool {
        planar_distance(disk.x, disk.y, x, y) <= disk.r + EPS
    }

    fn from2(a: (f64, f64), b: (f64, f64)) -> Disk {
        Disk {
            x: f64::midpoint(a.0, b.0),
            y: f64::midpoint(a.1, b.1),
            r: planar_distance(a.0, a.1, b.0, b.1) / 2.0,
        }
    }

    fn from3(a: (f64, f64), b: (f64, f64), c: (f64, f64)) -> Option<Disk> {
        let d = 2.0 * (a.0 * (b.1 - c.1) + b.0 * (c.1 - a.1) + c.0 * (a.1 - b.1));
        if d.abs() < 1e-15 {
            return None;
        }
        let a2 = a.0 * a.0 + a.1 * a.1;
        let b2 = b.0 * b.0 + b.1 * b.1;
        let c2 = c.0 * c.0 + c.1 * c.1;
        let ux = (a2 * (b.1 - c.1) + b2 * (c.1 - a.1) + c2 * (a.1 - b.1)) / d;
        let uy = (a2 * (c.0 - b.0) + b2 * (a.0 - c.0) + c2 * (b.0 - a.0)) / d;
        Some(Disk {
            x: ux,
            y: uy,
            r: planar_distance(ux, uy, a.0, a.1),
        })
    }

    let first = *points.first()?;
    let lat_ref = points.iter().map(|(lat, _)| *lat).sum::<f64>() / points.len() as f64;
    let scale = lon_scale(lat_ref);
    let mut unique = Vec::with_capacity(points.len());
    for &(lat, lon) in points {
        let scaled = (lon * scale, lat);
        if !unique.contains(&scaled) {
            unique.push(scaled);
        }
    }
    let mut disk = Disk {
        x: first.1 * scale,
        y: first.0,
        r: 0.0,
    };
    for i in 0..unique.len() {
        if in_disk(&disk, unique[i].0, unique[i].1) {
            continue;
        }
        disk = Disk {
            x: unique[i].0,
            y: unique[i].1,
            r: 0.0,
        };
        for j in 0..i {
            if in_disk(&disk, unique[j].0, unique[j].1) {
                continue;
            }
            disk = from2(unique[i], unique[j]);
            for k in 0..j {
                if in_disk(&disk, unique[k].0, unique[k].1) {
                    continue;
                }
                if let Some(candidate) = from3(unique[i], unique[j], unique[k]) {
                    disk = candidate;
                }
            }
        }
    }

    let center = (disk.y, disk.x / scale);
    let radius_km = points
        .iter()
        .map(|&(lat, lon)| haversine_km(center.0, center.1, lat, lon))
        .fold(0.0, f64::max);
    Some(EnclosingCircle { center, radius_km })
}

#[must_use]
pub fn geometric_median(points: &[(f64, f64)]) -> Option<(f64, f64)> {
    let weighted: Vec<((f64, f64), f64)> = points.iter().map(|&point| (point, 1.0)).collect();
    weighted_geometric_median(&weighted)
}

#[must_use]
pub fn weighted_geometric_median(weighted: &[((f64, f64), f64)]) -> Option<(f64, f64)> {
    if weighted.is_empty() {
        return None;
    }
    let any_positive = weighted.iter().any(|(_, weight)| *weight > 0.0);
    let mut lat_sum = 0.0;
    let mut weight_sum = 0.0;
    for &((lat, _), weight) in weighted {
        let weight = if any_positive { weight.max(0.0) } else { 1.0 };
        lat_sum += weight * lat;
        weight_sum += weight;
    }
    let lat_ref = if weight_sum > 0.0 {
        lat_sum / weight_sum
    } else {
        0.0
    };
    let scale = lon_scale(lat_ref);

    let points: Vec<((f64, f64), f64)> = weighted
        .iter()
        .map(|&((lat, lon), weight)| {
            (
                (lon * scale, lat),
                if any_positive { weight.max(0.0) } else { 1.0 },
            )
        })
        .filter(|(_, weight)| *weight > 0.0)
        .collect();
    if points.len() == 1 {
        let ((x, y), _) = points[0];
        return Some((y, x / scale));
    }

    let total_weight: f64 = points.iter().map(|(_, weight)| *weight).sum();
    let initial = points.iter().fold((0.0, 0.0), |acc, ((x, y), weight)| {
        (acc.0 + weight * x, acc.1 + weight * y)
    });
    let mut estimate = (initial.0 / total_weight, initial.1 / total_weight);

    const MAX_ITERS: usize = 128;
    const CONVERGED: f64 = 1e-10;
    const ON_POINT: f64 = 1e-12;

    for _ in 0..MAX_ITERS {
        let mut num = (0.0, 0.0);
        let mut den = 0.0;
        let mut snapped = None;
        for &((x, y), weight) in &points {
            let distance = ((estimate.0 - x).powi(2) + (estimate.1 - y).powi(2)).sqrt();
            if distance < ON_POINT {
                snapped = Some((x, y));
                break;
            }
            let factor = weight / distance;
            num.0 += x * factor;
            num.1 += y * factor;
            den += factor;
        }
        if let Some(point) = snapped {
            estimate = point;
            break;
        }
        let next = (num.0 / den, num.1 / den);
        let moved = ((next.0 - estimate.0).powi(2) + (next.1 - estimate.1).powi(2)).sqrt();
        estimate = next;
        if moved < CONVERGED {
            break;
        }
    }

    Some((estimate.1, estimate.0 / scale))
}

#[must_use]
pub fn median_distance_km(center: (f64, f64), points: &[(f64, f64)]) -> f64 {
    if points.is_empty() {
        return 0.0;
    }
    let mut distances: Vec<f64> = points
        .iter()
        .map(|&(lat, lon)| haversine_km(center.0, center.1, lat, lon))
        .collect();
    distances.sort_by(f64::total_cmp);
    let len = distances.len();
    if len % 2 == 1 {
        distances[len / 2]
    } else {
        f64::midpoint(distances[len / 2 - 1], distances[len / 2])
    }
}

#[must_use]
pub fn weighted_centroid(points: &[((f64, f64), f64)]) -> Option<(f64, f64)> {
    if points.is_empty() {
        return None;
    }
    let mut sum_weight = 0.0;
    let mut sum_lat = 0.0;
    let mut sum_lon = 0.0;
    for &((lat, lon), weight) in points {
        let weight = weight.max(0.0);
        sum_weight += weight;
        sum_lat += weight * lat;
        sum_lon += weight * lon;
    }
    if sum_weight <= 0.0 {
        let count = points.len() as f64;
        return Some((
            points.iter().map(|((lat, _), _)| *lat).sum::<f64>() / count,
            points.iter().map(|((_, lon), _)| *lon).sum::<f64>() / count,
        ));
    }
    Some((sum_lat / sum_weight, sum_lon / sum_weight))
}

#[must_use]
pub fn point_in_convex_hull(hull: &[(f64, f64)], point: (f64, f64)) -> bool {
    if hull.len() < 3 {
        return false;
    }
    const EPS: f64 = -1e-12;
    let cross = |a: (f64, f64), b: (f64, f64)| {
        (b.1 - a.1) * (point.0 - a.0) - (b.0 - a.0) * (point.1 - a.1)
    };
    (0..hull.len()).all(|index| cross(hull[index], hull[(index + 1) % hull.len()]) >= EPS)
}

#[must_use]
pub fn location_fix(weighted_points: &[((f64, f64), f64)]) -> Option<LocationFix> {
    let points: Vec<(f64, f64)> = weighted_points.iter().map(|(point, _)| *point).collect();
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

#[must_use]
pub fn coherent_groups(points: &[(f64, f64)], link_km: f64) -> Vec<Vec<usize>> {
    if points.is_empty() {
        return Vec::new();
    }
    let mut union_find = UnionFind::new(points.len());
    for i in 0..points.len() {
        for j in (i + 1)..points.len() {
            if haversine_km(points[i].0, points[i].1, points[j].0, points[j].1) <= link_km {
                union_find.union(i, j);
            }
        }
    }
    let mut groups = union_find.groups();
    groups.sort_by(|left, right| {
        right
            .len()
            .cmp(&left.len())
            .then_with(|| left.first().cmp(&right.first()))
    });
    groups
}

#[must_use]
pub fn is_coherent(points: &[(f64, f64)], link_km: f64) -> bool {
    coherent_groups(points, link_km).len() <= 1
}

#[must_use]
pub fn max_pairwise_km(points: &[(f64, f64)]) -> f64 {
    let mut worst = 0.0_f64;
    for i in 0..points.len() {
        for j in (i + 1)..points.len() {
            worst = worst.max(haversine_km(
                points[i].0,
                points[i].1,
                points[j].0,
                points[j].1,
            ));
        }
    }
    worst
}

pub(crate) fn lon_scale(lat_ref_deg: f64) -> f64 {
    lat_ref_deg.to_radians().cos().max(1e-6)
}

pub(crate) fn polygon_centroid_latlon(hull: &[(f64, f64)]) -> (f64, f64) {
    let len = hull.len();
    let mut area2 = 0.0;
    let mut cx = 0.0;
    let mut cy = 0.0;
    for i in 0..len {
        let (lat0, lon0) = hull[i];
        let (lat1, lon1) = hull[(i + 1) % len];
        let cross = lon0 * lat1 - lon1 * lat0;
        area2 += cross;
        cx += (lon0 + lon1) * cross;
        cy += (lat0 + lat1) * cross;
    }
    if area2.abs() < 1e-12 {
        let count = len as f64;
        return (
            hull.iter().map(|(lat, _)| *lat).sum::<f64>() / count,
            hull.iter().map(|(_, lon)| *lon).sum::<f64>() / count,
        );
    }
    (cy / (3.0 * area2), cx / (3.0 * area2))
}

pub(crate) fn convex_hull_latlon(points: &[(f64, f64)]) -> Vec<(f64, f64)> {
    let mut sorted = points.to_vec();
    sorted.sort_by(|left, right| left.1.total_cmp(&right.1).then(left.0.total_cmp(&right.0)));
    let cross = |o: (f64, f64), a: (f64, f64), b: (f64, f64)| {
        (a.1 - o.1) * (b.0 - o.0) - (a.0 - o.0) * (b.1 - o.1)
    };

    let mut lower = Vec::new();
    for point in &sorted {
        while lower.len() >= 2
            && cross(lower[lower.len() - 2], lower[lower.len() - 1], *point) <= 0.0
        {
            lower.pop();
        }
        lower.push(*point);
    }

    let mut upper = Vec::new();
    for point in sorted.iter().rev() {
        while upper.len() >= 2
            && cross(upper[upper.len() - 2], upper[upper.len() - 1], *point) <= 0.0
        {
            upper.pop();
        }
        upper.push(*point);
    }

    lower.pop();
    upper.pop();
    lower.extend(upper);
    lower
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    const SYDNEY: (f64, f64) = (-33.8688, 151.2093);
    const SYDNEY_NEARBY: (f64, f64) = (-33.8568, 151.2153);
    const PARRAMATTA: (f64, f64) = (-33.8150, 151.0);
    const PERTH: (f64, f64) = (-31.9523, 115.8613);
    const LONDON: (f64, f64) = (51.5074, -0.1278);

    #[test]
    fn footprint_requires_three_distinct_non_collinear_points() {
        assert!(geo_footprint(&[]).is_none());
        assert!(geo_footprint(&[(0.0, 0.0)]).is_none());
        assert!(geo_footprint(&[(0.0, 0.0), (1.0, 1.0)]).is_none());
        assert!(geo_footprint(&[(0.0, 0.0), (0.0, 0.0), (1.0, 1.0)]).is_none());
        assert!(geo_footprint(&[(0.0, 0.0), (1.0, 1.0), (2.0, 2.0)]).is_none());
    }

    #[test]
    fn footprint_reports_hull_centroid_and_diameter() {
        let pts = [(0.0, 0.0), (0.0, 1.0), (1.0, 1.0), (1.0, 0.0), (0.5, 0.5)];
        let footprint = geo_footprint(&pts).unwrap();
        assert_eq!(footprint.hull.len(), 4);
        assert!((footprint.centroid.0 - 0.5).abs() < 1e-9);
        assert!((footprint.centroid.1 - 0.5).abs() < 1e-9);
        assert!(footprint.diameter_km > 111.0 && footprint.diameter_km < 160.0);
        assert!(!footprint.is_tight());
    }

    #[test]
    fn polygon_centroid_is_area_centre_not_vertex_mean() {
        let pts = [(0.0, 0.0), (0.0, 4.0), (2.0, 3.0), (2.0, 0.0)];
        let footprint = geo_footprint(&pts).unwrap();
        let vertex_mean_lon =
            footprint.hull.iter().map(|(_, lon)| *lon).sum::<f64>() / footprint.hull.len() as f64;
        assert!((footprint.centroid.1 - vertex_mean_lon).abs() > 1e-3);
    }

    #[test]
    fn enclosing_circle_covers_every_point_and_is_order_independent() {
        let pts = [
            (-33.8700, 151.2100),
            (-33.8800, 151.2300),
            (-33.8600, 151.2000),
            (-33.8750, 151.2200),
        ];
        let circle = min_enclosing_circle(&pts).unwrap();
        for &(lat, lon) in &pts {
            assert!(
                haversine_km(circle.center.0, circle.center.1, lat, lon) <= circle.radius_km + 1e-6
            );
        }
        let mut reversed = pts;
        reversed.reverse();
        let other = min_enclosing_circle(&reversed).unwrap();
        assert!((circle.center.0 - other.center.0).abs() < 1e-9);
        assert!((circle.center.1 - other.center.1).abs() < 1e-9);
        assert!((circle.radius_km - other.radius_km).abs() < 1e-6);
    }

    #[test]
    fn geometric_median_is_robust_and_weighted_version_pulls_to_trusted_point() {
        let pts = [(0.0, 0.0), (0.0, 0.02), (0.02, 0.0), (10.0, 10.0)];
        let median = geometric_median(&pts).unwrap();
        let mean = (
            pts.iter().map(|(lat, _)| *lat).sum::<f64>() / 4.0,
            pts.iter().map(|(_, lon)| *lon).sum::<f64>() / 4.0,
        );
        let d0 = |p: (f64, f64)| haversine_km(0.0, 0.0, p.0, p.1);
        assert!(d0(median) < 5.0);
        assert!(d0(median) < d0(mean));

        let a = (0.0, 0.0);
        let weighted =
            weighted_geometric_median(&[(a, 12.0), ((0.0, 1.0), 1.0), ((0.8, 0.5), 1.0)]).unwrap();
        assert!(
            haversine_km(a.0, a.1, weighted.0, weighted.1)
                < haversine_km(
                    a.0,
                    a.1,
                    geometric_median(&[a, (0.0, 1.0), (0.8, 0.5)]).unwrap().0,
                    geometric_median(&[a, (0.0, 1.0), (0.8, 0.5)]).unwrap().1
                )
        );
    }

    #[test]
    fn weighted_centroid_and_median_radius_handle_edge_cases() {
        assert!(weighted_centroid(&[]).is_none());
        assert_eq!(median_distance_km((0.0, 0.0), &[]), 0.0);
        let zero = weighted_centroid(&[((0.0, 0.0), 0.0), ((2.0, 2.0), 0.0)]).unwrap();
        assert_eq!(zero, (1.0, 1.0));
    }

    #[test]
    fn location_fix_bundles_estimators_and_summarises() {
        let weighted = [
            ((-33.8700, 151.2100), 0.9),
            ((-33.8720, 151.2150), 0.6),
            ((-33.8680, 151.2080), 0.7),
        ];
        let fix = location_fix(&weighted).unwrap();
        assert!(fix.location_summary().contains("geometric median"));
        assert!(fix.location_summary().contains("Chebyshev centre"));
        assert!(point_in_convex_hull(
            &fix.footprint.hull,
            fix.weighted_centroid
        ));
    }

    #[test]
    fn coherence_groups_chain_through_intermediates() {
        let none = coherent_groups(&[], 5.0);
        assert!(none.is_empty(), "{none:?}");
        let groups = coherent_groups(&[SYDNEY, SYDNEY_NEARBY], 5.0);
        assert_eq!(groups, vec![vec![0, 1]]);
        assert!(is_coherent(&[SYDNEY, SYDNEY_NEARBY], 5.0));
        assert!(!is_coherent(&[SYDNEY, PERTH], 5.0));

        let midpoint = (-33.8420, 151.1050);
        assert_eq!(
            coherent_groups(&[SYDNEY, PARRAMATTA, midpoint], 15.0).len(),
            1
        );
        assert_eq!(coherent_groups(&[SYDNEY, PARRAMATTA], 15.0).len(), 2);

        let ordered = coherent_groups(&[LONDON, SYDNEY, SYDNEY_NEARBY], 5.0);
        assert_eq!(ordered[0], vec![1, 2]);
        assert_eq!(ordered[1], vec![0]);
        assert!(max_pairwise_km(&[SYDNEY, SYDNEY_NEARBY, PERTH]) > 3200.0);
    }
}
