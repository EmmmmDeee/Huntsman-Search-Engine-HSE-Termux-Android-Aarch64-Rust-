//! Spatial coherence: partition sightings into groups that plausibly describe
//! the same place.
//!
//! Every estimator in this module (geometric median, centroid, enclosing
//! circle) answers "given points that belong together, where is the centre?".
//! None of them answer "do these points belong together at all?" — and fed a
//! set that does not, they return a confident number for a place nobody was.
//! Two sightings 3,000 km apart have a perfectly well-defined midpoint; it is
//! simply not a location either sighting supports.
//!
//! This is the missing gate. Single-linkage union-find at a caller-chosen link
//! distance splits sightings into coherent groups, so a fusion step can run on
//! one group at a time instead of averaging across a continent.

/// Partition points into spatially coherent groups by single-linkage
/// clustering: two points join the same group when they are within `link_km`,
/// transitively.
///
/// Returns index groups into `points`, each group's indices ascending, and the
/// groups ordered by descending size with a smallest-first-index tie-break —
/// deterministic for identical input, so a caller that takes the first group
/// gets a stable answer.
///
/// Single-linkage (rather than a fixed-radius test against the centre) is what
/// suits geographic sightings: a person's movements through a city form a
/// chain of overlapping observations, not a disc around one point.
pub fn coherent_groups(points: &[(f64, f64)], link_km: f64) -> Vec<Vec<usize>> {
    if points.is_empty() {
        return Vec::new();
    }
    let mut uf = crate::util::union_find::UnionFind::new(points.len());
    for i in 0..points.len() {
        for j in (i + 1)..points.len() {
            let d = crate::util::geohash::haversine_km(
                points[i].0,
                points[i].1,
                points[j].0,
                points[j].1,
            );
            if d <= link_km {
                uf.union(i, j);
            }
        }
    }

    // `components()` groups indices by root under a BTreeMap, so each group's
    // indices are already ascending and the group order is itself deterministic
    // before the sort below refines it.
    let mut groups: Vec<Vec<usize>> = uf.components().into_values().collect();
    groups.sort_by(|a, b| {
        b.len()
            .cmp(&a.len())
            .then_with(|| a.first().cmp(&b.first()))
    });
    groups
}

/// True when every point lies within `link_km` of the whole set through a
/// chain of neighbours — i.e. [`coherent_groups`] would return a single group.
///
/// The cheap precondition for fusing a set of sightings into one estimate.
pub fn is_coherent(points: &[(f64, f64)], link_km: f64) -> bool {
    coherent_groups(points, link_km).len() <= 1
}

/// Greatest great-circle distance between any two points, in kilometres.
///
/// The honest "how far apart are these sightings?" figure — unlike a median
/// distance to the centre, one distant outlier cannot hide in it.
pub fn max_pairwise_km(points: &[(f64, f64)]) -> f64 {
    let mut worst = 0.0_f64;
    for i in 0..points.len() {
        for j in (i + 1)..points.len() {
            let d = crate::util::geohash::haversine_km(
                points[i].0,
                points[i].1,
                points[j].0,
                points[j].1,
            );
            if d > worst {
                worst = d;
            }
        }
    }
    worst
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYDNEY: (f64, f64) = (-33.8688, 151.2093);
    const SYDNEY_NEARBY: (f64, f64) = (-33.8568, 151.2153); // Opera House, ~1.4 km
    const PARRAMATTA: (f64, f64) = (-33.8150, 151.0000); // ~20 km west
    const PERTH: (f64, f64) = (-31.9523, 115.8613); // ~3,290 km west
    const LONDON: (f64, f64) = (51.5074, -0.1278);

    #[test]
    fn empty_input_yields_no_groups() {
        assert!(coherent_groups(&[], 5.0).is_empty());
    }

    #[test]
    fn nearby_points_form_one_group() {
        let groups = coherent_groups(&[SYDNEY, SYDNEY_NEARBY], 5.0);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0], vec![0, 1]);
        assert!(is_coherent(&[SYDNEY, SYDNEY_NEARBY], 5.0));
    }

    #[test]
    fn distant_points_stay_separate() {
        // The defect this gate exists to stop: Sydney and Perth have a tidy
        // midpoint in the Nullarbor that neither sighting supports.
        let points = [SYDNEY, PERTH];
        let groups = coherent_groups(&points, 5.0);
        assert_eq!(groups.len(), 2, "a 3,290 km gap is not one place");
        assert!(!is_coherent(&points, 5.0));
    }

    #[test]
    fn single_linkage_chains_through_intermediates() {
        // Sydney↔Parramatta is ~20 km: too far to link directly at 15 km, but a
        // point between them chains the two into one metropolitan group.
        let midpoint = (-33.8420, 151.1050);
        let points = [SYDNEY, PARRAMATTA, midpoint];
        assert_eq!(coherent_groups(&points, 15.0).len(), 1);
        // Without the intermediate they stay apart at the same link distance.
        assert_eq!(coherent_groups(&[SYDNEY, PARRAMATTA], 15.0).len(), 2);
    }

    #[test]
    fn groups_are_ordered_by_descending_size() {
        // Two Sydney sightings and one London: the better-supported group leads.
        let points = [LONDON, SYDNEY, SYDNEY_NEARBY];
        let groups = coherent_groups(&points, 5.0);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0], vec![1, 2], "the 2-point group must come first");
        assert_eq!(groups[1], vec![0]);
    }

    #[test]
    fn grouping_is_deterministic_across_equal_sized_groups() {
        let points = [SYDNEY, LONDON];
        let first = coherent_groups(&points, 5.0);
        for _ in 0..8 {
            assert_eq!(coherent_groups(&points, 5.0), first);
        }
        // Tie on size → smallest leading index first.
        assert_eq!(first[0], vec![0]);
    }

    #[test]
    fn max_pairwise_reports_the_widest_separation() {
        assert_eq!(max_pairwise_km(&[SYDNEY]), 0.0);
        let spread = max_pairwise_km(&[SYDNEY, SYDNEY_NEARBY, PERTH]);
        assert!(
            (3200.0..3400.0).contains(&spread),
            "Sydney–Perth is ~3,290 km, got {spread}"
        );
    }
}
