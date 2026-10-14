//! Simple pivot scoring over the entity graph.

use serde::{Deserialize, Serialize};

use crate::graph::Graph;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PivotScore {
    pub uid: String,
    pub degree: usize,
    pub reachable: usize,
    pub closeness: f64,
    pub articulation: bool,
}

#[must_use]
pub fn rank_pivots(graph: &Graph) -> Vec<PivotScore> {
    let (cut_vertices, _) = graph.cut_vertices_and_bridges();
    let cut_vertices = cut_vertices
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let reach = reach_and_distance_sums(graph);
    let mut scores = (0..graph.node_count())
        .map(|node| {
            let (reachable, total_distance) = reach[node];
            let closeness = if reachable > 1 && total_distance > 0 {
                let reachable_f =
                    f64::from(u32::try_from(reachable.saturating_sub(1)).unwrap_or(u32::MAX));
                let distance_f = f64::from(u32::try_from(total_distance).unwrap_or(u32::MAX));
                reachable_f / distance_f
            } else {
                0.0
            };
            PivotScore {
                uid: graph.uid(node).to_owned(),
                degree: graph.degree(node),
                reachable,
                closeness,
                articulation: cut_vertices.contains(&node),
            }
        })
        .collect::<Vec<_>>();
    scores.sort_by(|left, right| {
        right
            .articulation
            .cmp(&left.articulation)
            .then_with(|| right.closeness.total_cmp(&left.closeness))
            .then_with(|| right.degree.cmp(&left.degree))
            .then_with(|| left.uid.cmp(&right.uid))
    });
    scores
}

/// For each node, how many nodes a breadth-first search from it reaches, itself included, and
/// the sum of their distances from it. The searches run 64 at a time, one bit of a word per
/// search: a level expands each frontier node once for every search that holds it, so searches
/// that meet share their work, and a word operation advances up to 64 of them.
fn reach_and_distance_sums(graph: &Graph) -> Vec<(usize, usize)> {
    let n = graph.node_count();
    let mut sums = vec![(1, 0); n];
    let mut seen = vec![0_u64; n];
    // The searches holding each frontier node; written for a node whenever it joins a frontier,
    // so it is read only as written for that frontier.
    let mut frontier_bits = vec![0_u64; n];
    let mut next_bits = vec![0_u64; n];
    let mut frontier = Vec::new();
    let mut next = Vec::new();
    for batch in (0..n).step_by(64) {
        seen.fill(0);
        for (bit, source) in (batch..n.min(batch + 64)).enumerate() {
            seen[source] = 1 << bit;
            frontier_bits[source] = 1 << bit;
            frontier.push(source);
        }
        let mut level = 0;
        while !frontier.is_empty() {
            level += 1;
            for &node in &frontier {
                let bits = frontier_bits[node];
                for &neighbour in graph.neighbours(node) {
                    let reached = bits & !seen[neighbour];
                    if reached != 0 {
                        if next_bits[neighbour] == 0 {
                            next.push(neighbour);
                        }
                        next_bits[neighbour] |= reached;
                    }
                }
            }
            for &node in &next {
                let reached = next_bits[node];
                next_bits[node] = 0;
                seen[node] |= reached;
                frontier_bits[node] = reached;
                let mut rest = reached;
                while rest != 0 {
                    let bit = usize::try_from(rest.trailing_zeros()).unwrap_or(0);
                    rest &= rest - 1;
                    sums[batch + bit].0 += 1;
                    sums[batch + bit].1 += level;
                }
            }
            std::mem::swap(&mut frontier, &mut next);
            next.clear();
        }
    }
    sums
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Entity, EntityKind};
    use crate::graph::{EntityRelation, RelationKind, UNREACHABLE};

    fn entity(name: &str) -> Entity {
        Entity::new(
            EntityKind::Email,
            format!("{name}@example.com"),
            0.6,
            "scan",
        )
    }

    #[test]
    fn articulation_broker_ranks_first() {
        let a = entity("a");
        let b = entity("b");
        let c = entity("c");
        let d = entity("d");
        let graph = Graph::build(
            &[a.clone(), b.clone(), c.clone(), d.clone()],
            &[
                EntityRelation::new(a.uid.clone(), b.uid.clone(), RelationKind::Uses, 0.5),
                EntityRelation::new(b.uid.clone(), c.uid.clone(), RelationKind::Uses, 0.5),
                EntityRelation::new(c.uid.clone(), d.uid.clone(), RelationKind::Uses, 0.5),
            ],
        );
        let first = &rank_pivots(&graph)[0];
        assert!(first.articulation);
        assert!(first.uid == b.uid || first.uid == c.uid);
    }

    /// `rank_pivots` as it was, kept as its oracle: a fresh distance vector per node, scanned
    /// whole, reachable or not.
    fn rank_pivots_by_full_scans(graph: &Graph) -> Vec<PivotScore> {
        let (cut_vertices, _) = graph.cut_vertices_and_bridges();
        let cut_vertices = cut_vertices
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        let mut scores = (0..graph.node_count())
            .map(|node| {
                let levels = graph.bfs_levels(node);
                let reachable = levels.iter().filter(|&&d| d != UNREACHABLE).count();
                let total_distance: usize = levels.iter().filter(|&&d| d != UNREACHABLE).sum();
                let closeness = if reachable > 1 && total_distance > 0 {
                    let reachable_f =
                        f64::from(u32::try_from(reachable.saturating_sub(1)).unwrap_or(u32::MAX));
                    let distance_f = f64::from(u32::try_from(total_distance).unwrap_or(u32::MAX));
                    reachable_f / distance_f
                } else {
                    0.0
                };
                PivotScore {
                    uid: graph.uid(node).to_owned(),
                    degree: graph.degree(node),
                    reachable,
                    closeness,
                    articulation: cut_vertices.contains(&node),
                }
            })
            .collect::<Vec<_>>();
        scores.sort_by(|left, right| {
            right
                .articulation
                .cmp(&left.articulation)
                .then_with(|| right.closeness.total_cmp(&left.closeness))
                .then_with(|| right.degree.cmp(&left.degree))
                .then_with(|| left.uid.cmp(&right.uid))
        });
        scores
    }

    /// Searching 64 nodes at a time ranks every pivot as one full scan per node did: isolated
    /// nodes, separate components, and graphs of one, two and three batches.
    #[test]
    fn rank_pivots_matches_full_scans_on_random_graphs() {
        let mut state = 0x2545_F491_4F6C_DD1D_u64;
        for round in 0..300 {
            let graph = crate::test_support::random_graph(&mut state, 150);
            assert_eq!(
                rank_pivots(&graph),
                rank_pivots_by_full_scans(&graph),
                "round {round}: {:?}",
                graph.edge_pairs()
            );
        }
    }
}
