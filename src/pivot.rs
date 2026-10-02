//! Simple pivot scoring over the entity graph.

use serde::{Deserialize, Serialize};

use crate::graph::{Graph, UNREACHABLE};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Entity, EntityKind};
    use crate::graph::{EntityRelation, RelationKind};

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
}
