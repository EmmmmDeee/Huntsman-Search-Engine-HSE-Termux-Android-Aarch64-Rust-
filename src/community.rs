//! Community detection by bridge removal.

use serde::{Deserialize, Serialize};

use crate::graph::Graph;
use crate::union_find::UnionFind;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Community {
    pub id: usize,
    pub members: Vec<String>,
}

#[must_use]
pub fn detect_communities(graph: &Graph) -> Vec<Community> {
    let (_, bridges) = graph.cut_vertices_and_bridges();
    let bridge_set = bridges
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let mut uf = UnionFind::new(graph.node_count());
    for (left, right) in graph.edge_pairs() {
        if !bridge_set.contains(&(left, right)) {
            uf.union(left, right);
        }
    }
    let mut communities = uf
        .groups()
        .into_iter()
        .enumerate()
        .map(|(id, group)| Community {
            id,
            members: group
                .into_iter()
                .map(|index| graph.uid(index).to_owned())
                .collect(),
        })
        .collect::<Vec<_>>();
    communities.sort_by(|left, right| {
        right
            .members
            .len()
            .cmp(&left.members.len())
            .then_with(|| left.members[0].cmp(&right.members[0]))
    });
    communities
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
    fn bridge_splits_two_triangles() {
        let entities = ["a", "b", "c", "d", "e", "f"]
            .into_iter()
            .map(entity)
            .collect::<Vec<_>>();
        let uid = |name: &str| {
            entities
                .iter()
                .find(|entity| entity.raw_value.starts_with(name))
                .unwrap()
                .uid
                .clone()
        };
        let rel = |a: &str, b: &str| {
            EntityRelation::new(uid(a), uid(b), RelationKind::AssociatedWith, 0.6)
        };
        let graph = Graph::build(
            &entities,
            &[
                rel("a", "b"),
                rel("b", "c"),
                rel("a", "c"),
                rel("d", "e"),
                rel("e", "f"),
                rel("d", "f"),
                rel("c", "d"),
            ],
        );
        let communities = detect_communities(&graph);
        assert_eq!(communities.len(), 2);
        assert_eq!(communities[0].members.len(), 3);
    }
}
