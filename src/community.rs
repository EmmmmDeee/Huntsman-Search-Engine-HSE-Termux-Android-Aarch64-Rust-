//! Community detection by bridge removal.

use std::collections::BTreeSet;

use crate::graph::Graph;
use crate::union_find::UnionFind;

/// How many communities `graph` falls into once its `bridges` (from
/// [`Graph::cut_vertices_and_bridges`]) are removed: its 2-edge-connected components, an
/// isolated node being one of its own.
#[must_use]
pub fn community_count(graph: &Graph, bridges: &[(usize, usize)]) -> usize {
    let bridges = bridges.iter().collect::<BTreeSet<_>>();
    let mut uf = UnionFind::new(graph.node_count());
    for (left, right) in graph.edge_pairs() {
        if !bridges.contains(&(left, right)) {
            uf.union(left, right);
        }
    }
    uf.groups().len()
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

    fn count(names: &[&str], edges: &[(&str, &str)]) -> usize {
        let entities = names.iter().copied().map(entity).collect::<Vec<_>>();
        let uid = |name: &str| {
            entities
                .iter()
                .find(|entity| entity.raw_value.starts_with(name))
                .unwrap()
                .uid
                .clone()
        };
        let relations = edges
            .iter()
            .map(|(a, b)| EntityRelation::new(uid(a), uid(b), RelationKind::AssociatedWith, 0.6))
            .collect::<Vec<_>>();
        let graph = Graph::build(&entities, &relations);
        let (_, bridges) = graph.cut_vertices_and_bridges();
        community_count(&graph, &bridges)
    }

    #[test]
    fn bridge_splits_two_triangles() {
        let triangles = [
            ("a", "b"),
            ("b", "c"),
            ("a", "c"),
            ("d", "e"),
            ("e", "f"),
            ("d", "f"),
            ("c", "d"),
        ];
        assert_eq!(count(&["a", "b", "c", "d", "e", "f"], &triangles), 2);
    }

    #[test]
    fn every_bridge_and_isolated_node_is_its_own_community() {
        // A path of three is two bridges and three communities; the lone node is a fourth.
        assert_eq!(count(&["a", "b", "c", "z"], &[("a", "b"), ("b", "c")]), 4);
    }
}
