//! Shortest paths through the entity graph.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::graph::{Graph, RelationKind, UNREACHABLE};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathHop {
    pub from_uid: String,
    pub to_uid: String,
    pub relation_kinds: Vec<RelationKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphPath {
    pub hops: Vec<PathHop>,
}

#[must_use]
pub fn shortest_path(graph: &Graph, start_uid: &str, goal_uid: &str) -> Option<GraphPath> {
    let start = graph.index_of(start_uid)?;
    let goal = graph.index_of(goal_uid)?;
    if start == goal {
        return Some(GraphPath { hops: Vec::new() });
    }
    let mut parents = vec![UNREACHABLE; graph.node_count()];
    let mut queue = VecDeque::from([start]);
    parents[start] = start;
    while let Some(node) = queue.pop_front() {
        for &next in graph.neighbours(node) {
            if parents[next] != UNREACHABLE {
                continue;
            }
            parents[next] = node;
            if next == goal {
                break;
            }
            queue.push_back(next);
        }
    }
    if parents[goal] == UNREACHABLE {
        return None;
    }
    let mut nodes = vec![goal];
    let mut cursor = goal;
    while cursor != start {
        cursor = parents[cursor];
        nodes.push(cursor);
    }
    nodes.reverse();
    let mut hops = Vec::with_capacity(nodes.len().saturating_sub(1));
    for pair in nodes.windows(2) {
        let edge = graph.edge(pair[0], pair[1])?;
        hops.push(PathHop {
            from_uid: graph.uid(pair[0]).to_owned(),
            to_uid: graph.uid(pair[1]).to_owned(),
            relation_kinds: edge.relation_kinds.clone(),
        });
    }
    Some(GraphPath { hops })
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
    fn shortest_path_is_reconstructed() {
        let a = entity("a");
        let b = entity("b");
        let c = entity("c");
        let graph = Graph::build(
            &[a.clone(), b.clone(), c.clone()],
            &[
                EntityRelation::new(a.uid.clone(), b.uid.clone(), RelationKind::Uses, 0.4),
                EntityRelation::new(b.uid.clone(), c.uid.clone(), RelationKind::Owns, 0.5),
            ],
        );
        let path = shortest_path(&graph, &a.uid, &c.uid).unwrap();
        assert_eq!(path.hops.len(), 2);
        assert_eq!(path.hops[0].relation_kinds, vec![RelationKind::Uses]);
    }
}
