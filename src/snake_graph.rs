//! Compact tree-like graph rendering.

use std::collections::VecDeque;

use crate::graph::Graph;

#[must_use]
pub fn render_snake_graph(graph: &Graph, root_uid: &str) -> Option<String> {
    let root = graph.index_of(root_uid)?;
    let mut parents = vec![usize::MAX; graph.node_count()];
    let mut order = Vec::new();
    let mut queue = VecDeque::from([root]);
    parents[root] = root;
    while let Some(node) = queue.pop_front() {
        order.push(node);
        for &next in graph.neighbours(node) {
            if parents[next] == usize::MAX {
                parents[next] = node;
                queue.push_back(next);
            }
        }
    }
    let mut children = vec![Vec::new(); graph.node_count()];
    for &node in &order[1..] {
        children[parents[node]].push(node);
    }
    let mut out = String::new();
    fn walk(graph: &Graph, children: &[Vec<usize>], node: usize, prefix: &str, out: &mut String) {
        out.push_str(prefix);
        out.push_str(graph.uid(node));
        out.push('\n');
        for (i, &child) in children[node].iter().enumerate() {
            let branch = if i + 1 == children[node].len() {
                "└─ "
            } else {
                "├─ "
            };
            let next_prefix = format!("{prefix}{branch}");
            walk(graph, children, child, &next_prefix, out);
        }
    }
    walk(graph, &children, root, "", &mut out);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Entity, EntityKind};
    use crate::graph::{EntityRelation, RelationKind};

    #[test]
    fn renders_bfs_tree() {
        let a = Entity::new(EntityKind::Email, "a@example.com", 0.6, "scan");
        let b = Entity::new(EntityKind::Email, "b@example.com", 0.6, "scan");
        let c = Entity::new(EntityKind::Email, "c@example.com", 0.6, "scan");
        let graph = Graph::build(
            &[a.clone(), b.clone(), c.clone()],
            &[
                EntityRelation::new(a.uid.clone(), b.uid.clone(), RelationKind::Uses, 0.5),
                EntityRelation::new(b.uid.clone(), c.uid.clone(), RelationKind::Uses, 0.5),
            ],
        );
        let rendered = render_snake_graph(&graph, &a.uid).unwrap();
        assert!(rendered.contains(&a.uid));
        assert!(rendered.contains("└"));
    }
}
