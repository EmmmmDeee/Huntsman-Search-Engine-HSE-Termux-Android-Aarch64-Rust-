//! Deterministic, iterative entity-tree rendering with a byte-exact export budget.
//! Size preflight prevents allocating an oversized quadratic-depth text artifact.

use std::collections::VecDeque;

use crate::graph::Graph;

const BRANCH_BYTES: usize = "└─ ".len();

/// Preserve the original unlimited public interface and tree text format.
#[must_use]
pub fn render_snake_graph(graph: &Graph, root_uid: &str) -> Option<String> {
    render_snake_graph_bounded(graph, root_uid, usize::MAX)?.ok()
}

/// Return the complete tree or its required UTF-8 byte count when it exceeds
/// the supplied byte limit. A missing root is None; no output is ever truncated.
#[must_use]
pub fn render_snake_graph_bounded(
    graph: &Graph,
    root_uid: &str,
    max_bytes: usize,
) -> Option<Result<String, usize>> {
    let root = graph.index_of(root_uid)?;
    let mut parents = vec![usize::MAX; graph.node_count()];
    let mut depths = vec![0_usize; graph.node_count()];
    let mut order = Vec::new();
    let mut queue = VecDeque::from([root]);
    parents[root] = root;

    while let Some(node) = queue.pop_front() {
        order.push(node);
        for &next in graph.neighbours(node) {
            if parents[next] == usize::MAX {
                parents[next] = node;
                depths[next] = depths[node].saturating_add(1);
                queue.push_back(next);
            }
        }
    }

    // Branches have a fixed UTF-8 width, regardless of ├ versus └.
    // Saturated size arithmetic can only trigger omission, never wraparound.
    let required_bytes = order.iter().fold(0_usize, |total, &node| {
        total.saturating_add(
            depths[node]
                .saturating_mul(BRANCH_BYTES)
                .saturating_add(graph.uid(node).len())
                .saturating_add(1),
        )
    });
    if required_bytes > max_bytes {
        return Some(Err(required_bytes));
    }

    let mut children = vec![Vec::new(); graph.node_count()];
    for &node in order.iter().skip(1) {
        children[parents[node]].push(node);
    }

    let mut out = String::with_capacity(required_bytes);
    let mut prefix = String::new();
    // Stack frames keep the next-child cursor; recursion and prefix clones are unnecessary.
    let mut stack = vec![(root, 0_usize)];
    while let Some((node, child_index)) = stack.last_mut() {
        if *child_index == 0 {
            out.push_str(&prefix);
            out.push_str(graph.uid(*node));
            out.push('\n');
        }
        if *child_index < children[*node].len() {
            let child = children[*node][*child_index];
            let branch = if *child_index + 1 == children[*node].len() {
                "└─ "
            } else {
                "├─ "
            };
            *child_index += 1;
            prefix.push_str(branch);
            stack.push((child, 0));
        } else {
            stack.pop();
            if !stack.is_empty() {
                prefix.truncate(prefix.len() - BRANCH_BYTES);
            }
        }
    }
    debug_assert_eq!(out.len(), required_bytes);
    Some(Ok(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Entity, EntityKind};
    use crate::graph::{EntityRelation, RelationKind};

    fn entity(value: &str) -> Entity {
        Entity::new(EntityKind::Email, value, 0.6, "scan")
    }

    #[test]
    fn renders_bfs_tree() {
        let a = entity("a@example.com");
        let b = entity("b@example.com");
        let c = entity("c@example.com");
        let graph = Graph::build(
            &[a.clone(), b.clone(), c.clone()],
            &[
                EntityRelation::new(a.uid.clone(), b.uid.clone(), RelationKind::Uses, 0.5),
                EntityRelation::new(b.uid.clone(), c.uid.clone(), RelationKind::Uses, 0.5),
            ],
        );
        assert_eq!(
            render_snake_graph(&graph, &a.uid).unwrap(),
            format!("{}\n└─ {}\n└─ └─ {}\n", a.uid, b.uid, c.uid)
        );
    }

    #[test]
    fn preserves_branch_order_and_exact_budget() {
        let a = entity("a@example.com");
        let b = entity("b@example.com");
        let c = entity("c@example.com");
        let graph = Graph::build(
            &[a.clone(), b.clone(), c.clone()],
            &[
                EntityRelation::new(a.uid.clone(), b.uid.clone(), RelationKind::Uses, 0.5),
                EntityRelation::new(a.uid.clone(), c.uid.clone(), RelationKind::Uses, 0.5),
            ],
        );
        let root = graph.index_of(&a.uid).unwrap();
        let neighbours = graph.neighbours(root);
        let want = format!(
            "{}\n├─ {}\n└─ {}\n",
            a.uid,
            graph.uid(neighbours[0]),
            graph.uid(neighbours[1]),
        );
        assert_eq!(render_snake_graph(&graph, &a.uid).unwrap(), want);
        assert_eq!(
            render_snake_graph_bounded(&graph, &a.uid, want.len()),
            Some(Ok(want.clone())),
        );
        assert_eq!(
            render_snake_graph_bounded(&graph, &a.uid, want.len() - 1),
            Some(Err(want.len())),
        );
        assert_eq!(render_snake_graph_bounded(&graph, "unknown", 1), None);
    }

    #[test]
    fn deep_chains_are_measured_without_rendering_the_quadratic_text() {
        const N: usize = 3_000;
        let entities = (0..N)
            .map(|index| entity(&format!("node-{index}@example.com")))
            .collect::<Vec<_>>();
        let relations = entities
            .windows(2)
            .map(|pair| {
                EntityRelation::new(
                    pair[0].uid.clone(),
                    pair[1].uid.clone(),
                    RelationKind::AssociatedWith,
                    0.5,
                )
            })
            .collect::<Vec<_>>();
        let graph = Graph::build(&entities, &relations);
        let required = (0..N).fold(0_usize, |sum, index| {
            sum + entities[index].uid.len() + 1 + index * BRANCH_BYTES
        });
        assert_eq!(
            render_snake_graph_bounded(&graph, &entities[0].uid, 1_024),
            Some(Err(required))
        );
    }
}
