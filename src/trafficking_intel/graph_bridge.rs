//! Bounded, evidence-filtered tree view over Huntsman's existing graph.
//!
//! This adapter uses the existing graph's stable node IDs and adjacency. It does not
//! duplicate graph storage, infer criminal involvement, or promote unsupported
//! associations into documented relationships.

use std::collections::{BTreeSet, VecDeque};

use crate::graph::{EntityRelation, Graph};

use super::entity_tree::{GraphError, TreeEntry};

/// Expand only graph edges that have at least one attributable, non-inferred,
/// non-operator evidence record in the supplied original relations.
///
/// The graph provides connectivity; the relations provide inspectable evidence.
/// Callers must retain those original records for subsequent human review.
/// The resulting parent is a traversal parent, not an inferred factual hierarchy.
pub fn expand_documented(
    graph: &Graph,
    relations: &[EntityRelation],
    root: &str,
    max_depth: usize,
    max_nodes: usize,
) -> Result<Vec<TreeEntry>, GraphError> {
    let start = graph
        .index_of(root)
        .ok_or_else(|| GraphError::UnknownEndpoint(root.to_owned()))?;
    let limit = max_nodes.min(10_000);
    if limit == 0 {
        return Ok(Vec::new());
    }

    let documented: BTreeSet<(usize, usize)> = relations
        .iter()
        .filter(|relation| {
            relation.evidence.iter().any(|item| {
                !item.is_inferred
                    && !item.is_operator_seed()
                    && !item.provenance.source.trim().is_empty()
                    && !item.summary.trim().is_empty()
            })
        })
        .filter_map(|relation| {
            let from = graph.index_of(&relation.from_uid)?;
            let to = graph.index_of(&relation.to_uid)?;
            (from != to).then_some((from.min(to), from.max(to)))
        })
        .collect();

    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::new();
    let mut output = Vec::new();
    seen.insert(start);
    queue.push_back((start, 0, None));

    while let Some((index, depth, parent)) = queue.pop_front() {
        let id = graph.uid(index).to_owned();
        output.push(TreeEntry {
            id: id.clone(),
            depth,
            parent,
        });

        if output.len() >= limit {
            break;
        }
        if depth >= max_depth {
            continue;
        }

        for &neighbour in graph.neighbours(index) {
            if seen.len() >= limit {
                break;
            }
            let key = (index.min(neighbour), index.max(neighbour));
            if documented.contains(&key) && seen.insert(neighbour) {
                queue.push_back((neighbour, depth + 1, Some(id.clone())));
            }
        }
    }

    Ok(output)
}
