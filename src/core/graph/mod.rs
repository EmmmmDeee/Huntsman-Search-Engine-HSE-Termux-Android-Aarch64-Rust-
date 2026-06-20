//! `core::graph` — the shared undirected graph primitive for the engine's graph
//! analytics.
//!
//! Centrality (`core::pivot`), reach (`core::metrics::reachability`), and every future
//! structural pass need the same thing first: the deduplicated, deterministic
//! undirected adjacency over a scan's entities and relations. Before this primitive each
//! pass re-implemented that build (and its determinism discipline) inline; this is the
//! single place that does it, so a fix or a determinism guarantee lands once. It is
//! index-based — nodes are `0..n` in ascending-UID order — for cache-friendly,
//! allocation-light traversal on a low-RAM Termux device, with [`Graph::uid`] /
//! [`Graph::index_of`] bridging back to UIDs.
//!
//! Cycle safety is built in: [`Graph::bfs_levels`] settles each node on first dequeue
//! via an explicit visited/`dist` array, so a cyclic graph can never re-expand a node
//! or loop unboundedly — the traversal is O(V+E) regardless of cycles.
//!
//! Pure and read-only: building a [`Graph`] borrows the slices and copies only the UID
//! strings it needs for the index; it performs no I/O and is independent of input order.

use std::collections::{BTreeSet, HashMap, VecDeque};

use crate::core::entity::Entity;
use crate::core::relation::Relation;

/// The hop distance assigned by [`Graph::bfs_levels`] to a node that is NOT reachable
/// from the source (a different connected component).
pub const UNREACHABLE: usize = usize::MAX;

/// An undirected, unweighted graph over a scan's entities, with deterministic node
/// indexing and deduplicated adjacency. Nodes are the present entities, indexed `0..n`
/// in ascending-UID order.
pub struct Graph {
    /// index → UID, ascending-sorted (the deterministic node order every pass walks).
    uids: Vec<String>,
    /// UID → index.
    index: HashMap<String, usize>,
    /// index → its sorted, deduplicated neighbour indices (undirected).
    adj: Vec<Vec<usize>>,
}

impl Graph {
    /// Build the undirected graph over the PRESENT entities: every entity is a node (in
    /// ascending-UID order), and each relation whose BOTH endpoints are present
    /// contributes one undirected edge — parallel edges between a pair collapse to one,
    /// self-loops are dropped, and neighbour lists are sorted. Deterministic and
    /// independent of the order the entities and relations are supplied in.
    #[must_use]
    pub fn build(entities: &[Entity], relations: &[Relation]) -> Self {
        let mut uids: Vec<String> = entities.iter().map(|e| e.uid.clone()).collect();
        uids.sort_unstable();
        uids.dedup();
        let index: HashMap<String, usize> = uids
            .iter()
            .enumerate()
            .map(|(i, u)| (u.clone(), i))
            .collect();

        // A BTreeSet per node gives dedup (parallel edges) + sorted order for free.
        let mut sets: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); uids.len()];
        for r in relations {
            let (Some(&a), Some(&b)) =
                (index.get(r.from_uid.as_str()), index.get(r.to_uid.as_str()))
            else {
                continue; // a dangling endpoint links nothing
            };
            if a == b {
                continue; // a self-loop is not a link between two nodes
            }
            sets[a].insert(b);
            sets[b].insert(a);
        }
        let adj = sets.into_iter().map(|s| s.into_iter().collect()).collect();
        Self { uids, index, adj }
    }

    /// Number of nodes (present entities).
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.uids.len()
    }

    /// Whether the graph has no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.uids.is_empty()
    }

    /// The UID of node `i` (panics only on an out-of-range index, a caller bug).
    #[must_use]
    pub fn uid(&self, i: usize) -> &str {
        &self.uids[i]
    }

    /// The index of `uid`, or `None` if it is not a node in this graph.
    #[must_use]
    pub fn index_of(&self, uid: &str) -> Option<usize> {
        self.index.get(uid).copied()
    }

    /// Node `i`'s sorted, deduplicated neighbour indices.
    #[must_use]
    pub fn neighbours(&self, i: usize) -> &[usize] {
        &self.adj[i]
    }

    /// Node `i`'s degree (its distinct neighbour count).
    #[must_use]
    pub fn degree(&self, i: usize) -> usize {
        self.adj[i].len()
    }

    /// Cycle-safe breadth-first hop distances from `source` to every node, via an
    /// explicit visited/`dist` array: a node is settled the first time it is reached, so
    /// a cycle can never re-expand it or loop unboundedly. The returned vector has
    /// length [`node_count`](Graph::node_count); `dist[source] == 0`, and an unreachable
    /// node (a different component) is [`UNREACHABLE`]. O(V+E).
    #[must_use]
    pub fn bfs_levels(&self, source: usize) -> Vec<usize> {
        let mut dist = vec![UNREACHABLE; self.uids.len()];
        if source >= self.uids.len() {
            return dist;
        }
        dist[source] = 0;
        let mut queue: VecDeque<usize> = VecDeque::new();
        queue.push_back(source);
        while let Some(v) = queue.pop_front() {
            for &w in &self.adj[v] {
                if dist[w] == UNREACHABLE {
                    dist[w] = dist[v] + 1;
                    queue.push_back(w);
                }
            }
        }
        dist
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
