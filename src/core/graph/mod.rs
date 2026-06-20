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

    /// The graph's **cut vertices** (articulation points) and **bridges** (cut edges)
    /// — the single points of failure in its connectivity.
    ///
    /// A *cut vertex* is a node whose removal increases the number of connected
    /// components: the critical broker that, alone, holds part of the network onto the
    /// rest. A *bridge* is an edge with the same property: the irreplaceable single link
    /// whose loss splits the graph. For an OSINT network this is the sharp, exact
    /// question betweenness only approximates — *which entity, if disproven, fragments
    /// the subject's footprint, and which lone relationship is load-bearing?*
    ///
    /// Returns `(articulation_points, bridges)`: the cut-vertex node indices in
    /// ascending order, and the bridge edges as `(min, max)` index pairs in ascending
    /// order. Both are deterministic and independent of input order (the [`Graph`]
    /// already canonicalises node and neighbour ordering).
    ///
    /// Single exact Hopcroft–Tarjan low-link pass, O(V+E), handling a disconnected
    /// graph (every component is rooted in turn). The depth-first search is **iterative**
    /// — an explicit frame stack with explicit visited state (`disc`), never native
    /// recursion — so a long path can never overflow the stack on a low-RAM Termux
    /// device. Because [`Graph::build`] yields a simple graph (parallel edges collapsed,
    /// self-loops dropped), the "skip the one edge back to the DFS parent" rule is sound.
    #[must_use]
    pub fn cut_vertices_and_bridges(&self) -> (Vec<usize>, Vec<(usize, usize)>) {
        let n = self.uids.len();
        let mut disc = vec![0usize; n]; // discovery time; 0 marks "unvisited"
        let mut low = vec![0usize; n]; // lowest discovery time reachable via back edges
        let mut is_cut = vec![false; n];
        let mut bridges: Vec<(usize, usize)> = Vec::new();
        let mut timer = 0usize;

        for start in 0..n {
            if disc[start] != 0 {
                continue; // already covered by an earlier component's DFS
            }
            // Iterative DFS from this component's root. Each frame is
            // `(node, parent, neighbour-cursor)`; the root's parent is `usize::MAX`.
            timer += 1;
            disc[start] = timer;
            low[start] = timer;
            let mut root_children = 0usize;
            let mut stack: Vec<(usize, usize, usize)> = vec![(start, usize::MAX, 0)];

            while let Some(&(u, parent, ci)) = stack.last() {
                if ci < self.adj[u].len() {
                    let v = self.adj[u][ci];
                    stack.last_mut().unwrap().2 = ci + 1; // advance past v
                    if disc[v] == 0 {
                        // Tree edge u→v: descend.
                        if parent == usize::MAX {
                            root_children += 1; // a fresh DFS-tree child of the root
                        }
                        timer += 1;
                        disc[v] = timer;
                        low[v] = timer;
                        stack.push((v, u, 0));
                    } else if v != parent {
                        // Back edge u→v: tighten u's low-link to v's discovery time.
                        low[u] = low[u].min(disc[v]);
                    }
                } else {
                    // u is finished: fold its low-link into its parent, then test the
                    // parent edge for the articulation / bridge conditions.
                    stack.pop();
                    if parent != usize::MAX {
                        low[parent] = low[parent].min(low[u]);
                        // A non-root parent is a cut vertex when u's subtree cannot
                        // reach strictly above the parent (no back edge past it).
                        if parent != start && low[u] >= disc[parent] {
                            is_cut[parent] = true;
                        }
                        // The parent edge is a bridge when u's subtree has no back edge
                        // to the parent or above it at all.
                        if low[u] > disc[parent] {
                            let e = if parent < u { (parent, u) } else { (u, parent) };
                            bridges.push(e);
                        }
                    }
                }
            }
            // The root is a cut vertex iff it has more than one DFS-tree child.
            if root_children > 1 {
                is_cut[start] = true;
            }
        }

        let articulation_points: Vec<usize> = (0..n).filter(|&i| is_cut[i]).collect();
        bridges.sort_unstable();
        (articulation_points, bridges)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
