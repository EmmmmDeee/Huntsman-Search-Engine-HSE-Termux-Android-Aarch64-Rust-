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
    ///
    /// **Distinct by design from
    /// [`crate::core::relation::graph::connection_brokers`].** This is the
    /// *unweighted, structural* articulation set over the full entity graph — every
    /// edge counts equally — feeding the analytics surfaces (pivot scoring, the
    /// benchmark). `connection_brokers` is the *confidence-floored, identity-framed*
    /// view used by the correlator (AU-068/AU-070) and the dossier, where a
    /// `min_confidence` floor stops one weak edge making a common-name node look like
    /// the linchpin of dozens of unrelated namesakes. The two deliberately answer
    /// different questions — pure topology vs binding-at-confidence — so a node can be
    /// a structural cut vertex here yet not a broker there; that is expected, not a
    /// discrepancy. They are kept separate on purpose (do not "unify" by dropping the
    /// floor — that reintroduces the namesake-linchpin false positive the floor exists
    /// to prevent).
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
                    stack.last_mut().expect("should succeed").2 = ci + 1; // advance past v
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

    /// Each node's **coreness** (core number): the largest `k` for which the node belongs
    /// to a `k`-core — the maximal subgraph in which *every* node has at least `k`
    /// neighbours that are themselves in the subgraph.
    ///
    /// Coreness is the **embeddedness / robustness** axis of the graph, the exact
    /// structural *complement* to the fragility that
    /// [`cut_vertices_and_bridges`](Graph::cut_vertices_and_bridges) and
    /// [`crate::core::pivot`]'s betweenness measure. A bridge/cut-vertex/high-betweenness
    /// node is *load-bearing because it is the only route* — disprove it and the footprint
    /// fragments. A high-coreness node is the opposite: it sits inside a densely,
    /// *redundantly* interconnected cluster where many independent paths reinforce one
    /// another, so it survives the loss of any single link. For an OSINT footprint the two
    /// answer different questions an analyst must keep apart — *which entity is a fragile
    /// single point of failure?* (low coreness, often a cut vertex) versus *which entities
    /// form the cohesive, mutually-corroborated core that holds together no matter which
    /// one link you doubt?* (high coreness). A hub-in-a-tree (a star centre) has high
    /// degree yet coreness 1; a member of a 4-clique has coreness 3. Degree and
    /// betweenness cannot tell those apart — coreness can.
    ///
    /// Returns a vector of length [`node_count`](Graph::node_count) indexed by node, so
    /// `coreness()[i]` is node `i`'s core number. An isolated node (degree 0) has coreness
    /// `0`; an empty graph yields an empty vector.
    ///
    /// # Algorithm — Batagelj–Zaversnik bucket peeling, O(V+E)
    /// Repeatedly remove a node of minimum *current* degree; a node's coreness is its
    /// degree at the instant it is removed. The classic linear-time realisation (Batagelj
    /// & Zaversnik, 2003) keeps the nodes bucket-sorted by current degree in a flat array
    /// and, on each removal, decrements each still-present higher-degree neighbour by
    /// sliding it one bucket down in O(1) — so the whole decomposition is a single O(V+E)
    /// sweep with O(V) integer working arrays, **no recursion** and no allocation inside
    /// the peel loop. That keeps it cheap and stack-safe on a low-RAM, no-root Termux
    /// aarch64 device, in the same spirit as the iterative Hopcroft–Tarjan pass above.
    ///
    /// # Determinism
    /// The coreness of a node is a graph **invariant** — it does not depend on the order
    /// equal-degree ties are peeled in — so the result is reproducible by construction,
    /// independent of the order entities/relations were supplied in (the [`Graph`] already
    /// canonicalises node and neighbour ordering). The bucket sort below is itself stable
    /// in ascending-UID (index) order, so even the transient internal state is fixed.
    #[must_use]
    pub fn coreness(&self) -> Vec<usize> {
        let n = self.uids.len();
        if n == 0 {
            return Vec::new();
        }

        // `deg[v]` is v's *current* degree — it starts at the full degree and is
        // decremented as neighbours are peeled. Its value at v's own removal is v's core.
        let mut deg: Vec<usize> = (0..n).map(|i| self.adj[i].len()).collect();
        let max_deg = deg.iter().copied().max().unwrap_or(0);

        // Bucket-sort the nodes by degree. `bin[d]` becomes the start index, in the
        // degree-sorted `vert` array, of the block of nodes whose current degree is `d`.
        let mut bin = vec![0usize; max_deg + 1];
        for &d in &deg {
            bin[d] += 1;
        }
        let mut start = 0usize;
        for slot in &mut bin {
            let count = *slot;
            *slot = start;
            start += count;
        }
        // `vert` lists nodes in ascending-degree order; `pos[v]` is v's index within it.
        // Filled in ascending node order within each degree block, so ties are ordered by
        // node index (ascending UID) — fixing the transient layout deterministically.
        let mut vert = vec![0usize; n];
        let mut pos = vec![0usize; n];
        {
            let mut cursor = bin.clone();
            for (v, &d) in deg.iter().enumerate() {
                let p = cursor[d];
                vert[p] = v;
                pos[v] = p;
                cursor[d] += 1;
            }
        }

        // Peel in ascending-degree order. When `v` is removed its core number is fixed at
        // its current degree; each still-present neighbour with a strictly higher current
        // degree loses one degree, realised by sliding it to the front of its degree block
        // (a single swap) and shrinking that block — the O(1) Batagelj–Zaversnik update.
        // An already-peeled neighbour `u` has `deg[u] ≤ deg[v]` (it was removed no later),
        // so the `>` guard skips it without a separate "removed" flag.
        let mut core = vec![0usize; n];
        for i in 0..n {
            let v = vert[i];
            core[v] = deg[v];
            for &u in &self.adj[v] {
                if deg[u] > deg[v] {
                    let du = deg[u];
                    let pu = pos[u];
                    let pw = bin[du]; // first position of u's current degree block
                    let w = vert[pw]; // node at that block start
                    if u != w {
                        // Swap u to the front of its block (positions pu ↔ pw).
                        vert[pu] = w;
                        vert[pw] = u;
                        pos[u] = pw;
                        pos[w] = pu;
                    }
                    bin[du] += 1; // the degree-du block now starts one later
                    deg[u] -= 1; // u drops into the degree-(du-1) block it now heads
                }
            }
        }
        core
    }

    /// The graph's **degeneracy**: the largest `k` for which a non-empty `k`-core exists,
    /// equivalently `max` over every node's [`coreness`](Graph::coreness) (`0` for an empty
    /// or edgeless graph).
    ///
    /// A single-number measure of how cohesive the whole footprint is: degeneracy `1` is a
    /// tree/forest (no redundant structure), `2` means every core node sits on a cycle, and
    /// a degeneracy-`k` graph contains a subgraph where everyone has `k`+ mutually
    /// reinforcing links. It is the headline companion to the per-node coreness and to the
    /// fragility counts (cut vertices / bridges) — high degeneracy says the footprint has a
    /// densely corroborated heart, not just a sprawl of one-off leads. O(V+E).
    #[must_use]
    pub fn degeneracy(&self) -> usize {
        self.coreness().into_iter().max().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
