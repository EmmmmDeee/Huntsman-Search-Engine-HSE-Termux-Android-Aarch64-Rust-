//! `core::pivot` — pivot-node detection: the high-connectivity INTERMEDIARIES that
//! bridge a scan's relationship graph.
//!
//! A pivot is a node many connections route THROUGH — a shared address two families
//! both touch, a registrant email half a dozen domains share, a phone that bridges
//! otherwise-separate identities. Surfacing them is what makes graph traversal
//! efficient: expanding a pivot reaches the most of the graph for the least work, and
//! it tells the analyst which single entity, if confirmed or removed, most changes the
//! picture. It is a distinct axis from the engine's other graph analytics —
//! [`crate::core::trust`] propagates CONFIDENCE from anchors and
//! [`crate::core::community`] CLUSTERS, while this is pure STRUCTURE: how central a
//! node is to the graph's connectivity, regardless of its confidence.
//!
//! Two complementary measures, both computed here:
//!   * **degree** — direct connections (a hub);
//!   * **betweenness** — the fraction of all shortest paths that pass through the node
//!     (a bridge), via Brandes' exact algorithm.
//!
//! Pure over `(entities, relations)`: deterministic, read-only, and bounded
//! ([`MAX_BETWEENNESS_NODES`]) so the O(V·E) betweenness can't run away on a low-RAM
//! Termux device — above the bound it ranks on degree alone.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::Serialize;

use crate::core::entity::Entity;
use crate::core::relation::Relation;

/// Above this node count the exact betweenness (Brandes, O(V·E)) is skipped and pivots
/// rank on degree alone — keeps a pathological graph bounded on a low-RAM device. An
/// OSINT scan's graph is far smaller, so this rarely bites; it just caps the worst case.
pub const MAX_BETWEENNESS_NODES: usize = 1500;

/// Max pivots returned — a focused shortlist of the graph's key intermediaries.
const PIVOT_CAP: usize = 25;

/// A pivot node: a high-connectivity intermediary in the relationship graph, with the
/// two structural measures that define it and a combined ranking score.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PivotNode {
    pub uid: String,
    /// Direct connections (degree centrality).
    pub degree: usize,
    /// Fraction of all shortest paths that route THROUGH this node (betweenness
    /// centrality, normalised to `[0, 1]`); `0.0` when the graph exceeded
    /// [`MAX_BETWEENNESS_NODES`] and only degree was computed.
    pub betweenness: f64,
    /// Combined pivot score in `[0, 1]` — how much of a bridging intermediary the node
    /// is (betweenness-weighted, with degree as the secondary hub signal).
    pub score: f64,
}

/// Detect the pivot nodes — the high-connectivity intermediaries — of a scan's
/// relationship graph, ranked most-central first.
///
/// Builds the undirected graph over present entities (parallel edges and self-loops
/// collapsed), then scores each connected node by Brandes betweenness (the bridge
/// measure, weighted 0.7) and normalised degree (the hub measure, 0.3). Isolated nodes
/// (degree 0) are omitted — they pivot nothing. Deterministic (sorted node and
/// neighbour order), bounded ([`MAX_BETWEENNESS_NODES`] / [`PIVOT_CAP`]), read-only.
#[must_use]
pub fn detect(entities: &[Entity], relations: &[Relation]) -> Vec<PivotNode> {
    // Node set = present entities, indexed in sorted-UID order for determinism.
    let present: HashSet<&str> = entities.iter().map(|e| e.uid.as_str()).collect();
    let mut uids: Vec<&str> = present.iter().copied().collect();
    uids.sort_unstable();
    let n = uids.len();
    if n == 0 {
        return Vec::new();
    }
    let index: HashMap<&str, usize> = uids.iter().enumerate().map(|(i, &u)| (u, i)).collect();

    // Undirected adjacency over edges whose BOTH endpoints are present; collapse
    // parallel edges and skip self-loops so a node's degree is its distinct neighbours.
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut seen: HashSet<(usize, usize)> = HashSet::new();
    for r in relations {
        let (Some(&a), Some(&b)) = (index.get(r.from_uid.as_str()), index.get(r.to_uid.as_str()))
        else {
            continue;
        };
        if a == b {
            continue;
        }
        let key = if a < b { (a, b) } else { (b, a) };
        if seen.insert(key) {
            adj[a].push(b);
            adj[b].push(a);
        }
    }
    for neighbours in &mut adj {
        neighbours.sort_unstable();
    }

    let degree: Vec<usize> = adj.iter().map(Vec::len).collect();
    let betweenness = if n <= MAX_BETWEENNESS_NODES {
        brandes_betweenness(&adj)
    } else {
        vec![0.0; n]
    };

    // Combine: betweenness (the bridge) dominates, degree (the hub) is secondary; when
    // betweenness was skipped, degree carries the whole score.
    let max_degree = n.saturating_sub(1).max(1) as f64;
    let mut pivots: Vec<PivotNode> = (0..n)
        .filter(|&i| degree[i] > 0)
        .map(|i| {
            let norm_degree = degree[i] as f64 / max_degree;
            let score = (0.7 * betweenness[i] + 0.3 * norm_degree).clamp(0.0, 1.0);
            PivotNode {
                uid: uids[i].to_string(),
                degree: degree[i],
                betweenness: betweenness[i],
                score,
            }
        })
        .collect();
    pivots.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| b.degree.cmp(&a.degree))
            .then_with(|| a.uid.cmp(&b.uid))
    });
    pivots.truncate(PIVOT_CAP);
    pivots
}

/// Brandes' exact betweenness centrality for an unweighted UNDIRECTED graph, normalised
/// to `[0, 1]` by the maximum possible value `(n-1)(n-2)/2`. Deterministic (the caller
/// sorts each node's neighbours). O(V·E) time, O(V) working space per source — the
/// standard accumulation: a forward BFS counts shortest-path multiplicities, a reverse
/// pass over the BFS stack accumulates each node's dependency.
fn brandes_betweenness(adj: &[Vec<usize>]) -> Vec<f64> {
    let n = adj.len();
    let mut bc = vec![0.0f64; n];
    for s in 0..n {
        let mut stack: Vec<usize> = Vec::new();
        let mut pred: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut sigma = vec![0.0f64; n];
        sigma[s] = 1.0;
        let mut dist = vec![-1i64; n];
        dist[s] = 0;
        let mut queue: VecDeque<usize> = VecDeque::new();
        queue.push_back(s);
        while let Some(v) = queue.pop_front() {
            stack.push(v);
            for &w in &adj[v] {
                if dist[w] < 0 {
                    dist[w] = dist[v] + 1;
                    queue.push_back(w);
                }
                if dist[w] == dist[v] + 1 {
                    sigma[w] += sigma[v];
                    pred[w].push(v);
                }
            }
        }
        let mut delta = vec![0.0f64; n];
        while let Some(w) = stack.pop() {
            for &v in &pred[w] {
                delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w]);
            }
            if w != s {
                bc[w] += delta[w];
            }
        }
    }
    // Undirected: every shortest path is counted from both ends → halve.
    for x in &mut bc {
        *x /= 2.0;
    }
    // Normalise to [0, 1] by the maximum possible betweenness of an undirected graph.
    if n > 2 {
        let norm = ((n - 1) * (n - 2)) as f64 / 2.0;
        for x in &mut bc {
            *x /= norm;
        }
    }
    bc
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
