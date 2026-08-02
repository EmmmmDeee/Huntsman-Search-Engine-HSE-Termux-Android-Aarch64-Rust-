//! `core::path` — connection-path discovery between entities over the relation graph.
//!
//! The universal "how are A and B connected?" capability. Given the entities and
//! relations a scan accumulated — a recursive expansion outward from one seed — this
//! finds the shortest chain of relationships linking two target entities, and, for
//! richer analysis, several DISTINCT alternative chains. It is link analysis: the
//! degrees of separation between two nodes, the backbone of relationship-discovery
//! and network-analysis investigations. It is universal — it works for ANY pair of
//! entities in ANY scan, not a fixed case.
//!
//! Division of labour: the scan engine RECURSES from a seed and BUILDS the graph
//! (each expansion round adds nodes and edges), while this module READS that graph
//! and traverses it. A path that does not exist at depth 1 appears once depth 2/3
//! has drawn in the intermediary that bridges the two targets — so "keep expanding
//! until a link is found" is the recursion feeding an ever-larger graph for these
//! pure, deterministic queries to resolve over.
//!
//! Resolution by value ([`resolve_value`]) lets a caller ask for `"Kyle Diegmann"` →
//! `"Erik Diegmann"` without knowing UIDs; [`connect_values`] does the whole job
//! end to end. Pure over the scan's [`Entity`] and [`Relation`] sets: deterministic,
//! read-only, and bounded ([`MAX_HOPS`]) for a low-RAM Termux device.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::Serialize;

use crate::core::entity::Entity;
use crate::core::port::StoragePort;
use crate::core::relation::Relation;

/// Hard cap on path length (degrees of separation) explored. Six is the classic
/// small-world bound and keeps the breadth-first search cheap on Termux; a genuine
/// OSINT link is almost always far shorter. A pair separated by more than this is
/// reported as having no connection (within this graph).
pub const MAX_HOPS: usize = 6;

/// Default number of distinct alternative pathways [`paths_between`] /
/// [`connect_values`] return — enough to show the strongest link plus a couple of
/// independent corroborating routes, without flooding a phone screen.
pub const DEFAULT_MAX_PATHS: usize = 3;

/// One relationship step along a connection path.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PathEdge {
    pub from_uid: String,
    pub to_uid: String,
    /// Relation kind in its original `from_uid -> to_uid` derivation direction. The
    /// edge is TRAVERSED undirected (a relationship connects both ways), but the
    /// kind is reported in the direction the scan actually derived it.
    pub kind: String,
    pub confidence: f64,
}

/// A discovered connection between two entities: the ordered chain of nodes and the
/// relationship edges between them.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConnectionPath {
    /// Ordered entity UIDs from source to target (length = `hops + 1`).
    pub nodes: Vec<String>,
    /// The edges between consecutive nodes (length = `hops`).
    pub edges: Vec<PathEdge>,
    /// Number of relationship hops — the degrees of separation.
    pub hops: usize,
    /// Path reliability = the WEAKEST edge confidence along it; a chain is only as
    /// strong as its weakest link. `1.0` for the trivial zero-hop self-path.
    pub strength: f64,
}

/// Build the UNDIRECTED adjacency `uid -> [(neighbour_uid, edge)]` over only the
/// relations whose BOTH endpoints are present in the graph (a dangling edge connects
/// nothing); self-loops are skipped. Neighbour lists are sorted (uid, kind,
/// confidence) so the breadth-first search is fully deterministic.
fn build_adjacency(
    present: &HashSet<&str>,
    relations: &[Relation],
) -> HashMap<String, Vec<(String, PathEdge)>> {
    let mut adj: HashMap<String, Vec<(String, PathEdge)>> = HashMap::new();
    for r in relations {
        if r.from_uid == r.to_uid
            || !present.contains(r.from_uid.as_str())
            || !present.contains(r.to_uid.as_str())
        {
            continue;
        }
        let edge = PathEdge {
            from_uid: r.from_uid.clone(),
            to_uid: r.to_uid.clone(),
            kind: r.kind.as_str().to_string(),
            confidence: r.confidence,
        };
        adj.entry(r.from_uid.clone())
            .or_default()
            .push((r.to_uid.clone(), edge.clone()));
        adj.entry(r.to_uid.clone())
            .or_default()
            .push((r.from_uid.clone(), edge));
    }
    for neighbours in adj.values_mut() {
        neighbours.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.kind.cmp(&b.1.kind))
                .then_with(|| b.1.confidence.total_cmp(&a.1.confidence))
        });
    }
    adj
}

/// Canonical key for an UNDIRECTED edge — the two endpoint UIDs sorted — so a
/// traversed edge can be blocked regardless of the direction it is walked.
fn edge_key(a: &str, b: &str) -> (String, String) {
    if a <= b {
        (a.to_string(), b.to_string())
    } else {
        (b.to_string(), a.to_string())
    }
}

/// Breadth-first shortest path from `from` to `to` over `adj`, never traversing any
/// edge in `blocked` (used by [`paths_between`] to find EDGE-DISJOINT alternatives —
/// a genuinely different route, even one that reuses a node). Deterministic (sorted
/// adjacency, first-discovered predecessor wins) and bounded to [`MAX_HOPS`]. `None`
/// if unreachable within the bound.
fn bfs_path(
    adj: &HashMap<String, Vec<(String, PathEdge)>>,
    from: &str,
    to: &str,
    blocked: &HashSet<(String, String)>,
) -> Option<ConnectionPath> {
    if from == to {
        return Some(ConnectionPath {
            nodes: vec![from.to_string()],
            edges: Vec::new(),
            hops: 0,
            strength: 1.0,
        });
    }
    // node -> (predecessor node, the edge taken to reach it).
    let mut prev: HashMap<String, (String, PathEdge)> = HashMap::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    visited.insert(from.to_string());
    queue.push_back((from.to_string(), 0));
    while let Some((cur, depth)) = queue.pop_front() {
        if depth >= MAX_HOPS {
            continue;
        }
        let Some(neighbours) = adj.get(&cur) else {
            continue;
        };
        for (nb, edge) in neighbours {
            if visited.contains(nb) || blocked.contains(&edge_key(&cur, nb)) {
                continue;
            }
            visited.insert(nb.clone());
            prev.insert(nb.clone(), (cur.clone(), edge.clone()));
            if nb == to {
                return Some(reconstruct(from, to, &prev));
            }
            queue.push_back((nb.clone(), depth + 1));
        }
    }
    None
}

/// Insert every edge of `path` into `blocked`, so a subsequent [`bfs_path`] must
/// find an EDGE-DISJOINT route. No-op for a zero-hop self-path.
fn block_path_edges(path: &ConnectionPath, blocked: &mut HashSet<(String, String)>) {
    for pair in path.nodes.windows(2) {
        blocked.insert(edge_key(&pair[0], &pair[1]));
    }
}

/// Walk the predecessor map back from `to` to `from` into an ordered
/// [`ConnectionPath`]. Only called once `to` is reached, so every step resolves.
fn reconstruct(from: &str, to: &str, prev: &HashMap<String, (String, PathEdge)>) -> ConnectionPath {
    let mut nodes_rev: Vec<String> = vec![to.to_string()];
    let mut edges_rev: Vec<PathEdge> = Vec::new();
    let mut cur = to.to_string();
    while cur != from {
        let (p, edge) = &prev[&cur];
        edges_rev.push(edge.clone());
        nodes_rev.push(p.clone());
        cur = p.clone();
    }
    nodes_rev.reverse();
    edges_rev.reverse();
    let strength = edges_rev
        .iter()
        .map(|e| e.confidence)
        .fold(1.0_f64, f64::min);
    ConnectionPath {
        hops: edges_rev.len(),
        nodes: nodes_rev,
        edges: edges_rev,
        strength,
    }
}

/// The set of UIDs actually present in the entity slice — the graph's node set.
fn present_uids(entities: &[Entity]) -> HashSet<&str> {
    entities.iter().map(|e| e.uid.as_str()).collect()
}

/// Up to `max_paths` DISTINCT connection pathways between two UIDs, shortest first.
/// Each successive path is forced to route around the previous paths' edges
/// (edge-disjoint), so the result is genuinely diverse routes — the multiple
/// analytical pathways a corroborating investigation wants — not trivial reorderings
/// of one chain. Deterministic and bounded. Empty if unconnected or an endpoint is
/// absent.
#[must_use]
pub fn paths_between(
    entities: &[Entity],
    relations: &[Relation],
    from_uid: &str,
    to_uid: &str,
    max_paths: usize,
) -> Vec<ConnectionPath> {
    let present = present_uids(entities);
    if max_paths == 0 || !present.contains(from_uid) || !present.contains(to_uid) {
        return Vec::new();
    }
    let adj = build_adjacency(&present, relations);
    let mut out: Vec<ConnectionPath> = Vec::new();
    let mut blocked: HashSet<(String, String)> = HashSet::new();
    for _ in 0..max_paths {
        let Some(path) = bfs_path(&adj, from_uid, to_uid, &blocked) else {
            break;
        };
        let trivial = path.hops == 0;
        block_path_edges(&path, &mut blocked);
        out.push(path);
        // A zero-hop self-path (from == to) has no edge to block, so there is no
        // second route — stop rather than loop emitting the same node.
        if trivial {
            break;
        }
    }
    out
}

/// Resolve a human-supplied value (e.g. `"Erik Diegmann"`) to the candidate entity
/// UIDs it names — a case-insensitive match against each entity's normalised
/// `value` and original `raw_value`. Returns every match (usually one), sorted and
/// deduplicated, so a caller can connect by value without knowing UIDs.
#[must_use]
pub fn resolve_value(entities: &[Entity], value: &str) -> Vec<String> {
    let needle = value.trim();
    if needle.is_empty() {
        return Vec::new();
    }
    let lower = needle.to_lowercase();
    let mut hits: Vec<String> = entities
        .iter()
        .filter(|e| e.value.to_lowercase() == lower || e.raw_value.to_lowercase() == lower)
        .map(|e| e.uid.clone())
        .collect();
    hits.sort_unstable();
    hits.dedup();
    hits
}

/// Connect two VALUES end to end: resolve each to its entity UID(s), find up to
/// `max_paths` distinct pathways between them, and return them ranked by fewest hops,
/// then strongest weakest-link, then node order. Handles a value that resolves to
/// several entities by trying each candidate pair (bounded) and keeping the best
/// distinct paths. Empty if either value is unknown or they are unconnected.
#[must_use]
pub fn connect_values(
    entities: &[Entity],
    relations: &[Relation],
    from_value: &str,
    to_value: &str,
    max_paths: usize,
) -> Vec<ConnectionPath> {
    if max_paths == 0 {
        return Vec::new();
    }
    let froms = resolve_value(entities, from_value);
    let tos = resolve_value(entities, to_value);
    if froms.is_empty() || tos.is_empty() {
        return Vec::new();
    }
    let present = present_uids(entities);
    let adj = build_adjacency(&present, relations);
    // Bound the candidate fan-out so an ambiguous value can't blow up the work.
    let mut all: Vec<ConnectionPath> = Vec::new();
    for f in froms.iter().take(5) {
        for t in tos.iter().take(5) {
            if f == t {
                continue;
            }
            let mut blocked: HashSet<(String, String)> = HashSet::new();
            for _ in 0..max_paths {
                let Some(path) = bfs_path(&adj, f, t, &blocked) else {
                    break;
                };
                block_path_edges(&path, &mut blocked);
                all.push(path);
            }
        }
    }
    // Rank: fewest hops, then strongest weakest-link, then node sequence (stable);
    // drop duplicate routes that distinct candidate pairs may have produced.
    all.sort_by(|a, b| {
        a.hops
            .cmp(&b.hops)
            .then_with(|| b.strength.total_cmp(&a.strength))
            .then_with(|| a.nodes.cmp(&b.nodes))
    });
    all.dedup_by(|a, b| a.nodes == b.nodes);
    all.truncate(max_paths);
    all
}

/// Max bridging scans loaded when expanding a connection query across the local
/// intelligence database — bounds the store reads so a value shared by many scans
/// can't pull the whole database into memory on a Termux device.
pub const CROSS_SCAN_MAX_SCANS: usize = 12;

/// Hard cap on the merged cross-scan graph's entity count; once reached no more scans
/// are pulled in, keeping the breadth-first search and adjacency bounded.
const CROSS_SCAN_MAX_ENTITIES: usize = 4000;

/// Max entity UIDs a single endpoint VALUE resolves to (a value that names several
/// entities) — bounds the endpoint-pair fan-out.
const CROSS_SCAN_ENDPOINT_CANDIDATES: usize = 5;

/// Resolve a value to the entity UIDs it names ANYWHERE in the store — an exact
/// (case-insensitive) match over the indexed search, deduped, sorted, and bounded.
/// The cross-scan analog of [`resolve_value`]: it reaches entities in OTHER scans, not
/// just a slice already in hand.
fn resolve_across(store: &dyn StoragePort, value: &str, cap: usize) -> Vec<String> {
    let needle = value.trim();
    if needle.is_empty() {
        return Vec::new();
    }
    let lower = needle.to_lowercase();
    let Ok(hits) = store.search_entities(needle, cap.saturating_mul(8)) else {
        return Vec::new();
    };
    let mut uids: Vec<String> = hits
        .into_iter()
        .filter(|e| e.value.to_lowercase() == lower || e.raw_value.to_lowercase() == lower)
        .map(|e| e.uid)
        .collect();
    uids.sort_unstable();
    uids.dedup();
    uids.truncate(cap);
    uids
}

/// Connect two values across the WHOLE local intelligence database, not just one scan:
/// resolve each endpoint to its entity anywhere in the store, pull in the bounded set
/// of scans that recorded either endpoint, merge their entities and relations into one
/// graph, and find the connection path(s) over it. This is how a seed reaches an entity
/// discovered in a SEPARATE investigation — the cross-scan culmination of the historical
/// flywheel, so connection discovery spans every scan, not the current one alone.
///
/// Store-driven but strictly bounded ([`CROSS_SCAN_MAX_SCANS`] /
/// [`CROSS_SCAN_MAX_ENTITIES`]) and store-error-tolerant (a failed query is skipped,
/// never propagated), so it is safe on a low-RAM Termux device. The traversal itself is
/// the same pure, deterministic, [`MAX_HOPS`]-bounded breadth-first search as
/// [`connect_values`] — only the graph it runs over is wider. Empty if either endpoint
/// is unknown or they are unconnected across the loaded scans.
#[must_use]
pub fn connect_cross_scan(
    store: &dyn StoragePort,
    from_value: &str,
    to_value: &str,
    max_paths: usize,
) -> Vec<ConnectionPath> {
    if max_paths == 0 {
        return Vec::new();
    }
    let from_uids = resolve_across(store, from_value, CROSS_SCAN_ENDPOINT_CANDIDATES);
    let to_uids = resolve_across(store, to_value, CROSS_SCAN_ENDPOINT_CANDIDATES);
    if from_uids.is_empty() || to_uids.is_empty() {
        return Vec::new();
    }

    // Bounded set of scans that recorded either endpoint — the bridging neighbourhood.
    let mut scan_ids: Vec<String> = Vec::new();
    let mut seen_scans: HashSet<String> = HashSet::new();
    for uid in from_uids.iter().chain(to_uids.iter()) {
        let Ok(ids) = store.scan_ids_for_entity(uid) else {
            continue;
        };
        for sid in ids {
            if seen_scans.insert(sid.clone()) {
                scan_ids.push(sid);
            }
        }
    }
    scan_ids.sort();
    scan_ids.truncate(CROSS_SCAN_MAX_SCANS);

    // Merge the bridging scans into one graph, deduped by uid / relation id, bounded.
    let mut entities: HashMap<String, Entity> = HashMap::new();
    let mut relations: HashMap<String, Relation> = HashMap::new();
    for sid in &scan_ids {
        if let Ok(ents) = store.entities_for_scan(sid) {
            for e in ents {
                entities.entry(e.uid.clone()).or_insert(e);
            }
        }
        if let Ok(rels) = store.relations_for_scan(sid) {
            for r in rels {
                relations.entry(r.id.clone()).or_insert(r);
            }
        }
        if entities.len() >= CROSS_SCAN_MAX_ENTITIES {
            break;
        }
    }

    // Deterministic merged graph (sorted), then the pure BFS over the wider graph.
    let mut merged_entities: Vec<Entity> = entities.into_values().collect();
    merged_entities.sort_by(|a, b| a.uid.cmp(&b.uid));
    let mut merged_relations: Vec<Relation> = relations.into_values().collect();
    merged_relations.sort_by(|a, b| a.id.cmp(&b.id));

    let mut all: Vec<ConnectionPath> = Vec::new();
    for fu in &from_uids {
        for tu in &to_uids {
            if fu != tu {
                all.extend(paths_between(
                    &merged_entities,
                    &merged_relations,
                    fu,
                    tu,
                    max_paths,
                ));
            }
        }
    }
    all.sort_by(|a, b| {
        a.hops
            .cmp(&b.hops)
            .then_with(|| b.strength.total_cmp(&a.strength))
            .then_with(|| a.nodes.cmp(&b.nodes))
    });
    all.dedup_by(|a, b| a.nodes == b.nodes);
    all.truncate(max_paths);
    all
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
