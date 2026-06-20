//! Graph analysis over the relation edge set — the canonical adjacency,
//! reachability, and shortest-path primitives the whole system shares.
//!
//! The relation layer ([`super`]) produces typed edges; this module is the one
//! place that turns them into a traversable graph. It owns:
//!   - [`undirected_adjacency`] — the single both-directions adjacency builder
//!     (the subject-network view and the path finder used to keep private copies;
//!     now they share one, so they cannot drift — `Rule 4`, "delegate, never
//!     copy");
//!   - [`reachable_count`] — connected-component size from a node;
//!   - [`identity_paths`] — the graph-free link-analysis finder behind both the
//!     dossier's CONNECTIONS section and the AU-060 transitive-identity rule:
//!     instead of handing the operator a canvas to pivot by hand (Maltego), it
//!     computes the *thread* — the ordered chain of typed edges that ties one
//!     identity to another — and delivers it as a reproducible conclusion.
//!
//! # Determinism (architecture invariant)
//! Pure BFS over a value-derived edge set. Adjacency lists are sorted by
//! `(neighbour UID, kind, confidence)`, so a node's first-visited edge to a
//! given neighbour is always its lexicographically-smallest-kind edge (parallel
//! edges collapse to a stable label), and every identity pair is computed once
//! from its smaller-UID endpoint — so the same entity + relation set always
//! yields the byte-identical path set, independent of input order. Guarded by
//! `identity_paths_is_order_independent` in the sibling test module.

use std::collections::{HashMap, HashSet, VecDeque};

use super::{Relation, RelationKind};
use crate::core::entity::{Entity, EntityKind};

/// The relation graph as an undirected adjacency list: each node UID maps to its
/// incident `(neighbour UID, edge kind, edge confidence)` edges. Borrows from the
/// `relations`/`entities` it is built from (see [`undirected_adjacency`]).
pub type Adjacency<'a> = HashMap<&'a str, Vec<(&'a str, RelationKind, f64)>>;

/// One hop on a connection path: the typed edge traversed and the entity it
/// reaches. The first step leaves the path's `from_uid`; the last step's
/// `to_uid` is the path's `to_uid`.
#[derive(Debug, Clone, PartialEq)]
pub struct PathStep {
    pub kind: RelationKind,
    pub to_uid: String,
}

/// The shortest typed chain linking two identity entities through the relation
/// graph. `from_uid` is always the lexicographically-smaller endpoint UID, so a
/// pair appears exactly once with a stable orientation.
#[derive(Debug, Clone, PartialEq)]
pub struct IdentityPath {
    pub from_uid: String,
    pub to_uid: String,
    /// Ordered hops from `from_uid` to `to_uid`; `steps.len() == hops`.
    pub steps: Vec<PathStep>,
    pub hops: usize,
    /// Weakest edge confidence along the path — a chain is only as trustworthy
    /// as its weakest link, so this, not the average, is the headline number.
    pub min_confidence: f64,
}

/// Identity-bearing entity kinds — the nodes a connection path links end to end.
/// Intermediate nodes may be any kind (a domain, an IP, an address); only the
/// two endpoints must be identities. Mirrors the AU-034/AU-060 identity notion.
pub fn is_identity_kind(kind: &EntityKind) -> bool {
    matches!(
        kind,
        EntityKind::Person | EntityKind::Email | EntityKind::Phone | EntityKind::Username
    )
}

/// The sorted, de-duplicated UIDs of the identity-bearing entities ([`is_identity_kind`])
/// in `entities` — the canonical endpoint set every pair-wise link-analysis pass
/// iterates. Sorting fixes a stable orientation (each unordered pair is visited
/// once from its smaller UID) and deterministic tie-breaks. One definition, shared
/// by [`identity_paths`] and the AU-062/AU-063 detectors, so they can't drift on
/// which entities count as identity endpoints.
pub fn identity_uids(entities: &[Entity]) -> Vec<&str> {
    let mut uids: Vec<&str> = entities
        .iter()
        .filter(|e| is_identity_kind(&e.kind))
        .map(|e| e.uid.as_str())
        .collect();
    uids.sort_unstable();
    uids.dedup();
    uids
}

/// Build the undirected adjacency of the relation graph — every edge added in
/// both directions. Self-loops are skipped (they connect nothing). When
/// `confine` is `Some(set)`, only edges whose *both* endpoints are in the set
/// are added (the path / correlation view, which must never traverse a dangling
/// or quarantined node); pass `None` to keep every edge (the subject-network
/// view, which tolerates a dangling endpoint and prunes it at lookup time).
///
/// Per-node edge lists are returned in input order; callers that need a
/// deterministic traversal sort them (see [`identity_paths`]).
pub fn undirected_adjacency<'a>(
    relations: &'a [Relation],
    confine: Option<&HashSet<&'a str>>,
) -> Adjacency<'a> {
    let mut adj: Adjacency<'a> = HashMap::new();
    for r in relations {
        let (a, b) = (r.from_uid.as_str(), r.to_uid.as_str());
        if a == b {
            continue; // a self-loop connects nothing
        }
        if let Some(set) = confine
            && (!set.contains(a) || !set.contains(b))
        {
            continue; // dangling / quarantined endpoint — not traversable
        }
        adj.entry(a).or_default().push((b, r.kind, r.confidence));
        adj.entry(b).or_default().push((a, r.kind, r.confidence));
    }
    adj
}

/// The canonical traversal adjacency: [`undirected_adjacency`] confined to the
/// confirmed entity set and sorted by `(neighbour, kind, confidence)`, so every
/// finder walks the same deterministic graph (a node's first-visited edge to a
/// neighbour is its lexicographically-smallest-kind edge; parallel edges collapse
/// to one stable label).
///
/// Factored so the shortest-path, disjoint-pathway, and widest-path finders share
/// ONE build — and, crucially, so a rule running many pairwise queries can build
/// it **once** and pass it to the `*_in` variants ([`disjoint_pathways_in`],
/// [`strongest_path_in`]) instead of rebuilding and re-sorting it per pair (an
/// O(N²)→O(N) reduction in graph builds on the correlator's hot path).
pub fn sorted_confined_adjacency<'a>(
    entities: &'a [Entity],
    relations: &'a [Relation],
) -> Adjacency<'a> {
    let confirmed: HashSet<&str> = entities.iter().map(|e| e.uid.as_str()).collect();
    let mut adj = undirected_adjacency(relations, Some(&confirmed));
    for v in adj.values_mut() {
        v.sort_by(|x, y| {
            x.0.cmp(y.0)
                .then_with(|| x.1.as_str().cmp(y.1.as_str()))
                .then_with(|| x.2.total_cmp(&y.2))
        });
    }
    adj
}

/// Count the entities reachable from `start` over the undirected graph,
/// excluding `start` itself — the size of its connected component minus one.
pub fn reachable_count<'a>(start: &'a str, adj: &Adjacency<'a>) -> usize {
    let mut seen: HashSet<&str> = HashSet::new();
    seen.insert(start);
    let mut stack = vec![start];
    while let Some(u) = stack.pop() {
        if let Some(neighbours) = adj.get(u) {
            for &(v, _, _) in neighbours {
                if seen.insert(v) {
                    stack.push(v);
                }
            }
        }
    }
    seen.len().saturating_sub(1)
}

/// Compute the shortest typed path between every pair of identity entities that
/// are connected through `1..=max_hops` relation edges.
///
/// Endpoints must both be identities ([`is_identity_kind`]); intermediate nodes
/// may be any kind. Only edges whose *both* endpoints are present in `entities`
/// are traversed — a dangling edge to an unknown UID is ignored, exactly as a
/// post-scan correlation pass must treat an edge to a quarantined node. The
/// graph is treated as undirected (a connection is a connection regardless of
/// which way the edge was recorded).
///
/// The result is sorted deterministically: fewest hops first, then strongest
/// (highest [`IdentityPath::min_confidence`]), then by endpoint UID — so the
/// tightest, most-trustworthy links lead.
pub fn identity_paths(
    entities: &[Entity],
    relations: &[Relation],
    max_hops: usize,
) -> Vec<IdentityPath> {
    if max_hops == 0 {
        return Vec::new();
    }

    // The canonical sorted adjacency, confined to confirmed nodes so a
    // dangling/quarantined edge is never walked (see [`sorted_confined_adjacency`]).
    let adj = sorted_confined_adjacency(entities, relations);

    // Identity endpoints in sorted UID order — each pair is computed once from
    // the smaller UID, fixing both orientation and shortest-path tie-breaks.
    let identity_uids = identity_uids(entities);
    let identity_set: HashSet<&str> = identity_uids.iter().copied().collect();

    let mut out: Vec<IdentityPath> = Vec::new();

    for &start in &identity_uids {
        // BFS from `start`, recording each node's shortest-path predecessor edge.
        let mut dist: HashMap<&str, usize> = HashMap::new();
        let mut prev: HashMap<&str, (&str, RelationKind, f64)> = HashMap::new();
        dist.insert(start, 0);
        let mut queue: VecDeque<&str> = VecDeque::new();
        queue.push_back(start);
        while let Some(u) = queue.pop_front() {
            let d = dist[u];
            if d >= max_hops {
                continue;
            }
            for &(nbr, kind, conf) in adj.get(u).into_iter().flatten() {
                if dist.contains_key(nbr) {
                    continue; // BFS: first visit is the shortest path
                }
                dist.insert(nbr, d + 1);
                prev.insert(nbr, (u, kind, conf));
                queue.push_back(nbr);
            }
        }

        // Emit a path to every identity destination with a *larger* UID (the
        // canonical pair direction), reachable within the hop budget.
        for &dest in &identity_uids {
            if dest <= start || !identity_set.contains(dest) {
                continue;
            }
            let Some(&hops) = dist.get(dest) else {
                continue;
            };
            if hops == 0 {
                continue;
            }
            // Reconstruct dest ← … ← start, then reverse to forward order.
            let mut steps: Vec<PathStep> = Vec::with_capacity(hops);
            let mut min_confidence = f64::INFINITY;
            let mut cur = dest;
            while cur != start {
                let (p, kind, conf) = prev[cur];
                steps.push(PathStep {
                    kind,
                    to_uid: cur.to_string(),
                });
                min_confidence = min_confidence.min(conf);
                cur = p;
            }
            steps.reverse();
            out.push(IdentityPath {
                from_uid: start.to_string(),
                to_uid: dest.to_string(),
                steps,
                hops,
                min_confidence: if min_confidence.is_finite() {
                    min_confidence
                } else {
                    0.0
                },
            });
        }
    }

    out.sort_by(|a, b| {
        a.hops
            .cmp(&b.hops)
            .then(
                b.min_confidence
                    .partial_cmp(&a.min_confidence)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then_with(|| a.from_uid.cmp(&b.from_uid))
            .then_with(|| a.to_uid.cmp(&b.to_uid))
    });
    out
}

/// Up to `max_paths` **edge-disjoint** shortest pathways between two confirmed
/// nodes, each at most `max_hops` long. Found greedily — shortest path, then its
/// traversed adjacencies are removed and the search repeats — so every returned
/// pathway is an *independent route*: it shares no relation edge with another.
///
/// The count is the **corroboration multiplicity**, the heart of cross-pathway
/// linking: the more independent ways one entity reaches another, the more
/// robustly the link is confirmed, and the more angles exist to re-derive it.
/// Deterministic — the adjacency is sorted (fixing each greedy shortest path) and
/// edges are removed by value. Each pathway is a `Vec<PathStep>` leaving
/// `from_uid`; the final step's `to_uid` is `to_uid`.
pub fn disjoint_pathways(
    entities: &[Entity],
    relations: &[Relation],
    from_uid: &str,
    to_uid: &str,
    max_hops: usize,
    max_paths: usize,
) -> Vec<Vec<PathStep>> {
    if from_uid == to_uid || max_hops == 0 || max_paths == 0 {
        return Vec::new();
    }
    let adj = sorted_confined_adjacency(entities, relations);
    disjoint_pathways_in(&adj, from_uid, to_uid, max_hops, max_paths)
}

/// [`disjoint_pathways`] over a **prebuilt** [`sorted_confined_adjacency`] — for a
/// caller running the search across many identity pairs (AU-062 / AU-063), which
/// builds the adjacency once and reuses it here rather than rebuilding it per
/// pair. Each call clones the template internally because the greedy search
/// removes traversed edges to force independent routes; the clone is still far
/// cheaper than a rebuild-and-resort. A node absent from `adj` (unconfirmed /
/// dangling) is simply unreachable, so no separate confirmed-set check is needed.
pub fn disjoint_pathways_in(
    adj: &Adjacency<'_>,
    from_uid: &str,
    to_uid: &str,
    max_hops: usize,
    max_paths: usize,
) -> Vec<Vec<PathStep>> {
    if from_uid == to_uid || max_hops == 0 || max_paths == 0 {
        return Vec::new();
    }
    // A mutable working copy: the greedy search removes each route's edges so the
    // next route must be edge-disjoint.
    let mut adj = adj.clone();

    let mut pathways: Vec<Vec<PathStep>> = Vec::new();
    for _ in 0..max_paths {
        let Some(nodes) = bfs_node_path(&adj, from_uid, to_uid, max_hops) else {
            break;
        };
        let mut steps: Vec<PathStep> = Vec::with_capacity(nodes.len().saturating_sub(1));
        for pair in nodes.windows(2) {
            let (u, v) = (pair[0].as_str(), pair[1].as_str());
            // The smallest-kind edge u→v is the one BFS traversed; record it.
            if let Some(&(_, kind, _)) = adj.get(u).and_then(|es| es.iter().find(|e| e.0 == v)) {
                steps.push(PathStep {
                    kind,
                    to_uid: v.to_string(),
                });
            }
            remove_pair_edges(&mut adj, u, v);
        }
        if steps.is_empty() {
            break;
        }
        pathways.push(steps);
    }
    pathways
}

/// Shortest path (by hop count, ≤ `max_hops`) between `from` and `to` over `adj`,
/// as the ordered node-UID sequence (`from … to`), or `None` if unreachable.
/// Owned-`String` frontier so it composes with the mutable edge removal in
/// [`disjoint_pathways`] without borrow gymnastics; deterministic on a sorted
/// adjacency.
fn bfs_node_path(
    adj: &Adjacency<'_>,
    from: &str,
    to: &str,
    max_hops: usize,
) -> Option<Vec<String>> {
    let mut dist: HashMap<String, usize> = HashMap::new();
    let mut prev: HashMap<String, String> = HashMap::new();
    dist.insert(from.to_string(), 0);
    let mut queue: VecDeque<String> = VecDeque::new();
    queue.push_back(from.to_string());
    while let Some(u) = queue.pop_front() {
        if u == to {
            break;
        }
        let d = dist[&u];
        if d >= max_hops {
            continue;
        }
        for &(nbr, _, _) in adj.get(u.as_str()).into_iter().flatten() {
            if !dist.contains_key(nbr) {
                dist.insert(nbr.to_string(), d + 1);
                prev.insert(nbr.to_string(), u.clone());
                queue.push_back(nbr.to_string());
            }
        }
    }
    dist.get(to)?;
    let mut seq = vec![to.to_string()];
    let mut cur = to.to_string();
    while cur != from {
        let p = prev[&cur].clone();
        seq.push(p.clone());
        cur = p;
    }
    seq.reverse();
    Some(seq)
}

/// Remove every edge between `u` and `v` (both directions) — so a subsequent
/// shortest-path search cannot reuse this connection, forcing an independent route.
fn remove_pair_edges(adj: &mut Adjacency<'_>, u: &str, v: &str) {
    if let Some(es) = adj.get_mut(u) {
        es.retain(|e| e.0 != v);
    }
    if let Some(es) = adj.get_mut(v) {
        es.retain(|e| e.0 != u);
    }
}

/// The **max-bottleneck** ("widest") path between two confirmed nodes within
/// `max_hops` — the route whose WEAKEST edge is as strong as possible.
///
/// Where [`identity_paths`] finds the *shortest* route (fewest hops), this finds
/// the *most trustworthy* one: a connection is only as reliable as its weakest
/// link, so the route that maximises that weakest link is the strongest evidence
/// two nodes are genuinely connected — and it may be longer than the shortest. A
/// superior traversal for connection *quality* (the AU-069 high-integrity rule),
/// complementing the shortest-route rule (AU-060) and the redundancy rule
/// (AU-062). Returns the path with its bottleneck as [`IdentityPath::min_confidence`],
/// or `None` if `to_uid` is unreachable within the hop budget.
///
/// Deterministic: a Bellman-Ford-style relaxation (≤ `max_hops` rounds) over a
/// sorted adjacency, with predecessors for reconstruction. The hops/round cap and
/// the confirmed-node confinement match [`identity_paths`].
pub fn strongest_path(
    entities: &[Entity],
    relations: &[Relation],
    from_uid: &str,
    to_uid: &str,
    max_hops: usize,
) -> Option<IdentityPath> {
    if from_uid == to_uid || max_hops == 0 {
        return None;
    }
    let adj = sorted_confined_adjacency(entities, relations);
    strongest_path_in(&adj, from_uid, to_uid, max_hops)
}

/// [`strongest_path`] over a **prebuilt** [`sorted_confined_adjacency`] — for a
/// caller running the widest-path search across many identity pairs (AU-069),
/// which builds the adjacency once and reuses it here instead of rebuilding it per
/// pair. The relaxation is read-only, so no per-call clone is needed. A node
/// absent from `adj` (unconfirmed / dangling) is simply unreachable.
pub fn strongest_path_in(
    adj: &Adjacency<'_>,
    from_uid: &str,
    to_uid: &str,
    max_hops: usize,
) -> Option<IdentityPath> {
    if from_uid == to_uid || max_hops == 0 {
        return None;
    }

    // ── Phase 1: the max-bottleneck VALUE, hop-bounded ──
    // A max-min Bellman-Ford: after k rounds, `bn[v]` is the widest (greatest
    // weakest-edge) route to `v` using ≤ k edges. Each round relaxes every edge
    // from the PREVIOUS round's snapshot, so the "≤ k edges" invariant holds
    // exactly and the hop budget is honoured. (A naive single-array relaxation
    // that lets a node's hop count grow when its bottleneck improves can trade a
    // shorter route for a wider-but-longer one and then overrun the budget — a
    // real reachability asymmetry the property tests caught.) Max/`min` is
    // commutative, so reading from the snapshot also makes the values
    // order-independent (determinism).
    let mut bn: HashMap<&str, f64> = HashMap::new();
    bn.insert(from_uid, f64::INFINITY);
    for _ in 0..max_hops {
        let mut changed = false;
        let prev: Vec<(&str, f64)> = bn.iter().map(|(&k, &v)| (k, v)).collect();
        for (u, ub) in prev {
            for &(v, _, c) in adj.get(u).into_iter().flatten() {
                let cand = ub.min(c);
                let slot = bn.entry(v).or_insert(f64::NEG_INFINITY);
                if cand > *slot {
                    *slot = cand;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    let bottleneck = bn.get(to_uid).copied().filter(|b| b.is_finite())?;

    // ── Phase 2: reconstruct the SHORTEST route achieving that bottleneck ──
    // BFS over the subgraph of edges at least as wide as `bottleneck`. Such a
    // route exists (the value is achievable) and, since no route within budget is
    // wider, its weakest edge is exactly `bottleneck` — so the reported path's
    // strength matches phase 1 while staying as short as possible.
    let mut wide = adj.clone();
    for es in wide.values_mut() {
        es.retain(|&(_, _, c)| c >= bottleneck - 1e-9);
    }
    let nodes = bfs_node_path(&wide, from_uid, to_uid, max_hops)?;

    let mut steps: Vec<PathStep> = Vec::with_capacity(nodes.len().saturating_sub(1));
    let mut min_confidence = f64::INFINITY;
    for pair in nodes.windows(2) {
        let (u, v) = (pair[0].as_str(), pair[1].as_str());
        // The smallest-kind wide-enough edge u→v BFS traversed (adjacency sorted).
        let edge = wide.get(u).and_then(|es| es.iter().find(|e| e.0 == v))?;
        steps.push(PathStep {
            kind: edge.1,
            to_uid: v.to_string(),
        });
        min_confidence = min_confidence.min(edge.2);
    }
    if steps.is_empty() {
        return None;
    }
    let hops = steps.len();
    Some(IdentityPath {
        from_uid: from_uid.to_string(),
        to_uid: to_uid.to_string(),
        steps,
        hops,
        min_confidence,
    })
}

/// A pathway pattern generalised from the scan's connections: the
/// direction-canonical route string and every identity pair it linked. The unit
/// of *"what route connected these kinds of identity"*, shared by the AU-064
/// generalisation rule (a template repeated within one scan) and the engine's
/// cross-scan template store (a template repeated across scans — so a route
/// learned once lifts every later scan).
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionTemplate {
    /// e.g. `email →belongs_to_domain→ domain →registered_by→ person`.
    pub template: String,
    /// The `(from_uid, to_uid)` identity pairs this route linked.
    pub pairs: Vec<(String, String)>,
}

/// Render a path's node-kind / relation sequence to its **direction-canonical**
/// string — oriented to the lexicographically-smaller of the route and its
/// reverse, so a route and its mirror are one template regardless of which
/// endpoint hashed smaller.
fn render_template(node_kinds: &[String], rel_strs: &[&str]) -> String {
    let render = |fwd: bool| -> String {
        let n = node_kinds.len();
        let mut s = String::new();
        for i in 0..n {
            let k = if fwd {
                &node_kinds[i]
            } else {
                &node_kinds[n - 1 - i]
            };
            s.push_str(k);
            if i < rel_strs.len() {
                let r = if fwd {
                    rel_strs[i]
                } else {
                    rel_strs[rel_strs.len() - 1 - i]
                };
                s.push_str(" →");
                s.push_str(r);
                s.push_str("→ ");
            }
        }
        s
    };
    render(true).min(render(false))
}

/// Generalise every multi-step identity connection into its direction-canonical
/// pathway template, grouped with the identity pairs it linked. Deterministic,
/// sorted by template. The basis for AU-064 (a template repeated *within* a scan)
/// and the engine's cross-scan template store (repeated *across* scans).
pub fn connection_templates(
    entities: &[Entity],
    relations: &[Relation],
    max_hops: usize,
) -> Vec<ConnectionTemplate> {
    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
    let kind_of = |uid: &str| -> String {
        by_uid
            .get(uid)
            .map_or_else(|| "?".to_string(), |e| e.kind.to_string())
    };

    let mut grouped: std::collections::BTreeMap<String, Vec<(String, String)>> =
        std::collections::BTreeMap::new();
    for path in identity_paths(entities, relations, max_hops) {
        if path.hops < 2 {
            continue; // a direct one-hop link is not a multi-step route to generalise
        }
        let mut node_kinds: Vec<String> = Vec::with_capacity(path.hops + 1);
        node_kinds.push(kind_of(&path.from_uid));
        let mut rel_strs: Vec<&str> = Vec::with_capacity(path.hops);
        for step in &path.steps {
            rel_strs.push(step.kind.as_str());
            node_kinds.push(kind_of(&step.to_uid));
        }
        grouped
            .entry(render_template(&node_kinds, &rel_strs))
            .or_default()
            .push((path.from_uid.clone(), path.to_uid.clone()));
    }
    grouped
        .into_iter()
        .map(|(template, pairs)| ConnectionTemplate { template, pairs })
        .collect()
}

/// A resolved identity: the set of identity entities that fall into one
/// transitive equivalence class over the confirmed relation graph, with the
/// weakest-link confidence of the links that bind them. The cluster-level
/// counterpart to [`identity_paths`]' pairwise links — where the path finder
/// answers "is A linked to B?", this answers "which identities are, together,
/// one identity?" by taking the connected components of the identity-link graph.
#[derive(Debug, Clone, PartialEq)]
pub struct IdentityClusterResult {
    /// The identity member UIDs, sorted; always `len() >= 2`.
    pub members: Vec<String>,
    /// Weakest-link confidence — the minimum pairwise [`IdentityPath::min_confidence`]
    /// across the links that merged the component. A resolved identity is only as
    /// trustworthy as the weakest connection holding it together.
    pub min_confidence: f64,
}

/// Resolve the **transitive identity equivalence classes** of the relation graph:
/// group every identity entity reachable from another (within `max_hops`) into a
/// single cluster, via union-find over the [`identity_paths`] link set. Returns
/// only multi-member clusters (`len() >= 2`), each carrying the weakest-link
/// confidence of the links that bind it, sorted by first member UID.
///
/// This is the cluster-level synthesis of the pairwise transitive closure: where
/// AU-060 reports "A is linked to B", this collapses every such link into "{A, B,
/// C, …} is one identity". Built on the shared `identity_paths` finder, so a
/// cluster's membership can never disagree with the pairwise links the dossier
/// renders (one finder, no drift). Deterministic — members and clusters are
/// sorted, independent of input and hash-iteration order.
pub fn resolve_identity_clusters(
    entities: &[Entity],
    relations: &[Relation],
    max_hops: usize,
) -> Vec<IdentityClusterResult> {
    let paths = identity_paths(entities, relations, max_hops);
    if paths.is_empty() {
        return Vec::new();
    }

    // Intern every identity UID that participates in a link.
    let mut index: HashMap<&str, usize> = HashMap::new();
    let mut uids: Vec<&str> = Vec::new();
    for p in &paths {
        for u in [p.from_uid.as_str(), p.to_uid.as_str()] {
            if !index.contains_key(u) {
                index.insert(u, uids.len());
                uids.push(u);
            }
        }
    }

    // Union-find with iterative path-halving — merge the endpoints of every link.
    fn find(parent: &mut [usize], mut x: usize) -> usize {
        while parent[x] != x {
            parent[x] = parent[parent[x]];
            x = parent[x];
        }
        x
    }
    let mut parent: Vec<usize> = (0..uids.len()).collect();
    for p in &paths {
        let a = find(&mut parent, index[p.from_uid.as_str()]);
        let b = find(&mut parent, index[p.to_uid.as_str()]);
        if a != b {
            parent[a] = b;
        }
    }

    // Weakest-link confidence per component: the minimum link min_confidence
    // among every link whose endpoints landed in that component.
    let mut comp_conf: HashMap<usize, f64> = HashMap::new();
    for p in &paths {
        let r = find(&mut parent, index[p.from_uid.as_str()]);
        let e = comp_conf.entry(r).or_insert(f64::INFINITY);
        *e = e.min(p.min_confidence);
    }

    // Group members by component root.
    let mut groups: HashMap<usize, Vec<&str>> = HashMap::new();
    for (i, &u) in uids.iter().enumerate() {
        let r = find(&mut parent, i);
        groups.entry(r).or_default().push(u);
    }

    let mut out: Vec<IdentityClusterResult> = groups
        .into_iter()
        .filter(|(_, m)| m.len() >= 2)
        .map(|(r, mut members)| {
            members.sort_unstable();
            IdentityClusterResult {
                members: members.into_iter().map(str::to_string).collect(),
                min_confidence: comp_conf.get(&r).copied().unwrap_or(0.0),
            }
        })
        .collect();
    out.sort_by(|a, b| a.members[0].cmp(&b.members[0]));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::relation::Relation;

    #[test]
    fn resolve_identity_clusters_groups_transitive_identities_with_weakest_link() {
        let mk = |k: EntityKind, v: &str| Entity::new(k, v, 0.8, "s");
        let rel = |from: &Entity, to: &Entity, c: f64| {
            Relation::new(
                from.uid.clone(),
                to.uid.clone(),
                RelationKind::DerivedFrom,
                c,
                "s",
            )
        };
        // email — uname (0.9) — phone (0.4): one component of 3 identities, whose
        // weakest binding link is 0.4. A separate unlinked person is excluded.
        let email = mk(EntityKind::Email, "a@x.com");
        let uname = mk(EntityKind::Username, "alice");
        let phone = mk(EntityKind::Phone, "+61400000000");
        let lone = mk(EntityKind::Person, "Bob");
        let rels = [rel(&email, &uname, 0.9), rel(&uname, &phone, 0.4)];
        let ents = [email, uname, phone, lone];

        let clusters = resolve_identity_clusters(&ents, &rels, 4);
        assert_eq!(clusters.len(), 1, "one multi-identity cluster");
        assert_eq!(clusters[0].members.len(), 3, "email + username + phone");
        assert!(
            (clusters[0].min_confidence - 0.4).abs() < 1e-9,
            "the weakest link sets the cluster confidence"
        );
        // Deterministic: identical inputs yield byte-identical output.
        assert_eq!(resolve_identity_clusters(&ents, &rels, 4), clusters);
    }

    #[test]
    fn resolve_identity_clusters_empty_without_links() {
        let a = Entity::new(EntityKind::Email, "a@x.com", 0.8, "s");
        let b = Entity::new(EntityKind::Username, "bob", 0.8, "s");
        assert!(resolve_identity_clusters(&[a, b], &[], 4).is_empty());
    }

    #[test]
    fn strongest_path_prefers_the_widest_route_over_the_shortest() {
        let mk = |k: EntityKind, v: &str| Entity::new(k, v, 0.8, "s");
        let edge = |from: &Entity, to: &Entity, c: f64| {
            Relation::new(
                from.uid.clone(),
                to.uid.clone(),
                RelationKind::DerivedFrom,
                c,
                "s",
            )
        };
        let a = mk(EntityKind::Email, "a@x.com");
        let b = mk(EntityKind::Username, "bob");
        let x = mk(EntityKind::Person, "Mid");
        let rels = [
            edge(&a, &b, 0.30), // direct but weak — the SHORTEST route (1 hop)
            edge(&a, &x, 0.90), // a strong 2-hop route via x …
            edge(&x, &b, 0.90),
        ];
        let ents = [a.clone(), b.clone(), x.clone()];

        // identity_paths takes the shortest (the weak direct edge).
        let shortest = identity_paths(&ents, &rels, 4);
        let direct = shortest
            .iter()
            .find(|p| p.from_uid == a.uid || p.to_uid == a.uid)
            .expect("a path exists");
        assert_eq!(direct.hops, 1);

        // strongest_path takes the WIDEST: the 2-hop route, bottleneck 0.90.
        let p = strongest_path(&ents, &rels, &a.uid, &b.uid, 4).expect("reachable");
        assert_eq!(p.hops, 2, "the widest route is the longer, stronger one");
        assert!(
            (p.min_confidence - 0.90).abs() < 1e-9,
            "bottleneck is the weakest edge on the widest route"
        );
        // Deterministic.
        assert_eq!(strongest_path(&ents, &rels, &a.uid, &b.uid, 4), Some(p));
    }

    #[test]
    fn strongest_path_none_when_unreachable() {
        let a = Entity::new(EntityKind::Email, "a@x.com", 0.8, "s");
        let b = Entity::new(EntityKind::Username, "bob", 0.8, "s");
        assert!(strongest_path(&[a.clone(), b.clone()], &[], &a.uid, &b.uid, 4).is_none());
    }

    fn ent(kind: EntityKind, value: &str) -> Entity {
        Entity::new(kind, value, 0.8, "s")
    }

    fn rel(from: &Entity, to: &Entity, kind: RelationKind, conf: f64) -> Relation {
        Relation::new(from.uid.clone(), to.uid.clone(), kind, conf, "s")
    }

    #[test]
    fn two_hop_path_records_ordered_steps_and_weakest_edge() {
        // email → domain → person: identity endpoints, one intermediate.
        let email = ent(EntityKind::Email, "alice@example.com");
        let domain = ent(EntityKind::Domain, "example.com");
        let person = ent(EntityKind::Person, "Alice Doe");
        let rels = [
            rel(&email, &domain, RelationKind::BelongsToDomain, 0.9),
            rel(&domain, &person, RelationKind::RegisteredBy, 0.6),
        ];
        let paths = identity_paths(&[email.clone(), domain.clone(), person.clone()], &rels, 4);
        assert_eq!(paths.len(), 1);
        let p = &paths[0];
        assert_eq!(p.hops, 2);
        assert_eq!(p.steps.len(), 2);
        // Forward order: first hop reaches the domain, second reaches the person.
        assert_eq!(p.steps[0].to_uid, domain.uid);
        assert_eq!(p.steps[1].to_uid, person.uid);
        // Endpoints are the two identities (smaller UID is `from`).
        let (lo, hi) = if email.uid < person.uid {
            (&email, &person)
        } else {
            (&person, &email)
        };
        assert_eq!(p.from_uid, lo.uid);
        assert_eq!(p.to_uid, hi.uid);
        // Weakest link = the 0.6 RegisteredBy edge, not the 0.9 one.
        assert!((p.min_confidence - 0.6).abs() < 1e-9);
    }

    #[test]
    fn one_hop_direct_identity_link_is_reported() {
        // A direct edge IS a connection — the dossier shows it; AU-060 filters it.
        let email = ent(EntityKind::Email, "a@x.com");
        let person = ent(EntityKind::Person, "A");
        let rels = [rel(&email, &person, RelationKind::IdentifiedBy, 0.7)];
        let paths = identity_paths(&[email, person], &rels, 4);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].hops, 1);
    }

    #[test]
    fn shortest_path_wins_over_a_longer_alternative() {
        // email → person (direct) AND email → domain → person. Shortest = 1 hop.
        let email = ent(EntityKind::Email, "alice@example.com");
        let domain = ent(EntityKind::Domain, "example.com");
        let person = ent(EntityKind::Person, "Alice Doe");
        let rels = [
            rel(&email, &person, RelationKind::IdentifiedBy, 0.7),
            rel(&email, &domain, RelationKind::BelongsToDomain, 0.9),
            rel(&domain, &person, RelationKind::RegisteredBy, 0.9),
        ];
        let paths = identity_paths(&[email, domain, person], &rels, 4);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].hops, 1, "the direct edge is the shortest path");
    }

    #[test]
    fn hop_budget_is_respected() {
        // email → d1 → d2 → person is 3 hops; a budget of 2 finds nothing.
        let email = ent(EntityKind::Email, "a@x.com");
        let d1 = ent(EntityKind::Domain, "x.com");
        let d2 = ent(EntityKind::IpAddress, "1.2.3.4");
        let person = ent(EntityKind::Person, "A");
        let rels = [
            rel(&email, &d1, RelationKind::BelongsToDomain, 0.8),
            rel(&d1, &d2, RelationKind::ResolvesTo, 0.8),
            rel(&d2, &person, RelationKind::RegisteredBy, 0.8),
        ];
        let ents = [email, d1, d2, person];
        assert!(identity_paths(&ents, &rels, 2).is_empty());
        assert_eq!(identity_paths(&ents, &rels, 3).len(), 1);
    }

    #[test]
    fn edges_to_unknown_nodes_are_ignored() {
        let email = ent(EntityKind::Email, "a@x.com");
        let person = ent(EntityKind::Person, "B");
        let phantom = "phantom-uid-not-present".to_string();
        let r1 = Relation::new(
            email.uid.clone(),
            phantom.clone(),
            RelationKind::DerivedFrom,
            0.8,
            "s",
        );
        let r2 = Relation::new(
            phantom,
            person.uid.clone(),
            RelationKind::DerivedFrom,
            0.8,
            "s",
        );
        assert!(identity_paths(&[email, person], &[r1, r2], 4).is_empty());
    }

    #[test]
    fn non_identity_endpoints_yield_no_pair() {
        // Only one identity (email); a domain↔ip edge has no identity endpoint.
        let email = ent(EntityKind::Email, "a@x.com");
        let domain = ent(EntityKind::Domain, "x.com");
        let ip = ent(EntityKind::IpAddress, "1.2.3.4");
        let rels = [
            rel(&email, &domain, RelationKind::BelongsToDomain, 0.8),
            rel(&domain, &ip, RelationKind::ResolvesTo, 0.8),
        ];
        assert!(identity_paths(&[email, domain, ip], &rels, 4).is_empty());
    }

    #[test]
    fn parallel_edges_collapse_to_a_stable_label() {
        // Two edges between the same pair, different kinds: the lexicographically
        // smallest label (`belongs_to_domain` < `identified_by`) must win, both
        // orderings.
        let email = ent(EntityKind::Email, "a@x.com");
        let person = ent(EntityKind::Person, "A");
        let forward = [
            rel(&email, &person, RelationKind::IdentifiedBy, 0.9),
            rel(&email, &person, RelationKind::BelongsToDomain, 0.5),
        ];
        let reverse = [
            rel(&email, &person, RelationKind::BelongsToDomain, 0.5),
            rel(&email, &person, RelationKind::IdentifiedBy, 0.9),
        ];
        let pf = identity_paths(&[email.clone(), person.clone()], &forward, 4);
        let pr = identity_paths(&[email, person], &reverse, 4);
        assert_eq!(pf, pr);
        assert_eq!(pf[0].steps[0].kind, RelationKind::BelongsToDomain);
    }

    #[test]
    fn max_hops_zero_is_empty() {
        let email = ent(EntityKind::Email, "a@x.com");
        let person = ent(EntityKind::Person, "A");
        let rels = [rel(&email, &person, RelationKind::IdentifiedBy, 0.7)];
        assert!(identity_paths(&[email, person], &rels, 0).is_empty());
    }

    #[test]
    fn adjacency_is_bidirectional_and_confinable() {
        let a = ent(EntityKind::Email, "a@x.com");
        let b = ent(EntityKind::Person, "B");
        let phantom = "ghost-uid";
        let rels = [
            rel(&a, &b, RelationKind::IdentifiedBy, 0.8),
            Relation::new(
                a.uid.clone(),
                phantom.to_string(),
                RelationKind::DerivedFrom,
                0.8,
                "s",
            ),
        ];
        // Unconfined keeps the dangling edge (the subject-network view).
        let raw = undirected_adjacency(&rels, None);
        assert!(raw[a.uid.as_str()].iter().any(|&(n, _, _)| n == phantom));
        // Confined to {a,b} prunes it; edges remain bidirectional.
        let confirmed: HashSet<&str> = [a.uid.as_str(), b.uid.as_str()].into_iter().collect();
        let confined = undirected_adjacency(&rels, Some(&confirmed));
        assert!(
            !confined[a.uid.as_str()]
                .iter()
                .any(|&(n, _, _)| n == phantom)
        );
        assert!(confined[b.uid.as_str()].iter().any(|&(n, _, _)| n == a.uid));
    }

    #[test]
    fn adjacency_skips_self_loops() {
        let a = ent(EntityKind::Email, "a@x.com");
        let rels = [rel(&a, &a, RelationKind::AliasOf, 0.8)];
        assert!(undirected_adjacency(&rels, None).is_empty());
    }

    #[test]
    fn reachable_count_is_component_size_minus_one() {
        // a — b — c chain; d isolated.
        let a = ent(EntityKind::Email, "a@x.com");
        let b = ent(EntityKind::Domain, "x.com");
        let c = ent(EntityKind::Person, "C");
        let d = ent(EntityKind::Username, "loner");
        let rels = [
            rel(&a, &b, RelationKind::BelongsToDomain, 0.8),
            rel(&b, &c, RelationKind::RegisteredBy, 0.8),
        ];
        let adj = undirected_adjacency(&rels, None);
        assert_eq!(reachable_count(a.uid.as_str(), &adj), 2); // reaches b, c
        assert_eq!(reachable_count(d.uid.as_str(), &adj), 0); // isolated
    }

    #[test]
    fn disjoint_pathways_finds_independent_routes() {
        // A and B linked by TWO edge-disjoint routes: A→m1→B and A→m2→B.
        let a = ent(EntityKind::Email, "a@x.com");
        let b = ent(EntityKind::Username, "bob");
        let m1 = ent(EntityKind::Domain, "x.com");
        let m2 = ent(EntityKind::Person, "Bob R");
        let rels = [
            rel(&a, &m1, RelationKind::BelongsToDomain, 0.8),
            rel(&m1, &b, RelationKind::DerivedFrom, 0.8),
            rel(&a, &m2, RelationKind::IdentifiedBy, 0.8),
            rel(&m2, &b, RelationKind::IdentifiedBy, 0.8),
        ];
        let ents = [a.clone(), b.clone(), m1, m2];
        let paths = disjoint_pathways(&ents, &rels, &a.uid, &b.uid, 4, 4);
        assert_eq!(paths.len(), 2, "two independent routes");
        for p in &paths {
            assert_eq!(p.len(), 2);
            assert_eq!(p.last().unwrap().to_uid, b.uid);
        }
        let mids: HashSet<&str> = paths.iter().map(|p| p[0].to_uid.as_str()).collect();
        assert_eq!(mids.len(), 2, "the routes go through different nodes");
    }

    #[test]
    fn disjoint_pathways_single_route_yields_one() {
        // One route A→m→B; its shared edge can't be reused for a second.
        let a = ent(EntityKind::Email, "a@x.com");
        let b = ent(EntityKind::Username, "bob");
        let m = ent(EntityKind::Domain, "x.com");
        let rels = [
            rel(&a, &m, RelationKind::BelongsToDomain, 0.8),
            rel(&m, &b, RelationKind::DerivedFrom, 0.8),
        ];
        let ents = [a.clone(), b.clone(), m];
        assert_eq!(
            disjoint_pathways(&ents, &rels, &a.uid, &b.uid, 4, 4).len(),
            1
        );
    }

    #[test]
    fn disjoint_pathways_is_order_independent() {
        let a = ent(EntityKind::Email, "a@x.com");
        let b = ent(EntityKind::Username, "bob");
        let m1 = ent(EntityKind::Domain, "x.com");
        let m2 = ent(EntityKind::Person, "Bob R");
        let rels = vec![
            rel(&a, &m1, RelationKind::BelongsToDomain, 0.8),
            rel(&m1, &b, RelationKind::DerivedFrom, 0.8),
            rel(&a, &m2, RelationKind::IdentifiedBy, 0.8),
            rel(&m2, &b, RelationKind::IdentifiedBy, 0.8),
        ];
        let ents = [a.clone(), b.clone(), m1, m2];
        let forward = disjoint_pathways(&ents, &rels, &a.uid, &b.uid, 4, 4);
        let mut reversed = rels.clone();
        reversed.reverse();
        let backward = disjoint_pathways(&ents, &reversed, &a.uid, &b.uid, 4, 4);
        assert_eq!(forward, backward, "pathways independent of edge order");
    }

    #[test]
    fn connection_templates_group_repeated_routes_direction_invariantly() {
        // Two pairs, the same abstract route → one canonical template, two pairs.
        let e1 = ent(EntityKind::Email, "a@x.com");
        let d1 = ent(EntityKind::Domain, "x.com");
        let p1 = ent(EntityKind::Person, "Alice");
        let e2 = ent(EntityKind::Email, "b@y.com");
        let d2 = ent(EntityKind::Domain, "y.com");
        let p2 = ent(EntityKind::Person, "Bob");
        let rels = [
            rel(&e1, &d1, RelationKind::BelongsToDomain, 0.8),
            rel(&d1, &p1, RelationKind::RegisteredBy, 0.8),
            rel(&e2, &d2, RelationKind::BelongsToDomain, 0.8),
            rel(&d2, &p2, RelationKind::RegisteredBy, 0.8),
        ];
        let cts = connection_templates(&[e1, d1, p1, e2, d2, p2], &rels, 4);
        assert_eq!(cts.len(), 1, "both pairs share one canonical template");
        assert_eq!(cts[0].pairs.len(), 2);
        assert!(cts[0].template.contains("email") && cts[0].template.contains("person"));
        assert!(
            cts[0].template.contains("belongs_to_domain")
                && cts[0].template.contains("registered_by")
        );
    }

    mod property {
        use super::*;
        use proptest::prelude::*;

        /// A small random identity graph: 2–6 nodes, the first two always
        /// identities (so a pair is possible), random edges over them.
        fn graph() -> impl Strategy<Value = (Vec<Entity>, Vec<Relation>)> {
            let kinds = proptest::collection::vec(0u8..6, 2..6);
            (
                kinds,
                proptest::collection::vec((0usize..6, 0usize..6, 0u8..11), 0..10),
            )
                .prop_map(|(ks, raw_edges): (Vec<u8>, Vec<(usize, usize, u8)>)| {
                    let mk = |i: usize, k: u8| {
                        let kind = match k {
                            0 => EntityKind::Email,
                            1 => EntityKind::Username,
                            2 => EntityKind::Person,
                            3 => EntityKind::Phone,
                            4 => EntityKind::Domain,
                            _ => EntityKind::IpAddress,
                        };
                        Entity::new(kind, format!("n{i}"), 0.8, "s")
                    };
                    // Force the first two nodes to be identities.
                    let mut ents: Vec<Entity> = Vec::new();
                    ents.push(mk(0, 0));
                    ents.push(mk(1, 1));
                    for (i, &k) in ks.iter().enumerate() {
                        ents.push(mk(i + 2, k));
                    }
                    let kind_of = |k: usize| match k % 11 {
                        0 => RelationKind::SubdomainOf,
                        1 => RelationKind::BelongsToDomain,
                        2 => RelationKind::HostedOn,
                        3 => RelationKind::ResolvesTo,
                        4 => RelationKind::RegisteredBy,
                        5 => RelationKind::CoLocatedWith,
                        6 => RelationKind::DerivedFrom,
                        7 => RelationKind::IdentifiedBy,
                        8 => RelationKind::AliasOf,
                        9 => RelationKind::LocatedAt,
                        _ => RelationKind::AssociatedWith,
                    };
                    let n = ents.len();
                    let rels = raw_edges
                        .into_iter()
                        .filter(|(a, b, _)| a != b && *a < n && *b < n)
                        .map(|(a, b, k)| {
                            rel(
                                &ents[a],
                                &ents[b],
                                kind_of(k as usize),
                                0.5 + (k as f64) / 30.0,
                            )
                        })
                        .collect::<Vec<_>>();
                    (ents, rels)
                })
        }

        proptest! {
            /// The path set is **independent of relation input order** — the
            /// reproducibility guarantee the whole product rests on. Computing
            /// over the edges as-generated and over the same edges sorted by id
            /// must yield byte-identical paths.
            #[test]
            fn identity_paths_is_order_independent((ents, rels) in graph()) {
                let mut sorted = rels.clone();
                sorted.sort_by(|x, y| x.id.cmp(&y.id));
                prop_assert_eq!(
                    identity_paths(&ents, &rels, 4),
                    identity_paths(&ents, &sorted, 4)
                );
            }

            /// Every reported path is a real, well-formed chain: `steps.len()`
            /// equals `hops`, the last step lands on `to_uid`, endpoints differ,
            /// and the orientation is canonical (`from_uid < to_uid`). No path
            /// ever exceeds the hop budget.
            #[test]
            fn reported_paths_are_well_formed((ents, rels) in graph()) {
                for p in identity_paths(&ents, &rels, 4) {
                    prop_assert_eq!(p.steps.len(), p.hops);
                    prop_assert!(p.hops >= 1 && p.hops <= 4);
                    prop_assert!(p.from_uid < p.to_uid);
                    prop_assert_eq!(&p.steps.last().unwrap().to_uid, &p.to_uid);
                }
            }

            /// The **defining invariant of the widest path**: its bottleneck is at
            /// least as strong as the weakest edge of the *shortest* path between
            /// the same pair. `strongest_path` exists precisely to beat the
            /// shortest route on reliability, so it can never be weaker. (The two
            /// forced identities `n0`/`n1` are the probe pair; both finders share
            /// the 4-hop budget so the comparison is apples-to-apples.)
            #[test]
            fn strongest_path_bottleneck_dominates_shortest((ents, rels) in graph()) {
                let (a, b) = if ents[0].uid <= ents[1].uid {
                    (&ents[0].uid, &ents[1].uid)
                } else {
                    (&ents[1].uid, &ents[0].uid)
                };
                let shortest = identity_paths(&ents, &rels, 4)
                    .into_iter()
                    .find(|p| &p.from_uid == a && &p.to_uid == b);
                if let Some(sp) = shortest {
                    let widest = strongest_path(&ents, &rels, a, b, 4);
                    prop_assert!(widest.is_some(), "reachable shortest ⇒ reachable widest");
                    let w = widest.unwrap();
                    prop_assert!(w.min_confidence >= sp.min_confidence - 1e-9);
                    // …and it is itself a well-formed, hop-bounded chain.
                    prop_assert_eq!(w.steps.len(), w.hops);
                    prop_assert!(w.hops >= 1 && w.hops <= 4);
                    prop_assert_eq!(&w.steps.last().unwrap().to_uid, b);
                }
            }

            /// Reachability and bottleneck are **symmetric** over the undirected
            /// graph: the widest route a→b is exactly as strong as b→a. (The path
            /// itself is oriented, so only the bottleneck is compared.)
            #[test]
            fn strongest_path_bottleneck_is_symmetric((ents, rels) in graph()) {
                let (a, b) = (&ents[0].uid, &ents[1].uid);
                let ab = strongest_path(&ents, &rels, a, b, 4).map(|p| p.min_confidence);
                let ba = strongest_path(&ents, &rels, b, a, 4).map(|p| p.min_confidence);
                match (ab, ba) {
                    (Some(x), Some(y)) => prop_assert!((x - y).abs() < 1e-9),
                    (None, None) => {}
                    _ => prop_assert!(false, "reachability must be symmetric"),
                }
            }
        }
    }
}
