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

    // A path may only traverse confirmed (present) nodes — the shared adjacency
    // builder, confined to the confirmed UID set so a dangling/quarantined edge
    // is never walked.
    let confirmed: HashSet<&str> = entities.iter().map(|e| e.uid.as_str()).collect();
    let mut adj = undirected_adjacency(relations, Some(&confirmed));
    // Sort each list by (neighbour, kind, confidence) so BFS's first visit to a
    // neighbour deterministically takes the smallest-kind (then weakest) edge —
    // parallel edges thus collapse to one stable label with no separate pass, and
    // traversal is independent of input order.
    for v in adj.values_mut() {
        v.sort_by(|x, y| {
            x.0.cmp(y.0)
                .then_with(|| x.1.as_str().cmp(y.1.as_str()))
                .then_with(|| x.2.total_cmp(&y.2))
        });
    }

    // Identity endpoints in sorted UID order — each pair is computed once from
    // the smaller UID, fixing both orientation and shortest-path tie-breaks.
    let mut identity_uids: Vec<&str> = entities
        .iter()
        .filter(|e| is_identity_kind(&e.kind))
        .map(|e| e.uid.as_str())
        .collect();
    identity_uids.sort_unstable();
    identity_uids.dedup();
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
    let confirmed: HashSet<&str> = entities.iter().map(|e| e.uid.as_str()).collect();
    if !confirmed.contains(from_uid) || !confirmed.contains(to_uid) {
        return Vec::new();
    }
    let mut adj = undirected_adjacency(relations, Some(&confirmed));
    for v in adj.values_mut() {
        v.sort_by(|x, y| {
            x.0.cmp(y.0)
                .then_with(|| x.1.as_str().cmp(y.1.as_str()))
                .then_with(|| x.2.total_cmp(&y.2))
        });
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::relation::Relation;

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
        }
    }
}
