//! Shortest-path link analysis over the relation graph — the canonical
//! "how are these two identities connected?" finder.
//!
//! This is the graph-free link-analysis primitive behind both the dossier's
//! CONNECTIONS section and the AU-060 transitive-identity correlation rule.
//! Instead of handing the operator a canvas to pivot by hand (Maltego), it
//! computes the *thread* — the ordered chain of typed edges that ties one
//! identity to another — and delivers it as a reproducible conclusion. One
//! authoritative implementation, so the rule and the rendered dossier can never
//! disagree about what links two entities (the `Rule 4` "delegate, never copy"
//! invariant — a hand-rolled second BFS is exactly how two views drift).
//!
//! # Determinism (architecture invariant)
//! Pure BFS over a value-derived edge set. Parallel edges between one pair
//! collapse to the lexicographically-smallest [`RelationKind`] label (so the
//! rendered hop is stable), adjacency lists are sorted by neighbour UID, and
//! every pair is computed exactly once from its smaller-UID endpoint — so the
//! same entity + relation set always yields the byte-identical path set,
//! independent of input order. Guarded by `identity_paths_is_order_independent`
//! in the sibling test module.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use super::{Relation, RelationKind};
use crate::core::entity::{Entity, EntityKind};

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

    // A path may only traverse confirmed (present) nodes.
    let by_uid: HashSet<&str> = entities.iter().map(|e| e.uid.as_str()).collect();

    // Undirected edge map keyed by the unordered pair (smaller-UID, larger-UID),
    // collapsing parallels to the smallest-kind label (and, for an equal kind,
    // the weaker confidence — the conservative choice). A BTreeMap keeps the
    // build deterministic before adjacency lists are materialised.
    let mut edge: BTreeMap<(&str, &str), (RelationKind, f64)> = BTreeMap::new();
    for r in relations {
        let (a, b) = (r.from_uid.as_str(), r.to_uid.as_str());
        if a == b || !by_uid.contains(a) || !by_uid.contains(b) {
            continue;
        }
        let key = if a < b { (a, b) } else { (b, a) };
        edge.entry(key)
            .and_modify(|cur| {
                let newer_label = r.kind.as_str() < cur.0.as_str();
                let same_label_weaker = r.kind.as_str() == cur.0.as_str() && r.confidence < cur.1;
                if newer_label || same_label_weaker {
                    *cur = (r.kind, r.confidence);
                }
            })
            .or_insert((r.kind, r.confidence));
    }

    // Adjacency: node -> [(neighbour, kind, confidence)], sorted by neighbour UID
    // so BFS predecessor selection is independent of edge-map iteration order.
    let mut adj: HashMap<&str, Vec<(&str, RelationKind, f64)>> = HashMap::new();
    for (&(a, b), &(kind, conf)) in &edge {
        adj.entry(a).or_default().push((b, kind, conf));
        adj.entry(b).or_default().push((a, kind, conf));
    }
    for v in adj.values_mut() {
        v.sort_by(|x, y| x.0.cmp(y.0));
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
