//! `core::community` — deterministic, dependency-free community detection over
//! the entity relation graph (OSINT link analysis).
//!
//! # What this is for
//! The relation layer ([`crate::core::relation`]) wires a subject's findings into
//! one typed graph, and [`crate::core::network`] renders that graph from the
//! subject's point of view. But a real person scan's graph is not one
//! homogeneous blob: inside it sit *sub-clusters* — the **family** cluster (the
//! people, their shared addresses, their relatives), distinct from the
//! **infrastructure** cluster (a domain, its subdomains, the IPs it resolves to,
//! the registrant org). They are often joined by a thin bridge (one email that
//! both a person owns and a domain registers), so the whole thing is technically
//! *connected* yet plainly two groups to an analyst. This module surfaces those
//! groups: it partitions the graph's nodes into communities so the dossier can
//! say "here is the human network, and separately here is the estate".
//!
//! # Algorithm — synchronous label propagation (not connected components, not
//! spectral)
//! Two simple, dependency-free partitions were on the table:
//!   * **Weakly-connected components** — group nodes that are reachable from one
//!     another. Trivial and deterministic, but it can only ever return *one*
//!     group per connected blob. The family/infrastructure split above lives
//!     *inside* a single connected component (the bridge email connects them), so
//!     components would collapse exactly the distinction this module exists to
//!     draw — useless for the stated OSINT goal.
//!   * **Label propagation** (Raghavan et al., 2007) — each node starts as its
//!     own label and repeatedly adopts the label most common among its
//!     neighbours; dense intra-cluster wiring outvotes the sparse inter-cluster
//!     bridge, so a weakly-bridged two-lobe graph settles into two labels. This
//!     *can* sub-divide a connected component, which is precisely what we want,
//!     and it needs no linear algebra — unlike spectral clustering, which would
//!     drag in an eigensolver / dense matrix far too heavy (RAM and deps) for a
//!     low-power Termux aarch64 device. We therefore use label propagation.
//!
//! Plain label propagation is famously *non-deterministic*: its result depends on
//! node visitation order and on how ties between equally-popular neighbour labels
//! are broken, so two runs over the same graph can disagree. That is unacceptable
//! here (the engine's determinism invariant — same input ⇒ same output, never
//! dependent on `HashMap` iteration order). Every non-determinism source is
//! pinned:
//!   * **Synchronous rounds.** All nodes are scored against the *previous*
//!     round's labelling, then updated together — no within-round feedback whose
//!     effect would depend on visitation order.
//!   * **Deterministic node order.** Nodes are processed in ascending-UID order,
//!     and a node's neighbour list is sorted by UID, so accumulation order is
//!     fixed regardless of how the relations or entities were ordered on input.
//!   * **Deterministic tie-break.** Among the labels with the maximum neighbour
//!     weight, the lexicographically smallest label (a UID string) wins. A node
//!     also always *counts itself*, so a node with no more-popular neighbour
//!     keeps its own label rather than flipping arbitrarily.
//!   * **Bounded work.** Iteration stops at the first fixed point (a round that
//!     changes no label) or after [`MAX_ROUNDS`] rounds, whichever comes first —
//!     so the pass is `O(MAX_ROUNDS · edges)` and cannot spin on the rare
//!     oscillating configuration. Synchronous LPA can oscillate between two
//!     labellings on bipartite-ish structures; the round cap makes that a bounded,
//!     deterministic stop rather than a hang.
//!
//! The product is a pure function of `(entities, relations)`: byte-for-byte
//! reproducible, independent of input ordering and of hash-map iteration order.
//!
//! # What is (and isn't) a community
//! Edges are taken **undirected** (a relation links its two endpoints regardless
//! of direction) and **unweighted by kind** — every relation is one vote; the
//! edge `confidence` is not used to weight the count, only the graph *topology*
//! decides membership. Only entities that **participate in at least one relation**
//! are placed: an isolated node (in the entity set but in no relation) is *not* a
//! community and is omitted entirely — a community is a thing with internal
//! structure, and a lone node has none. Dangling endpoints (a relation naming a
//! UID absent from `entities`) are skipped, never panicking, mirroring
//! [`crate::core::network::synthesize`].
//!
//! # Output
//! [`detect`] returns the communities sorted **largest first**, ties broken by
//! the smallest member UID, and assigns each a stable `id` from that order (so
//! `id` is reproducible and `0` is always the biggest cluster). Each [`Community`]
//! carries its sorted member `uids`, its `size`, and a deterministic human
//! `label` derived from the cluster's dominant [`crate::core::entity::EntityKind`]
//! plus a representative member value (see [`Community::from_members`]).

use std::collections::HashMap;

use serde::Serialize;

use crate::core::entity::Entity;
use crate::core::graph::Graph;
use crate::core::relation::Relation;

/// Hard cap on label-propagation rounds. Synchronous LPA reaches a stable
/// labelling on realistic OSINT graphs in a handful of rounds (it converges in
/// roughly the graph's diameter), but a pathological / oscillating configuration
/// could otherwise iterate without settling. Capping the rounds bounds the work
/// at `O(MAX_ROUNDS · edges)` — cheap and predictable on a low-RAM Termux device
/// — and guarantees termination. Picked generously enough that any graph a phone
/// can hold converges well within it.
const MAX_ROUNDS: usize = 100;

/// One detected community: a sub-cluster of the relation graph.
///
/// `id` is assigned from the deterministic output order (largest community
/// first, ties broken by smallest member UID), so it is stable across runs and
/// `0` is always the biggest cluster. Serialisable so a future report / SPA view
/// can render the clusters directly.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Community {
    /// Stable index in the deterministically-sorted result (`0` = largest).
    pub id: usize,
    /// Member entity UIDs, sorted ascending (so the set is order-independent).
    pub uids: Vec<String>,
    /// Number of members (`uids.len()`), surfaced for convenient ranking/display.
    pub size: usize,
    /// Human, deterministic label for the cluster — its dominant entity kind and
    /// a representative member value (see [`Community::from_members`]).
    pub label: String,
}

impl Community {
    /// Build a community from its members, deriving the deterministic `label`.
    ///
    /// The label is `"<dominant kind> cluster: <representative value>"`, where:
    ///   * the **dominant kind** is the [`crate::core::entity::EntityKind`] held
    ///     by the most members (ties broken by the kind's display string, so the
    ///     choice never depends on entity iteration order); and
    ///   * the **representative value** is the `value` of the smallest-UID member
    ///     *of that dominant kind* — a stable, human-recognisable exemplar (a
    ///     person's name for a family cluster, a domain for an infra cluster).
    ///
    /// `members` must be non-empty (every detected community has ≥ 1 member) and
    /// is expected pre-sorted by UID; `id` is assigned by [`detect`] from the
    /// final ordering.
    fn from_members(id: usize, members: &[&Entity]) -> Self {
        let label = derive_label(members);
        let uids: Vec<String> = members.iter().map(|e| e.uid.clone()).collect();
        Self {
            id,
            size: uids.len(),
            uids,
            label,
        }
    }
}

/// Derive the deterministic human label for a cluster from its members.
///
/// Counts members per kind, picks the dominant kind (max count, tie-broken by the
/// kind's display string for stability), then names the smallest-UID member of
/// that kind as the exemplar. Pure and order-independent: the kind tally and the
/// "smallest UID of the dominant kind" exemplar are both invariant to the order
/// `members` arrives in.
fn derive_label(members: &[&Entity]) -> String {
    // Tally members per kind. The kind's display string is the stable key (and
    // doubles as the tie-break), so two runs can't disagree on the winner.
    let mut counts: HashMap<String, usize> = HashMap::new();
    for e in members {
        *counts.entry(e.kind.to_string()).or_insert(0) += 1;
    }
    // Dominant kind: highest count, ties broken by the SMALLER kind string so the
    // pick is deterministic regardless of `HashMap` iteration order.
    let dominant_kind = counts
        .into_iter()
        .max_by(|(ka, ca), (kb, cb)| ca.cmp(cb).then_with(|| kb.cmp(ka)))
        .map(|(k, _)| k)
        .unwrap_or_default();

    // Representative member: the smallest-UID entity whose kind is the dominant
    // one — a stable, recognisable exemplar of the cluster.
    let exemplar = members
        .iter()
        .filter(|e| e.kind.to_string() == dominant_kind)
        .min_by(|a, b| a.uid.cmp(&b.uid))
        .map_or("", |e| e.value.as_str());

    format!("{dominant_kind} cluster: {exemplar}")
}

/// Detect communities (sub-clusters) in the entity relation graph.
///
/// Builds the undirected graph from `relations`, runs deterministic synchronous
/// label propagation to a fixed point (or [`MAX_ROUNDS`]), and returns the
/// resulting clusters sorted largest-first (ties broken by smallest member UID)
/// with stable `id`s assigned from that order. See the module documentation for
/// the algorithm, determinism guarantees, and membership rules.
///
/// Pure and deterministic: the same `(entities, relations)` snapshot always
/// yields the same `Vec<Community>`, independent of the order entities/relations
/// are supplied in and of `HashMap` iteration order. Only entities that take part
/// in at least one relation appear; isolated entities are omitted. Dangling
/// relation endpoints (UIDs not present in `entities`) are skipped without
/// panicking. An empty entity set, an empty relation set, or relations whose
/// endpoints are all dangling all yield an empty result.
///
/// ```
/// use huntsman_search_engine::core::community::detect;
/// use huntsman_search_engine::core::entity::{Entity, EntityKind};
/// use huntsman_search_engine::core::relation::{Relation, RelationKind};
///
/// // Two people linked to each other — one community of two.
/// let a = Entity::new(EntityKind::Person, "Ada Lovelace", 0.9, "scan");
/// let b = Entity::new(EntityKind::Person, "Bertrand Russell", 0.9, "scan");
/// let edge = Relation::new(&a.uid, &b.uid, RelationKind::AssociatedWith, 0.5, "scan");
///
/// let communities = detect(&[a, b], &[edge]);
/// assert_eq!(communities.len(), 1);
/// assert_eq!(communities[0].size, 2);
/// assert_eq!(communities[0].id, 0);
/// ```
#[must_use]
pub fn detect(entities: &[Entity], relations: &[Relation]) -> Vec<Community> {
    // ── Resolve entities by UID, so a community can carry the real entities (for
    // its label and exemplar). A relation endpoint absent here is dangling. ──
    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();

    // ── Undirected, deduplicated adjacency over the present entities, from the shared
    // primitive: parallel edges collapse, self-loops and dangling endpoints drop, and
    // nodes are indexed in ascending-UID order. ──
    let g = Graph::build(entities, relations);

    // A community needs internal structure, so only CONNECTED nodes (degree ≥ 1)
    // participate — an isolated entity is omitted entirely. The graph already orders
    // nodes by ascending UID, so this connected subset inherits that fixed order and
    // every later pass is independent of input and of `HashMap` iteration order.
    let nodes: Vec<usize> = (0..g.node_count()).filter(|&i| g.degree(i) > 0).collect();
    if nodes.is_empty() {
        return Vec::new();
    }

    // ── Label propagation. Each node's label starts as its own UID; `labels` is keyed
    // by graph index so a node's neighbours resolve in O(1). An isolated node keeps a
    // never-read slot — it is neither processed nor any node's neighbour. ──
    let mut labels: Vec<&str> = (0..g.node_count()).map(|i| g.uid(i)).collect();

    for _ in 0..MAX_ROUNDS {
        // Synchronous: compute every node's next label against THIS round's
        // labelling, then swap in all at once. No within-round feedback, so the
        // result can't depend on node visitation order.
        let mut next: Vec<&str> = labels.clone();
        let mut changed = false;
        for &i in &nodes {
            // Tally neighbour labels (+ the node's own, so it never flips away from
            // itself without a strictly more popular neighbour label). The neighbour
            // indices are UID-sorted, so the tally is built in fixed order.
            let mut tally: HashMap<&str, usize> = HashMap::new();
            *tally.entry(labels[i]).or_insert(0) += 1;
            for &nb in g.neighbours(i) {
                *tally.entry(labels[nb]).or_insert(0) += 1;
            }
            // Winner: max count, ties broken by the lexicographically SMALLEST
            // label — the determinism pin (no dependence on map iteration order).
            let best = tally
                .into_iter()
                .max_by(|(la, ca), (lb, cb)| ca.cmp(cb).then_with(|| lb.cmp(la)))
                .map_or(labels[i], |(l, _)| l);
            if best != labels[i] {
                changed = true;
            }
            next[i] = best;
        }
        labels = next;
        if !changed {
            break; // fixed point — no further rounds can change anything
        }
    }

    // ── Group connected nodes by their final label into communities. ──
    let mut groups: HashMap<&str, Vec<&Entity>> = HashMap::new();
    for &i in &nodes {
        // Every connected node resolves in `by_uid` by construction.
        if let Some(&ent) = by_uid.get(g.uid(i)) {
            groups.entry(labels[i]).or_default().push(ent);
        }
    }

    // Within each community, sort members by UID so `uids` is order-independent.
    let mut communities: Vec<Vec<&Entity>> = groups.into_values().collect();
    for members in &mut communities {
        members.sort_by(|a, b| a.uid.cmp(&b.uid));
    }

    // Deterministic output order: largest first, ties broken by smallest member
    // UID (every community has ≥ 1 member, so `[0]` is safe). `id` follows.
    communities.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a[0].uid.cmp(&b[0].uid)));

    communities
        .iter()
        .enumerate()
        .map(|(id, members)| Community::from_members(id, members))
        .collect()
}

#[cfg(test)]
mod tests;
