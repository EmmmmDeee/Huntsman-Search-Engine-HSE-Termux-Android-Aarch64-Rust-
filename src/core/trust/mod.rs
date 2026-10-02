//! `core::trust` — confidence/trust propagation across the relation graph.
//!
//! # What this answers
//! Which discovered entities are most strongly *corroborated by their position
//! in the network*? A high-confidence anchor — the subject and its
//! directly-evidenced identifiers — should lend trust to the entities tightly
//! connected to it, and that lent trust should attenuate with graph distance.
//! This surfaces, for the analyst, the nodes the network itself vouches for: a
//! handle two hops from a Verified subject through strong edges is more
//! believable than the same handle floating alone.
//!
//! # What this is NOT
//! This is a **read-only analytical ranking** over HSE's own discovered
//! public-OSINT graph. It does NOT mutate
//! [`Entity::confidence`](crate::core::entity::Entity::confidence) or any other
//! entity field — it returns a separate [`TrustScore`] list — and it performs
//! **no traversal of any external system**: the only graph it walks is the
//! persisted `(entities, relations)` snapshot already collected. It is therefore
//! **non-corroborating**: a propagated trust score is a navigational/ranking aid,
//! never a new independent source, and must never feed back into
//! [`Entity::c_effective`](crate::core::entity::Entity::c_effective) or the
//! corroboration count. (Compare the deliberately non-corroborating evidence
//! passes in [`crate::core::entity::is_non_corroborating_source`].)
//!
//! # Algorithm — damped propagation (personalized-PageRank style)
//! Like [`crate::core::network`], this is pure synthesis over a
//! `(entities, relations)` snapshot: no store access, no engine access, no I/O,
//! so it is deterministic and unit-testable.
//!
//! Build the **undirected** adjacency from the relations whose *both* endpoints
//! are present in `entities` (dangling endpoints and self-loops are skipped,
//! exactly as [`crate::core::network::synthesize`] does). Each edge carries a
//! weight = the relation's `confidence` clamped to `[0, 1]`; when several
//! relations join the same unordered pair we keep the **maximum** confidence (the
//! strongest attested link between two entities is the one that should carry
//! trust — taking the max is also commutative, so it cannot depend on relation
//! order).
//!
//! Seed every node's trust with its **intrinsic** confidence
//! [`Entity::c_effective`](crate::core::entity::Entity::c_effective) — the
//! cross-source effective confidence the rest of the engine already trusts as a
//! node's standalone believability. Then iterate, for a bounded number of rounds,
//! the damped update
//!
//! ```text
//! trust'(v) = (1 - DAMPING) * seed(v) + DAMPING * weighted_avg(trust(u) for u ~ v)
//! ```
//!
//! where `weighted_avg` weights each neighbour `u` by the `v–u` edge weight. The
//! `(1 - DAMPING) * seed` teleport term re-anchors every node to its own intrinsic
//! confidence on every round, so trust *flows from* high-confidence anchors and
//! *decays geometrically* with each additional hop away from them (a node `k`
//! hops from the anchor receives roughly `DAMPING^k` of the anchor's surplus) —
//! which is exactly the "attenuates with distance" behaviour we want. It is the
//! standard random-surfer / personalized-PageRank recurrence, restricted to an
//! intrinsic-confidence personalization vector and a confidence-weighted graph.
//!
//! # Why bounded — and Termux-appropriate
//! The iteration is **doubly bounded**: it runs at most [`MAX_ROUNDS`] rounds, and
//! converges early as soon as the largest per-node change in a round drops below
//! [`EPSILON`]. The damped recurrence is a contraction with factor `DAMPING < 1`,
//! so the per-round change shrinks geometrically and a handful of rounds suffices;
//! the hard [`MAX_ROUNDS`] cap guarantees termination even on a pathological graph.
//! Each round is `O(V + E)`, so total work is `O(MAX_ROUNDS · (V + E))` with **no
//! allocation inside the loop** beyond two reused score vectors — cheap and
//! predictable on a low-RAM, no-root Termux aarch64 device. This is deliberately
//! chosen over heavier spectral methods (eigenvector centrality, a full PageRank
//! solve via repeated sparse mat-vec to tight tolerance, spectral clustering):
//! those need either many more iterations to a tight eigen-tolerance or
//! dense/decomposition workspace that does not fit the device budget, and their
//! floating-point reductions are far harder to make bit-reproducible. A fixed,
//! short, contraction-bounded sweep gives the same "trust radiates from anchors"
//! signal at a fraction of the cost, deterministically.
//!
//! # Determinism (architecture invariant)
//! Like the rest of `core::relation`/`core::network`, this is **pure, reproducible
//! math** — no LLM, no free inference. The result is identical across runs and
//! **independent of the order** of the `entities` and `relations` slices:
//!   - nodes are processed in ascending-UID order;
//!   - each node's neighbour list is sorted by UID, and the weighted sum is
//!     accumulated in that fixed order (floating-point addition is not
//!     associative, so a fixed summation order is what makes the score
//!     bit-reproducible);
//!   - the round/epsilon bounds are fixed constants;
//!   - the output is sorted by score descending, then UID ascending, a total
//!     order with no ties left to input chance.
//!
//! Isolated nodes (no surviving edge) have no neighbours, so their update is
//! `(1 - DAMPING) * seed + DAMPING * seed = seed`: **they keep their intrinsic
//! seed unchanged**, which is the correct "the network neither vouches for nor
//! against an unconnected node" behaviour.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::core::entity::Entity;
use crate::core::relation::Relation;

/// Damping (teleport) factor of the propagation — the share of a node's updated
/// trust that comes from its neighbours, with the remaining `1 - DAMPING`
/// re-anchored to the node's own intrinsic seed each round.
///
/// At `0.85` (the classic PageRank value) trust carries strongly across an edge
/// yet still attenuates with distance: the anchor's *surplus* over a node's own
/// seed decays by ~`DAMPING` per hop, so a direct neighbour is lifted markedly, a
/// two-hop node less, and the lift is negligible by a few hops out.
pub const DAMPING: f64 = 0.85;

/// Hard upper bound on propagation rounds. The damped update is a contraction
/// (factor [`DAMPING`] `< 1`), so the per-round change decays geometrically and
/// the [`EPSILON`] early-exit almost always fires first; this cap is the
/// guaranteed termination bound that keeps the cost fixed and small on Termux.
pub const MAX_ROUNDS: usize = 20;

/// Convergence epsilon. When the largest per-node trust change within a round is
/// below this, the scores have effectively stabilised and the iteration stops —
/// keeping the common case to a handful of `O(V + E)` rounds.
pub const EPSILON: f64 = 1e-6;

/// A single entity's propagated trust — the believability the network confers on
/// it given its position relative to the high-confidence anchors. **Read-only
/// analysis**: this never mutates the underlying [`Entity`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TrustScore {
    /// The entity this score is for (its [`Entity::uid`](crate::core::entity::Entity::uid)).
    pub uid: String,
    /// Propagated trust in `[0, 1]` — high where the node is itself confident
    /// and/or tightly bound to confident anchors, attenuating with graph distance.
    pub score: f64,
}

/// Propagate confidence/trust across the undirected relation graph and return a
/// [`TrustScore`] per entity, ranked most-trusted first.
///
/// Pure, deterministic and bounded — see the [module docs](self) for the
/// algorithm, the determinism guarantees, and why it is cheap on Termux. The
/// result is sorted by `score` descending then `uid` ascending, every score is
/// clamped to `[0, 1]`, and isolated nodes keep their intrinsic
/// [`Entity::c_effective`](crate::core::entity::Entity::c_effective) seed.
///
/// Robust to bad input: a relation endpoint whose UID is not present in
/// `entities` is skipped (never panics), as is a self-loop. Empty input yields an
/// empty result.
///
/// This does **not** mutate any [`Entity`] — it is a read-only, non-corroborating
/// ranking aid (see the module docs).
#[must_use]
pub fn propagate(entities: &[Entity], relations: &[Relation]) -> Vec<TrustScore> {
    // Stable node index in ascending-UID order. A `BTreeMap` gives both the
    // deduplicated UID set and the sorted iteration order in one structure, so
    // every later loop walks nodes in the same deterministic order regardless of
    // the input slice order. (Two entities sharing a UID — they would have merged
    // upstream — collapse to one node; the last seen wins its seed, but their
    // c_effective is identical by construction so it does not matter.)
    let mut index: BTreeMap<&str, usize> = BTreeMap::new();
    for e in entities {
        index.insert(e.uid.as_str(), 0);
    }
    let n = index.len();
    if n == 0 {
        return Vec::new();
    }
    // Assign dense indices in ascending-UID order and remember each node's UID.
    let mut uids: Vec<&str> = Vec::with_capacity(n);
    for (i, (uid, slot)) in index.iter_mut().enumerate() {
        *slot = i;
        uids.push(uid);
    }

    // Intrinsic trust seed per node = its cross-source effective confidence.
    // Look the entity up by UID so a seed is matched to its node regardless of
    // the order `entities` arrived in.
    let by_uid: BTreeMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
    let seed: Vec<f64> = uids
        .iter()
        .map(|uid| by_uid[uid].c_effective().clamp(0.0, 1.0))
        .collect();

    // Undirected, max-confidence-combined adjacency keyed by the unordered pair
    // of node indices. Skip dangling endpoints (UID absent from `entities`) and
    // self-loops, exactly as `core::network` does. Keeping the max confidence per
    // pair is commutative, so the adjacency does not depend on relation order.
    let mut edge_weight: BTreeMap<(usize, usize), f64> = BTreeMap::new();
    for r in relations {
        let (Some(&a), Some(&b)) = (index.get(r.from_uid.as_str()), index.get(r.to_uid.as_str()))
        else {
            continue; // dangling endpoint — skip, don't panic
        };
        if a == b {
            continue; // self-loop is not a propagation edge
        }
        let key = if a < b { (a, b) } else { (b, a) };
        let w = r.confidence.clamp(0.0, 1.0);
        edge_weight
            .entry(key)
            .and_modify(|cur| *cur = cur.max(w))
            .or_insert(w);
    }

    // Per-node neighbour lists, each sorted by neighbour UID so the weighted sum
    // is accumulated in a fixed order (floating-point addition is not associative,
    // so fixing the order is what makes the scores bit-reproducible). Building
    // from the sorted `edge_weight` map and pushing both directions yields lists
    // already in ascending neighbour-index order — which is ascending neighbour
    // UID order, since indices were assigned in ascending-UID order.
    let mut neighbours: Vec<Vec<(usize, f64)>> = vec![Vec::new(); n];
    for (&(a, b), &w) in &edge_weight {
        neighbours[a].push((b, w));
        neighbours[b].push((a, w));
    }
    for list in &mut neighbours {
        list.sort_by_key(|x| x.0);
    }

    // Damped propagation. `cur` starts at the seed; each round computes `next`
    // from `cur` and swaps. Two reused buffers — no allocation inside the loop.
    let mut cur = seed.clone();
    let mut next = vec![0.0_f64; n];
    for _ in 0..MAX_ROUNDS {
        let mut max_delta = 0.0_f64;
        for v in 0..n {
            let nbrs = &neighbours[v];
            let new_v = if nbrs.is_empty() {
                // Isolated node: weighted_avg over an empty neighbourhood is, by
                // convention, the node's own current trust, so the update reduces
                // to `(1-D)*seed + D*seed = seed`. Pin it to the seed exactly
                // (seeds never change) so an isolated node provably keeps its seed.
                seed[v]
            } else {
                // weighted_avg(neighbour trust) = Σ w·trust / Σ w, summed in the
                // fixed (sorted) neighbour order for reproducibility. Σ w > 0 here
                // because every stored edge weight that contributed a neighbour is
                // ≥ 0 and at least one is > 0 only if confidences are > 0; guard
                // the all-zero-weight case by falling back to the seed (no usable
                // neighbour signal), keeping the result finite and deterministic.
                let mut wsum = 0.0_f64;
                let mut acc = 0.0_f64;
                for &(u, w) in nbrs {
                    wsum += w;
                    acc += w * cur[u];
                }
                if wsum > 0.0 {
                    let weighted_avg = acc / wsum;
                    DAMPING.mul_add(weighted_avg, (1.0 - DAMPING) * seed[v])
                } else {
                    seed[v]
                }
            };
            let new_v = new_v.clamp(0.0, 1.0);
            max_delta = max_delta.max((new_v - cur[v]).abs());
            next[v] = new_v;
        }
        std::mem::swap(&mut cur, &mut next);
        if max_delta < EPSILON {
            break; // converged — further rounds would not move any score
        }
    }

    // Emit one score per node, then rank: score DESC, UID ASC (a total order, so
    // the result is stable and fully determined). `total_cmp` orders the f64s
    // without the partial-order pitfalls of `<`/`>`.
    let mut out: Vec<TrustScore> = uids
        .iter()
        .enumerate()
        .map(|(i, uid)| TrustScore {
            uid: (*uid).to_string(),
            score: cur[i],
        })
        .collect();
    out.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.uid.cmp(&b.uid)));
    out
}

#[cfg(test)]
mod tests;
