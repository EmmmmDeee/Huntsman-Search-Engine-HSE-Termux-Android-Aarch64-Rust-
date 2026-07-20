//! Disjoint-set (union-find) — the one canonical connected-components primitive.
//!
//! Four rules and diagnostics used to hand-roll this exact structure inline
//! (coordinate proximity clustering, identity-path clustering, credential-reuse
//! closure AU-121, and shared-infrastructure closure AU-116). They all agreed on
//! the algorithm — a flat `Vec<usize>` parent forest, path-halving on `find`, and
//! union by reparenting one root onto the other — but each carried its own copy,
//! so a fix or optimisation to one never reached the rest. This module is the
//! single source of truth they now delegate to.
//!
//! The component partition a union-find computes depends *only* on which pairs
//! were unioned — never on the `find` strategy (path-halving vs recursive
//! compression only reshapes the trees) nor on the union direction (which root
//! becomes the representative). Every former call site used the component root
//! purely as an opaque grouping key, so this primitive is a byte-for-byte
//! drop-in: identical components, identical downstream output.
//!
//! Pure, deterministic, and dependency-free — no I/O, no allocation beyond the
//! parent vector, same leaf category as [`super::geometry`]. That is why
//! `core`'s correlation rules are permitted to import it directly (see the
//! `core_does_not_import_util_directly` architecture guard).

use std::collections::BTreeMap;

/// A disjoint-set forest over the contiguous ids `0..n`.
///
/// Construct with [`UnionFind::new`], merge with [`UnionFind::union`], and read
/// the partition back with [`UnionFind::find`] (per element) or
/// [`UnionFind::components`] (the whole grouping at once).
///
/// `find` mutates the forest (path-halving), so the read methods take `&mut
/// self` — hold the value mutably for the lifetime of a clustering pass.
#[derive(Debug, Clone)]
pub struct UnionFind {
    /// `parent[i]` is `i`'s parent in the forest; a root is its own parent.
    parent: Vec<usize>,
}

impl UnionFind {
    /// A forest of `n` singleton sets: every id `0..n` is initially its own root.
    #[must_use]
    pub fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
        }
    }

    /// The canonical representative (root) of the set containing `x`,
    /// compressing the path via path-halving as it climbs.
    ///
    /// # Panics
    /// Panics if `x >= self.len()` (out-of-range id).
    pub fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            // Path-halving: point x at its grandparent, then step up. Amortised
            // near-constant without the second pass a full compression needs.
            self.parent[x] = self.parent[self.parent[x]];
            x = self.parent[x];
        }
        x
    }

    /// Merge the set containing `a` into the set containing `b`. Afterwards
    /// `self.find(a) == self.find(b)`. Returns `true` when the two were in
    /// different sets (a merge happened), `false` when already joined.
    ///
    /// Union direction is fixed: the root of `a`'s tree is reparented onto the
    /// root of `b`'s tree (`parent[find(a)] = find(b)`) — exactly what the four
    /// former hand-rolled call sites did, so the representative chosen for each
    /// component is identical and every root-keyed grouping stays byte-stable.
    ///
    /// # Panics
    /// Panics if `a` or `b` is out of range (see [`UnionFind::find`]).
    pub fn union(&mut self, a: usize, b: usize) -> bool {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra == rb {
            return false;
        }
        self.parent[ra] = rb;
        true
    }

    /// Whether `a` and `b` currently belong to the same set.
    ///
    /// # Panics
    /// Panics if `a` or `b` is out of range (see [`UnionFind::find`]).
    pub fn connected(&mut self, a: usize, b: usize) -> bool {
        self.find(a) == self.find(b)
    }

    /// Every id grouped by its component root: `root -> ascending member ids`.
    ///
    /// Both the map keys and each member vector are ascending, so iteration
    /// order is deterministic and independent of the order unions were applied.
    pub fn components(&mut self) -> BTreeMap<usize, Vec<usize>> {
        let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for i in 0..self.parent.len() {
            let root = self.find(i);
            // `i` ascends, so each group's vector is pushed in ascending order.
            groups.entry(root).or_default().push(i);
        }
        groups
    }

    /// The number of ids in the forest (its fixed universe size).
    #[must_use]
    pub fn len(&self) -> usize {
        self.parent.len()
    }

    /// Whether the forest is empty (`new(0)`).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.parent.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn singletons_are_their_own_roots() {
        let mut uf = UnionFind::new(4);
        for i in 0..4 {
            assert_eq!(uf.find(i), i);
        }
        assert_eq!(uf.len(), 4);
        assert!(!uf.is_empty());
        assert!(UnionFind::new(0).is_empty());
    }

    #[test]
    fn union_joins_and_reports_novelty() {
        let mut uf = UnionFind::new(3);
        assert!(uf.union(0, 1)); // first merge — novel
        assert!(!uf.union(0, 1)); // already joined — no-op
        assert!(uf.connected(0, 1));
        assert!(!uf.connected(0, 2));
    }

    #[test]
    fn union_is_transitive() {
        let mut uf = UnionFind::new(5);
        uf.union(0, 1);
        uf.union(1, 2);
        uf.union(3, 4);
        assert!(uf.connected(0, 2)); // 0-1-2 chain
        assert!(uf.connected(3, 4));
        assert!(!uf.connected(2, 3)); // two disjoint components
        assert_eq!(uf.find(0), uf.find(2));
    }

    #[test]
    fn components_are_deterministic_and_partition_the_universe() {
        let mut uf = UnionFind::new(6);
        uf.union(0, 2);
        uf.union(4, 2);
        uf.union(1, 5);
        let comps = uf.components();
        // Every id present exactly once, groups internally ascending.
        let total: usize = comps.values().map(Vec::len).sum();
        assert_eq!(total, 6);
        let mut sets: Vec<Vec<usize>> = comps.into_values().collect();
        sets.sort();
        assert_eq!(sets, vec![vec![0, 2, 4], vec![1, 5], vec![3]]);
    }

    #[test]
    fn partition_is_invariant_to_union_order_and_direction() {
        // Same edge set applied in different orders/directions must yield the
        // same partition — the property every former call site relied on.
        let edges_a = [(0, 1), (2, 3), (1, 2)];
        let edges_b = [(3, 2), (1, 0), (2, 1)];
        let partition = |edges: &[(usize, usize)]| {
            let mut uf = UnionFind::new(4);
            for &(a, b) in edges {
                uf.union(a, b);
            }
            let mut sets: Vec<Vec<usize>> = uf.components().into_values().collect();
            sets.sort();
            sets
        };
        assert_eq!(partition(&edges_a), partition(&edges_b));
        assert_eq!(partition(&edges_a), vec![vec![0, 1, 2, 3]]);
    }

    #[test]
    fn find_survives_deep_chains_via_path_halving() {
        // A degenerate chain 0<-1<-2<-...<-99; find must still resolve to one
        // root without overflowing (path-halving is iterative, not recursive).
        let mut uf = UnionFind::new(100);
        for i in 1..100 {
            uf.union(i, i - 1);
        }
        let root = uf.find(99);
        for i in 0..100 {
            assert_eq!(uf.find(i), root);
        }
    }
}
