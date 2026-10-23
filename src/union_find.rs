//! Deterministic disjoint-set union.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<u8>,
}

impl UnionFind {
    #[must_use]
    pub fn new(size: usize) -> Self {
        Self {
            parent: (0..size).collect(),
            rank: vec![0; size],
        }
    }

    pub fn find(&mut self, mut index: usize) -> usize {
        while self.parent[index] != index {
            self.parent[index] = self.parent[self.parent[index]];
            index = self.parent[index];
        }
        index
    }

    pub fn union(&mut self, left: usize, right: usize) -> bool {
        let mut left = self.find(left);
        let mut right = self.find(right);
        if left == right {
            return false;
        }
        if self.rank[left] < self.rank[right] {
            std::mem::swap(&mut left, &mut right);
        }
        self.parent[right] = left;
        if self.rank[left] == self.rank[right] {
            self.rank[left] = self.rank[left].saturating_add(1);
        }
        true
    }

    /// Every set in ascending index order, the sets ordered by their smallest index, so the
    /// result depends only on which indices were joined, not on the order of the unions.
    pub fn groups(&mut self) -> Vec<Vec<usize>> {
        let mut position: BTreeMap<usize, usize> = BTreeMap::new();
        let mut groups: Vec<Vec<usize>> = Vec::new();
        for index in 0..self.parent.len() {
            let root = self.find(index);
            let at = *position.entry(root).or_insert_with(|| {
                groups.push(Vec::new());
                groups.len() - 1
            });
            groups[at].push(index);
        }
        groups
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unions_and_groups_are_deterministic() {
        let mut uf = UnionFind::new(5);
        assert!(uf.union(0, 1));
        assert!(uf.union(2, 3));
        assert!(uf.union(1, 2));
        assert!(!uf.union(0, 3));
        assert_eq!(uf.groups(), vec![vec![0, 1, 2, 3], vec![4]]);
    }

    #[test]
    fn group_order_does_not_depend_on_union_order() {
        let mut forward = UnionFind::new(4);
        forward.union(0, 3);
        forward.union(1, 2);
        let mut reversed = UnionFind::new(4);
        reversed.union(3, 0);
        reversed.union(2, 1);
        assert_eq!(forward.groups(), vec![vec![0, 3], vec![1, 2]]);
        assert_eq!(reversed.groups(), forward.groups());
    }
}
