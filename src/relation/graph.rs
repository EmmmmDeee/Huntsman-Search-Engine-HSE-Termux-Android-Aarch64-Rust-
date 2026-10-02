use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet, VecDeque};

use crate::union_find::UnionFind;

use super::types::{Relation, RelationKind};

fn identity_edges(relations: &[Relation]) -> HashMap<&str, Vec<&Relation>> {
    let mut out = HashMap::<&str, Vec<&Relation>>::new();
    for relation in relations
        .iter()
        .filter(|relation| relation.kind.binds_identity())
    {
        out.entry(relation.from_uid.as_str())
            .or_default()
            .push(relation);
        out.entry(relation.to_uid.as_str())
            .or_default()
            .push(relation);
    }
    out
}

#[must_use]
pub fn provenance_chain(start_uid: &str, relations: &[Relation]) -> Vec<String> {
    let mut parents = relations
        .iter()
        .filter(|relation| relation.kind == RelationKind::DerivedFrom)
        .collect::<Vec<_>>();
    parents.sort_by(|left, right| {
        right
            .confidence
            .partial_cmp(&left.confidence)
            .unwrap_or(Ordering::Equal)
            .then(left.to_uid.cmp(&right.to_uid))
    });
    let mut seen = HashSet::<String>::new();
    let mut chain = vec![start_uid.to_owned()];
    seen.insert(start_uid.to_owned());
    let mut current = start_uid.to_owned();
    while let Some(next) = parents
        .iter()
        .find(|relation| relation.from_uid == current && !seen.contains(&relation.to_uid))
        .map(|relation| relation.to_uid.clone())
    {
        seen.insert(next.clone());
        chain.push(next.clone());
        current = next;
    }
    chain
}

#[must_use]
pub fn strongest_path(
    start_uid: &str,
    end_uid: &str,
    relations: &[Relation],
    max_depth: usize,
) -> Option<Vec<String>> {
    #[derive(Clone, Debug)]
    struct State {
        width: f64,
        depth: usize,
        node: String,
        path: Vec<String>,
    }
    impl PartialEq for State {
        fn eq(&self, other: &Self) -> bool {
            self.width == other.width && self.depth == other.depth && self.node == other.node
        }
    }
    impl Eq for State {}
    impl PartialOrd for State {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }
    impl Ord for State {
        fn cmp(&self, other: &Self) -> Ordering {
            self.width
                .partial_cmp(&other.width)
                .unwrap_or(Ordering::Equal)
                .then_with(|| other.depth.cmp(&self.depth))
        }
    }

    let adj = identity_edges(relations);
    let mut heap = BinaryHeap::new();
    heap.push(State {
        width: 1.0,
        depth: 0,
        node: start_uid.to_owned(),
        path: vec![start_uid.to_owned()],
    });
    let mut best = HashMap::<String, f64>::new();
    while let Some(state) = heap.pop() {
        if state.node == end_uid {
            return Some(state.path);
        }
        if state.depth >= max_depth {
            continue;
        }
        if best
            .get(state.node.as_str())
            .is_some_and(|seen| *seen >= state.width)
        {
            continue;
        }
        best.insert(state.node.clone(), state.width);
        for relation in adj.get(state.node.as_str()).into_iter().flatten() {
            let next = if relation.from_uid == state.node {
                relation.to_uid.clone()
            } else {
                relation.from_uid.clone()
            };
            if state.path.contains(&next) {
                continue;
            }
            let mut path = state.path.clone();
            path.push(next.clone());
            heap.push(State {
                width: state.width.min(relation.confidence),
                depth: state.depth + 1,
                node: next,
                path,
            });
        }
    }
    None
}

#[must_use]
pub fn disjoint_pathways(start_uid: &str, end_uid: &str, relations: &[Relation]) -> usize {
    let mut remaining = relations.to_vec();
    let mut count = 0;
    while let Some(path) = strongest_path(start_uid, end_uid, &remaining, 8) {
        if path.len() < 2 {
            break;
        }
        count += 1;
        let mut used = BTreeSet::<(String, String)>::new();
        for pair in path.windows(2) {
            used.insert((pair[0].clone(), pair[1].clone()));
            used.insert((pair[1].clone(), pair[0].clone()));
        }
        remaining.retain(|relation| {
            !used.contains(&(relation.from_uid.clone(), relation.to_uid.clone()))
        });
    }
    count
}

#[must_use]
pub fn resolve_identity_clusters(relations: &[Relation]) -> Vec<Vec<String>> {
    let mut ids = relations
        .iter()
        .filter(|relation| relation.kind.binds_identity())
        .flat_map(|relation| [relation.from_uid.clone(), relation.to_uid.clone()])
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    let index = ids
        .iter()
        .enumerate()
        .map(|(i, id)| (id.clone(), i))
        .collect::<HashMap<_, _>>();
    let mut uf = UnionFind::new(ids.len());
    for relation in relations
        .iter()
        .filter(|relation| relation.kind.binds_identity())
    {
        uf.union(index[&relation.from_uid], index[&relation.to_uid]);
    }
    let mut groups = uf
        .groups()
        .into_iter()
        .map(|group| {
            group
                .into_iter()
                .map(|idx| ids[idx].clone())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    groups.sort();
    groups
}

#[must_use]
pub fn connection_templates(relations: &[Relation]) -> BTreeMap<Vec<RelationKind>, usize> {
    let adj = identity_edges(relations);
    let nodes = adj.keys().copied().collect::<Vec<_>>();
    let mut counts = BTreeMap::<Vec<RelationKind>, usize>::new();
    for left in 0..nodes.len() {
        for right in left + 1..nodes.len() {
            let Some(path) = strongest_path(nodes[left], nodes[right], relations, 4) else {
                continue;
            };
            let mut kinds = Vec::new();
            for pair in path.windows(2) {
                if let Some(relation) = relations.iter().find(|relation| {
                    (relation.from_uid == pair[0] && relation.to_uid == pair[1])
                        || (relation.from_uid == pair[1] && relation.to_uid == pair[0])
                }) {
                    kinds.push(relation.kind);
                }
            }
            if !kinds.is_empty() {
                *counts.entry(kinds).or_default() += 1;
            }
        }
    }
    counts
}

#[must_use]
pub fn connection_brokers(relations: &[Relation]) -> Vec<(String, usize)> {
    let adj = identity_edges(relations);
    let nodes = adj.keys().copied().collect::<Vec<_>>();
    let mut scores = BTreeMap::<String, usize>::new();
    for left in 0..nodes.len() {
        for right in left + 1..nodes.len() {
            if let Some(path) = strongest_path(nodes[left], nodes[right], relations, 6) {
                for node in path.into_iter().skip(1).rev().skip(1) {
                    *scores.entry(node).or_default() += 1;
                }
            }
        }
    }
    let mut ranked = scores.into_iter().collect::<Vec<_>>();
    ranked.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
    ranked
}

#[must_use]
pub fn reachable_count(start_uid: &str, relations: &[Relation]) -> usize {
    let adj = identity_edges(relations);
    let mut seen = HashSet::<String>::from([start_uid.to_owned()]);
    let mut queue = VecDeque::from([start_uid.to_owned()]);
    while let Some(node) = queue.pop_front() {
        for relation in adj.get(node.as_str()).into_iter().flatten() {
            let next = if relation.from_uid == node {
                relation.to_uid.clone()
            } else {
                relation.from_uid.clone()
            };
            if seen.insert(next.clone()) {
                queue.push_back(next);
            }
        }
    }
    seen.len().saturating_sub(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_chain_walks_back_safely() {
        let relations = vec![
            Relation::new("child", "root", RelationKind::DerivedFrom, 0.9, "s"),
            Relation::new("grand", "child", RelationKind::DerivedFrom, 0.9, "s"),
        ];
        assert_eq!(
            provenance_chain("grand", &relations),
            ["grand", "child", "root"]
        );
        let cycle = vec![
            Relation::new("a", "b", RelationKind::DerivedFrom, 0.9, "s"),
            Relation::new("b", "a", RelationKind::DerivedFrom, 0.9, "s"),
        ];
        assert_eq!(provenance_chain("a", &cycle), ["a", "b"]);
    }

    #[test]
    fn strongest_path_and_clusters_follow_identity_edges() {
        let relations = vec![
            Relation::new("a", "b", RelationKind::AliasOf, 0.8, "s"),
            Relation::new("b", "c", RelationKind::IdentifiedBy, 0.7, "s"),
            Relation::new("c", "d", RelationKind::AssociatedWith, 0.9, "s"),
        ];
        assert_eq!(
            strongest_path("a", "c", &relations, 4).unwrap(),
            ["a", "b", "c"]
        );
        assert_eq!(reachable_count("a", &relations), 2);
        assert_eq!(
            resolve_identity_clusters(&relations),
            vec![vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]]
        );
    }
}
