//! Deterministic undirected entity graph and relation types.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::entity::{Entity, Evidence};

pub const UNREACHABLE: usize = usize::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    SameAs,
    AliasOf,
    AssociatedWith,
    LocatedAt,
    Uses,
    Owns,
    MemberOf,
    MentionedWith,
    ExposedWith,
    Supports,
    Contradicts,
}

impl RelationKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SameAs => "same_as",
            Self::AliasOf => "alias_of",
            Self::AssociatedWith => "associated_with",
            Self::LocatedAt => "located_at",
            Self::Uses => "uses",
            Self::Owns => "owns",
            Self::MemberOf => "member_of",
            Self::MentionedWith => "mentioned_with",
            Self::ExposedWith => "exposed_with",
            Self::Supports => "supports",
            Self::Contradicts => "contradicts",
        }
    }
}

impl std::fmt::Display for RelationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityRelation {
    pub from_uid: String,
    pub to_uid: String,
    pub kind: RelationKind,
    pub confidence: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
}

impl EntityRelation {
    #[must_use]
    pub fn new(
        from_uid: impl Into<String>,
        to_uid: impl Into<String>,
        kind: RelationKind,
        confidence: f64,
    ) -> Self {
        Self {
            from_uid: from_uid.into(),
            to_uid: to_uid.into(),
            kind,
            confidence: if confidence.is_finite() {
                confidence.clamp(0.0, 1.0)
            } else {
                0.0
            },
            label: None,
            evidence: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    #[must_use]
    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GraphEdge {
    pub to: usize,
    pub relation_kinds: Vec<RelationKind>,
    pub max_confidence: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Graph {
    uids: Vec<String>,
    index: HashMap<String, usize>,
    adj: Vec<Vec<usize>>,
    edge_map: HashMap<(usize, usize), GraphEdge>,
}

impl Graph {
    #[must_use]
    pub fn build(entities: &[Entity], relations: &[EntityRelation]) -> Self {
        let mut uids: Vec<String> = entities.iter().map(|entity| entity.uid.clone()).collect();
        uids.sort_unstable();
        uids.dedup();
        let index: HashMap<String, usize> = uids
            .iter()
            .enumerate()
            .map(|(i, uid)| (uid.clone(), i))
            .collect();
        let mut adj_sets: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); uids.len()];
        let mut pairs: BTreeMap<(usize, usize), (BTreeSet<RelationKind>, f64)> = BTreeMap::new();
        for relation in relations {
            let (Some(&left), Some(&right)) = (
                index.get(relation.from_uid.as_str()),
                index.get(relation.to_uid.as_str()),
            ) else {
                continue;
            };
            if left == right {
                continue;
            }
            let pair = if left < right {
                (left, right)
            } else {
                (right, left)
            };
            adj_sets[left].insert(right);
            adj_sets[right].insert(left);
            let (kinds, confidence) = pairs.entry(pair).or_insert_with(|| (BTreeSet::new(), 0.0));
            kinds.insert(relation.kind);
            *confidence = confidence.max(relation.confidence);
        }
        let adj = adj_sets
            .into_iter()
            .map(|set| set.into_iter().collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let mut edge_map = HashMap::new();
        for ((left, right), (kinds, max_confidence)) in pairs {
            let mut relation_kinds = kinds.into_iter().collect::<Vec<_>>();
            relation_kinds.sort_by_key(|kind| kind.as_str());
            let edge = GraphEdge {
                to: right,
                relation_kinds,
                max_confidence,
            };
            edge_map.insert((left, right), edge.clone());
            edge_map.insert((right, left), GraphEdge { to: left, ..edge });
        }
        Self {
            uids,
            index,
            adj,
            edge_map,
        }
    }

    #[must_use]
    pub fn node_count(&self) -> usize {
        self.uids.len()
    }

    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edge_map.len() / 2
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.uids.is_empty()
    }

    #[must_use]
    pub fn uid(&self, index: usize) -> &str {
        &self.uids[index]
    }

    #[must_use]
    pub fn index_of(&self, uid: &str) -> Option<usize> {
        self.index.get(uid).copied()
    }

    #[must_use]
    pub fn neighbours(&self, index: usize) -> &[usize] {
        &self.adj[index]
    }

    #[must_use]
    pub fn degree(&self, index: usize) -> usize {
        self.adj[index].len()
    }

    #[must_use]
    pub fn edge(&self, from: usize, to: usize) -> Option<&GraphEdge> {
        self.edge_map.get(&(from, to))
    }

    #[must_use]
    pub fn edge_pairs(&self) -> Vec<(usize, usize)> {
        let mut pairs = self
            .edge_map
            .keys()
            .filter(|(left, right)| left < right)
            .copied()
            .collect::<Vec<_>>();
        pairs.sort_unstable();
        pairs
    }

    #[must_use]
    pub fn bfs_levels(&self, source: usize) -> Vec<usize> {
        let mut distances = vec![UNREACHABLE; self.uids.len()];
        if source >= self.uids.len() {
            return distances;
        }
        distances[source] = 0;
        let mut queue = VecDeque::from([source]);
        while let Some(node) = queue.pop_front() {
            for &next in &self.adj[node] {
                if distances[next] == UNREACHABLE {
                    distances[next] = distances[node] + 1;
                    queue.push_back(next);
                }
            }
        }
        distances
    }

    #[must_use]
    pub fn connected_components(&self) -> Vec<Vec<usize>> {
        let mut seen = vec![false; self.uids.len()];
        let mut components = Vec::new();
        for start in 0..self.uids.len() {
            if seen[start] {
                continue;
            }
            let mut component = Vec::new();
            let mut queue = VecDeque::from([start]);
            seen[start] = true;
            while let Some(node) = queue.pop_front() {
                component.push(node);
                for &next in &self.adj[node] {
                    if !seen[next] {
                        seen[next] = true;
                        queue.push_back(next);
                    }
                }
            }
            component.sort_unstable();
            components.push(component);
        }
        components
    }

    #[must_use]
    pub fn coreness(&self) -> Vec<usize> {
        let n = self.node_count();
        let mut remaining = vec![true; n];
        let mut degree: Vec<usize> = (0..n).map(|index| self.degree(index)).collect();
        let mut out = vec![0; n];
        let mut current_core = 0;
        for _ in 0..n {
            let Some((node, min_degree)) = (0..n)
                .filter(|&index| remaining[index])
                .map(|index| (index, degree[index]))
                .min_by_key(|&(index, deg)| (deg, index))
            else {
                break;
            };
            remaining[node] = false;
            current_core = current_core.max(min_degree);
            out[node] = current_core;
            for &neighbour in &self.adj[node] {
                if remaining[neighbour] && degree[neighbour] > 0 {
                    degree[neighbour] -= 1;
                }
            }
        }
        out
    }

    #[must_use]
    pub fn cut_vertices_and_bridges(&self) -> (Vec<usize>, Vec<(usize, usize)>) {
        let n = self.uids.len();
        let mut disc = vec![0usize; n];
        let mut low = vec![0usize; n];
        let mut is_cut = vec![false; n];
        let mut bridges = Vec::new();
        let mut timer = 0usize;
        for start in 0..n {
            if disc[start] != 0 {
                continue;
            }
            timer += 1;
            disc[start] = timer;
            low[start] = timer;
            let mut root_children = 0usize;
            let mut stack = vec![(start, usize::MAX, 0usize)];
            while let Some(&(node, parent, cursor)) = stack.last() {
                if cursor < self.adj[node].len() {
                    let next = self.adj[node][cursor];
                    stack.last_mut().expect("frame present").2 = cursor + 1;
                    if disc[next] == 0 {
                        if parent == usize::MAX {
                            root_children += 1;
                        }
                        timer += 1;
                        disc[next] = timer;
                        low[next] = timer;
                        stack.push((next, node, 0));
                    } else if next != parent {
                        low[node] = low[node].min(disc[next]);
                    }
                } else {
                    stack.pop();
                    if parent != usize::MAX {
                        low[parent] = low[parent].min(low[node]);
                        if parent != start && low[node] >= disc[parent] {
                            is_cut[parent] = true;
                        }
                        if low[node] > disc[parent] {
                            bridges.push((parent.min(node), parent.max(node)));
                        }
                    }
                }
            }
            if root_children > 1 {
                is_cut[start] = true;
            }
        }
        let articulation_points = (0..n).filter(|&index| is_cut[index]).collect();
        bridges.sort_unstable();
        (articulation_points, bridges)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::EntityKind;

    fn entity(name: &str) -> Entity {
        Entity::new(
            EntityKind::Email,
            format!("{name}@example.com"),
            0.6,
            "scan",
        )
    }

    #[test]
    fn graph_is_deterministic_and_deduplicated() {
        let a = entity("a");
        let b = entity("b");
        let c = entity("c");
        let relations = vec![
            EntityRelation::new(
                a.uid.clone(),
                b.uid.clone(),
                RelationKind::AssociatedWith,
                0.5,
            ),
            EntityRelation::new(b.uid.clone(), a.uid.clone(), RelationKind::SameAs, 0.9),
            EntityRelation::new(b.uid.clone(), c.uid.clone(), RelationKind::Uses, 0.7),
        ];
        let graph = Graph::build(&[c.clone(), a.clone(), b.clone()], &relations);
        assert_eq!(graph.node_count(), 3);
        assert_eq!(graph.edge_count(), 2);
        let left = graph.index_of(&a.uid).unwrap();
        let right = graph.index_of(&b.uid).unwrap();
        assert_eq!(
            graph.edge(left, right).unwrap().relation_kinds,
            vec![RelationKind::AssociatedWith, RelationKind::SameAs]
        );
    }

    #[test]
    fn bfs_and_cut_vertices_work() {
        let a = entity("a");
        let b = entity("b");
        let c = entity("c");
        let d = entity("d");
        let relations = vec![
            EntityRelation::new(
                a.uid.clone(),
                b.uid.clone(),
                RelationKind::AssociatedWith,
                0.5,
            ),
            EntityRelation::new(
                b.uid.clone(),
                c.uid.clone(),
                RelationKind::AssociatedWith,
                0.5,
            ),
            EntityRelation::new(
                c.uid.clone(),
                d.uid.clone(),
                RelationKind::AssociatedWith,
                0.5,
            ),
        ];
        let graph = Graph::build(&[a.clone(), b.clone(), c.clone(), d.clone()], &relations);
        let levels = graph.bfs_levels(graph.index_of(&a.uid).unwrap());
        assert_eq!(levels[graph.index_of(&d.uid).unwrap()], 3);
        let (cuts, bridges) = graph.cut_vertices_and_bridges();
        assert_eq!(cuts.len(), 2);
        assert_eq!(bridges.len(), 3);
    }
}
