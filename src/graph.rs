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
    /// Build a deterministic undirected graph from known entities and relations.
    /// Public relation fields and deserialized data may bypass the checked
    /// constructor, so invalid confidences are normalized at graph ingress.
    /// The canonical pair map is the only intermediate edge authority;
    /// adjacency is derived from it without redundant ordered-set bookkeeping.
    #[must_use]
    pub fn build(entities: &[Entity], relations: &[EntityRelation]) -> Self {
        let mut uids: Vec<String> = entities.iter().map(|entity| entity.uid.clone()).collect();
        uids.sort_unstable();
        uids.dedup();
        let index: HashMap<String, usize> = uids
            .iter()
            .enumerate()
            .map(|(position, uid)| (uid.clone(), position))
            .collect();
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
            let pair = (left.min(right), left.max(right));
            let (kinds, confidence) = pairs.entry(pair).or_insert_with(|| (BTreeSet::new(), 0.0));
            kinds.insert(relation.kind);
            let value = if relation.confidence.is_finite() {
                relation.confidence.clamp(0.0, 1.0)
            } else {
                0.0
            };
            *confidence = confidence.max(value);
        }

        let mut adj = vec![Vec::new(); uids.len()];
        let mut edge_map = HashMap::with_capacity(pairs.len().saturating_mul(2));
        for ((left, right), (kinds, max_confidence)) in pairs {
            adj[left].push(right);
            adj[right].push(left);
            let mut relation_kinds: Vec<RelationKind> = kinds.into_iter().collect();
            relation_kinds.sort_by_key(|kind| kind.as_str());
            let edge = GraphEdge {
                to: right,
                relation_kinds,
                max_confidence,
            };
            edge_map.insert((left, right), edge.clone());
            edge_map.insert((right, left), GraphEdge { to: left, ..edge });
        }
        for neighbours in &mut adj {
            neighbours.sort_unstable();
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

    /// The core number of each node: the largest `k` such that the node lies in a subgraph
    /// whose every node has at least `k` neighbours in it. Computed by Batagelj and Zaversnik's
    /// bucket peeling in O(V + E): nodes sit in one array sorted by remaining degree, and peeling
    /// a node moves each neighbour of higher degree down one bucket with a swap.
    #[must_use]
    pub fn coreness(&self) -> Vec<usize> {
        let n = self.node_count();
        let mut degree: Vec<usize> = (0..n).map(|index| self.degree(index)).collect();
        let max_degree = degree.iter().copied().max().unwrap_or(0);
        // `bucket[d]` is the position in `order` of the first node of remaining degree `d`.
        let mut bucket = vec![0_usize; max_degree + 1];
        for &d in &degree {
            bucket[d] += 1;
        }
        let mut first = 0;
        for slot in &mut bucket {
            let size = *slot;
            *slot = first;
            first += size;
        }
        let mut order = vec![0_usize; n];
        let mut position = vec![0_usize; n];
        let mut fill = bucket.clone();
        for node in 0..n {
            position[node] = fill[degree[node]];
            order[position[node]] = node;
            fill[degree[node]] += 1;
        }
        for peel in 0..n {
            let node = order[peel];
            for &neighbour in &self.adj[node] {
                if degree[neighbour] > degree[node] {
                    let d = degree[neighbour];
                    let head = order[bucket[d]];
                    if head != neighbour {
                        let at = position[neighbour];
                        order[at] = head;
                        position[head] = at;
                        order[bucket[d]] = neighbour;
                        position[neighbour] = bucket[d];
                    }
                    bucket[d] += 1;
                    degree[neighbour] -= 1;
                }
            }
        }
        degree
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

    /// The min-degree peeling `coreness` used to run, kept as its oracle: each round scanned
    /// every node left for the one of least remaining degree, so it was quadratic.
    fn peeled_coreness(graph: &Graph) -> Vec<usize> {
        let n = graph.node_count();
        let mut remaining = vec![true; n];
        let mut degree: Vec<usize> = (0..n).map(|index| graph.degree(index)).collect();
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
            for &neighbour in graph.neighbours(node) {
                if remaining[neighbour] && degree[neighbour] > 0 {
                    degree[neighbour] -= 1;
                }
            }
        }
        out
    }

    /// Bucket peeling finds every core number the quadratic peeling found.
    #[test]
    fn coreness_matches_min_degree_peeling_on_random_graphs() {
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        for round in 0..300 {
            let graph = crate::test_support::random_graph(&mut state, 40);
            assert_eq!(
                graph.coreness(),
                peeled_coreness(&graph),
                "round {round}: {:?}",
                graph.edge_pairs()
            );
        }
    }

    /// A 4-clique with a tail: the clique is the 3-core, the tail the 1-core, and the isolated
    /// node the 0-core.
    #[test]
    fn coreness_of_a_clique_with_a_tail() {
        let nodes = ["a", "b", "c", "d", "e", "f"].map(entity);
        let link = |left: usize, right: usize| {
            EntityRelation::new(
                nodes[left].uid.clone(),
                nodes[right].uid.clone(),
                RelationKind::AssociatedWith,
                0.5,
            )
        };
        let graph = Graph::build(
            &nodes,
            &[
                link(0, 1),
                link(0, 2),
                link(0, 3),
                link(1, 2),
                link(1, 3),
                link(2, 3),
                link(3, 4),
            ],
        );
        let core = |name: usize| graph.coreness()[graph.index_of(&nodes[name].uid).unwrap()];
        assert_eq!((0..6).map(core).collect::<Vec<_>>(), [3, 3, 3, 3, 1, 0]);
    }

    #[test]
    fn graph_normalizes_public_relation_confidence_without_losing_topology() {
        let a = entity("invalid-a");
        let b = entity("invalid-b");
        let c = entity("invalid-c");
        let cases = [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.25, 1.5];
        let mut relations = Vec::new();
        for (index, confidence) in cases.into_iter().enumerate() {
            let kind = if index % 2 == 0 {
                RelationKind::Uses
            } else {
                RelationKind::AssociatedWith
            };
            let mut relation = EntityRelation::new(a.uid.clone(), b.uid.clone(), kind, 0.0);
            relation.confidence = confidence;
            relations.push(relation);
        }
        relations.push(EntityRelation::new(
            b.uid.clone(),
            c.uid.clone(),
            RelationKind::Owns,
            0.4,
        ));
        let graph = Graph::build(&[a.clone(), b.clone(), c.clone()], &relations);
        let left = graph.index_of(&a.uid).unwrap();
        let middle = graph.index_of(&b.uid).unwrap();
        let right = graph.index_of(&c.uid).unwrap();
        assert_eq!(graph.edge_count(), 2);
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(graph.edge(left, middle).unwrap().max_confidence, 1.0);
            assert_eq!(graph.edge(middle, left).unwrap().max_confidence, 1.0);
            assert_eq!(graph.edge(middle, right).unwrap().max_confidence, 0.4);
        }
        assert_eq!(graph.bfs_levels(left)[right], 2);
    }

    #[test]
    fn graph_rejects_nonfinite_confidence_as_strength_evidence() {
        let a = entity("finite-a");
        let b = entity("finite-b");
        let mut relation = EntityRelation::new(
            a.uid.clone(),
            b.uid.clone(),
            RelationKind::AssociatedWith,
            0.0,
        );
        relation.confidence = f64::INFINITY;
        let graph = Graph::build(&[a.clone(), b.clone()], &[relation]);
        let left = graph.index_of(&a.uid).unwrap();
        let right = graph.index_of(&b.uid).unwrap();
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(graph.edge(left, right).unwrap().max_confidence, 0.0);
        }
    }

    #[test]
    fn reverse_and_duplicate_relations_preserve_deterministic_adjacency() {
        let nodes = (0..12)
            .map(|i| entity(&format!("node-{i}")))
            .collect::<Vec<_>>();
        let mut relations = Vec::new();
        for left in 0..nodes.len() {
            for right in left + 1..nodes.len() {
                if (left + right) % 3 == 0 {
                    relations.push(EntityRelation::new(
                        nodes[left].uid.clone(),
                        nodes[right].uid.clone(),
                        RelationKind::Uses,
                        0.3,
                    ));
                    relations.push(EntityRelation::new(
                        nodes[right].uid.clone(),
                        nodes[left].uid.clone(),
                        RelationKind::SameAs,
                        0.8,
                    ));
                }
            }
        }
        let first = Graph::build(&nodes, &relations);
        let reverse = Graph::build(
            &nodes.iter().rev().cloned().collect::<Vec<_>>(),
            &relations.iter().rev().cloned().collect::<Vec<_>>(),
        );
        assert_eq!(first, reverse);
        assert_eq!(first.edge_count(), relations.len() / 2);
        for left in 0..first.node_count() {
            assert!(
                first
                    .neighbours(left)
                    .windows(2)
                    .all(|window| window[0] < window[1])
            );
            for &right in first.neighbours(left) {
                #[allow(clippy::float_cmp)]
                {
                    assert_eq!(
                        first.edge(left, right).unwrap().max_confidence,
                        first.edge(right, left).unwrap().max_confidence
                    );
                }
            }
        }
    }

    #[test]
    fn graph_sparse_scale_keeps_core_and_cut_results() {
        let nodes = (0..2_000)
            .map(|i| entity(&format!("sparse-{i}")))
            .collect::<Vec<_>>();
        let relations = (1..nodes.len())
            .map(|index| {
                EntityRelation::new(
                    nodes[index - 1].uid.clone(),
                    nodes[index].uid.clone(),
                    RelationKind::AssociatedWith,
                    0.5,
                )
            })
            .collect::<Vec<_>>();
        let graph = Graph::build(&nodes, &relations);
        assert_eq!(graph.node_count(), nodes.len());
        assert_eq!(graph.edge_count(), nodes.len() - 1);
        assert!(graph.coreness().iter().all(|&core| core == 1));
        let (cut_vertices, bridges) = graph.cut_vertices_and_bridges();
        assert_eq!(cut_vertices.len(), nodes.len() - 2);
        assert_eq!(bridges.len(), nodes.len() - 1);
    }
}
