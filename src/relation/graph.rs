use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};

use crate::union_find::UnionFind;

use super::types::{Relation, RelationKind};

/// How deep a pathway that `disjoint_pathways` counts may run.
const PATHWAY_MAX_DEPTH: usize = 8;
/// How deep a path whose intermediate nodes `connection_brokers` scores may run.
const BROKER_MAX_DEPTH: usize = 6;
/// How deep a path whose relation kinds `connection_templates` counts may run.
const TEMPLATE_MAX_DEPTH: usize = 4;
/// The parent of a search's first step.
const ROOT: usize = usize::MAX;

/// The identity-binding relations with their uids interned. It is built once per call, so the
/// searches over it index vectors instead of hashing, comparing and cloning uids.
struct IdentityIndex<'a> {
    uids: Vec<&'a str>,
    nodes: HashMap<&'a str, usize>,
    /// The endpoints and confidence of each identity-binding relation, in input order.
    edges: Vec<(usize, usize, f64)>,
    /// The edges at each node, in input order. A self-loop is listed twice and never followed.
    incident: Vec<Vec<usize>>,
}

impl<'a> IdentityIndex<'a> {
    fn new(relations: &'a [Relation]) -> Self {
        let mut index = Self {
            uids: Vec::new(),
            nodes: HashMap::new(),
            edges: Vec::new(),
            incident: Vec::new(),
        };
        for relation in relations
            .iter()
            .filter(|relation| relation.kind.binds_identity())
        {
            let from = index.intern(&relation.from_uid);
            let to = index.intern(&relation.to_uid);
            let edge = index.edges.len();
            index.edges.push((from, to, relation.confidence));
            index.incident[from].push(edge);
            index.incident[to].push(edge);
        }
        index
    }

    fn intern(&mut self, uid: &'a str) -> usize {
        if let Some(&node) = self.nodes.get(uid) {
            return node;
        }
        let node = self.uids.len();
        self.uids.push(uid);
        self.nodes.insert(uid, node);
        self.incident.push(Vec::new());
        node
    }
}

impl IdentityIndex<'_> {
    fn len(&self) -> usize {
        self.uids.len()
    }

    fn node(&self, uid: &str) -> Option<usize> {
        self.nodes.get(uid).copied()
    }

    /// The end of `edge` that is not `node`: its `to` end, unless `node` is its `from` end.
    fn across(&self, edge: usize, node: usize) -> usize {
        let (from, to, _) = self.edges[edge];
        if from == node { to } else { from }
    }

    fn owned(&self, path: &[usize]) -> Vec<String> {
        path.iter()
            .map(|&node| self.uids[node].to_owned())
            .collect()
    }

    /// The component of identity relations each node falls in, named by one of its nodes.
    fn components(&self) -> Vec<usize> {
        let mut sets = UnionFind::new(self.len());
        for &(from, to, _) in &self.edges {
            sets.union(from, to);
        }
        (0..self.len()).map(|node| sets.find(node)).collect()
    }

    /// Retires every live edge joining two consecutive nodes of `path`, either way round, as a
    /// counted pathway has always retired its relations, and records each in `retired`. Each
    /// step scans the edges of whichever of its nodes has fewer, so a hub costs nothing extra.
    fn retire(&self, path: &[usize], removed: &mut [bool], retired: &mut Vec<usize>) {
        for pair in path.windows(2) {
            let (near, far) = (pair[0], pair[1]);
            let scanned = if self.incident[near].len() <= self.incident[far].len() {
                near
            } else {
                far
            };
            for &edge in &self.incident[scanned] {
                let (from, to) = (self.edges[edge].0, self.edges[edge].1);
                let joins = (from, to) == (near, far) || (from, to) == (far, near);
                if joins && !removed[edge] {
                    removed[edge] = true;
                    retired.push(edge);
                }
            }
        }
    }

    /// Calls `visit` with the path `strongest_path` returns, within `max_depth`, from each node
    /// to each node after it in uid order. One search from each node finds all of them: a search
    /// pops paths in the same order whichever node it is looking for, so the first path it pops
    /// to a node is the one a search that stops there returns.
    fn each_strongest_path(&self, max_depth: usize, mut visit: impl FnMut(&[usize])) {
        let mut order = (0..self.len()).collect::<Vec<_>>();
        order.sort_unstable_by_key(|&node| self.uids[node]);
        let mut rank = vec![0; self.len()];
        for (position, &node) in order.iter().enumerate() {
            rank[node] = position;
        }
        let removed = vec![false; self.edges.len()];
        let mut search = Search::new(self.len());
        let mut first = vec![None; self.len()];
        let mut reached = Vec::new();
        for (position, &start) in order.iter().enumerate() {
            search.run(self, start, &removed, max_depth, |node, step| {
                if rank[node] > position && first[node].is_none() {
                    first[node] = Some(step);
                    reached.push(node);
                }
                false
            });
            reached.sort_unstable_by_key(|&node| rank[node]);
            for &node in &reached {
                if let Some(step) = first[node].take() {
                    visit(&search.path(step));
                }
            }
            reached.clear();
        }
    }
}

/// One step of a search: the node it reached, and the step it was taken from.
#[derive(Clone, Copy)]
struct Step {
    node: usize,
    parent: usize,
}

/// A path waiting to be expanded, ordered as the widest-path search has always ordered them:
/// wider first, then shallower. Paths equal on both leave the heap in its own order.
#[derive(Clone, Copy)]
struct Frontier {
    width: f64,
    depth: usize,
    node: usize,
    step: usize,
}

impl Ord for Frontier {
    fn cmp(&self, other: &Self) -> Ordering {
        self.width
            .partial_cmp(&other.width)
            .unwrap_or(Ordering::Equal)
            .then_with(|| other.depth.cmp(&self.depth))
    }
}

impl PartialOrd for Frontier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Frontier {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Frontier {}

/// The scratch space of widest-path searches over one index, kept from search to search.
struct Search {
    heap: BinaryHeap<Frontier>,
    steps: Vec<Step>,
    best: Vec<Option<f64>>,
    expanded: Vec<usize>,
}

impl Search {
    fn new(nodes: usize) -> Self {
        Self {
            heap: BinaryHeap::new(),
            steps: Vec::new(),
            best: vec![None; nodes],
            expanded: Vec::new(),
        }
    }

    /// Runs the widest-path search `strongest_path` has always run, from `start` over the edges
    /// not `removed`: a path never revisits a node, expands no deeper than `max_depth`, and
    /// expands a node only when it is wider than every path that expanded the node before. Each
    /// path popped is offered to `accept`, by its last node and step, before it is expanded.
    /// Returns the step of the first path accepted, or `None` once no path is left.
    fn run(
        &mut self,
        index: &IdentityIndex<'_>,
        start: usize,
        removed: &[bool],
        max_depth: usize,
        mut accept: impl FnMut(usize, usize) -> bool,
    ) -> Option<usize> {
        self.heap.clear();
        self.steps.clear();
        for node in self.expanded.drain(..) {
            self.best[node] = None;
        }
        self.steps.push(Step {
            node: start,
            parent: ROOT,
        });
        self.heap.push(Frontier {
            width: 1.0,
            depth: 0,
            node: start,
            step: 0,
        });
        while let Some(state) = self.heap.pop() {
            if accept(state.node, state.step) {
                return Some(state.step);
            }
            if state.depth >= max_depth {
                continue;
            }
            match self.best[state.node] {
                Some(seen) if seen >= state.width => continue,
                Some(_) => {}
                None => self.expanded.push(state.node),
            }
            self.best[state.node] = Some(state.width);
            for &edge in &index.incident[state.node] {
                if removed[edge] {
                    continue;
                }
                let next = index.across(edge, state.node);
                if self.on_path(state.step, next) {
                    continue;
                }
                let step = self.steps.len();
                self.steps.push(Step {
                    node: next,
                    parent: state.step,
                });
                self.heap.push(Frontier {
                    width: state.width.min(index.edges[edge].2),
                    depth: state.depth + 1,
                    node: next,
                    step,
                });
            }
        }
        None
    }

    /// Whether `node` lies on the path that ends at `step`.
    fn on_path(&self, mut step: usize, node: usize) -> bool {
        while step != ROOT {
            let Step { node: at, parent } = self.steps[step];
            if at == node {
                return true;
            }
            step = parent;
        }
        false
    }

    /// The nodes of the path that ends at `step`, from the node the search started at.
    fn path(&self, mut step: usize) -> Vec<usize> {
        let mut nodes = Vec::new();
        while step != ROOT {
            nodes.push(self.steps[step].node);
            step = self.steps[step].parent;
        }
        nodes.reverse();
        nodes
    }
}

/// Counts pathways between pairs of one index as `disjoint_pathways` counts them, keeping its
/// scratch space from pair to pair.
struct PathwayCounter<'i, 'a> {
    index: &'i IdentityIndex<'a>,
    search: Search,
    removed: Vec<bool>,
    retired: Vec<usize>,
}

impl<'i, 'a> PathwayCounter<'i, 'a> {
    fn new(index: &'i IdentityIndex<'a>) -> Self {
        Self {
            index,
            search: Search::new(index.len()),
            removed: vec![false; index.edges.len()],
            retired: Vec::new(),
        }
    }

    /// The pathways from `start` to `end`, up to `cap`: take the strongest path within
    /// `PATHWAY_MAX_DEPTH`, retire its relations, and repeat until none is left. `first`, when
    /// given, is the strongest path over every relation, found already.
    fn count(&mut self, start: usize, end: usize, first: Option<&[usize]>, cap: usize) -> usize {
        if start == end || cap == 0 {
            return 0;
        }
        let mut count = 0;
        if let Some(path) = first {
            count = 1;
            self.index
                .retire(path, &mut self.removed, &mut self.retired);
        }
        while count < cap {
            let Some(step) = self.search.run(
                self.index,
                start,
                &self.removed,
                PATHWAY_MAX_DEPTH,
                |node, _| node == end,
            ) else {
                break;
            };
            count += 1;
            let path = self.search.path(step);
            self.index
                .retire(&path, &mut self.removed, &mut self.retired);
        }
        for edge in self.retired.drain(..) {
            self.removed[edge] = false;
        }
        count
    }
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

/// The widest path of identity-binding relations from `start_uid` to `end_uid`, at most
/// `max_depth` relations long: the path whose weakest relation is strongest, the shallower of
/// two equally wide paths.
#[must_use]
pub fn strongest_path(
    start_uid: &str,
    end_uid: &str,
    relations: &[Relation],
    max_depth: usize,
) -> Option<Vec<String>> {
    if start_uid == end_uid {
        return Some(vec![start_uid.to_owned()]);
    }
    let index = IdentityIndex::new(relations);
    let (start, end) = (index.node(start_uid)?, index.node(end_uid)?);
    let removed = vec![false; index.edges.len()];
    let mut search = Search::new(index.len());
    let step = search.run(&index, start, &removed, max_depth, |node, _| node == end)?;
    Some(index.owned(&search.path(step)))
}

/// How many pathways connect `start_uid` to `end_uid` when each pathway counted retires the
/// relations it used: the strongest path within eight relations, then the strongest over what
/// is left, until none is left.
#[must_use]
pub fn disjoint_pathways(start_uid: &str, end_uid: &str, relations: &[Relation]) -> usize {
    let index = IdentityIndex::new(relations);
    match (index.node(start_uid), index.node(end_uid)) {
        (Some(start), Some(end)) => PathwayCounter::new(&index).count(start, end, None, usize::MAX),
        _ => 0,
    }
}

/// `disjoint_pathways(uids[left], uids[right], relations)`, counted up to `cap`, for every pair
/// with `left < right`: the positions and count of each pair connected by a pathway, in order of
/// `left` and then `right`. One search from each uid finds its first pathway to every other uid,
/// so only the pathways after the first take a search per pair, and a pair in different
/// components of the identity relations takes none.
#[must_use]
pub fn pairwise_disjoint_pathways(
    uids: &[&str],
    relations: &[Relation],
    cap: usize,
) -> Vec<(usize, usize, usize)> {
    let index = IdentityIndex::new(relations);
    let component = index.components();
    let mut members = HashMap::<usize, Vec<(usize, usize)>>::new();
    for (position, uid) in uids.iter().enumerate() {
        if let Some(node) = index.node(uid) {
            members
                .entry(component[node])
                .or_default()
                .push((position, node));
        }
    }
    let removed = vec![false; index.edges.len()];
    let mut search = Search::new(index.len());
    let mut counter = PathwayCounter::new(&index);
    let mut first = vec![None; index.len()];
    let mut reached = Vec::new();
    let mut out = Vec::new();
    for (left, uid) in uids.iter().enumerate() {
        let Some(start) = index.node(uid) else {
            continue;
        };
        let group = &members[&component[start]];
        let later = &group[group.partition_point(|&(position, _)| position <= left)..];
        if cap == 0 || later.iter().all(|&(_, node)| node == start) {
            continue;
        }
        search.run(&index, start, &removed, PATHWAY_MAX_DEPTH, |node, step| {
            if first[node].is_none() {
                first[node] = Some(step);
                reached.push(node);
            }
            false
        });
        for &(right, end) in later {
            let Some(step) = first[end].filter(|_| end != start) else {
                continue;
            };
            let path = search.path(step);
            let count = counter.count(start, end, Some(&path), cap);
            out.push((left, right, count));
        }
        for node in reached.drain(..) {
            first[node] = None;
        }
    }
    out
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

/// How often each sequence of relation kinds makes up the strongest path, within four
/// relations, between two uids. A step's kind is that of the first relation joining its two
/// uids, either way round.
#[must_use]
pub fn connection_templates(relations: &[Relation]) -> BTreeMap<Vec<RelationKind>, usize> {
    let mut joining = HashMap::<(&str, &str), RelationKind>::new();
    for relation in relations {
        joining
            .entry(unordered(&relation.from_uid, &relation.to_uid))
            .or_insert(relation.kind);
    }
    let index = IdentityIndex::new(relations);
    let mut counts = BTreeMap::<Vec<RelationKind>, usize>::new();
    index.each_strongest_path(TEMPLATE_MAX_DEPTH, |path| {
        let kinds = path
            .windows(2)
            .filter_map(|pair| {
                joining
                    .get(&unordered(index.uids[pair[0]], index.uids[pair[1]]))
                    .copied()
            })
            .collect::<Vec<_>>();
        if !kinds.is_empty() {
            *counts.entry(kinds).or_default() += 1;
        }
    });
    counts
}

fn unordered<'s>(left: &'s str, right: &'s str) -> (&'s str, &'s str) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

/// The uids that the strongest paths, within six relations, between other uids pass through,
/// with how many such paths pass through each: most first, then by uid.
#[must_use]
pub fn connection_brokers(relations: &[Relation]) -> Vec<(String, usize)> {
    let index = IdentityIndex::new(relations);
    let mut scores = vec![0_usize; index.len()];
    index.each_strongest_path(BROKER_MAX_DEPTH, |path| {
        for &node in &path[1..path.len() - 1] {
            scores[node] += 1;
        }
    });
    let mut ranked = scores
        .iter()
        .enumerate()
        .filter(|&(_, &score)| score > 0)
        .map(|(node, &score)| (index.uids[node].to_owned(), score))
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
    ranked
}

#[must_use]
pub fn reachable_count(start_uid: &str, relations: &[Relation]) -> usize {
    let index = IdentityIndex::new(relations);
    let Some(start) = index.node(start_uid) else {
        return 0;
    };
    let mut seen = vec![false; index.len()];
    seen[start] = true;
    let mut queue = vec![start];
    let mut head = 0;
    while let Some(&node) = queue.get(head) {
        head += 1;
        for &edge in &index.incident[node] {
            let next = index.across(edge, node);
            if !seen[next] {
                seen[next] = true;
                queue.push(next);
            }
        }
    }
    queue.len() - 1
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

    /// Addresses on one domain, domains on one address, a registrant and a handle guessed from a
    /// name relate different people. Only the alias chain is one identity, so the clusters, the
    /// pair counts and the brokers see the chain and nothing else.
    #[test]
    fn shared_infrastructure_merges_no_identities() {
        let relations = vec![
            Relation::new("ann@corp", "corp", RelationKind::BelongsToDomain, 0.9, "s"),
            Relation::new("bob@corp", "corp", RelationKind::BelongsToDomain, 0.9, "s"),
            Relation::new("www.corp", "corp", RelationKind::SubdomainOf, 0.9, "s"),
            Relation::new("corp", "192.0.2.1", RelationKind::ResolvesTo, 0.9, "s"),
            Relation::new("other", "192.0.2.1", RelationKind::ResolvesTo, 0.9, "s"),
            Relation::new("www.corp", "192.0.2.1", RelationKind::HostedOn, 0.9, "s"),
            Relation::new(
                "192.0.2.1",
                "192.0.2.2",
                RelationKind::CoLocatedWith,
                0.9,
                "s",
            ),
            Relation::new("corp", "registrant", RelationKind::RegisteredBy, 0.9, "s"),
            Relation::new("other", "registrant", RelationKind::RegisteredBy, 0.9, "s"),
            Relation::new("ann@corp", "Ann", RelationKind::DerivedFrom, 0.9, "s"),
            Relation::new("ann@corp", "ann", RelationKind::AliasOf, 0.8, "s"),
            Relation::new("ann", "ann@mail", RelationKind::SameAs, 0.8, "s"),
        ];
        let identity = ["ann", "ann@corp", "ann@mail"].map(str::to_owned);
        assert_eq!(resolve_identity_clusters(&relations), [identity.to_vec()]);
        assert_eq!(strongest_path("bob@corp", "ann@corp", &relations, 8), None);
        assert_eq!(reachable_count("corp", &relations), 0);
        let mut uids = relations
            .iter()
            .flat_map(|relation| [relation.from_uid.as_str(), relation.to_uid.as_str()])
            .collect::<Vec<_>>();
        uids.sort_unstable();
        uids.dedup();
        let pairs = pairwise_disjoint_pathways(&uids, &relations, usize::MAX)
            .into_iter()
            .map(|(left, right, count)| (uids[left], uids[right], count))
            .collect::<Vec<_>>();
        assert_eq!(
            pairs,
            [
                ("ann", "ann@corp", 1),
                ("ann", "ann@mail", 1),
                ("ann@corp", "ann@mail", 1),
            ]
        );
        assert_eq!(connection_brokers(&relations), [("ann".to_owned(), 1)]);
    }

    /// A ring of four identity relations with a pendant `e` on `d`, and one more relation that
    /// binds no identity. Each pair on the ring has two pathways, round either side; a pair with
    /// `e` has one, through `d`. A counted pathway retires every relation joining its steps, so
    /// the parallel `same_as` beside the alias of `a` and `b` adds no third pathway.
    #[test]
    fn disjoint_pathways_retire_every_relation_of_a_counted_pathway() {
        let relations = vec![
            Relation::new("a", "b", RelationKind::AliasOf, 0.9, "s"),
            Relation::new("b", "a", RelationKind::SameAs, 0.9, "s"),
            Relation::new("b", "d", RelationKind::AliasOf, 0.9, "s"),
            Relation::new("a", "c", RelationKind::AliasOf, 0.5, "s"),
            Relation::new("c", "d", RelationKind::AliasOf, 0.5, "s"),
            Relation::new("d", "e", RelationKind::AliasOf, 0.9, "s"),
            Relation::new("a", "d", RelationKind::AssociatedWith, 0.9, "s"),
        ];
        assert_eq!(disjoint_pathways("a", "b", &relations), 2);
        assert_eq!(disjoint_pathways("a", "d", &relations), 2);
        assert_eq!(disjoint_pathways("e", "a", &relations), 1);
        assert_eq!(disjoint_pathways("a", "a", &relations), 0);
        assert_eq!(disjoint_pathways("a", "ghost", &relations), 0);
        assert_eq!(
            pairwise_disjoint_pathways(&["a", "ghost", "e", "a", "d"], &relations, usize::MAX),
            [(0, 2, 1), (0, 4, 2), (2, 3, 1), (2, 4, 1), (3, 4, 2)]
        );
        assert_eq!(
            pairwise_disjoint_pathways(&["a", "d"], &relations, 1),
            [(0, 1, 1)]
        );
        assert_eq!(pairwise_disjoint_pathways(&["a", "d"], &relations, 0), []);
    }

    /// The implementations every search here replaced, kept verbatim as the oracle the
    /// differential tests compare against. Each ran a search per pair, cloning every relation
    /// and rebuilding the adjacency per call, and a path per state. Only the order the pairwise
    /// passes visit nodes in differs: it is uid order here, where it was a hash map's order, which
    /// changed from run to run.
    mod reference {
        use std::cmp::Ordering;
        use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet, VecDeque};

        use super::super::super::types::{Relation, RelationKind};

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

        fn sorted_nodes<'a>(adj: &HashMap<&'a str, Vec<&Relation>>) -> Vec<&'a str> {
            let mut nodes = adj.keys().copied().collect::<Vec<_>>();
            nodes.sort_unstable();
            nodes
        }

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
                    self.width == other.width
                        && self.depth == other.depth
                        && self.node == other.node
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

        pub fn connection_templates(relations: &[Relation]) -> BTreeMap<Vec<RelationKind>, usize> {
            let adj = identity_edges(relations);
            let nodes = sorted_nodes(&adj);
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

        pub fn connection_brokers(relations: &[Relation]) -> Vec<(String, usize)> {
            let adj = identity_edges(relations);
            let nodes = sorted_nodes(&adj);
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
    }

    /// A fixed-seed xorshift64 generator, so that a failing case reproduces from its round.
    struct XorShift(u64);

    impl XorShift {
        fn draw(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn below(&mut self, bound: usize) -> usize {
            let bound = u64::try_from(bound).unwrap_or(u64::MAX);
            usize::try_from(self.draw() % bound).unwrap_or(0)
        }
    }

    const NODES: [&str; 9] = ["n0", "n1", "n2", "n3", "n4", "n5", "n6", "n7", "n8"];
    const KINDS: [RelationKind; 8] = [
        RelationKind::AliasOf,
        RelationKind::SameAs,
        RelationKind::IdentifiedBy,
        RelationKind::BelongsToDomain,
        RelationKind::ResolvesTo,
        RelationKind::AssociatedWith,
        RelationKind::EmployedBy,
        RelationKind::LocatedAt,
    ];
    /// Few distinct confidences, so that equally wide paths, and so heap ties, are common. The
    /// last is not a number, which the heap orders as equal to every width.
    const CONFIDENCES: [f64; 6] = [0.5, 0.7, 0.9, 1.0, 0.0, f64::NAN];

    /// A random multigraph over the first few of `NODES`: duplicate, reversed and self-loop
    /// relations, relations that bind no identity, and widths that tie.
    fn random_relations(rng: &mut XorShift) -> (Vec<&'static str>, Vec<Relation>) {
        let nodes = &NODES[..2 + rng.below(NODES.len() - 1)];
        let relations = (0..rng.below(4 * nodes.len()))
            .map(|_| {
                let from = nodes[rng.below(nodes.len())];
                let to = nodes[rng.below(nodes.len())];
                let mut relation = Relation::new(from, to, KINDS[rng.below(KINDS.len())], 0.5, "s");
                relation.confidence = CONFIDENCES[rng.below(CONFIDENCES.len())];
                relation
            })
            .collect();
        (nodes.to_vec(), relations)
    }

    /// Every multi-hop query answers exactly as the per-pair searches it replaced did, on random
    /// multigraphs, for every pair of known and unknown uids and every depth the rules use.
    #[test]
    fn the_shared_searches_answer_exactly_as_the_per_pair_searches_did() {
        let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
        for round in 0..400 {
            let (nodes, relations) = random_relations(&mut rng);
            let mut uids = nodes.clone();
            uids.push("ghost");
            for &from in &uids {
                for &to in &uids {
                    for depth in [0, 1, 2, 3, 4, 6, 8] {
                        assert_eq!(
                            strongest_path(from, to, &relations, depth),
                            reference::strongest_path(from, to, &relations, depth),
                            "round {round}: {from} to {to} within {depth}: {relations:?}"
                        );
                    }
                    assert_eq!(
                        disjoint_pathways(from, to, &relations),
                        reference::disjoint_pathways(from, to, &relations),
                        "round {round}: {from} to {to}: {relations:?}"
                    );
                }
                assert_eq!(
                    reachable_count(from, &relations),
                    reference::reachable_count(from, &relations),
                    "round {round}: {from}: {relations:?}"
                );
            }
            assert_eq!(
                connection_brokers(&relations),
                reference::connection_brokers(&relations),
                "round {round}: {relations:?}"
            );
            assert_eq!(
                connection_templates(&relations),
                reference::connection_templates(&relations),
                "round {round}: {relations:?}"
            );
        }
    }

    /// Counting every pair at once gives each pair the count `disjoint_pathways` gives it alone,
    /// capped, whatever order the uids come in, unknown and repeated uids included.
    #[test]
    fn pairwise_pathways_count_each_pair_as_disjoint_pathways_does() {
        let mut rng = XorShift(0x2545_F491_4F6C_DD1D);
        for round in 0..400 {
            let (nodes, relations) = random_relations(&mut rng);
            let mut uids = (0..rng.below(nodes.len() + 3))
                .map(|_| nodes[rng.below(nodes.len())])
                .collect::<Vec<_>>();
            uids.insert(rng.below(uids.len() + 1), "ghost");
            for cap in [0, 1, 2, 3, usize::MAX] {
                let expected = (0..uids.len())
                    .flat_map(|left| (left + 1..uids.len()).map(move |right| (left, right)))
                    .filter_map(|(left, right)| {
                        let count =
                            reference::disjoint_pathways(uids[left], uids[right], &relations)
                                .min(cap);
                        (count > 0).then_some((left, right, count))
                    })
                    .collect::<Vec<_>>();
                assert_eq!(
                    pairwise_disjoint_pathways(&uids, &relations, cap),
                    expected,
                    "round {round}: {uids:?} capped at {cap}: {relations:?}"
                );
            }
        }
    }

    /// A person identified by a thousand handles joins every pair of them through itself. Each
    /// pair used to take a search over a fresh copy of every relation, so a thousand handles
    /// took minutes; one search from each handle is quadratic.
    #[test]
    fn a_shared_hub_is_counted_in_quadratic_time() {
        let leaves = (0..1000).map(|n| format!("user{n}")).collect::<Vec<_>>();
        let relations = leaves
            .iter()
            .map(|leaf| Relation::new("person", leaf, RelationKind::IdentifiedBy, 0.9, "s"))
            .collect::<Vec<_>>();
        let mut uids = leaves.iter().map(String::as_str).collect::<Vec<_>>();
        uids.push("person");
        let started = std::time::Instant::now();
        let counts = pairwise_disjoint_pathways(&uids, &relations, usize::MAX);
        let brokers = connection_brokers(&relations);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(counts.len(), 1001 * 1000 / 2);
        assert!(counts.iter().all(|&(_, _, count)| count == 1));
        assert_eq!(brokers, [("person".to_owned(), 1000 * 999 / 2)]);
    }
}
