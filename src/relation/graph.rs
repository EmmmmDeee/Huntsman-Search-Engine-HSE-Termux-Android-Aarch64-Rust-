use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};

use crate::union_find::UnionFind;

use super::types::{Basis, Relation, RelationKind};

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
    /// The number of what each edge rests on (see [`Relation::rests_on`]): its relation's named
    /// basis, or the link between its two nodes, shared by every relation without a named basis
    /// that joins them, either way round.
    basis: Vec<usize>,
    /// What each basis number stands for.
    bases: Vec<Basis<'a>>,
    /// The edges at each node, in input order. A self-loop is listed twice and never followed.
    incident: Vec<Vec<usize>>,
}

impl<'a> IdentityIndex<'a> {
    fn new(relations: &'a [Relation]) -> Self {
        let mut index = Self {
            uids: Vec::new(),
            nodes: HashMap::new(),
            edges: Vec::new(),
            basis: Vec::new(),
            bases: Vec::new(),
            incident: Vec::new(),
        };
        let mut numbers = HashMap::<Basis<'a>, usize>::new();
        for relation in relations
            .iter()
            .filter(|relation| relation.kind.binds_identity())
        {
            let from = index.intern(&relation.from_uid);
            let to = index.intern(&relation.to_uid);
            let edge = index.edges.len();
            let rests_on = relation.rests_on();
            let fresh = index.bases.len();
            let basis = *numbers.entry(rests_on).or_insert(fresh);
            if basis == fresh {
                index.bases.push(rests_on);
            }
            index.edges.push((from, to, relation.confidence));
            index.basis.push(basis);
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

    /// The shape of the component each node falls in, given each node's component. A self-loop
    /// joins no two nodes and is never followed, so it counts for none of it.
    fn shapes(&self, component: &[usize]) -> Vec<Shape> {
        let nodes = self.len();
        let mut size = vec![0_usize; nodes];
        for &root in component {
            size[root] += 1;
        }
        let mut widest = vec![f64::NEG_INFINITY; nodes];
        let mut neighbours = vec![0_usize; nodes];
        let mut counted = vec![ROOT; nodes];
        for (node, edges) in self.incident.iter().enumerate() {
            for &edge in edges {
                let other = self.across(edge, node);
                if other == node {
                    continue;
                }
                widest[node] = widest[node].max(width(self.edges[edge].2));
                if counted[other] != node {
                    counted[other] = node;
                    neighbours[node] += 1;
                }
            }
        }
        let mut shapes = vec![
            Shape {
                complete: true,
                bounded: true,
                basis: None,
            };
            nodes
        ];
        for (node, &root) in component.iter().enumerate() {
            shapes[root].complete &= neighbours[node] + 1 == size[root];
        }
        let mut mixed = vec![false; nodes];
        for (edge, &(from, to, confidence)) in self.edges.iter().enumerate() {
            if from == to {
                continue;
            }
            let root = component[from];
            let shape = &mut shapes[root];
            // An edge is never wider than the widest edge at either end, so it is as wide as the
            // narrower of those two only when it is at least that narrow.
            shape.bounded &= width(confidence) >= widest[from].min(widest[to]);
            match shape.basis {
                None if !mixed[root] => shape.basis = Some(self.basis[edge]),
                Some(basis) if basis != self.basis[edge] => {
                    shape.basis = None;
                    mixed[root] = true;
                }
                _ => {}
            }
        }
        component.iter().map(|&root| shapes[root]).collect()
    }

    /// The name of the basis that carries every pathway in a component of this `shape`: one
    /// named basis that every edge rests on, in a component where every two nodes are joined.
    /// A search from any of its nodes then reaches every other in one step, and the first
    /// pathway it counts to each uses that basis up, so each pair has that one pathway.
    fn sole_carrier(&self, shape: Shape) -> Option<&'a str> {
        match shape
            .basis
            .filter(|_| shape.complete)
            .map(|basis| self.bases[basis])
        {
            Some(Basis::Named(name)) => Some(name),
            _ => None,
        }
    }

    /// Retires the basis of every edge on the path that ends at `step` of `search`, and records
    /// each in `retired`: a counted pathway uses up what it rests on, so no later pathway may take
    /// a relation resting on the same basis. For a relation without a basis that is the link
    /// between its two nodes, so every relation without a basis joining them, either way round,
    /// is retired with it, as a counted pathway has always retired its relations. A relation
    /// that rests on a shared handle retires every relation resting on that handle.
    fn retire(&self, search: &Search, step: usize, removed: &mut [bool], retired: &mut Vec<usize>) {
        for edge in search.edges(step) {
            let basis = self.basis[edge];
            if !removed[basis] {
                removed[basis] = true;
                retired.push(basis);
            }
        }
    }

    /// The name of the basis that every edge on the path ending at `step` of `search` rests on,
    /// when one named basis carries the whole path.
    fn sole_basis(&self, search: &Search, step: usize) -> Option<&'a str> {
        let mut edges = search.edges(step).map(|edge| self.basis[edge]);
        let first = edges.next()?;
        match self.bases[first] {
            Basis::Named(name) if edges.all(|basis| basis == first) => Some(name),
            _ => None,
        }
    }

    /// Calls `visit` with the path `strongest_path` returns, within `max_depth`, from each node
    /// to each node after it in uid order. One search from each node finds all of them: a search
    /// pops paths in the same order whichever node it is looking for, so the first path it pops
    /// to a node is the one a search that stops there returns.
    ///
    /// A node in a complete, bounded component (see [`Shape`]) needs no search: no path is wider
    /// than the edge joining its ends, because its first and last edges are no wider than the
    /// widest at those ends, and a path as wide is deeper, so it pops after that edge, which the
    /// search queues first. So the first path to each other node is the edge to it.
    fn each_strongest_path(&self, max_depth: usize, mut visit: impl FnMut(&[usize])) {
        let mut order = (0..self.len()).collect::<Vec<_>>();
        order.sort_unstable_by_key(|&node| self.uids[node]);
        let mut rank = vec![0; self.len()];
        for (position, &node) in order.iter().enumerate() {
            rank[node] = position;
        }
        let component = self.components();
        let shapes = self.shapes(&component);
        let mut members = vec![Vec::new(); self.len()];
        for &node in &order {
            members[component[node]].push(node);
        }
        let removed = vec![false; self.bases.len()];
        let mut search = Search::new(self.len());
        let mut first = vec![None; self.len()];
        let mut reached = Vec::new();
        for (position, &start) in order.iter().enumerate() {
            if max_depth > 0 && shapes[start].complete && shapes[start].bounded {
                let group = &members[component[start]];
                for &node in &group[group.partition_point(|&node| rank[node] <= position)..] {
                    visit(&[start, node]);
                }
                continue;
            }
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

/// What one component of the identity relations looks like, where that lets a search be skipped
/// (see [`IdentityIndex::shapes`]).
#[derive(Clone, Copy)]
struct Shape {
    /// Every two of the component's nodes are joined by an edge.
    complete: bool,
    /// Every edge is as wide as the narrower of the widest edges at its two ends, as when each
    /// relation is as strong as the weaker of the two entities it joins. A path is then no wider
    /// than the edge joining its ends, since its first and last edges are no wider than the
    /// widest edges at those ends.
    bounded: bool,
    /// The number of the basis every edge rests on, when one basis carries them all.
    basis: Option<usize>,
}

/// How far an edge of `confidence` narrows the paths that take it. A search's paths start out
/// 1.0 wide, and the narrower of two widths that are not both numbers is the one that is, so an
/// edge whose confidence is not a number narrows none.
fn width(confidence: f64) -> f64 {
    1.0_f64.min(confidence)
}

/// One step of a search: the node it reached, the step it was taken from and the edge it took.
/// The first step of a search takes no edge, and its parent and edge are `ROOT`.
#[derive(Clone, Copy)]
struct Step {
    node: usize,
    parent: usize,
    edge: usize,
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
    /// whose basis is not `removed`: a path never revisits a node, expands no deeper than
    /// `max_depth`, and expands a node only when it is wider than every path that expanded the
    /// node before. Each path popped is offered to `accept`, by its last node and step, before it
    /// is expanded.
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
            edge: ROOT,
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
                if removed[index.basis[edge]] {
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
                    edge,
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
            let Step {
                node: at, parent, ..
            } = self.steps[step];
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

    /// The edges the path that ends at `step` took, from its last back to its first.
    fn edges(&self, step: usize) -> impl Iterator<Item = usize> + '_ {
        std::iter::successors(Some(step), |&at| {
            let parent = self.steps[at].parent;
            (parent != ROOT).then_some(parent)
        })
        .map(|at| self.steps[at].edge)
        .filter(|&edge| edge != ROOT)
    }
}

/// Counts pathways between pairs of one index as `disjoint_pathways` counts them, keeping its
/// scratch space from pair to pair.
struct PathwayCounter<'i, 'a> {
    index: &'i IdentityIndex<'a>,
    search: Search,
    /// Whether each basis is used up by a pathway already counted for the pair being counted.
    removed: Vec<bool>,
    retired: Vec<usize>,
}

impl<'i, 'a> PathwayCounter<'i, 'a> {
    fn new(index: &'i IdentityIndex<'a>) -> Self {
        Self {
            index,
            search: Search::new(index.len()),
            removed: vec![false; index.bases.len()],
            retired: Vec::new(),
        }
    }

    /// The pathways from `start` to `end`, up to `cap`: take the strongest path within
    /// `PATHWAY_MAX_DEPTH`, retire what it rests on, and repeat until none is left. `first`, when
    /// given, is the strongest path over every relation, found already: the search that found it
    /// and the step it ends at.
    fn count(
        &mut self,
        start: usize,
        end: usize,
        first: Option<(&Search, usize)>,
        cap: usize,
    ) -> usize {
        if start == end || cap == 0 {
            return 0;
        }
        let mut count = 0;
        if let Some((search, step)) = first {
            count = 1;
            self.index
                .retire(search, step, &mut self.removed, &mut self.retired);
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
            self.index
                .retire(&self.search, step, &mut self.removed, &mut self.retired);
        }
        for basis in self.retired.drain(..) {
            self.removed[basis] = false;
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
    let removed = vec![false; index.bases.len()];
    let mut search = Search::new(index.len());
    let step = search.run(&index, start, &removed, max_depth, |node, _| node == end)?;
    Some(index.owned(&search.path(step)))
}

/// How many pathways connect `start_uid` to `end_uid` when each pathway counted uses up what it
/// rests on: the strongest path within eight relations, then the strongest over what is left,
/// until none is left. Each relation a pathway takes uses up its basis (see `Relation::basis`).
/// A relation without one rests on the link between its two uids, so the pathway uses up every
/// such relation joining them. A relation that rests on a handle many addresses share uses up
/// every relation resting on that handle, so the handle connects them by one pathway, not by
/// one through each address.
#[must_use]
pub fn disjoint_pathways(start_uid: &str, end_uid: &str, relations: &[Relation]) -> usize {
    let index = IdentityIndex::new(relations);
    match (index.node(start_uid), index.node(end_uid)) {
        (Some(start), Some(end)) => PathwayCounter::new(&index).count(start, end, None, usize::MAX),
        _ => 0,
    }
}

/// The pathways [`pairwise_disjoint_pathways`] finds between one pair of uids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairPathways<'r> {
    /// The positions of the pair in the uids, `left` before `right`.
    pub left: usize,
    pub right: usize,
    /// How many pathways connect the pair, up to the cap.
    pub count: usize,
    /// The basis (see `Relation::basis`) that every relation of the pair's strongest pathway
    /// rests on, when one basis carries all of it. With a `count` of one, that basis is all that
    /// connects the pair.
    pub basis: Option<&'r str>,
}

/// `disjoint_pathways(uids[left], uids[right], relations)`, counted up to `cap`, for every pair
/// with `left < right` that a pathway connects, in order of `left` and then `right`. One search
/// from each uid finds its first pathway to every other uid, so only the pathways after the
/// first take a search per pair, and a pair in different components of the identity relations
/// takes none. A component that one named basis carries, such as the addresses one handle
/// joins, takes no search at all (see [`IdentityIndex::sole_carrier`]).
#[must_use]
pub fn pairwise_disjoint_pathways<'r>(
    uids: &[&str],
    relations: &'r [Relation],
    cap: usize,
) -> Vec<PairPathways<'r>> {
    let index = IdentityIndex::new(relations);
    let component = index.components();
    let shapes = index.shapes(&component);
    let mut members = HashMap::<usize, Vec<(usize, usize)>>::new();
    for (position, uid) in uids.iter().enumerate() {
        if let Some(node) = index.node(uid) {
            members
                .entry(component[node])
                .or_default()
                .push((position, node));
        }
    }
    let removed = vec![false; index.bases.len()];
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
        if let Some(basis) = index.sole_carrier(shapes[start]) {
            out.extend(
                later
                    .iter()
                    .filter(|&&(_, end)| end != start)
                    .map(|&(right, _)| PairPathways {
                        left,
                        right,
                        count: 1,
                        basis: Some(basis),
                    }),
            );
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
            out.push(PairPathways {
                left,
                right,
                count: counter.count(start, end, Some((&search, step)), cap),
                basis: index.sole_basis(&search, step),
            });
        }
        for node in reached.drain(..) {
            first[node] = None;
        }
    }
    out
}

#[must_use]
pub fn resolve_identity_clusters(relations: &[Relation]) -> Vec<Vec<String>> {
    let identity = relations
        .iter()
        .filter(|relation| relation.kind.binds_identity())
        .collect::<Vec<_>>();
    let mut ids = identity
        .iter()
        .flat_map(|relation| [relation.from_uid.as_str(), relation.to_uid.as_str()])
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    let index = ids
        .iter()
        .enumerate()
        .map(|(i, &id)| (id, i))
        .collect::<HashMap<&str, usize>>();
    let mut uf = UnionFind::new(ids.len());
    for relation in &identity {
        uf.union(
            index[relation.from_uid.as_str()],
            index[relation.to_uid.as_str()],
        );
    }
    let mut groups = uf
        .groups()
        .into_iter()
        .map(|group| {
            group
                .into_iter()
                .map(|idx| ids[idx].to_owned())
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

    /// The position and count of each pair, without the basis.
    fn counts(pairs: &[PairPathways<'_>]) -> Vec<(usize, usize, usize)> {
        pairs
            .iter()
            .map(|pair| (pair.left, pair.right, pair.count))
            .collect()
    }

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
            .map(|pair| (uids[pair.left], uids[pair.right], pair.count))
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
            counts(&pairwise_disjoint_pathways(
                &["a", "ghost", "e", "a", "d"],
                &relations,
                usize::MAX
            )),
            [(0, 2, 1), (0, 4, 2), (2, 3, 1), (2, 4, 1), (3, 4, 2)]
        );
        assert_eq!(
            counts(&pairwise_disjoint_pathways(&["a", "d"], &relations, 1)),
            [(0, 1, 1)]
        );
        assert_eq!(pairwise_disjoint_pathways(&["a", "d"], &relations, 0), []);
    }

    /// One handle that five addresses share makes every two of them aliases, and each of those
    /// relations rests on the handle. So the handle is one pathway for every pair, where each
    /// other address used to count as a pathway of its own. Evidence that rests on something
    /// else adds a pathway: an owner named on two of the addresses does for that pair, and so
    /// does a secret two of them share beside their alias. A relation without a basis rests on
    /// the link between its two entities, so a second one beside that secret adds nothing.
    #[test]
    fn a_shared_basis_carries_one_pathway() {
        let sites = ["s0", "s1", "s2", "s3", "s4"];
        let mut relations = Vec::new();
        for (left, from) in sites.iter().enumerate() {
            for to in &sites[left + 1..] {
                relations.push(
                    Relation::new(*from, *to, RelationKind::AliasOf, 0.9, "s")
                        .with_basis("handle:jsmith"),
                );
            }
        }
        let pairs = pairwise_disjoint_pathways(&sites, &relations, usize::MAX);
        assert_eq!(pairs.len(), 10);
        for pair in &pairs {
            assert_eq!(
                (pair.count, pair.basis),
                (1, Some("handle:jsmith")),
                "{pair:?}"
            );
        }
        let unbased = relations
            .iter()
            .cloned()
            .map(|mut relation| {
                relation.basis = None;
                relation
            })
            .collect::<Vec<_>>();
        for pair in pairwise_disjoint_pathways(&sites, &unbased, usize::MAX) {
            assert_eq!((pair.count, pair.basis), (4, None), "{pair:?}");
        }

        relations.push(Relation::new(
            "owner",
            "s0",
            RelationKind::IdentifiedBy,
            0.8,
            "s",
        ));
        relations.push(Relation::new(
            "owner",
            "s1",
            RelationKind::IdentifiedBy,
            0.8,
            "s",
        ));
        assert_eq!(disjoint_pathways("s0", "s1", &relations), 2);
        assert_eq!(disjoint_pathways("s0", "s2", &relations), 1);
        assert_eq!(disjoint_pathways("owner", "s0", &relations), 2);
        assert_eq!(disjoint_pathways("owner", "s2", &relations), 1);
        let owned = pairwise_disjoint_pathways(&["owner", "s2"], &relations, usize::MAX);
        assert_eq!(owned[0].basis, None, "the owner's link is not the handle");

        relations.push(Relation::new(
            "s2",
            "s3",
            RelationKind::SharesSecretWith,
            0.7,
            "s",
        ));
        assert_eq!(disjoint_pathways("s2", "s3", &relations), 2);
        relations.push(Relation::new("s3", "s2", RelationKind::SameAs, 0.7, "s"));
        assert_eq!(disjoint_pathways("s2", "s3", &relations), 2);
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

    /// Pathway counting with bases, written as plainly as it can be, as the oracle the basis
    /// tests compare against: the reference search, run over the relations whose basis no counted
    /// pathway has used, keeping the relations each path takes. A relation without a basis rests
    /// on the link between its two uids.
    mod by_basis {
        use std::cmp::Ordering;
        use std::collections::{BinaryHeap, HashMap, HashSet};

        use super::super::super::types::Relation;

        fn basis(relation: &Relation) -> (String, String) {
            match &relation.basis {
                Some(name) => (name.clone(), String::new()),
                None if relation.from_uid <= relation.to_uid => {
                    (relation.from_uid.clone(), relation.to_uid.clone())
                }
                None => (relation.to_uid.clone(), relation.from_uid.clone()),
            }
        }

        /// `reference::strongest_path` within eight relations over the relations whose basis is
        /// not `used`, as the positions in `relations` of the relations the path takes.
        fn strongest(
            start_uid: &str,
            end_uid: &str,
            relations: &[Relation],
            used: &HashSet<(String, String)>,
        ) -> Option<Vec<usize>> {
            struct State {
                width: f64,
                depth: usize,
                node: String,
                path: Vec<String>,
                taken: Vec<usize>,
            }
            impl PartialEq for State {
                fn eq(&self, other: &Self) -> bool {
                    self.cmp(other) == Ordering::Equal
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

            let mut adj = HashMap::<&str, Vec<usize>>::new();
            for (position, relation) in relations.iter().enumerate() {
                if relation.kind.binds_identity() && !used.contains(&basis(relation)) {
                    adj.entry(&relation.from_uid).or_default().push(position);
                    adj.entry(&relation.to_uid).or_default().push(position);
                }
            }
            let mut heap = BinaryHeap::from([State {
                width: 1.0,
                depth: 0,
                node: start_uid.to_owned(),
                path: vec![start_uid.to_owned()],
                taken: Vec::new(),
            }]);
            let mut best = HashMap::<String, f64>::new();
            while let Some(state) = heap.pop() {
                if state.node == end_uid {
                    return Some(state.taken);
                }
                if state.depth >= 8 || best.get(&state.node).is_some_and(|w| *w >= state.width) {
                    continue;
                }
                best.insert(state.node.clone(), state.width);
                for &position in adj.get(state.node.as_str()).into_iter().flatten() {
                    let relation = &relations[position];
                    let next = if relation.from_uid == state.node {
                        &relation.to_uid
                    } else {
                        &relation.from_uid
                    };
                    if state.path.contains(next) {
                        continue;
                    }
                    let mut path = state.path.clone();
                    path.push(next.clone());
                    let mut taken = state.taken.clone();
                    taken.push(position);
                    heap.push(State {
                        width: state.width.min(relation.confidence),
                        depth: state.depth + 1,
                        node: next.clone(),
                        path,
                        taken,
                    });
                }
            }
            None
        }

        /// How many pathways connect the two uids, and the basis that every relation of the
        /// first rests on, when one named basis carries it all.
        pub fn disjoint_pathways(
            start_uid: &str,
            end_uid: &str,
            relations: &[Relation],
        ) -> (usize, Option<String>) {
            let mut used = HashSet::new();
            let mut count = 0;
            let mut sole = None;
            while let Some(taken) = strongest(start_uid, end_uid, relations, &used) {
                if taken.is_empty() {
                    break;
                }
                if count == 0 {
                    let first = &relations[taken[0]].basis;
                    sole = first.clone().filter(|_| {
                        taken
                            .iter()
                            .all(|&position| relations[position].basis == *first)
                    });
                }
                count += 1;
                used.extend(taken.iter().map(|&position| basis(&relations[position])));
            }
            (count, sole)
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
                    counts(&pairwise_disjoint_pathways(&uids, &relations, cap)),
                    expected,
                    "round {round}: {uids:?} capped at {cap}: {relations:?}"
                );
            }
        }
    }

    /// Pathways count each basis once, exactly as the plain oracle counts them, on random
    /// multigraphs where some relations rest on one of two shared bases: every pair of known and
    /// unknown uids, in any order, repeated uids included, under every cap the rules use.
    #[test]
    fn pathways_count_each_basis_once_as_the_oracle_does() {
        let mut rng = XorShift(0x6A09_E667_F3BC_C908);
        for round in 0..600 {
            let (nodes, mut relations) = random_relations(&mut rng);
            for relation in &mut relations {
                relation.basis = match rng.below(4) {
                    0 => Some("handle:one".to_owned()),
                    1 => Some("handle:two".to_owned()),
                    _ => None,
                };
            }
            let mut uids = (0..rng.below(nodes.len() + 3))
                .map(|_| nodes[rng.below(nodes.len())])
                .collect::<Vec<_>>();
            uids.insert(rng.below(uids.len() + 1), "ghost");
            for &from in &uids {
                for &to in &uids {
                    assert_eq!(
                        disjoint_pathways(from, to, &relations),
                        by_basis::disjoint_pathways(from, to, &relations).0,
                        "round {round}: {from} to {to}: {relations:?}"
                    );
                }
            }
            for cap in [1, 2, usize::MAX] {
                assert_eq!(
                    found_pairs(&uids, &relations, cap),
                    oracle_pairs(&uids, &relations, cap),
                    "round {round}: {uids:?} capped at {cap}: {relations:?}"
                );
            }
        }
    }

    /// A pair of uids, by position, with its pathway count and the named basis that carries its
    /// first pathway alone.
    type Pair = (usize, usize, usize, Option<String>);

    /// The pairs `pairwise_disjoint_pathways` finds.
    fn found_pairs(uids: &[&str], relations: &[Relation], cap: usize) -> Vec<Pair> {
        pairwise_disjoint_pathways(uids, relations, cap)
            .into_iter()
            .map(|pair| {
                (
                    pair.left,
                    pair.right,
                    pair.count,
                    pair.basis.map(str::to_owned),
                )
            })
            .collect()
    }

    /// The pairs the plain oracle finds, counted pair by pair.
    fn oracle_pairs(uids: &[&str], relations: &[Relation], cap: usize) -> Vec<Pair> {
        (0..uids.len())
            .flat_map(|left| (left + 1..uids.len()).map(move |right| (left, right)))
            .filter_map(|(left, right)| {
                let (count, basis) =
                    by_basis::disjoint_pathways(uids[left], uids[right], relations);
                (count > 0).then(|| (left, right, count.min(cap), basis))
            })
            .collect()
    }

    const IDENTITY_KINDS: [RelationKind; 5] = [
        RelationKind::AliasOf,
        RelationKind::SameAs,
        RelationKind::IdentifiedBy,
        RelationKind::SameIdentity,
        RelationKind::SharesSecretWith,
    ];

    /// A random component in which every two of a few nodes are joined, by one to three
    /// relations each way round: either each as strong as the weaker of the two nodes it joins,
    /// as derived relations are, or of any strength; and either all resting on one handle, as the
    /// aliases one shared handle implies do, or on several bases. Some rounds leave two nodes
    /// unjoined or add a node joined to only one, so that the component is not complete, and
    /// some add a self-loop or a relation that binds no identity.
    fn random_clique(rng: &mut XorShift) -> (Vec<&'static str>, Vec<Relation>) {
        let size = 2 + rng.below(NODES.len() - 2);
        let strength = (0..size)
            .map(|_| CONFIDENCES[rng.below(CONFIDENCES.len())])
            .collect::<Vec<_>>();
        let bounded = rng.below(3) != 0;
        let one_handle = rng.below(3) != 0;
        let basis = |rng: &mut XorShift| match rng.below(if one_handle { 1 } else { 3 }) {
            0 => Some("handle:one".to_owned()),
            1 => Some("handle:two".to_owned()),
            _ => None,
        };
        let unjoined = (rng.below(4) == 0).then(|| (rng.below(size), rng.below(size)));
        let mut relations = Vec::new();
        for left in 0..size {
            for right in left + 1..size {
                if unjoined == Some((left, right)) || unjoined == Some((right, left)) {
                    continue;
                }
                for _ in 0..1 + rng.below(3) {
                    let (from, to) = if rng.below(2) == 0 {
                        (left, right)
                    } else {
                        (right, left)
                    };
                    let kind = IDENTITY_KINDS[rng.below(IDENTITY_KINDS.len())];
                    let mut relation = Relation::new(NODES[from], NODES[to], kind, 0.5, "s");
                    relation.confidence = if bounded {
                        strength[left].min(strength[right])
                    } else {
                        CONFIDENCES[rng.below(CONFIDENCES.len())]
                    };
                    relation.basis = basis(rng);
                    relations.push(relation);
                }
            }
        }
        let mut nodes = NODES[..size].to_vec();
        if rng.below(4) == 0 {
            nodes.push(NODES[size]);
            let mut relation = Relation::new(
                NODES[size],
                NODES[rng.below(size)],
                RelationKind::AliasOf,
                0.5,
                "s",
            );
            relation.confidence = CONFIDENCES[rng.below(CONFIDENCES.len())];
            relation.basis = basis(rng);
            relations.push(relation);
        }
        if rng.below(3) == 0 {
            let node = NODES[rng.below(size)];
            let mut relation = Relation::new(node, node, RelationKind::SameAs, 0.5, "s");
            relation.confidence = CONFIDENCES[rng.below(CONFIDENCES.len())];
            relation.basis = basis(rng);
            relations.push(relation);
        }
        if rng.below(3) == 0 {
            let (from, to) = (NODES[rng.below(size)], NODES[rng.below(size)]);
            relations.push(Relation::new(
                from,
                to,
                RelationKind::AssociatedWith,
                0.9,
                "s",
            ));
        }
        for at in (1..relations.len()).rev() {
            relations.swap(at, rng.below(at + 1));
        }
        (nodes, relations)
    }

    /// Components in which every two nodes are joined, which the searches skip when one named
    /// basis carries them or every relation is as strong as its weaker end, answer exactly as
    /// the per-pair searches do, whatever else the component holds. Both shortcuts are taken in
    /// many rounds.
    #[test]
    fn complete_components_answer_exactly_as_the_per_pair_searches_do() {
        let mut rng = XorShift(0x3C6E_F372_FE94_F82B);
        let (mut carried, mut bounded) = (0, 0);
        for round in 0..600 {
            let (nodes, relations) = random_clique(&mut rng);
            let index = IdentityIndex::new(&relations);
            let shapes = index.shapes(&index.components());
            carried += usize::from(
                shapes
                    .iter()
                    .any(|&shape| index.sole_carrier(shape).is_some()),
            );
            bounded += usize::from(shapes.iter().any(|shape| shape.complete && shape.bounded));
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
            let mut uids = nodes.clone();
            uids.extend((0..rng.below(3)).map(|_| nodes[rng.below(nodes.len())]));
            uids.push("ghost");
            for at in (1..uids.len()).rev() {
                uids.swap(at, rng.below(at + 1));
            }
            for cap in [1, 2, usize::MAX] {
                assert_eq!(
                    found_pairs(&uids, &relations, cap),
                    oracle_pairs(&uids, &relations, cap),
                    "round {round}: {uids:?} capped at {cap}: {relations:?}"
                );
            }
        }
        assert!(carried >= 150 && bounded >= 150, "{carried} {bounded}");
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
        assert!(counts.iter().all(|pair| pair.count == 1));
        assert_eq!(brokers, [("person".to_owned(), 1000 * 999 / 2)]);
    }

    /// A handle shared by a thousand addresses, a full page of breach records, makes them a
    /// clique of 499,500 aliases, each resting on the handle and as strong as the weaker of its
    /// two addresses. A search from each address queued a path through every alias, so the
    /// pathways and the brokers grew as the cube of the group and took minutes. One handle
    /// carries every pathway, and no path between two addresses is stronger than the alias
    /// joining them, so neither takes a search and both are quadratic.
    #[test]
    fn a_shared_handle_is_counted_in_quadratic_time() {
        let sites = (0..1000)
            .map(|n| (format!("site{n}"), [0.9_f64, 0.8, 0.7][n % 3]))
            .collect::<Vec<_>>();
        let mut relations = Vec::new();
        for (left, (from, weak)) in sites.iter().enumerate() {
            for (to, strong) in &sites[left + 1..] {
                relations.push(
                    Relation::new(from, to, RelationKind::AliasOf, weak.min(*strong), "s")
                        .with_basis("handle:jsmith"),
                );
            }
        }
        let uids = sites
            .iter()
            .map(|(site, _)| site.as_str())
            .collect::<Vec<_>>();
        let started = std::time::Instant::now();
        let pairs = pairwise_disjoint_pathways(&uids, &relations, usize::MAX);
        let brokers = connection_brokers(&relations);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(pairs.len(), 1000 * 999 / 2);
        assert!(
            pairs
                .iter()
                .all(|pair| pair.count == 1 && pair.basis == Some("handle:jsmith"))
        );
        assert!(brokers.is_empty(), "{brokers:?}");
    }
}
