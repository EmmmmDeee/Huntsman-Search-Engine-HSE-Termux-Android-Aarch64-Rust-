use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};

use crate::union_find::UnionFind;

use super::types::{Basis, Relation};

/// How deep a pathway that `disjoint_pathways` counts may run.
const PATHWAY_MAX_DEPTH: usize = 8;
/// Resource caps for exact evidence-basis packing; larger inputs use the conservative fallback.
const EXACT_MAX_EDGES: usize = 20;
const EXACT_MAX_BASES: usize = 12;
const EXACT_MAX_NODES: usize = 12;
const EXACT_MAX_WALK_VISITS: usize = 2_048;
const EXACT_MAX_PATH_MASKS: usize = 96;
const EXACT_MAX_PACK_STATES: usize = 4_096;
/// How deep a path whose intermediate nodes `connection_brokers` scores may run.
const BROKER_MAX_DEPTH: usize = 6;
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

    /// Count independent evidence bases exactly when the graph is small enough to enumerate.
    /// All simple routes up to `PATHWAY_MAX_DEPTH` are considered; a shared named basis occupies
    /// just one bit even if several edges of a path use it. No relation confidence threshold
    /// is imposed on existence of a route. Resource limits make this a best-effort exact
    /// improvement over the legacy greedy lower bound, not a proof of global optimality on
    /// arbitrarily large or dense evidence graphs.
    fn exact_pathway_count(&self, start: usize, end: usize, cap: usize) -> Option<usize> {
        if start == end || cap == 0 {
            return Some(0);
        }
        if self.edges.len() > EXACT_MAX_EDGES
            || self.bases.len() > EXACT_MAX_BASES
            || self.len() > EXACT_MAX_NODES
        {
            return None;
        }

        struct Walk<'i, 'a> {
            index: &'i IdentityIndex<'a>,
            seen: Vec<bool>,
            masks: Vec<u32>,
            visits: usize,
        }

        impl Walk<'_, '_> {
            fn collect(&mut self, at: usize, end: usize, depth: usize, used: u32) -> bool {
                self.visits += 1;
                if self.visits > EXACT_MAX_WALK_VISITS {
                    return false;
                }
                if at == end {
                    self.masks.push(used);
                    return self.masks.len() <= EXACT_MAX_PATH_MASKS;
                }
                if depth == PATHWAY_MAX_DEPTH {
                    return true;
                }
                for &edge in &self.index.incident[at] {
                    let next = self.index.across(edge, at);
                    if self.seen[next] {
                        continue;
                    }
                    self.seen[next] = true;
                    let complete = self.collect(
                        next,
                        end,
                        depth + 1,
                        used | (1_u32 << self.index.basis[edge]),
                    );
                    self.seen[next] = false;
                    if !complete {
                        return false;
                    }
                }
                true
            }
        }

        struct Packing<'m> {
            masks: &'m [u32],
            memo: HashMap<u32, usize>,
            visited: usize,
            cap: usize,
        }

        impl Packing<'_> {
            fn best(&mut self, used: u32) -> Option<usize> {
                if let Some(&result) = self.memo.get(&used) {
                    return Some(result);
                }
                self.visited += 1;
                if self.visited > EXACT_MAX_PACK_STATES {
                    return None;
                }
                let mut result = 0;
                for index in 0..self.masks.len() {
                    let mask = self.masks[index];
                    if mask & used != 0 {
                        continue;
                    }
                    let candidate = 1 + self.best(used | mask)?;
                    result = result.max(candidate);
                    if result >= self.cap {
                        break;
                    }
                }
                let result = result.min(self.cap);
                self.memo.insert(used, result);
                Some(result)
            }
        }

        let mut walk = Walk {
            index: self,
            seen: vec![false; self.len()],
            masks: Vec::new(),
            visits: 0,
        };
        walk.seen[start] = true;
        if !walk.collect(start, end, 0, 0) {
            return None;
        }
        walk.masks.sort_unstable();
        walk.masks.dedup();
        let mut packing = Packing {
            masks: &walk.masks,
            memo: HashMap::new(),
            visited: 0,
            cap,
        };
        packing.best(0)
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

    /// Calls `visit` with the strongest path (see [`Search::run`]), within `max_depth`, from each
    /// node to each node after it in uid order. One search from each node finds all of them: a
    /// search pops paths in the same order whichever node it is looking for, so the first path
    /// it pops to a node is the one a search that stops there returns.
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
    /// The shallowest depth each node has been expanded at in the current search, if it has been.
    shallowest: Vec<Option<usize>>,
    expanded: Vec<usize>,
}

impl Search {
    fn new(nodes: usize) -> Self {
        Self {
            heap: BinaryHeap::new(),
            steps: Vec::new(),
            shallowest: vec![None; nodes],
            expanded: Vec::new(),
        }
    }

    /// Runs the widest-path search from `start` over the edges whose basis is not `removed`. A path
    /// never revisits a node and expands no deeper than `max_depth`. A node is expanded from a path
    /// only when no earlier expansion of it was from a path as shallow, and paths pop widest first,
    /// so an earlier expansion is never narrower. Hence the first path it pops to a node is a widest
    /// path from `start` to that node within `max_depth`, and of the widest, a shallowest one; paths
    /// equally wide and equally deep are not told apart. Each path popped is offered to `accept`, by
    /// its last node and step, before it is expanded.
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
            self.shallowest[node] = None;
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
            match self.shallowest[state.node] {
                Some(seen) if seen <= state.depth => continue,
                Some(_) => {}
                None => self.expanded.push(state.node),
            }
            self.shallowest[state.node] = Some(state.depth);
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

    /// For small bounded graphs, count the maximum basis-disjoint routes exactly. For large or
    /// combinatorially expensive graphs, fall back to the legacy strongest-first lower bound.
    /// `first`, when given, is the already-found strongest path for that fallback.
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
        if let Some(exact) = self.index.exact_pathway_count(start, end, cap) {
            return exact;
        }
        self.greedy_count(start, end, first, cap)
    }

    /// Use selected disjoint paths when the exact search exceeds its resource budget.
    fn greedy_count(
        &mut self,
        start: usize,
        end: usize,
        first: Option<(&Search, usize)>,
        cap: usize,
    ) -> usize {
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

/// Count evidence-basis-disjoint identity paths of at most eight relations. Small graphs use
/// bounded exact packing; larger or search-expensive graphs retain the strongest-first greedy
/// lower bound. An unnamed relation uses the undirected link between its endpoints as its basis;
/// relations sharing a named basis cannot independently corroborate each other. This numeric
/// API cannot convey whether the result was exact; callers MUST treat it as a lower bound when
/// graph size or search complexity exceeds the exact limits.
#[must_use]
pub fn disjoint_pathways(start_uid: &str, end_uid: &str, relations: &[Relation]) -> usize {
    let index = IdentityIndex::new(relations);
    match (index.node(start_uid), index.node(end_uid)) {
        (Some(start), Some(end)) => PathwayCounter::new(&index).count(start, end, None, usize::MAX),
        _ => 0,
    }
}

/// Whether the reported evidence-basis-disjoint pathway count is established exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathwayPrecision {
    /// Exhaustive bounded search completed, or a missing/identical selector proves zero.
    Exact,
    /// Exact enumeration hit a resource cap, leaving only a verified lower bound.
    ConservativeLowerBound,
}

/// A corroboration-pathway count accompanied by its epistemic scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct PathwayAssessment {
    /// Count of basis-disjoint paths within the eight-edge search limit.
    pub count: usize,
    /// Exact count or conservative lower bound; never infer precision from count alone.
    pub precision: PathwayPrecision,
}

/// Report both the number of disjoint corroboration pathways and its exactness.
/// The conservative lower bound may underestimate independent corroboration.
/// No provider requests, database writes or other I/O are performed.
#[must_use]
pub fn assess_disjoint_pathways(
    start_uid: &str,
    end_uid: &str,
    relations: &[Relation],
) -> PathwayAssessment {
    let index = IdentityIndex::new(relations);
    let (Some(start), Some(end)) = (index.node(start_uid), index.node(end_uid)) else {
        return PathwayAssessment {
            count: 0,
            precision: PathwayPrecision::Exact,
        };
    };
    if start == end {
        return PathwayAssessment {
            count: 0,
            precision: PathwayPrecision::Exact,
        };
    }
    match index.exact_pathway_count(start, end, usize::MAX) {
        Some(count) => PathwayAssessment {
            count,
            precision: PathwayPrecision::Exact,
        },
        None => PathwayAssessment {
            count: PathwayCounter::new(&index).greedy_count(start, end, None, usize::MAX),
            precision: PathwayPrecision::ConservativeLowerBound,
        },
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
    /// rests on, when one basis carries all of it. With a `count` of one, that basis is all the
    /// one pathway found rests on.
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
    // `ids` is sorted and each group lists its indices in order, so the groups come out
    // sorted by their first uid.
    uf.groups()
        .into_iter()
        .map(|group| {
            group
                .into_iter()
                .map(|idx| ids[idx].to_owned())
                .collect::<Vec<_>>()
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

    use super::super::types::{Basis, RelationKind};
    use super::*;

    /// The position and count of each pair, without the basis.
    fn counts(pairs: &[PairPathways<'_>]) -> Vec<(usize, usize, usize)> {
        pairs
            .iter()
            .map(|pair| (pair.left, pair.right, pair.count))
            .collect()
    }

    #[test]
    fn clusters_follow_identity_edges() {
        let relations = vec![
            Relation::new("a", "b", RelationKind::AliasOf, 0.8, "s"),
            Relation::new("b", "c", RelationKind::IdentifiedBy, 0.7, "s"),
            Relation::new("c", "d", RelationKind::AssociatedWith, 0.9, "s"),
        ];
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

    /// The widest greedy S-A-B-T route consumes both branches, although S-A-T and S-B-T
    /// provide two independent, basis-disjoint corroboration routes. Reversed input order
    /// must not change the exact count.
    #[test]
    fn strongest_path_cannot_destroy_independent_corroboration() {
        let relations = vec![
            Relation::new("S", "A", RelationKind::AliasOf, 0.95, "s"),
            Relation::new("A", "B", RelationKind::AliasOf, 0.95, "s"),
            Relation::new("B", "T", RelationKind::AliasOf, 0.95, "s"),
            Relation::new("A", "T", RelationKind::AliasOf, 0.80, "s"),
            Relation::new("S", "B", RelationKind::AliasOf, 0.80, "s"),
        ];
        for ordered in [relations.clone(), relations.iter().rev().cloned().collect()] {
            assert_eq!(disjoint_pathways("S", "T", &ordered), 2);
            assert_eq!(disjoint_pathways("T", "S", &ordered), 2);
            assert_eq!(
                counts(&pairwise_disjoint_pathways(&["S", "T"], &ordered, 2)),
                [(0, 1, 2)]
            );
            assert_eq!(
                counts(&pairwise_disjoint_pathways(&["S", "T"], &ordered, 1)),
                [(0, 1, 1)]
            );
        }
    }

    /// Dense components skip exact enumeration by design; the fallback remains bounded by the
    /// existing search and never fabricates more pathways than it actually selected.
    #[test]
    fn dense_components_keep_conservative_fallback() {
        let nodes = ["a", "b", "c", "d", "e", "f", "g", "h"];
        let mut relations = Vec::new();
        for (i, &left) in nodes.iter().enumerate() {
            for &right in &nodes[i + 1..] {
                relations.push(Relation::new(left, right, RelationKind::AliasOf, 0.8, "s"));
            }
        }
        let index = IdentityIndex::new(&relations);
        assert!(
            index
                .exact_pathway_count(
                    index.node("a").unwrap(),
                    index.node("b").unwrap(),
                    usize::MAX
                )
                .is_none()
        );
        assert!(disjoint_pathways("a", "b", &relations) >= 1);
    }

    /// A wide path of seven relations reaches `X` at depth seven, and would expand `X` before the
    /// narrow `S`-`X` relation is popped. The narrow path `S`, `X`, `Y`, `T` is three relations
    /// long, inside the bound, so it counts once; the wide path reaches `T` only at depth nine.
    #[test]
    fn a_wide_deep_path_does_not_prune_a_narrow_shallow_one() {
        assert_eq!(disjoint_pathways("S", "T", &probe_relations()), 1);
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

    /// The brute-force oracle the equivalence tests compare against. It walks every simple path of
    /// identity relations depth-first, with no search over states and no pruning by node. Its one
    /// cut cannot change its answer: a partial path is left unextended only when no completion of
    /// it can beat the strongest path found so far, since a completion is no wider and, being
    /// longer, no shallower. What it keeps is the widest path, then the shallowest, and of those
    /// the first in depth-first order. Equally strong paths are not told apart, so an exact count
    /// or broker score can depend on which of them is taken.
    mod reference {
        use std::cmp::Ordering;
        use std::collections::{BTreeSet, HashSet};

        use super::super::super::types::{Basis, Relation};

        /// The depth-first walk of [`strongest_path`]: the path so far, and the strongest path
        /// found.
        struct Walk<'a, 'r> {
            end_uid: &'a str,
            relations: &'r [Relation],
            max_depth: usize,
            used: &'a HashSet<Basis<'r>>,
            nodes: Vec<&'r str>,
            taken: Vec<usize>,
            best: Option<(f64, Vec<usize>)>,
        }

        impl<'r> Walk<'_, 'r> {
            /// Whether a path that is `depth` relations long and `width` wide beats the strongest
            /// path found: it does when it is wider, or as wide and shallower.
            fn beats(&self, width: f64, depth: usize) -> bool {
                match &self.best {
                    None => true,
                    Some((best, taken)) => match width.total_cmp(best) {
                        Ordering::Greater => true,
                        Ordering::Equal => depth < taken.len(),
                        Ordering::Less => false,
                    },
                }
            }

            /// Walks on from `at`, which the path so far reaches `width` wide.
            fn extend(&mut self, at: &'r str, width: f64) {
                if at == self.end_uid {
                    if self.beats(width, self.taken.len()) {
                        self.best = Some((width, self.taken.clone()));
                    }
                    return;
                }
                // Every completion is at least one relation longer and no wider than this path.
                if self.taken.len() == self.max_depth || !self.beats(width, self.taken.len() + 1) {
                    return;
                }
                let relations = self.relations;
                for (position, relation) in relations.iter().enumerate() {
                    if !relation.kind.binds_identity() || self.used.contains(&relation.rests_on()) {
                        continue;
                    }
                    let next = if relation.from_uid == at {
                        relation.to_uid.as_str()
                    } else if relation.to_uid == at {
                        relation.from_uid.as_str()
                    } else {
                        continue;
                    };
                    if self.nodes.contains(&next) {
                        continue;
                    }
                    self.nodes.push(next);
                    self.taken.push(position);
                    self.extend(next, width.min(relation.confidence));
                    self.taken.pop();
                    self.nodes.pop();
                }
            }
        }

        /// The strongest path of identity relations from `start_uid` to `end_uid` within
        /// `max_depth` relations, over the relations whose basis is not in `used`: the positions in
        /// `relations` of the relations it takes, from its start. It is the widest such path, then
        /// the shallowest, and of those the first in depth-first order.
        pub fn strongest_path<'r>(
            start_uid: &'r str,
            end_uid: &'r str,
            relations: &'r [Relation],
            max_depth: usize,
            used: &HashSet<Basis<'r>>,
        ) -> Option<Vec<usize>> {
            let mut walk = Walk {
                end_uid,
                relations,
                max_depth,
                used,
                nodes: vec![start_uid],
                taken: Vec::new(),
                best: None,
            };
            walk.extend(start_uid, 1.0);
            walk.best.map(|(_, taken)| taken)
        }

        /// How many pathways connect the two uids, and the basis that every relation of the first
        /// pathway rests on, when one named basis carries it all. A pathway is the strongest path
        /// within eight relations, with the bases it rests on used up, and the pathways repeat over
        /// what is left until none is left.
        pub fn disjoint_pathways<'r>(
            start_uid: &'r str,
            end_uid: &'r str,
            relations: &'r [Relation],
        ) -> (usize, Option<String>) {
            if start_uid == end_uid {
                return (0, None);
            }
            let mut used = HashSet::new();
            let mut count = 0;
            let mut sole = None;
            while let Some(taken) = strongest_path(start_uid, end_uid, relations, 8, &used) {
                if count == 0 {
                    let first = &relations[taken[0]].basis;
                    sole = first.clone().filter(|_| {
                        taken
                            .iter()
                            .all(|&position| relations[position].basis == *first)
                    });
                }
                count += 1;
                used.extend(taken.iter().map(|&position| relations[position].rests_on()));
            }
            (count, sole)
        }

        /// The depth-first walk of [`optimal_visit`]: the path so far, and the visitor that takes
        /// each path found.
        struct Gather<'a, 'r, 'v> {
            end_uid: &'a str,
            relations: &'r [Relation],
            used: &'a HashSet<Basis<'r>>,
            /// The width and the length every path found must have.
            width: f64,
            length: usize,
            nodes: Vec<&'r str>,
            taken: Vec<usize>,
            visit: &'v mut dyn FnMut(&[usize]) -> bool,
            /// Whether `visit` has asked the walk to stop.
            done: bool,
        }

        impl<'r> Gather<'_, 'r, '_> {
            /// Walks on from `at`, which the path so far reaches `width` wide.
            fn extend(&mut self, at: &'r str, width: f64) {
                if at == self.end_uid {
                    if width.total_cmp(&self.width).is_eq() && self.taken.len() == self.length {
                        self.done = (self.visit)(&self.taken);
                    }
                    return;
                }
                // Widths only narrow, and a path that is longer than the target cannot reach it.
                if self.taken.len() + 1 > self.length || width.total_cmp(&self.width).is_lt() {
                    return;
                }
                let relations = self.relations;
                for (position, relation) in relations.iter().enumerate() {
                    if self.done {
                        return;
                    }
                    if !relation.kind.binds_identity() || self.used.contains(&relation.rests_on()) {
                        continue;
                    }
                    let next = if relation.from_uid == at {
                        relation.to_uid.as_str()
                    } else if relation.to_uid == at {
                        relation.from_uid.as_str()
                    } else {
                        continue;
                    };
                    if self.nodes.contains(&next) {
                        continue;
                    }
                    self.nodes.push(next);
                    self.taken.push(position);
                    self.extend(next, width.min(relation.confidence));
                    self.taken.pop();
                    self.nodes.pop();
                }
            }
        }

        /// Calls `visit` with each path of identity relations from `start_uid` to `end_uid` within
        /// `max_depth` relations, over the relations whose basis is not in `used`, that is as strong
        /// as the strongest path ([`strongest_path`]): as wide and as long. Each is the positions of
        /// the relations it takes, from its start. The walk stops once `visit` returns true, and the
        /// result is whether it did.
        fn optimal_visit<'r>(
            start_uid: &'r str,
            end_uid: &'r str,
            relations: &'r [Relation],
            max_depth: usize,
            used: &HashSet<Basis<'r>>,
            visit: &mut dyn FnMut(&[usize]) -> bool,
        ) -> bool {
            let Some(best) = strongest_path(start_uid, end_uid, relations, max_depth, used) else {
                return false;
            };
            let width = best
                .iter()
                .map(|&position| relations[position].confidence)
                .fold(1.0, f64::min);
            let mut gather = Gather {
                end_uid,
                relations,
                used,
                width,
                length: best.len(),
                nodes: vec![start_uid],
                taken: Vec::new(),
                visit,
                done: false,
            };
            gather.extend(start_uid, 1.0);
            gather.done
        }

        /// The basis that every relation of `path` rests on, when it is a named one.
        fn sole_basis(path: &[usize], relations: &[Relation]) -> Option<String> {
            let first = &relations[path[0]].basis;
            first.clone().filter(|_| {
                path.iter()
                    .all(|&position| relations[position].basis == *first)
            })
        }

        /// How many paths a tie check may visit before it gives up. A check that gives up is
        /// undecided, and the test that asked fails rather than counting it as allowed.
        pub struct Budget {
            pub left: usize,
            pub exhausted: bool,
        }

        /// Spends one visit of `budget`, and says whether the walk must stop because it ran out.
        fn spend(budget: &mut Budget) -> bool {
            if budget.left == 0 {
                budget.exhausted = true;
                return true;
            }
            budget.left -= 1;
            false
        }

        /// The basis that a tie check asks the first pathway to rest on.
        #[derive(Clone, Copy)]
        pub enum Want<'a> {
            /// Any basis, or none.
            Any,
            /// No named basis: the first pathway rests on links alone.
            Unbased,
            /// This named basis alone.
            Named(&'a str),
        }

        impl Want<'_> {
            /// Whether a first pathway that rests on `sole` (see [`sole_basis`]) is wanted.
            fn fits(self, sole: Option<&str>) -> bool {
                match self {
                    Self::Any => true,
                    Self::Unbased => sole.is_none(),
                    Self::Named(name) => sole == Some(name),
                }
            }
        }

        /// A tie check's state: the two uids, the relations, the states known not to be allowed,
        /// and the budget it may still spend.
        struct Tie<'r, 'b> {
            start_uid: &'r str,
            end_uid: &'r str,
            relations: &'r [Relation],
            failed: HashSet<(BTreeSet<Basis<'r>>, usize, bool)>,
            budget: &'b mut Budget,
        }

        impl<'r> Tie<'r, '_> {
            /// Whether the pathways left after the bases in `used` are used up can number `need`
            /// (exactly, when `exact`, else at least `need`), over every way of breaking the ties
            /// between equally strong paths.
            fn remaining(&mut self, used: &HashSet<Basis<'r>>, need: usize, exact: bool) -> bool {
                let (start, end, relations) = (self.start_uid, self.end_uid, self.relations);
                if need == 0 {
                    // With no pathway left the count is zero, and otherwise it is at least one.
                    let any = optimal_visit(start, end, relations, 8, used, &mut |_| true);
                    return !any || !exact;
                }
                let key = (used.iter().copied().collect::<BTreeSet<_>>(), need, exact);
                if self.failed.contains(&key) {
                    return false;
                }
                let found = optimal_visit(start, end, relations, 8, used, &mut |path| {
                    if spend(self.budget) {
                        return true;
                    }
                    let mut next = used.clone();
                    next.extend(path.iter().map(|&position| relations[position].rests_on()));
                    self.remaining(&next, need - 1, exact)
                });
                // A walk that ran out of budget stopped early, which is not a found path.
                let allowed = found && !self.budget.exhausted;
                if !allowed && !self.budget.exhausted {
                    self.failed.insert(key);
                }
                allowed
            }

            /// Whether `disjoint_pathways` can return `count` for the two uids (exactly, unless
            /// `at_least`), with its first pathway resting as `want` asks, over every way of
            /// breaking the ties between equally strong paths.
            fn allows(&mut self, count: usize, at_least: bool, want: Want<'_>) -> bool {
                let (start, end, relations) = (self.start_uid, self.end_uid, self.relations);
                if start == end {
                    return count == 0 && want.fits(None);
                }
                let mut any = false;
                let mut allowed = false;
                optimal_visit(start, end, relations, 8, &HashSet::new(), &mut |first| {
                    if spend(self.budget) {
                        return true;
                    }
                    any = true;
                    let sole = sole_basis(first, relations);
                    allowed = want.fits(sole.as_deref())
                        && if count == 0 {
                            at_least
                        } else {
                            let used = first
                                .iter()
                                .map(|&position| relations[position].rests_on())
                                .collect::<HashSet<_>>();
                            self.remaining(&used, count - 1, !at_least)
                        };
                    allowed
                });
                if self.budget.exhausted {
                    false
                } else if any {
                    allowed
                } else {
                    count == 0 && want.fits(None)
                }
            }
        }

        /// Whether `disjoint_pathways` can return `count` for the two uids (exactly, unless
        /// `at_least`), with its first pathway resting as `want` asks, over every way of breaking
        /// the ties between equally strong paths. It stops at the first way that fits, and gives
        /// up, saying so in `budget`, once the budget is spent.
        pub fn allows<'r>(
            start_uid: &'r str,
            end_uid: &'r str,
            relations: &'r [Relation],
            count: usize,
            at_least: bool,
            want: Want<'_>,
            budget: &mut Budget,
        ) -> bool {
            Tie {
                start_uid,
                end_uid,
                relations,
                failed: HashSet::new(),
                budget,
            }
            .allows(count, at_least, want)
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
    /// multigraphs: the pathways between every pair of known and unknown uids, within the eight
    /// relations they count, and the brokers, within the six they score.
    #[test]
    fn the_shared_searches_answer_exactly_as_the_per_pair_searches_did() {
        let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
        for _ in 0..400 {
            let (nodes, relations) = random_relations(&mut rng);
            let mut uids = nodes.clone();
            uids.push("ghost");
            for &from in &uids {
                for &to in &uids {
                    assert_count_allowed(
                        from,
                        to,
                        &relations,
                        disjoint_pathways(from, to, &relations),
                    );
                }
            }
            assert_brokers_allowed(&relations);
        }
    }

    /// Counting every pair at once gives each pair the count `disjoint_pathways` gives it alone,
    /// capped, whatever order the uids come in, unknown and repeated uids included.
    #[test]
    fn pairwise_pathways_count_each_pair_as_disjoint_pathways_does() {
        let mut rng = XorShift(0x2545_F491_4F6C_DD1D);
        for _ in 0..400 {
            let (nodes, relations) = random_relations(&mut rng);
            let mut uids = (0..rng.below(nodes.len() + 3))
                .map(|_| nodes[rng.below(nodes.len())])
                .collect::<Vec<_>>();
            uids.insert(rng.below(uids.len() + 1), "ghost");
            for cap in [0, 1, 2, 3, usize::MAX] {
                let found = pairwise_disjoint_pathways(&uids, &relations, cap);
                assert_pairs_allowed(&uids, &relations, cap, &found);
            }
        }
    }

    /// Pathways count each basis once, exactly as the plain oracle counts them, on random
    /// multigraphs where some relations rest on one of two shared bases: every pair of known and
    /// unknown uids, in any order, repeated uids included, under every cap the rules use.
    #[test]
    fn pathways_count_each_basis_once_as_the_oracle_does() {
        let mut rng = XorShift(0x6A09_E667_F3BC_C908);
        for _ in 0..600 {
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
                    assert_count_allowed(
                        from,
                        to,
                        &relations,
                        disjoint_pathways(from, to, &relations),
                    );
                }
            }
            for cap in [1, 2, usize::MAX] {
                let found = pairwise_disjoint_pathways(&uids, &relations, cap);
                assert_pairs_allowed(&uids, &relations, cap, &found);
            }
        }
    }

    /// How many visits one tie check may spend (see [`reference::Budget`]).
    const TIE_BUDGET: usize = 20_000;

    /// Exact oracle for instances inside the production enumeration budget.
    fn exact_expected(start: &str, end: &str, relations: &[Relation], cap: usize) -> Option<usize> {
        let index = IdentityIndex::new(relations);
        match (index.node(start), index.node(end)) {
            (Some(a), Some(b)) => index.exact_pathway_count(a, b, cap),
            _ => Some(0),
        }
    }

    /// Asserts that `found`, the count `disjoint_pathways` returns for `start` to `end`, is a count
    /// the oracle allows. Ties between equally strong paths leave more than one count open, so the
    /// oracle's own count is one allowed answer, and any other count is checked against every
    /// count the ties allow.
    fn assert_count_allowed(start: &str, end: &str, relations: &[Relation], found: usize) {
        if let Some(exact) = exact_expected(start, end, relations, usize::MAX) {
            assert_eq!(found, exact, "exact evidence-basis packing: {relations:?}");
            return;
        }
        let (oracle, _) = reference::disjoint_pathways(start, end, relations);
        if found == oracle {
            return;
        }
        let mut budget = reference::Budget {
            left: TIE_BUDGET,
            exhausted: false,
        };
        let allowed = reference::allows(
            start,
            end,
            relations,
            found,
            false,
            reference::Want::Any,
            &mut budget,
        );
        assert!(
            allowed,
            "{start} to {end}: {found} is not a count the ties allow (budget spent: {}): \
                {relations:?}",
            budget.exhausted,
        );
    }

    /// Asserts that `found`, the pairs `pairwise_disjoint_pathways` returns for `uids` capped at
    /// `cap`, are the pairs the oracle finds, in the same order, each with a count and a basis the
    /// oracle allows (see [`assert_count_allowed`]). A pair that is not the oracle's own answer is
    /// checked against every answer the ties allow.
    fn assert_pairs_allowed(
        uids: &[&str],
        relations: &[Relation],
        cap: usize,
        found: &[PairPathways<'_>],
    ) {
        let mut expected = Vec::new();
        for left in 0..uids.len() {
            for right in left + 1..uids.len() {
                let (count, basis) =
                    reference::disjoint_pathways(uids[left], uids[right], relations);
                if count > 0 && cap > 0 {
                    expected.push((left, right, count.min(cap), basis));
                }
            }
        }
        let reached = expected
            .iter()
            .map(|&(left, right, _, _)| (left, right))
            .collect::<Vec<_>>();
        let found_reached = found
            .iter()
            .map(|pair| (pair.left, pair.right))
            .collect::<Vec<_>>();
        assert_eq!(
            found_reached, reached,
            "{uids:?} capped at {cap}: {relations:?}"
        );
        for (pair, (left, right, count, basis)) in found.iter().zip(&expected) {
            if let Some(exact) = exact_expected(uids[*left], uids[*right], relations, cap) {
                assert_eq!(pair.count, exact, "exact pairwise packing: {relations:?}");
                continue;
            }
            if pair.count == *count && pair.basis == basis.as_deref() {
                continue;
            }
            // A count that the cap holds at the cap is any count from the cap up.
            let at_least = pair.count == cap;
            let mut budget = reference::Budget {
                left: TIE_BUDGET,
                exhausted: false,
            };
            let allowed = reference::allows(
                uids[*left],
                uids[*right],
                relations,
                pair.count,
                at_least,
                pair.basis
                    .map_or(reference::Want::Unbased, reference::Want::Named),
                &mut budget,
            );
            assert!(
                allowed,
                "{} to {} capped at {cap}: {} {:?} is not allowed (budget spent: {}): \
                    {relations:?}",
                uids[*left], uids[*right], pair.count, pair.basis, budget.exhausted,
            );
        }
    }

    /// The two uids in order.
    fn ordered<'r>(a: &'r str, b: &'r str) -> (&'r str, &'r str) {
        if a <= b { (a, b) } else { (b, a) }
    }

    /// How far an identity relation of `confidence` narrows a path, as the search counts it.
    fn narrowing(confidence: f64) -> f64 {
        1.0_f64.min(confidence)
    }

    /// The fewest relations of identity that join `start` to `end`, over the relations at least
    /// `width` wide whose basis is not in `used`, by breadth-first search.
    fn fewest_relations<'r>(
        start: &str,
        end: &str,
        relations: &'r [Relation],
        width: f64,
        used: &HashSet<Basis<'r>>,
    ) -> Option<usize> {
        let mut distance = HashMap::from([(start, 0_usize)]);
        let mut queue = VecDeque::from([start]);
        while let Some(at) = queue.pop_front() {
            if at == end {
                return distance.get(at).copied();
            }
            for relation in relations {
                if !relation.kind.binds_identity()
                    || narrowing(relation.confidence) < width
                    || used.contains(&relation.rests_on())
                {
                    continue;
                }
                let next = if relation.from_uid == at {
                    relation.to_uid.as_str()
                } else if relation.to_uid == at {
                    relation.from_uid.as_str()
                } else {
                    continue;
                };
                if !distance.contains_key(next) {
                    let steps = distance[at] + 1;
                    distance.insert(next, steps);
                    queue.push_back(next);
                }
            }
        }
        None
    }

    /// The width and the length of the strongest path between `start` and `end` within `bound`
    /// relations over the relations whose basis is not in `used`, found without enumerating paths:
    /// the widest width at which a path within the bound still joins the two is the strongest
    /// width, since a path is as wide as its narrowest relation, and the fewest relations at that
    /// width is the length. `None` when no path within the bound joins them.
    fn strongest_by_width<'r>(
        start: &str,
        end: &str,
        relations: &'r [Relation],
        bound: usize,
        used: &HashSet<Basis<'r>>,
    ) -> Option<(f64, usize)> {
        let mut widths = relations
            .iter()
            .filter(|relation| {
                relation.kind.binds_identity() && !used.contains(&relation.rests_on())
            })
            .map(|relation| narrowing(relation.confidence))
            .collect::<Vec<_>>();
        widths.sort_by(|left, right| right.total_cmp(left));
        widths.dedup();
        widths.into_iter().find_map(|width| {
            fewest_relations(start, end, relations, width, used)
                .filter(|&length| length <= bound)
                .map(|length| (width, length))
        })
    }

    /// Asserts that the brokers are the ranking of the interiors of one strongest path per pair.
    /// Every pair that a path joins within the bound gets exactly one path from the search, and
    /// each path is as wide as the strongest width and as long as the strongest length, as
    /// [`strongest_by_width`] finds them. Ties leave the choice among equally strong paths open, so
    /// the brokers are checked against those two numbers and not against the oracle's own choice.
    fn assert_brokers_allowed(relations: &[Relation]) {
        let index = IdentityIndex::new(relations);
        let mut scores = vec![0_usize; index.len()];
        let mut visited = BTreeSet::new();
        index.each_strongest_path(BROKER_MAX_DEPTH, |path| {
            let (start, end) = (index.uids[path[0]], index.uids[path[path.len() - 1]]);
            // A search may take any of the relations between two uids, so each hop is as wide as
            // its widest relation, and the path as wide as its narrowest hop.
            let width = path.windows(2).fold(1.0_f64, |width, hop| {
                let widest = index
                    .edges
                    .iter()
                    .filter(|&&(from, to, _)| {
                        (from, to) == (hop[0], hop[1]) || (from, to) == (hop[1], hop[0])
                    })
                    .map(|&(_, _, confidence)| narrowing(confidence))
                    .fold(f64::NEG_INFINITY, f64::max);
                width.min(widest)
            });
            let (strongest_width, strongest_length) =
                strongest_by_width(start, end, relations, BROKER_MAX_DEPTH, &HashSet::new())
                    .expect("a visited pair is joined");
            assert!(
                width.total_cmp(&strongest_width).is_eq() && path.len() - 1 == strongest_length,
                "{start} to {end}: a path of width {width} and length {} is not the strongest, \
                 which is {strongest_width} and {strongest_length}: {relations:?}",
                path.len() - 1,
            );
            let mut distinct = path.to_vec();
            distinct.sort_unstable();
            distinct.dedup();
            assert_eq!(
                distinct.len(),
                path.len(),
                "{start} to {end}: a path revisits a node"
            );
            for &node in &path[1..path.len() - 1] {
                scores[node] += 1;
            }
            visited.insert(ordered(start, end));
        });
        let mut reached = BTreeSet::new();
        for (left, &a) in index.uids.iter().enumerate() {
            for &b in &index.uids[left + 1..] {
                if strongest_by_width(a, b, relations, BROKER_MAX_DEPTH, &HashSet::new()).is_some()
                {
                    reached.insert(ordered(a, b));
                }
            }
        }
        assert_eq!(visited, reached, "{relations:?}");
        let mut ranked = scores
            .iter()
            .enumerate()
            .filter(|&(_, &score)| score > 0)
            .map(|(node, &score)| (index.uids[node].to_owned(), score))
            .collect::<Vec<_>>();
        ranked.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
        assert_eq!(connection_brokers(relations), ranked, "{relations:?}");
    }

    /// Asserts that `found`, the pairs `pairwise_disjoint_pathways` returns for `uids` capped at
    /// `cap`, are exactly the pairs a path joins within the pathway bound, each with the count
    /// `disjoint_pathways` gives it alone, capped. Both are the production search, which takes the
    /// same steps for a pair either way, so the two agree whatever the ties.
    fn assert_pairs_match_per_pair(
        uids: &[&str],
        relations: &[Relation],
        cap: usize,
        found: &[PairPathways<'_>],
    ) {
        let mut expected = Vec::new();
        for left in 0..uids.len() {
            for right in left + 1..uids.len() {
                // A uid is not paired with itself, and a pair a path joins within the bound counts.
                if cap == 0
                    || uids[left] == uids[right]
                    || strongest_by_width(
                        uids[left],
                        uids[right],
                        relations,
                        PATHWAY_MAX_DEPTH,
                        &HashSet::new(),
                    )
                    .is_none()
                {
                    continue;
                }
                let count = disjoint_pathways(uids[left], uids[right], relations).min(cap);
                expected.push((left, right, count));
            }
        }
        assert_eq!(
            counts(found),
            expected,
            "{uids:?} capped at {cap}: {relations:?}"
        );
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
                for _ in 0..=rng.below(3) {
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

    /// The probe of `a_wide_deep_path_does_not_prune_a_narrow_shallow_one`: a wide path of seven
    /// relations reaches `X` at depth seven, and the narrow `S`-`X` relation, `X`-`Y` and `Y`-`T`
    /// make the narrow path `S`, `X`, `Y`, `T`, which the bound of eight relations admits.
    fn probe_relations() -> Vec<Relation> {
        vec![
            Relation::new("S", "A1", RelationKind::AliasOf, 1.0, "s"),
            Relation::new("A1", "A2", RelationKind::AliasOf, 1.0, "s"),
            Relation::new("A2", "A3", RelationKind::AliasOf, 1.0, "s"),
            Relation::new("A3", "A4", RelationKind::AliasOf, 1.0, "s"),
            Relation::new("A4", "A5", RelationKind::AliasOf, 1.0, "s"),
            Relation::new("A5", "A6", RelationKind::AliasOf, 1.0, "s"),
            Relation::new("A6", "X", RelationKind::AliasOf, 1.0, "s"),
            Relation::new("S", "X", RelationKind::AliasOf, 0.5, "s"),
            Relation::new("X", "Y", RelationKind::AliasOf, 1.0, "s"),
            Relation::new("Y", "T", RelationKind::AliasOf, 1.0, "s"),
        ]
    }

    /// Checks `Search::run` from each uid to each other one, within `max_depth` relations and with
    /// the bases in `removed` taken away. Where the brute-force enumeration finds a path, the search
    /// pops to the end a simple path over the relations that are left, as wide as the enumeration's
    /// and as long; where it finds none, the search finds none.
    fn check_search<'r>(
        uids: &[&'r str],
        relations: &'r [Relation],
        removed: &HashSet<Basis<'r>>,
        max_depth: usize,
    ) {
        let index = IdentityIndex::new(relations);
        let flags = index
            .bases
            .iter()
            .map(|basis| removed.contains(basis))
            .collect::<Vec<_>>();
        let mut search = Search::new(index.len());
        for &from in uids {
            for &to in uids {
                let (Some(start), Some(end)) = (index.node(from), index.node(to)) else {
                    continue;
                };
                if start == end {
                    continue;
                }
                let found = search.run(&index, start, &flags, max_depth, |node, _| node == end);
                let expected = reference::strongest_path(from, to, relations, max_depth, removed);
                let by_width = strongest_by_width(from, to, relations, max_depth, removed);
                let enumerated = expected.as_ref().map(|taken| {
                    let width = taken
                        .iter()
                        .map(|&position| relations[position].confidence)
                        .fold(1.0, f64::min);
                    (width, taken.len())
                });
                assert!(
                    match (enumerated, by_width) {
                        (None, None) => true,
                        (Some((width, length)), Some((other, other_length))) => {
                            width.total_cmp(&other).is_eq() && length == other_length
                        }
                        _ => false,
                    },
                    "{from} to {to} within {max_depth}: enumerated {enumerated:?}, by width {by_width:?}"
                );
                let Some(step) = found else {
                    assert!(
                        expected.is_none(),
                        "{from} to {to} within {max_depth}: {expected:?}"
                    );
                    continue;
                };
                let Some(taken) = expected else {
                    panic!("{from} to {to} within {max_depth}: a path where none is");
                };
                let path = search.path(step);
                assert_eq!(
                    (path[0], path[path.len() - 1]),
                    (start, end),
                    "{from} to {to}"
                );
                let mut distinct = path.clone();
                distinct.sort_unstable();
                distinct.dedup();
                assert_eq!(
                    distinct.len(),
                    path.len(),
                    "{from} to {to}: a path revisits a node"
                );
                assert!(
                    search.edges(step).all(|edge| !flags[index.basis[edge]]),
                    "{from} to {to}: a path takes a removed basis"
                );
                assert_eq!(path.len() - 1, taken.len(), "{from} to {to}: depth");
                let width = search
                    .edges(step)
                    .map(|edge| index.edges[edge].2)
                    .fold(1.0, f64::min);
                let strongest = taken
                    .iter()
                    .map(|&position| relations[position].confidence)
                    .fold(1.0, f64::min);
                assert!(
                    width.total_cmp(&strongest).is_eq(),
                    "{from} to {to} within {max_depth}: width {width} against {strongest}"
                );
            }
        }
    }

    /// `Search::run` answers the strongest path within the bound as the brute-force enumeration
    /// does: on the probe, and on random multigraphs and cliques with and without bases removed.
    #[test]
    fn search_pops_the_strongest_path_within_the_bound() {
        let probe = probe_relations();
        check_search(
            &[
                "S", "A1", "A2", "A3", "A4", "A5", "A6", "X", "Y", "T", "ghost",
            ],
            &probe,
            &HashSet::new(),
            8,
        );
        let mut rng = XorShift(0x510E_527F_ADE6_82D1);
        for round in 0..300 {
            let (nodes, relations) = if round % 2 == 0 {
                random_relations(&mut rng)
            } else {
                random_clique(&mut rng)
            };
            let mut uids = nodes.clone();
            uids.push("ghost");
            let removed = IdentityIndex::new(&relations)
                .bases
                .iter()
                .filter(|_| round % 3 != 0 && rng.below(3) == 0)
                .copied()
                .collect::<HashSet<_>>();
            let max_depth = 1 + rng.below(8);
            check_search(&uids, &relations, &removed, max_depth);
        }
    }

    /// Components in which every two nodes are joined, which the searches skip when one named
    /// basis carries them or every relation is as strong as its weaker end, answer exactly as
    /// the per-pair searches do, whatever else the component holds. Both shortcuts are taken in
    /// many rounds.
    #[test]
    fn complete_components_answer_exactly_as_the_per_pair_searches_do() {
        let mut rng = XorShift(0x3C6E_F372_FE94_F82B);
        let (mut carried, mut bounded) = (0, 0);
        for _ in 0..600 {
            let (nodes, relations) = random_clique(&mut rng);
            let index = IdentityIndex::new(&relations);
            let shapes = index.shapes(&index.components());
            carried += usize::from(
                shapes
                    .iter()
                    .any(|&shape| index.sole_carrier(shape).is_some()),
            );
            bounded += usize::from(shapes.iter().any(|shape| shape.complete && shape.bounded));
            assert_brokers_allowed(&relations);
            let mut uids = nodes.clone();
            uids.extend((0..rng.below(3)).map(|_| nodes[rng.below(nodes.len())]));
            uids.push("ghost");
            for at in (1..uids.len()).rev() {
                uids.swap(at, rng.below(at + 1));
            }
            for cap in [1, 2, usize::MAX] {
                let found = pairwise_disjoint_pathways(&uids, &relations, cap);
                assert_pairs_match_per_pair(&uids, &relations, cap, &found);
            }
        }
        assert!(carried >= 150 && bounded >= 150, "{carried} {bounded}");
    }

    /// Identity clusters written as plainly as they can be, as the oracle the cluster test
    /// compares against: each identity-binding relation merges the groups that hold its two uids,
    /// with them, into one, and the groups come out sorted, each holding its uids in order.
    fn merged_clusters(relations: &[Relation]) -> Vec<Vec<String>> {
        let mut groups = Vec::<BTreeSet<String>>::new();
        for relation in relations
            .iter()
            .filter(|relation| relation.kind.binds_identity())
        {
            let ends = [&relation.from_uid, &relation.to_uid];
            let (joined, apart): (Vec<_>, Vec<_>) = groups
                .into_iter()
                .partition(|group| ends.iter().any(|&uid| group.contains(uid)));
            let mut merged = joined.into_iter().flatten().collect::<BTreeSet<_>>();
            merged.extend(ends.into_iter().cloned());
            groups = apart;
            groups.push(merged);
        }
        let mut clusters = groups
            .into_iter()
            .map(|group| group.into_iter().collect::<Vec<_>>())
            .collect::<Vec<_>>();
        clusters.sort();
        clusters
    }

    /// The identity clusters the correlator reads (AU-060, AU-071) are the groups the plain
    /// oracle merges, in its order, on random multigraphs and random cliques: self-loops,
    /// repeated and reversed relations and relations that bind no identity included. Many rounds
    /// split the uids into more than one cluster, and some have none.
    #[test]
    fn identity_clusters_are_the_groups_identity_relations_merge() {
        let mut rng = XorShift(0xBB67_AE85_84CA_A73B);
        let (mut split, mut empty) = (0, 0);
        for round in 0..800 {
            let (_, relations) = if round % 2 == 0 {
                random_relations(&mut rng)
            } else {
                random_clique(&mut rng)
            };
            let clusters = resolve_identity_clusters(&relations);
            assert_eq!(
                clusters,
                merged_clusters(&relations),
                "round {round}: {relations:?}"
            );
            split += usize::from(clusters.len() > 1);
            empty += usize::from(clusters.is_empty());
        }
        assert!(split >= 75 && empty >= 25, "{split} {empty}");
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
