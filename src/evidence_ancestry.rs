//! Evidence ancestry and proof-route independence.
//!
//! Module count, provider diversity, and source-family labels are diagnostic signals,
//! not proof of independent origins. This graph is the canonical provenance authority:
//! copies and derivations retain upstream roots, while consequential independence
//! requires explicit, admissible evidence for the exact canonical root pair.
//!
//! Legacy family-based APIs remain for exploration and differential tests only. They
//! must not authorize claim verification or automatic identity merges.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::retrieval_artifact::ArtifactId;

const MAX_ROUTE_SEARCH_DEPTH: usize = 64;

pub const METHOD_DISTINCT_AUTHENTICATED_PRIMARY_ORIGINS_V1: &str =
    "distinct_authenticated_primary_origins";
pub const METHOD_DISTINCT_DIRECT_SENSOR_OBSERVATIONS_V1: &str =
    "distinct_direct_sensor_observations";
pub const METHOD_EXPLICIT_UPSTREAM_PROVENANCE_V1: &str = "explicit_upstream_provenance";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EvidenceNodeId(pub String);

impl From<&str> for EvidenceNodeId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceAncestryNode {
    pub id: EvidenceNodeId,
    /// Family, corpus, or provider-origin label. Canonicalised on insert.
    pub source_family: String,
    /// Direct evidence parents. Empty means an observed root.
    pub parents: BTreeSet<EvidenceNodeId>,
    /// Deterministic, enrichment, or recall derivation. Must have parents.
    pub derived: bool,
}

/// Relationship between two proof routes. `Unknown` is not independence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndependenceState {
    ProvenIndependent,
    KnownDependent,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndependenceBasis {
    DistinctAuthenticatedPrimaryOrigins,
    DistinctDirectSensorObservations,
    ExplicitUpstreamProvenance,
    OtherVersionedRule(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndependenceEvidence {
    pub left_root: EvidenceNodeId,
    pub right_root: EvidenceNodeId,
    pub basis: IndependenceBasis,
    pub method_id: String,
    pub method_version: u32,
    pub supporting_artifact_ids: BTreeSet<ArtifactId>,
    pub observed_at_unix: u64,
}

/// Conservative lower bound on proven pairwise-independent routes.
///
/// `incomplete` means the deterministic search budget or safety depth was reached.
/// A truncated search may under-credit evidence; it can never strengthen it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndependenceRouteCount {
    pub proven: usize,
    pub incomplete: bool,
}

/// Deserialisation re-runs graph and independence insertion, so persisted state cannot
/// bypass the same invariants enforced for live data.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawGraph")]
pub struct EvidenceAncestryGraph {
    nodes: BTreeMap<EvidenceNodeId, EvidenceAncestryNode>,
    #[serde(default)]
    independence: BTreeMap<EvidenceNodeId, BTreeMap<EvidenceNodeId, IndependenceEvidence>>,
}

#[derive(Deserialize)]
struct RawGraph {
    nodes: BTreeMap<EvidenceNodeId, EvidenceAncestryNode>,
    #[serde(default)]
    independence: BTreeMap<EvidenceNodeId, BTreeMap<EvidenceNodeId, IndependenceEvidence>>,
}

impl TryFrom<RawGraph> for EvidenceAncestryGraph {
    type Error = String;

    fn try_from(raw: RawGraph) -> Result<Self, String> {
        let mut graph = Self::default();
        for (key, node) in raw.nodes {
            if key != node.id {
                return Err(format!("graph key {} holds node {}", key.0, node.id.0));
            }
            graph.insert(node).map_err(|error| error.to_string())?;
        }

        for (stored_left, pairs) in raw.independence {
            for (stored_right, evidence) in pairs {
                let (left, right) = canonical_pair(&evidence.left_root, &evidence.right_root);
                if stored_left != left || stored_right != right {
                    return Err(format!(
                        "independence index ({}, {}) does not match canonical evidence pair ({}, {})",
                        stored_left.0, stored_right.0, left.0, right.0
                    ));
                }
                graph
                    .insert_independence_evidence(evidence)
                    .map_err(|error| error.to_string())?;
            }
        }
        Ok(graph)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AncestryError {
    #[error("duplicate evidence node {}", .0.0)]
    DuplicateNode(EvidenceNodeId),
    #[error("missing evidence node {}", .0.0)]
    MissingNode(EvidenceNodeId),
    #[error("evidence ancestry cycle at {}", .0.0)]
    Cycle(EvidenceNodeId),
    #[error("evidence node {} has an empty source family", .0.0)]
    EmptySourceFamily(EvidenceNodeId),
    #[error("derived evidence node {} names no parent", .0.0)]
    DerivedWithoutParent(EvidenceNodeId),
    #[error("invalid independence evidence: {0}")]
    InvalidIndependenceEvidence(String),
    #[error("conflicting independence evidence for roots {} and {}", .left_root.0, .right_root.0)]
    ConflictingIndependenceEvidence {
        left_root: EvidenceNodeId,
        right_root: EvidenceNodeId,
    },
}

/// Canonical family key: whitespace runs collapsed, Unicode lowercase. Conservative:
/// `adobe 2013` and `adobe 2014` stay distinct.
#[must_use]
pub fn canonical_family(raw: &str) -> String {
    raw.split_whitespace()
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
}

fn canonical_pair(
    left: &EvidenceNodeId,
    right: &EvidenceNodeId,
) -> (EvidenceNodeId, EvidenceNodeId) {
    if left <= right {
        (left.clone(), right.clone())
    } else {
        (right.clone(), left.clone())
    }
}

fn method_is_admissible(evidence: &IndependenceEvidence) -> bool {
    if evidence.method_version != 1
        || evidence.method_id.is_empty()
        || evidence.method_id.trim() != evidence.method_id
    {
        return false;
    }
    match &evidence.basis {
        IndependenceBasis::DistinctAuthenticatedPrimaryOrigins => {
            evidence.method_id == METHOD_DISTINCT_AUTHENTICATED_PRIMARY_ORIGINS_V1
        }
        IndependenceBasis::DistinctDirectSensorObservations => {
            evidence.method_id == METHOD_DISTINCT_DIRECT_SENSOR_OBSERVATIONS_V1
        }
        IndependenceBasis::ExplicitUpstreamProvenance => {
            evidence.method_id == METHOD_EXPLICIT_UPSTREAM_PROVENANCE_V1
        }
        IndependenceBasis::OtherVersionedRule(_) => false,
    }
}

impl EvidenceAncestryGraph {
    /// Insert one node. Parents may be inserted later; a missing parent fails at query time.
    pub fn insert(&mut self, mut node: EvidenceAncestryNode) -> Result<(), AncestryError> {
        node.source_family = canonical_family(&node.source_family);
        if node.source_family.is_empty() {
            return Err(AncestryError::EmptySourceFamily(node.id));
        }
        if node.derived && node.parents.is_empty() {
            return Err(AncestryError::DerivedWithoutParent(node.id));
        }
        if self.nodes.contains_key(&node.id) {
            return Err(AncestryError::DuplicateNode(node.id));
        }
        self.nodes.insert(node.id.clone(), node);
        Ok(())
    }

    #[must_use]
    pub fn get(&self, id: &EvidenceNodeId) -> Option<&EvidenceAncestryNode> {
        self.nodes.get(id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Canonical provenance roots reachable from `id`.
    ///
    /// Iterative three-colour DFS expands each node once, so shared ancestry is
    /// linear and deep chains cannot overflow the call stack.
    pub fn root_ids(&self, id: &EvidenceNodeId) -> Result<BTreeSet<EvidenceNodeId>, AncestryError> {
        let mut roots = BTreeSet::new();
        let mut done: BTreeSet<&EvidenceNodeId> = BTreeSet::new();
        let mut on_path: BTreeSet<&EvidenceNodeId> = BTreeSet::new();
        let start = self
            .nodes
            .get_key_value(id)
            .ok_or_else(|| AncestryError::MissingNode(id.clone()))?
            .0;
        let mut stack: Vec<(&EvidenceNodeId, bool)> = vec![(start, false)];

        while let Some((current, expanded)) = stack.pop() {
            if expanded {
                on_path.remove(current);
                done.insert(current);
                continue;
            }
            if done.contains(current) {
                continue;
            }
            if !on_path.insert(current) {
                return Err(AncestryError::Cycle(current.clone()));
            }

            let node = &self.nodes[current];
            stack.push((current, true));
            if node.parents.is_empty() {
                roots.insert(current.clone());
            }

            for parent in &node.parents {
                let (key, _) = self
                    .nodes
                    .get_key_value(parent)
                    .ok_or_else(|| AncestryError::MissingNode(parent.clone()))?;
                if on_path.contains(key) {
                    return Err(AncestryError::Cycle(key.clone()));
                }
                if !done.contains(key) {
                    stack.push((key, false));
                }
            }
        }
        Ok(roots)
    }

    /// Root-family labels reachable from `id`.
    ///
    /// Diagnostic compatibility only. Distinct labels do not prove independence.
    pub fn root_families(&self, id: &EvidenceNodeId) -> Result<BTreeSet<String>, AncestryError> {
        self.root_ids(id)?
            .into_iter()
            .map(|root| {
                self.nodes
                    .get(&root)
                    .map(|node| node.source_family.clone())
                    .ok_or(AncestryError::MissingNode(root))
            })
            .collect()
    }

    /// Count distinct root-family labels across a support set.
    ///
    /// Diagnostic compatibility only; this value must not authorize verification
    /// or automatic identity merge.
    pub fn independent_support_count<'a>(
        &self,
        ids: impl IntoIterator<Item = &'a EvidenceNodeId>,
    ) -> Result<usize, AncestryError> {
        let mut families = BTreeSet::new();
        for id in ids {
            families.extend(self.root_families(id)?);
        }
        Ok(families.len())
    }

    /// Legacy label-diversity predicate. `true` is not proof of independence.
    pub fn are_independent(
        &self,
        a: &EvidenceNodeId,
        b: &EvidenceNodeId,
    ) -> Result<bool, AncestryError> {
        Ok(self.root_families(a)?.is_disjoint(&self.root_families(b)?))
    }

    /// Insert auditable evidence that two exact canonical roots are distinct proof routes.
    ///
    /// Identical duplicate records are idempotent. A different record for the same
    /// canonical pair is rejected rather than silently replacing provenance.
    pub fn insert_independence_evidence(
        &mut self,
        mut evidence: IndependenceEvidence,
    ) -> Result<(), AncestryError> {
        if evidence.left_root.0.trim().is_empty() || evidence.right_root.0.trim().is_empty() {
            return Err(AncestryError::InvalidIndependenceEvidence(
                "root ids must be non-empty".to_owned(),
            ));
        }
        if evidence.left_root == evidence.right_root {
            return Err(AncestryError::InvalidIndependenceEvidence(
                "self-pairs cannot prove independence".to_owned(),
            ));
        }
        if !method_is_admissible(&evidence) {
            return Err(AncestryError::InvalidIndependenceEvidence(
                "unknown or incompatible method id/version/basis".to_owned(),
            ));
        }
        if evidence.supporting_artifact_ids.is_empty()
            || evidence
                .supporting_artifact_ids
                .iter()
                .any(|id| id.0.trim().is_empty())
        {
            return Err(AncestryError::InvalidIndependenceEvidence(
                "supporting artifact ids must be non-empty".to_owned(),
            ));
        }

        for endpoint in [&evidence.left_root, &evidence.right_root] {
            let node = self
                .get(endpoint)
                .ok_or_else(|| AncestryError::MissingNode(endpoint.clone()))?;
            if !node.parents.is_empty() {
                return Err(AncestryError::InvalidIndependenceEvidence(format!(
                    "{} is not a canonical provenance root",
                    endpoint.0
                )));
            }
        }

        let (left, right) = canonical_pair(&evidence.left_root, &evidence.right_root);
        evidence.left_root = left.clone();
        evidence.right_root = right.clone();

        if let Some(existing) = self.independence.get(&left).and_then(|pairs| pairs.get(&right)) {
            if existing == &evidence {
                return Ok(());
            }
            return Err(AncestryError::ConflictingIndependenceEvidence {
                left_root: left,
                right_root: right,
            });
        }

        self.independence
            .entry(left)
            .or_default()
            .insert(right, evidence);
        Ok(())
    }

    fn pair_is_proven(&self, left: &EvidenceNodeId, right: &EvidenceNodeId) -> bool {
        if left == right {
            return false;
        }
        let (left, right) = canonical_pair(left, right);
        self.independence
            .get(&left)
            .and_then(|pairs| pairs.get(&right))
            .is_some_and(|evidence| {
                evidence.left_root == left
                    && evidence.right_root == right
                    && method_is_admissible(evidence)
                    && !evidence.supporting_artifact_ids.is_empty()
                    && evidence
                        .supporting_artifact_ids
                        .iter()
                        .all(|id| !id.0.trim().is_empty())
            })
    }

    /// Evaluate whether two evidence nodes trace to proven-distinct proof routes.
    ///
    /// Shared roots are known dependence. Merely disjoint roots remain unknown.
    /// Phase 1 proves a relationship only when each side resolves to exactly one
    /// canonical root and that exact pair carries admissible independence evidence.
    pub fn independence_state(
        &self,
        a: &EvidenceNodeId,
        b: &EvidenceNodeId,
    ) -> Result<IndependenceState, AncestryError> {
        let left = self.root_ids(a)?;
        let right = self.root_ids(b)?;

        if !left.is_disjoint(&right) {
            return Ok(IndependenceState::KnownDependent);
        }

        if left.len() == 1 && right.len() == 1 {
            let left_root = left.iter().next().expect("length checked");
            let right_root = right.iter().next().expect("length checked");
            if self.pair_is_proven(left_root, right_root) {
                return Ok(IndependenceState::ProvenIndependent);
            }
        }
        Ok(IndependenceState::Unknown)
    }

    /// Return a conservative lower bound on pairwise-proven-independent roots.
    ///
    /// Search stops as soon as `required` routes are proved. If the deterministic
    /// state budget or depth safety bound is exhausted first, `incomplete` is set
    /// and the best already-proven lower bound is returned. Truncation never raises
    /// the result beyond what was explicitly demonstrated.
    pub fn proven_independent_route_count<'a>(
        &self,
        ids: impl IntoIterator<Item = &'a EvidenceNodeId>,
        required: usize,
        max_search_states: usize,
    ) -> Result<IndependenceRouteCount, AncestryError> {
        let mut root_set = BTreeSet::new();
        for id in ids {
            root_set.extend(self.root_ids(id)?);
        }
        let roots = root_set.into_iter().collect::<Vec<_>>();

        if required == 0 || roots.is_empty() {
            return Ok(IndependenceRouteCount {
                proven: 0,
                incomplete: false,
            });
        }
        if required == 1 {
            return Ok(IndependenceRouteCount {
                proven: 1,
                incomplete: false,
            });
        }

        let target = required.min(roots.len());
        if target <= 1 {
            return Ok(IndependenceRouteCount {
                proven: roots.len().min(1),
                incomplete: false,
            });
        }
        if max_search_states == 0 {
            return Ok(IndependenceRouteCount {
                proven: 1,
                incomplete: true,
            });
        }

        let search_target = target.min(MAX_ROUTE_SEARCH_DEPTH);
        let forced_incomplete = target > MAX_ROUTE_SEARCH_DEPTH;
        let mut best = 1;
        let mut visited = 0;
        let mut chosen = Vec::with_capacity(search_target);
        let outcome = search_proven_cliques(
            self,
            &roots,
            0,
            &mut chosen,
            search_target,
            max_search_states,
            &mut visited,
            &mut best,
        );

        let threshold_proven = !forced_incomplete && best >= target;
        Ok(IndependenceRouteCount {
            proven: best.min(target),
            incomplete: !threshold_proven
                && (forced_incomplete || matches!(outcome, SearchOutcome::Exhausted)),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SearchOutcome {
    Complete,
    ThresholdProven,
    Exhausted,
}

#[allow(clippy::too_many_arguments)]
fn search_proven_cliques(
    graph: &EvidenceAncestryGraph,
    roots: &[EvidenceNodeId],
    start: usize,
    chosen: &mut Vec<usize>,
    target: usize,
    max_states: usize,
    visited: &mut usize,
    best: &mut usize,
) -> SearchOutcome {
    *best = (*best).max(chosen.len());
    if *best >= target {
        return SearchOutcome::ThresholdProven;
    }
    if start >= roots.len() || chosen.len() + (roots.len() - start) <= *best {
        return SearchOutcome::Complete;
    }

    for candidate in start..roots.len() {
        if *visited >= max_states {
            return SearchOutcome::Exhausted;
        }
        *visited += 1;

        if chosen
            .iter()
            .all(|selected| graph.pair_is_proven(&roots[*selected], &roots[candidate]))
        {
            chosen.push(candidate);
            let outcome = search_proven_cliques(
                graph,
                roots,
                candidate + 1,
                chosen,
                target,
                max_states,
                visited,
                best,
            );
            chosen.pop();
            if outcome != SearchOutcome::Complete {
                return outcome;
            }
        }
    }
    SearchOutcome::Complete
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, family: &str, parents: &[&str], derived: bool) -> EvidenceAncestryNode {
        EvidenceAncestryNode {
            id: id.into(),
            source_family: family.to_owned(),
            parents: parents.iter().copied().map(EvidenceNodeId::from).collect(),
            derived,
        }
    }

    #[test]
    fn deserialised_graph_cannot_bypass_insert_invariants() {
        let bad = [
            r#"{"nodes":{"x":{"id":"x","source_family":"","parents":[],"derived":false}}}"#,
            r#"{"nodes":{"x":{"id":"x","source_family":"f","parents":[],"derived":true}}}"#,
            r#"{"nodes":{"x":{"id":"y","source_family":"f","parents":[],"derived":false}}}"#,
        ];
        for json in bad {
            assert!(
                serde_json::from_str::<EvidenceAncestryGraph>(json).is_err(),
                "{json}"
            );
        }
        let mut graph = EvidenceAncestryGraph::default();
        graph
            .insert(node("raw", "  Adobe  2013", &[], false))
            .unwrap();
        graph.insert(node("m", "p", &["raw"], true)).unwrap();
        let back: EvidenceAncestryGraph =
            serde_json::from_str(&serde_json::to_string(&graph).unwrap()).unwrap();
        assert_eq!(back, graph);
    }

    #[test]
    fn copied_reports_do_not_create_independence() {
        let mut graph = EvidenceAncestryGraph::default();
        graph.insert(node("raw", "adobe-2013", &[], false)).unwrap();
        graph
            .insert(node("mirror-a", "provider-a", &["raw"], true))
            .unwrap();
        graph
            .insert(node("mirror-b", "provider-b", &["raw"], true))
            .unwrap();

        assert!(
            !graph
                .are_independent(&"mirror-a".into(), &"mirror-b".into())
                .unwrap()
        );
        assert_eq!(
            graph
                .independent_support_count([&"mirror-a".into(), &"mirror-b".into()])
                .unwrap(),
            1
        );
        assert_eq!(
            graph
                .independence_state(&"mirror-a".into(), &"mirror-b".into())
                .unwrap(),
            IndependenceState::KnownDependent
        );
    }

    #[test]
    fn genuinely_distinct_root_labels_are_only_diagnostic_independence() {
        let mut graph = EvidenceAncestryGraph::default();
        graph.insert(node("a", "registry", &[], false)).unwrap();
        graph.insert(node("b", "court-record", &[], false)).unwrap();
        assert!(graph.are_independent(&"a".into(), &"b".into()).unwrap());
        assert_eq!(
            graph.independence_state(&"a".into(), &"b".into()).unwrap(),
            IndependenceState::Unknown
        );
    }

    #[test]
    fn cycles_fail_closed() {
        let mut graph = EvidenceAncestryGraph::default();
        graph.insert(node("a", "a", &["b"], true)).unwrap();
        graph.insert(node("b", "b", &["a"], true)).unwrap();
        assert!(matches!(
            graph.root_families(&"a".into()),
            Err(AncestryError::Cycle(_))
        ));
    }

    #[test]
    fn falsify_diamond_chain_is_linear_not_exponential() {
        let mut graph = EvidenceAncestryGraph::default();
        graph.insert(node("n0", "root", &[], false)).unwrap();
        for i in 1..=60 {
            let (l, r, prev) = (format!("l{i}"), format!("r{i}"), format!("n{}", i - 1));
            graph.insert(node(&l, "x", &[&prev], true)).unwrap();
            graph.insert(node(&r, "x", &[&prev], true)).unwrap();
            graph
                .insert(node(&format!("n{i}"), "x", &[&l, &r], true))
                .unwrap();
        }
        let start = std::time::Instant::now();
        assert_eq!(graph.root_families(&"n60".into()).unwrap().len(), 1);
        assert!(start.elapsed().as_secs() < 2);
    }

    #[test]
    fn falsify_parentless_derivation_is_not_a_root() {
        let mut graph = EvidenceAncestryGraph::default();
        assert!(graph.insert(node("d", "enrichment", &[], true)).is_err());
    }

    #[test]
    fn falsify_formatting_variants_are_one_family() {
        let mut graph = EvidenceAncestryGraph::default();
        graph
            .insert(node("a", "  Adobe   2013 ", &[], false))
            .unwrap();
        graph.insert(node("b", "ADOBE 2013", &[], false)).unwrap();
        assert!(!graph.are_independent(&"a".into(), &"b".into()).unwrap());
    }

    #[test]
    fn deep_chain_does_not_overflow_and_missing_parent_fails_closed() {
        let mut graph = EvidenceAncestryGraph::default();
        graph.insert(node("n0", "origin", &[], false)).unwrap();
        for i in 1..=200_000 {
            graph
                .insert(node(
                    &format!("n{i}"),
                    "copy",
                    &[&format!("n{}", i - 1)],
                    true,
                ))
                .unwrap();
        }
        let roots = graph.root_families(&"n200000".into()).unwrap();
        assert_eq!(roots.into_iter().collect::<Vec<_>>(), ["origin"]);
        graph
            .insert(node("orphan", "copy", &["ghost"], true))
            .unwrap();
        assert_eq!(
            graph.root_families(&"orphan".into()),
            Err(AncestryError::MissingNode("ghost".into()))
        );
        assert!(
            graph
                .independent_support_count([&"n1".into(), &"orphan".into()])
                .is_err()
        );
    }

    #[test]
    fn self_parent_is_a_cycle() {
        let mut graph = EvidenceAncestryGraph::default();
        graph.insert(node("s", "x", &["s"], true)).unwrap();
        assert_eq!(
            graph.root_families(&"s".into()),
            Err(AncestryError::Cycle("s".into()))
        );
    }
}
