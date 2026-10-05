//! Evidence ancestry and proof-route independence.
//!
//! Module count, provider diversity, and source-family labels are diagnostic signals,
//! not proof of independent origins. The graph is the canonical provenance authority:
//! copies and derivations retain their upstream roots, while consequential independence
//! requires explicit, admissible evidence for the exact canonical root pair.
//!
//! Legacy family-based APIs remain available for exploration and differential tests,
//! but they must not authorize claim verification or automatic identity merges.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum unique canonical roots evaluated by the exact proof-route search.
///
/// Claim-local proof sets are expected to be small. Larger sets fail closed rather
/// than returning a partial or heuristic strengthening result.
pub const MAX_PROOF_ROUTE_ROOTS: usize = 32;
const MAX_PROOF_ROUTE_SEARCH_VISITS: usize = 1_000_000;

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
    /// Family, corpus, or provider-origin label. Canonicalised on insert
    /// (whitespace collapsed, lowercased), so `"  Adobe   2013 "` and
    /// `"ADOBE 2013"` are one family.
    pub source_family: String,
    /// Direct evidence parents. Empty means an observed root.
    pub parents: BTreeSet<EvidenceNodeId>,
    /// Deterministic, enrichment, or recall derivation. Must have parents.
    pub derived: bool,
}

/// Proof-route state. `Unknown` is deliberately distinct from independence:
/// absence of a known shared cause does not establish distinct origins.
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
    pub supporting_artifact_ids: BTreeSet<String>,
    pub observed_at_unix: u64,
}

/// Deterministic exact-pair index for proof of distinct canonical origins.
///
/// The map shape serializes cleanly to JSON because both index levels use the
/// transparent string-backed [`EvidenceNodeId`] as map keys.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndependenceEvidenceSet {
    pairs: BTreeMap<EvidenceNodeId, BTreeMap<EvidenceNodeId, IndependenceEvidence>>,
}

/// Deserialisation re-runs `insert` on every node, so a stored graph cannot carry
/// what `insert` refuses: an empty family, a parentless derivation, or a key that
/// is not the node's id.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawGraph")]
pub struct EvidenceAncestryGraph {
    nodes: BTreeMap<EvidenceNodeId, EvidenceAncestryNode>,
}

#[derive(Deserialize)]
struct RawGraph {
    nodes: BTreeMap<EvidenceNodeId, EvidenceAncestryNode>,
}

impl TryFrom<RawGraph> for EvidenceAncestryGraph {
    type Error = String;

    fn try_from(raw: RawGraph) -> Result<Self, String> {
        let mut graph = Self::default();
        for (key, node) in raw.nodes {
            if key != node.id {
                return Err(format!("graph key {} holds node {}", key.0, node.id.0));
            }
            graph.insert(node).map_err(|e| e.to_string())?;
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
    #[error("proof-route exact search refused {roots} roots; deterministic maximum is {max_roots}")]
    ProofRouteSearchLimit { roots: usize, max_roots: usize },
    #[error(
        "proof-route exact search exhausted after {visited} visits; deterministic maximum is {max_visits}"
    )]
    ProofRouteSearchExhausted { visited: usize, max_visits: usize },
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
    if evidence.method_version != 1 || evidence.method_id.trim() != evidence.method_id {
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

impl IndependenceEvidenceSet {
    /// Insert proof for one exact canonical root pair.
    ///
    /// # Errors
    /// Fails closed for unknown methods/versions, empty proof references, self-pairs,
    /// missing endpoints, or endpoints that are not canonical graph roots.
    pub fn insert(
        &mut self,
        graph: &EvidenceAncestryGraph,
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
        if evidence.method_id.is_empty() || !method_is_admissible(&evidence) {
            return Err(AncestryError::InvalidIndependenceEvidence(
                "unknown or incompatible method id/version/basis".to_owned(),
            ));
        }
        if evidence.supporting_artifact_ids.is_empty()
            || evidence
                .supporting_artifact_ids
                .iter()
                .any(|id| id.trim().is_empty())
        {
            return Err(AncestryError::InvalidIndependenceEvidence(
                "supporting proof references must be non-empty".to_owned(),
            ));
        }

        for endpoint in [&evidence.left_root, &evidence.right_root] {
            let node = graph
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
        self.pairs.entry(left).or_default().insert(right, evidence);
        Ok(())
    }

    fn proves_pair(
        &self,
        graph: &EvidenceAncestryGraph,
        left: &EvidenceNodeId,
        right: &EvidenceNodeId,
    ) -> bool {
        if left == right {
            return false;
        }
        let (left, right) = canonical_pair(left, right);
        let Some(evidence) = self.pairs.get(&left).and_then(|pairs| pairs.get(&right)) else {
            return false;
        };

        if evidence.left_root != left
            || evidence.right_root != right
            || !method_is_admissible(evidence)
            || evidence.supporting_artifact_ids.is_empty()
            || evidence
                .supporting_artifact_ids
                .iter()
                .any(|id| id.trim().is_empty())
        {
            return false;
        }

        [left, right].iter().all(|root| {
            graph
                .get(root)
                .is_some_and(|node| node.parents.is_empty() && !root.0.trim().is_empty())
        })
    }
}

impl EvidenceAncestryGraph {
    /// Insert one node. Parents may be inserted later; a missing parent fails at query time.
    ///
    /// # Errors
    /// Empty family, duplicate id, or a parentless derivation.
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
    ///
    /// # Errors
    /// A missing node or cycle anywhere in the ancestry of `id`.
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
    /// This is a compatibility/diagnostic API. Distinct labels are not proof of
    /// independent origins and must not authorize verification or auto-merge.
    ///
    /// # Errors
    /// A missing node or cycle anywhere in the ancestry of `id`.
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
    /// Diagnostic compatibility only. This does **not** establish proof-route
    /// independence and must not authorize verification or automatic merge.
    ///
    /// # Errors
    /// As [`Self::root_families`].
    pub fn independent_support_count<'a>(
        &self,
        ids: impl IntoIterator<Item = &'a EvidenceNodeId>,
    ) -> Result<usize, AncestryError> {
        let mut roots = BTreeSet::new();
        for id in ids {
            roots.extend(self.root_families(id)?);
        }
        Ok(roots.len())
    }

    /// Legacy label-diversity predicate.
    ///
    /// Diagnostic compatibility only. `true` means no recorded root-family label
    /// overlaps; it does **not** mean the routes are proven independent.
    ///
    /// # Errors
    /// As [`Self::root_families`].
    pub fn are_independent(
        &self,
        a: &EvidenceNodeId,
        b: &EvidenceNodeId,
    ) -> Result<bool, AncestryError> {
        Ok(self.root_families(a)?.is_disjoint(&self.root_families(b)?))
    }

    /// Evaluate the relationship between two evidence routes.
    ///
    /// Shared canonical ancestry is known dependence. Merely disjoint ancestry is
    /// `Unknown` unless every cross-root pair is backed by exact admissible proof.
    ///
    /// # Errors
    /// Missing/cyclic ancestry fails closed.
    pub fn proof_route_relationship(
        &self,
        a: &EvidenceNodeId,
        b: &EvidenceNodeId,
        independence: &IndependenceEvidenceSet,
    ) -> Result<IndependenceState, AncestryError> {
        let left = self.root_ids(a)?;
        let right = self.root_ids(b)?;

        if !left.is_disjoint(&right) {
            return Ok(IndependenceState::KnownDependent);
        }

        let all_pairs_proven = left.iter().all(|left_root| {
            right
                .iter()
                .all(|right_root| independence.proves_pair(self, left_root, right_root))
        });

        Ok(if all_pairs_proven {
            IndependenceState::ProvenIndependent
        } else {
            IndependenceState::Unknown
        })
    }

    /// Exact maximum number of pairwise-proven-independent canonical roots behind
    /// the supplied evidence nodes.
    ///
    /// Unknown relationships are absent edges. Search bounds fail closed rather
    /// than returning a partial count.
    ///
    /// # Errors
    /// Missing/cyclic ancestry or deterministic search bounds.
    pub fn proven_independent_support_count<'a>(
        &self,
        ids: impl IntoIterator<Item = &'a EvidenceNodeId>,
        independence: &IndependenceEvidenceSet,
    ) -> Result<usize, AncestryError> {
        let mut root_set = BTreeSet::new();
        for id in ids {
            root_set.extend(self.root_ids(id)?);
        }

        if root_set.len() > MAX_PROOF_ROUTE_ROOTS {
            return Err(AncestryError::ProofRouteSearchLimit {
                roots: root_set.len(),
                max_roots: MAX_PROOF_ROUTE_ROOTS,
            });
        }
        if root_set.len() <= 1 {
            return Ok(root_set.len());
        }

        let roots: Vec<_> = root_set.into_iter().collect();
        let mut adjacency = vec![0_u64; roots.len()];
        for left in 0..roots.len() {
            for right in (left + 1)..roots.len() {
                if independence.proves_pair(self, &roots[left], &roots[right]) {
                    adjacency[left] |= 1_u64 << right;
                    adjacency[right] |= 1_u64 << left;
                }
            }
        }

        exact_maximum_clique_size(&adjacency)
    }
}

fn exact_maximum_clique_size(adjacency: &[u64]) -> Result<usize, AncestryError> {
    fn visit(
        adjacency: &[u64],
        candidates: u64,
        current_size: usize,
        best: &mut usize,
        visits: &mut usize,
    ) -> Result<(), AncestryError> {
        *visits = visits.saturating_add(1);
        if *visits > MAX_PROOF_ROUTE_SEARCH_VISITS {
            return Err(AncestryError::ProofRouteSearchExhausted {
                visited: *visits,
                max_visits: MAX_PROOF_ROUTE_SEARCH_VISITS,
            });
        }

        if candidates == 0 {
            *best = (*best).max(current_size);
            return Ok(());
        }

        let remaining = candidates.count_ones() as usize;
        if current_size + remaining <= *best {
            return Ok(());
        }

        let vertex = candidates.trailing_zeros() as usize;
        let bit = 1_u64 << vertex;
        let without_vertex = candidates & !bit;

        visit(
            adjacency,
            without_vertex & adjacency[vertex],
            current_size + 1,
            best,
            visits,
        )?;
        visit(adjacency, without_vertex, current_size, best, visits)
    }

    if adjacency.is_empty() {
        return Ok(0);
    }

    let candidates = if adjacency.len() == 64 {
        u64::MAX
    } else {
        (1_u64 << adjacency.len()) - 1
    };
    let mut best = 0;
    let mut visits = 0;
    visit(adjacency, candidates, 0, &mut best, &mut visits)?;
    Ok(best)
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
                .proof_route_relationship(
                    &"mirror-a".into(),
                    &"mirror-b".into(),
                    &IndependenceEvidenceSet::default(),
                )
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
            graph
                .proof_route_relationship(
                    &"a".into(),
                    &"b".into(),
                    &IndependenceEvidenceSet::default(),
                )
                .unwrap(),
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
