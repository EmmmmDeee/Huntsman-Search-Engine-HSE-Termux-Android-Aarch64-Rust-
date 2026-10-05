//! Evidence ancestry and independence. From refactor overlay feef60a (P3), reimplemented.
//!
//! Module count is not source independence. The graph keeps upstream ancestry so a
//! mirror, derivation, recall path, or copied corpus cannot manufacture corroboration
//! by being emitted again. Formatting variants of one family are one family.
//! A derivation must name what it derives from. Walks visit each node once.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::retrieval_artifact::ArtifactId;

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
    /// (whitespace collapsed, lowercased), so `"  Adobe   2013 "` and `"ADOBE 2013"` are one family.
    pub source_family: String,
    /// Direct evidence parents. Empty means an observed root.
    pub parents: BTreeSet<EvidenceNodeId>,
    /// Deterministic, enrichment, or recall derivation. Must have parents.
    pub derived: bool,
}

/// Why two roots are treated as proven independent.
///
/// A label, provider, URL, or dataset name is not a basis. Only an explicit,
/// versioned method record can move a pair out of `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IndependenceBasis {
    DistinctAuthenticatedPrimaryOrigins,
    DistinctDirectSensorObservations,
    ExplicitUpstreamProvenance,
}

/// Explicit, versioned evidence that two root nodes do not share a proof route.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IndependenceEvidence {
    pub left_root: EvidenceNodeId,
    pub right_root: EvidenceNodeId,
    pub basis: IndependenceBasis,
    pub method_id: String,
    pub method_version: u32,
    pub supporting_artifact_ids: BTreeSet<ArtifactId>,
    pub observed_at_unix: u64,
}

/// Conservative independence of two evidence nodes after ancestry resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IndependenceState {
    /// Explicit accepted evidence exists for the resolved root pair, and the
    /// nodes share no root.
    ProvenIndependent,
    /// The nodes reach at least one common root. Shared ancestry dominates any
    /// independence assertion.
    KnownDependent,
    /// Disjoint or otherwise unresolved. Unknown never strengthens a claim.
    Unknown,
}

/// Lower bound on mutually proven-independent proof routes.
///
/// `incomplete` means the search budget ended before the bound was closed.
/// A truncated search may under-count; it never over-counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndependenceRouteCount {
    pub proven: usize,
    pub incomplete: bool,
}

/// Deserialisation re-runs validating inserts, so a stored graph cannot carry
/// what constructors refuse: an empty family, a parentless derivation, a key
/// that is not the node's id, or an independence record that names a non-root.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawGraph")]
pub struct EvidenceAncestryGraph {
    nodes: BTreeMap<EvidenceNodeId, EvidenceAncestryNode>,
    #[serde(default)]
    independence: Vec<IndependenceEvidence>,
}

#[derive(Deserialize)]
struct RawGraph {
    nodes: BTreeMap<EvidenceNodeId, EvidenceAncestryNode>,
    #[serde(default)]
    independence: Vec<IndependenceEvidence>,
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
        for evidence in raw.independence {
            graph
                .insert_independence_evidence(evidence)
                .map_err(|e| e.to_string())?;
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
    #[error("independence evidence must name two distinct roots")]
    IndependenceNotDistinct,
    #[error("independence evidence names a node that is not a root: {}", .0.0)]
    IndependenceNotRoot(EvidenceNodeId),
    #[error("independence evidence has an empty method id")]
    EmptyIndependenceMethod,
    #[error("independence evidence method version must be greater than zero")]
    InvalidIndependenceVersion,
    #[error("independence evidence cites no supporting artifact")]
    IndependenceWithoutArtifact,
    #[error("conflicting independence evidence for the same root pair")]
    ConflictingIndependence,
}

/// Canonical family key: whitespace runs collapsed, Unicode lowercase. Conservative:
/// `adobe 2013` and `adobe 2014` stay distinct. From overlay patch 0007.
#[must_use]
pub fn canonical_family(raw: &str) -> String {
    raw.split_whitespace()
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
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

    /// Root families reachable from `id`. Iterative three-colour DFS: each node is
    /// expanded once, so shared ancestry is linear and depth cannot overflow the stack.
    ///
    /// # Errors
    /// A missing node or a cycle anywhere in the ancestry of `id`. Fails closed.
    pub fn root_families(&self, id: &EvidenceNodeId) -> Result<BTreeSet<String>, AncestryError> {
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
                roots.insert(node.source_family.clone());
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

    /// Distinct independent root families across a support set.
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

    /// True only when the two nodes share no root family.
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

    /// Record explicit independence for a canonical root pair.
    ///
    /// Diagnostic family labels are not accepted as proof. The record must name
    /// two existing root nodes, a non-empty versioned method, and at least one
    /// supporting artifact. An identical resubmission is a no-op. A different
    /// record for the same pair is rejected rather than overwritten.
    ///
    /// # Errors
    /// Missing nodes, non-roots, identical endpoints, empty method, version
    /// zero, no artifact, or conflicting evidence for the pair.
    pub fn insert_independence_evidence(
        &mut self,
        mut evidence: IndependenceEvidence,
    ) -> Result<(), AncestryError> {
        if evidence.left_root == evidence.right_root {
            return Err(AncestryError::IndependenceNotDistinct);
        }
        self.require_root(&evidence.left_root)?;
        self.require_root(&evidence.right_root)?;
        let method_id = evidence.method_id.trim().to_owned();
        if method_id.is_empty() {
            return Err(AncestryError::EmptyIndependenceMethod);
        }
        evidence.method_id = method_id;
        if evidence.method_version == 0 {
            return Err(AncestryError::InvalidIndependenceVersion);
        }
        if evidence.supporting_artifact_ids.is_empty() {
            return Err(AncestryError::IndependenceWithoutArtifact);
        }
        if evidence.left_root > evidence.right_root {
            std::mem::swap(&mut evidence.left_root, &mut evidence.right_root);
        }
        if let Some(existing) = self.independence.iter().find(|existing| {
            existing.left_root == evidence.left_root && existing.right_root == evidence.right_root
        }) {
            if existing != &evidence {
                return Err(AncestryError::ConflictingIndependence);
            }
            return Ok(());
        }
        self.independence.push(evidence);
        self.independence.sort();
        Ok(())
    }

    /// Proven, known-dependent, or unknown independence after root resolution.
    ///
    /// Shared ancestry wins over any stored independence record. A disjoint
    /// pair is `ProvenIndependent` only when each side resolves to exactly one
    /// root and accepted evidence exists for that root pair. Every other
    /// disjoint case stays `Unknown`.
    ///
    /// # Errors
    /// Missing nodes or cycles in either ancestry. Fails closed.
    pub fn independence_state(
        &self,
        a: &EvidenceNodeId,
        b: &EvidenceNodeId,
    ) -> Result<IndependenceState, AncestryError> {
        let left = self.root_ids(a)?;
        let right = self.root_ids(b)?;
        if left.intersection(&right).next().is_some() {
            return Ok(IndependenceState::KnownDependent);
        }
        if left.len() == 1 && right.len() == 1 {
            let mut left_root = left.iter().next().expect("len checked").clone();
            let mut right_root = right.iter().next().expect("len checked").clone();
            if left_root > right_root {
                std::mem::swap(&mut left_root, &mut right_root);
            }
            if self.independence.iter().any(|evidence| {
                evidence.left_root == left_root && evidence.right_root == right_root
            }) {
                return Ok(IndependenceState::ProvenIndependent);
            }
        }
        Ok(IndependenceState::Unknown)
    }

    /// Conservative count of mutually proven-independent routes.
    ///
    /// `required == 0` proves nothing. `required == 1` is satisfied by any
    /// single resolved root and does not consult pairwise evidence. Larger
    /// requirements search deterministic combinations and stop at `required`
    /// or `max_search_states`. Budget exhaustion returns the proven lower
    /// bound with `incomplete: true` and never invents a route.
    ///
    /// # Errors
    /// Missing nodes or cycles while resolving roots.
    pub fn proven_independent_route_count<'a>(
        &self,
        ids: impl IntoIterator<Item = &'a EvidenceNodeId>,
        required: usize,
        max_search_states: usize,
    ) -> Result<IndependenceRouteCount, AncestryError> {
        let roots = self.resolved_roots(ids)?;
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

        let mut proven = 1usize;
        let mut inspected = 0usize;
        let target = required.min(roots.len());
        for size in 2..=target {
            let mut combo = (0..size).collect::<Vec<_>>();
            loop {
                if inspected == max_search_states {
                    return Ok(IndependenceRouteCount {
                        proven,
                        incomplete: true,
                    });
                }
                inspected += 1;
                if self.subset_proven_independent(&roots, &combo)? {
                    proven = size;
                    break;
                }
                if !advance_combination(&mut combo, roots.len()) {
                    break;
                }
            }
            if proven < size {
                break;
            }
        }
        Ok(IndependenceRouteCount {
            proven,
            incomplete: false,
        })
    }

    fn require_root(&self, id: &EvidenceNodeId) -> Result<(), AncestryError> {
        let node = self
            .nodes
            .get(id)
            .ok_or_else(|| AncestryError::MissingNode(id.clone()))?;
        if !node.parents.is_empty() || node.derived {
            return Err(AncestryError::IndependenceNotRoot(id.clone()));
        }
        Ok(())
    }

    fn root_ids(&self, id: &EvidenceNodeId) -> Result<BTreeSet<EvidenceNodeId>, AncestryError> {
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

    /// Distinct root node identities reachable from `ids`.
    ///
    /// Family labels are not identities. Missing nodes and cycles fail closed.
    ///
    /// # Errors
    /// As [`Self::root_families`].
    pub fn distinct_root_ids<'a>(
        &self,
        ids: impl IntoIterator<Item = &'a EvidenceNodeId>,
    ) -> Result<BTreeSet<EvidenceNodeId>, AncestryError> {
        let mut roots = BTreeSet::new();
        for id in ids {
            roots.extend(self.root_ids(id)?);
        }
        Ok(roots)
    }

    fn resolved_roots<'a>(
        &self,
        ids: impl IntoIterator<Item = &'a EvidenceNodeId>,
    ) -> Result<Vec<EvidenceNodeId>, AncestryError> {
        let mut roots = BTreeSet::new();
        for id in ids {
            roots.extend(self.root_ids(id)?);
        }
        Ok(roots.into_iter().collect())
    }

    fn subset_proven_independent(
        &self,
        roots: &[EvidenceNodeId],
        indexes: &[usize],
    ) -> Result<bool, AncestryError> {
        for (i, left_index) in indexes.iter().enumerate() {
            for right_index in &indexes[i + 1..] {
                let state = self.independence_state(&roots[*left_index], &roots[*right_index])?;
                if state != IndependenceState::ProvenIndependent {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

fn advance_combination(combo: &mut [usize], n: usize) -> bool {
    let k = combo.len();
    if k == 0 || n < k {
        return false;
    }
    for i in (0..k).rev() {
        let limit = n - k + i;
        if combo[i] < limit {
            combo[i] += 1;
            for j in i + 1..k {
                combo[j] = combo[j - 1] + 1;
            }
            return true;
        }
    }
    false
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
    }

    #[test]
    fn genuinely_distinct_roots_are_independent() {
        let mut graph = EvidenceAncestryGraph::default();
        graph.insert(node("a", "registry", &[], false)).unwrap();
        graph.insert(node("b", "court-record", &[], false)).unwrap();
        assert!(graph.are_independent(&"a".into(), &"b".into()).unwrap());
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

    fn evidence(left: &str, right: &str) -> IndependenceEvidence {
        IndependenceEvidence {
            left_root: left.into(),
            right_root: right.into(),
            basis: IndependenceBasis::DistinctAuthenticatedPrimaryOrigins,
            method_id: "method:primary-origin".into(),
            method_version: 1,
            supporting_artifact_ids: BTreeSet::from([ArtifactId::from("sha256:evidence")]),
            observed_at_unix: 10,
        }
    }

    #[test]
    fn disjoint_root_labels_are_unknown_without_explicit_independence() {
        let mut graph = EvidenceAncestryGraph::default();
        graph.insert(node("a", "registry", &[], false)).unwrap();
        graph.insert(node("b", "court-record", &[], false)).unwrap();
        assert_eq!(
            graph.independence_state(&"a".into(), &"b".into()).unwrap(),
            IndependenceState::Unknown
        );
    }

    #[test]
    fn shared_root_is_known_dependent_even_if_labels_differ() {
        let mut graph = EvidenceAncestryGraph::default();
        graph.insert(node("raw", "corpus", &[], false)).unwrap();
        graph
            .insert(node("a", "provider-a", &["raw"], true))
            .unwrap();
        graph
            .insert(node("b", "provider-b", &["raw"], true))
            .unwrap();
        assert_eq!(
            graph.independence_state(&"a".into(), &"b".into()).unwrap(),
            IndependenceState::KnownDependent
        );
    }

    #[test]
    fn explicit_valid_independence_is_symmetric() {
        let mut graph = EvidenceAncestryGraph::default();
        graph.insert(node("a", "registry", &[], false)).unwrap();
        graph.insert(node("b", "court-record", &[], false)).unwrap();
        graph
            .insert_independence_evidence(evidence("b", "a"))
            .unwrap();
        graph
            .insert_independence_evidence(evidence("a", "b"))
            .unwrap();
        assert_eq!(
            graph.independence_state(&"a".into(), &"b".into()).unwrap(),
            IndependenceState::ProvenIndependent
        );
        assert_eq!(
            graph.independence_state(&"b".into(), &"a".into()).unwrap(),
            IndependenceState::ProvenIndependent
        );
    }

    #[test]
    fn invalid_independence_evidence_is_rejected() {
        let mut graph = EvidenceAncestryGraph::default();
        graph.insert(node("root", "registry", &[], false)).unwrap();
        graph.insert(node("other", "court", &[], false)).unwrap();
        graph
            .insert(node("derived", "copy", &["root"], true))
            .unwrap();

        assert!(matches!(
            graph.insert_independence_evidence(evidence("root", "root")),
            Err(AncestryError::IndependenceNotDistinct)
        ));
        assert!(matches!(
            graph.insert_independence_evidence(evidence("root", "missing")),
            Err(AncestryError::MissingNode(_))
        ));
        assert!(matches!(
            graph.insert_independence_evidence(evidence("root", "derived")),
            Err(AncestryError::IndependenceNotRoot(_))
        ));
        let mut empty_method = evidence("root", "other");
        empty_method.method_id = "   ".into();
        assert!(matches!(
            graph.insert_independence_evidence(empty_method),
            Err(AncestryError::EmptyIndependenceMethod)
        ));
        let mut version_zero = evidence("root", "other");
        version_zero.method_version = 0;
        assert!(matches!(
            graph.insert_independence_evidence(version_zero),
            Err(AncestryError::InvalidIndependenceVersion)
        ));
        let mut no_artifact = evidence("root", "other");
        no_artifact.supporting_artifact_ids.clear();
        assert!(matches!(
            graph.insert_independence_evidence(no_artifact),
            Err(AncestryError::IndependenceWithoutArtifact)
        ));
    }

    #[test]
    fn deserialization_cannot_bypass_independence_validation() {
        let bad = r#"{"nodes":{"a":{"id":"a","source_family":"a","parents":[],"derived":false}},"independence":[{"left_root":"a","right_root":"missing","basis":"DistinctAuthenticatedPrimaryOrigins","method_id":"m","method_version":1,"supporting_artifact_ids":["sha256:x"],"observed_at_unix":1}]}"#;
        assert!(serde_json::from_str::<EvidenceAncestryGraph>(bad).is_err());

        let mut graph = EvidenceAncestryGraph::default();
        graph.insert(node("a", "registry", &[], false)).unwrap();
        graph.insert(node("b", "court", &[], false)).unwrap();
        graph
            .insert_independence_evidence(evidence("a", "b"))
            .unwrap();
        let back: EvidenceAncestryGraph =
            serde_json::from_str(&serde_json::to_string(&graph).unwrap()).unwrap();
        assert_eq!(back, graph);
    }

    #[test]
    fn two_disjoint_unproven_roots_count_as_one_route() {
        let mut graph = EvidenceAncestryGraph::default();
        graph.insert(node("a", "registry", &[], false)).unwrap();
        graph.insert(node("b", "court", &[], false)).unwrap();
        assert_eq!(
            graph
                .proven_independent_route_count([&"a".into(), &"b".into()], 2, 16)
                .unwrap(),
            IndependenceRouteCount {
                proven: 1,
                incomplete: false
            }
        );
    }

    #[test]
    fn two_explicitly_independent_roots_count_as_two_routes() {
        let mut graph = EvidenceAncestryGraph::default();
        graph.insert(node("a", "registry", &[], false)).unwrap();
        graph.insert(node("b", "court", &[], false)).unwrap();
        graph
            .insert_independence_evidence(evidence("a", "b"))
            .unwrap();
        assert_eq!(
            graph
                .proven_independent_route_count([&"a".into(), &"b".into()], 2, 16)
                .unwrap(),
            IndependenceRouteCount {
                proven: 2,
                incomplete: false
            }
        );
    }

    #[test]
    fn mirror_nodes_over_one_root_count_as_one_route() {
        let mut graph = EvidenceAncestryGraph::default();
        graph.insert(node("raw", "corpus", &[], false)).unwrap();
        graph
            .insert(node("a", "provider-a", &["raw"], true))
            .unwrap();
        graph
            .insert(node("b", "provider-b", &["raw"], true))
            .unwrap();
        assert_eq!(
            graph
                .proven_independent_route_count([&"a".into(), &"b".into()], 2, 16)
                .unwrap(),
            IndependenceRouteCount {
                proven: 1,
                incomplete: false
            }
        );
    }

    #[test]
    fn three_roots_can_satisfy_two_when_one_proven_pair_exists() {
        let mut graph = EvidenceAncestryGraph::default();
        graph.insert(node("a", "registry", &[], false)).unwrap();
        graph.insert(node("b", "court", &[], false)).unwrap();
        graph.insert(node("c", "sensor", &[], false)).unwrap();
        graph
            .insert_independence_evidence(evidence("a", "b"))
            .unwrap();
        assert_eq!(
            graph
                .proven_independent_route_count([&"a".into(), &"b".into(), &"c".into()], 2, 16)
                .unwrap(),
            IndependenceRouteCount {
                proven: 2,
                incomplete: false
            }
        );
    }

    #[test]
    fn search_budget_exhaustion_is_incomplete_and_never_strengthens() {
        let mut graph = EvidenceAncestryGraph::default();
        graph.insert(node("a", "registry", &[], false)).unwrap();
        graph.insert(node("b", "court", &[], false)).unwrap();
        graph.insert(node("c", "sensor", &[], false)).unwrap();
        graph
            .insert_independence_evidence(evidence("a", "b"))
            .unwrap();
        assert_eq!(
            graph
                .proven_independent_route_count([&"a".into(), &"b".into(), &"c".into()], 2, 0)
                .unwrap(),
            IndependenceRouteCount {
                proven: 1,
                incomplete: true
            }
        );
    }

    #[test]
    fn required_zero_and_one_have_bounded_semantics() {
        let mut graph = EvidenceAncestryGraph::default();
        graph.insert(node("a", "registry", &[], false)).unwrap();
        graph.insert(node("b", "court", &[], false)).unwrap();
        assert_eq!(
            graph
                .proven_independent_route_count([&"a".into(), &"b".into()], 0, 0)
                .unwrap(),
            IndependenceRouteCount {
                proven: 0,
                incomplete: false
            }
        );
        assert_eq!(
            graph
                .proven_independent_route_count([&"a".into(), &"b".into()], 1, 0)
                .unwrap(),
            IndependenceRouteCount {
                proven: 1,
                incomplete: false
            }
        );
    }
}
