//! Evidence ancestry and independence. From refactor overlay feef60a (P3), reimplemented.
//!
//! Module count is not source independence. The graph keeps upstream ancestry so a
//! mirror, derivation, recall path, or copied corpus cannot manufacture corroboration
//! by being emitted again. Formatting variants of one family are one family.
//! A derivation must name what it derives from. Walks visit each node once.

use std::collections::{BTreeMap, BTreeSet};

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
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

/// Epistemic relationship between two proof routes.
///
/// Disjoint recorded labels are deliberately insufficient for `ProvenIndependent`:
/// absence of a known common cause is not evidence that no common cause exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndependenceState {
    ProvenIndependent,
    KnownDependent,
    Unknown,
}

/// Classes of evidence that may establish distinct causal origins.
///
/// `OtherVersionedRule` is retained for forward-compatible persisted evidence, but
/// remains fail-closed until a governing policy explicitly knows that rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndependenceBasis {
    DistinctAuthenticatedPrimaryOrigins,
    DistinctDirectSensorObservations,
    ExplicitUpstreamProvenance,
    OtherVersionedRule(String),
}

/// Explicit, versioned evidence that two canonical provenance roots are distinct
/// proof routes. The artifact references are evidence for this relationship, not
/// additional proof roots by themselves.
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

/// Sole canonical provenance authority. Independence records are keyed by an ordered
/// root-id pair so lookup is symmetric and conflicting duplicates cannot coexist.
///
/// Deserialisation re-runs `insert` and `insert_independence_evidence`; persisted state
/// therefore cannot bypass node, pair-key, or independence-evidence validation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawGraph")]
pub struct EvidenceAncestryGraph {
    nodes: BTreeMap<EvidenceNodeId, EvidenceAncestryNode>,
    independence: BTreeMap<(EvidenceNodeId, EvidenceNodeId), IndependenceEvidence>,
}

#[derive(Deserialize)]
struct RawGraph {
    nodes: BTreeMap<EvidenceNodeId, EvidenceAncestryNode>,
    #[serde(default)]
    independence: BTreeMap<String, IndependenceEvidence>,
}

impl Serialize for EvidenceAncestryGraph {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let independence: BTreeMap<String, &IndependenceEvidence> = self
            .independence
            .iter()
            .map(|((left, right), evidence)| (canonical_pair_key(left, right), evidence))
            .collect();
        let mut state = serializer.serialize_struct("EvidenceAncestryGraph", 2)?;
        state.serialize_field("nodes", &self.nodes)?;
        state.serialize_field("independence", &independence)?;
        state.end()
    }
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
        for (encoded_pair, evidence) in raw.independence {
            let decoded_pair = decode_pair_key(&encoded_pair)?;
            let expected_pair = ordered_pair(&evidence.left_root, &evidence.right_root);
            if decoded_pair != expected_pair {
                return Err(format!(
                    "independence key {encoded_pair:?} does not match evidence roots"
                ));
            }
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
    #[error("independence evidence names the same root twice: {}", .0.0)]
    IndependenceSameRoot(EvidenceNodeId),
    #[error("independence evidence node {} is not a provenance root", .0.0)]
    IndependenceNodeNotRoot(EvidenceNodeId),
    #[error("independence evidence method id is empty")]
    EmptyIndependenceMethod,
    #[error("independence evidence method version must be positive")]
    InvalidIndependenceMethodVersion,
    #[error("independence evidence has no supporting artifact")]
    MissingIndependenceArtifact,
    #[error("independence evidence contains an empty supporting artifact id")]
    EmptyIndependenceArtifact,
    #[error("independence evidence names an empty versioned rule")]
    EmptyIndependenceRule,
    #[error("conflicting independence evidence for roots {} and {}", .0.0, .1.0)]
    ConflictingIndependenceEvidence(EvidenceNodeId, EvidenceNodeId),
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

fn ordered_pair(a: &EvidenceNodeId, b: &EvidenceNodeId) -> (EvidenceNodeId, EvidenceNodeId) {
    if a <= b {
        (a.clone(), b.clone())
    } else {
        (b.clone(), a.clone())
    }
}

fn canonical_pair_key(left: &EvidenceNodeId, right: &EvidenceNodeId) -> String {
    serde_json::to_string(&(left, right)).expect("evidence node ids always serialize")
}

fn decode_pair_key(encoded: &str) -> Result<(EvidenceNodeId, EvidenceNodeId), String> {
    serde_json::from_str(encoded)
        .map_err(|error| format!("invalid independence pair key {encoded:?}: {error}"))
}

fn basis_is_accepted(basis: &IndependenceBasis) -> bool {
    matches!(
        basis,
        IndependenceBasis::DistinctAuthenticatedPrimaryOrigins
            | IndependenceBasis::DistinctDirectSensorObservations
            | IndependenceBasis::ExplicitUpstreamProvenance
    )
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

    /// Insert explicit evidence that two existing canonical roots have distinct causal origins.
    ///
    /// The record is canonicalised to root-id order. Re-inserting the identical record is
    /// idempotent; a different record for the same pair is rejected rather than silently
    /// replacing the previously audited basis.
    ///
    /// Source-family labels are deliberately not used as proof or disproof here. They are
    /// compatibility metadata; explicit evidence and actual root ancestry govern this API.
    ///
    /// # Errors
    /// Returns an ancestry error when either node is missing or not a root, both ids are the
    /// same, method metadata is invalid, supporting artifact identity is missing, a custom
    /// rule id is blank, or conflicting evidence for the canonical pair already exists.
    pub fn insert_independence_evidence(
        &mut self,
        mut evidence: IndependenceEvidence,
    ) -> Result<(), AncestryError> {
        if evidence.left_root == evidence.right_root {
            return Err(AncestryError::IndependenceSameRoot(evidence.left_root));
        }

        let (left, right) = ordered_pair(&evidence.left_root, &evidence.right_root);
        let left_node = self
            .nodes
            .get(&left)
            .ok_or_else(|| AncestryError::MissingNode(left.clone()))?;
        let right_node = self
            .nodes
            .get(&right)
            .ok_or_else(|| AncestryError::MissingNode(right.clone()))?;

        if left_node.derived || !left_node.parents.is_empty() {
            return Err(AncestryError::IndependenceNodeNotRoot(left));
        }
        if right_node.derived || !right_node.parents.is_empty() {
            return Err(AncestryError::IndependenceNodeNotRoot(right));
        }

        let normalized_method_id = evidence.method_id.trim().to_owned();
        evidence.method_id = normalized_method_id;
        if evidence.method_id.is_empty() {
            return Err(AncestryError::EmptyIndependenceMethod);
        }
        if evidence.method_version == 0 {
            return Err(AncestryError::InvalidIndependenceMethodVersion);
        }
        if evidence.supporting_artifact_ids.is_empty() {
            return Err(AncestryError::MissingIndependenceArtifact);
        }
        if evidence
            .supporting_artifact_ids
            .iter()
            .any(|artifact| artifact.0.trim().is_empty())
        {
            return Err(AncestryError::EmptyIndependenceArtifact);
        }
        if let IndependenceBasis::OtherVersionedRule(rule) = &mut evidence.basis {
            let normalized_rule = rule.trim().to_owned();
            *rule = normalized_rule;
            if rule.is_empty() {
                return Err(AncestryError::EmptyIndependenceRule);
            }
        }

        evidence.left_root = left.clone();
        evidence.right_root = right.clone();
        let key = (left.clone(), right.clone());
        match self.independence.get(&key) {
            Some(current) if current == &evidence => Ok(()),
            Some(_) => Err(AncestryError::ConflictingIndependenceEvidence(left, right)),
            None => {
                self.independence.insert(key, evidence);
                Ok(())
            }
        }
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
                roots.insert(EvidenceNodeId(current.0.clone()));
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

    /// Root families reachable from `id`. Iterative three-colour DFS: each node is
    /// expanded once, so shared ancestry is linear and depth cannot overflow the stack.
    ///
    /// # Errors
    /// A missing node or a cycle anywhere in the ancestry of `id`. Fails closed.
    pub fn root_families(&self, id: &EvidenceNodeId) -> Result<BTreeSet<String>, AncestryError> {
        self.root_ids(id).map(|roots| {
            roots
                .into_iter()
                .map(|root| self.nodes[&root].source_family.clone())
                .collect()
        })
    }

    /// Conservative epistemic relationship between two evidence nodes.
    ///
    /// A shared provenance root is known dependence. Merely equal or disjoint source-family
    /// labels do not decide the relationship. Distinct singleton roots become
    /// `ProvenIndependent` only through accepted explicit evidence for their canonical pair.
    ///
    /// # Errors
    /// Missing nodes, missing parents, or cycles fail closed as ancestry errors.
    pub fn independence_state(
        &self,
        a: &EvidenceNodeId,
        b: &EvidenceNodeId,
    ) -> Result<IndependenceState, AncestryError> {
        let left_roots = self.root_ids(a)?;
        let right_roots = self.root_ids(b)?;
        if !left_roots.is_disjoint(&right_roots) {
            return Ok(IndependenceState::KnownDependent);
        }

        if left_roots.len() != 1 || right_roots.len() != 1 {
            return Ok(IndependenceState::Unknown);
        }
        let left = left_roots.iter().next().expect("length checked");
        let right = right_roots.iter().next().expect("length checked");
        let key = ordered_pair(left, right);
        let accepted = self
            .independence
            .get(&key)
            .is_some_and(|evidence| basis_is_accepted(&evidence.basis));
        Ok(if accepted {
            IndependenceState::ProvenIndependent
        } else {
            IndependenceState::Unknown
        })
    }

    /// Distinct root families across a support set.
    ///
    /// Compatibility/diagnostic API only: distinct recorded families are not, by
    /// themselves, proof of causal independence. Verification-capable callers must use
    /// [`Self::independence_state`] and the bounded proven-route API introduced next.
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

    /// Legacy diagnostic predicate: true when recorded root-family labels are disjoint.
    ///
    /// This does **not** establish [`IndependenceState::ProvenIndependent`]. New
    /// verification logic must use [`Self::independence_state`] instead.
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
}
