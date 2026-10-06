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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndependenceState {
    ProvenIndependent,
    KnownDependent,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndependenceBasis {
    DistinctAuthenticatedPrimaryOrigins,
    DistinctDirectSensorObservations,
    ExplicitUpstreamProvenance,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndependenceRouteCount {
    pub proven: usize,
    pub incomplete: bool,
}

/// Deserialisation re-runs validating insertion for every node and every
/// independence record, so persisted state cannot bypass runtime invariants.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawGraph")]
pub struct EvidenceAncestryGraph {
    nodes: BTreeMap<EvidenceNodeId, EvidenceAncestryNode>,
    #[serde(default)]
    independence_evidence: BTreeMap<EvidenceNodeId, BTreeMap<EvidenceNodeId, IndependenceEvidence>>,
}

#[derive(Deserialize)]
struct RawGraph {
    nodes: BTreeMap<EvidenceNodeId, EvidenceAncestryNode>,
    #[serde(default)]
    independence_evidence: BTreeMap<EvidenceNodeId, BTreeMap<EvidenceNodeId, IndependenceEvidence>>,
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
        for (left_key, records) in raw.independence_evidence {
            for (right_key, evidence) in records {
                let (left, right) = canonical_pair(&evidence.left_root, &evidence.right_root)
                    .map_err(|e| e.to_string())?;
                if left_key != left || right_key != right {
                    return Err(format!(
                        "independence key {}/{} holds evidence {}/{}",
                        left_key.0, right_key.0, evidence.left_root.0, evidence.right_root.0
                    ));
                }
                graph
                    .insert_independence_evidence(evidence)
                    .map_err(|e| e.to_string())?;
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
    #[error("conflicting independence evidence for roots {}/{}", .0.0, .1.0)]
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

fn canonical_pair(
    left: &EvidenceNodeId,
    right: &EvidenceNodeId,
) -> Result<(EvidenceNodeId, EvidenceNodeId), AncestryError> {
    if left == right {
        return Err(AncestryError::InvalidIndependenceEvidence(
            "independence requires two distinct roots".to_owned(),
        ));
    }
    Ok(if left < right {
        (left.clone(), right.clone())
    } else {
        (right.clone(), left.clone())
    })
}

struct IndependenceSearch<'a> {
    graph: &'a EvidenceAncestryGraph,
    roots: &'a [EvidenceNodeId],
    states: usize,
    max_states: usize,
    exhausted: bool,
}

impl IndependenceSearch<'_> {
    fn search_exact(
        &mut self,
        target: usize,
        start: usize,
        chosen: &mut Vec<usize>,
    ) -> Result<bool, AncestryError> {
        if chosen.len() == target {
            return Ok(true);
        }
        let need = target - chosen.len();
        if self.roots.len().saturating_sub(start) < need {
            return Ok(false);
        }

        for index in start..self.roots.len() {
            if self.states >= self.max_states {
                self.exhausted = true;
                return Ok(false);
            }
            self.states += 1;

            let compatible = chosen.iter().copied().all(|selected| {
                self.graph
                    .independence_state(&self.roots[selected], &self.roots[index])
                    .is_ok_and(|state| state == IndependenceState::ProvenIndependent)
            });
            if !compatible {
                continue;
            }

            chosen.push(index);
            if self.search_exact(target, index + 1, chosen)? {
                return Ok(true);
            }
            chosen.pop();
            if self.exhausted {
                return Ok(false);
            }
        }
        Ok(false)
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

    /// Insert explicit, versioned evidence that two observed roots are distinct
    /// proof routes. Merely different labels never satisfy this contract.
    ///
    /// # Errors
    /// Returns a typed error for invalid roots, method metadata, supporting
    /// artifacts, or conflicting evidence for an already-recorded pair.
    pub fn insert_independence_evidence(
        &mut self,
        mut evidence: IndependenceEvidence,
    ) -> Result<(), AncestryError> {
        let (left, right) = canonical_pair(&evidence.left_root, &evidence.right_root)?;
        for root in [&left, &right] {
            let node = self
                .nodes
                .get(root)
                .ok_or_else(|| AncestryError::MissingNode(root.clone()))?;
            if node.derived || !node.parents.is_empty() {
                return Err(AncestryError::InvalidIndependenceEvidence(format!(
                    "{} is not an observed root",
                    root.0
                )));
            }
        }
        let method_id = evidence.method_id.trim().to_owned();
        if method_id.is_empty() {
            return Err(AncestryError::InvalidIndependenceEvidence(
                "method_id is empty".to_owned(),
            ));
        }
        if evidence.method_version == 0 {
            return Err(AncestryError::InvalidIndependenceEvidence(
                "method_version must be greater than zero".to_owned(),
            ));
        }
        if evidence.supporting_artifact_ids.is_empty()
            || evidence
                .supporting_artifact_ids
                .iter()
                .any(|artifact| artifact.0.trim().is_empty())
        {
            return Err(AncestryError::InvalidIndependenceEvidence(
                "supporting_artifact_ids must contain non-empty ids".to_owned(),
            ));
        }

        evidence.left_root = left.clone();
        evidence.right_root = right.clone();
        evidence.method_id = method_id;

        let records = self.independence_evidence.entry(left.clone()).or_default();
        match records.get(&right) {
            Some(existing) if existing == &evidence => Ok(()),
            Some(_) => Err(AncestryError::ConflictingIndependenceEvidence(left, right)),
            None => {
                records.insert(right, evidence);
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

    /// Root families reachable from `id`. Iterative three-colour DFS: each node is
    /// expanded once, so shared ancestry is linear and depth cannot overflow the stack.
    ///
    /// # Errors
    /// A missing node or a cycle anywhere in the ancestry of `id`. Fails closed.
    pub fn root_families(&self, id: &EvidenceNodeId) -> Result<BTreeSet<String>, AncestryError> {
        let mut families = BTreeSet::new();
        for root in self.root_ids(id)? {
            families.insert(
                self.nodes
                    .get(&root)
                    .expect("root id came from graph traversal")
                    .source_family
                    .clone(),
            );
        }
        Ok(families)
    }

    /// Relationship between two proof routes under explicit independence evidence.
    /// Shared ancestry dominates any independence assertion. Disjoint ancestry is
    /// `Unknown` unless each side resolves to exactly one root and that canonical
    /// root pair carries accepted explicit evidence.
    ///
    /// # Errors
    /// Missing nodes/parents and cycles fail closed through ancestry traversal.
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
        let (left, right) = canonical_pair(left, right)?;
        Ok(
            if self
                .independence_evidence
                .get(&left)
                .is_some_and(|records| records.contains_key(&right))
            {
                IndependenceState::ProvenIndependent
            } else {
                IndependenceState::Unknown
            },
        )
    }

    /// Count a conservative lower bound of mutually proven-independent proof
    /// routes. The deterministic search is bounded by `max_search_states`.
    /// Exhaustion marks the result incomplete and never adds an unproven route.
    ///
    /// # Errors
    /// Missing nodes/parents and cycles fail closed while resolving roots.
    pub fn proven_independent_route_count<'a>(
        &self,
        ids: impl IntoIterator<Item = &'a EvidenceNodeId>,
        required: usize,
        max_search_states: usize,
    ) -> Result<IndependenceRouteCount, AncestryError> {
        if required == 0 {
            return Ok(IndependenceRouteCount {
                proven: 0,
                incomplete: false,
            });
        }

        let mut root_set = BTreeSet::new();
        for id in ids {
            root_set.extend(self.root_ids(id)?);
        }
        if root_set.is_empty() {
            return Ok(IndependenceRouteCount {
                proven: 0,
                incomplete: false,
            });
        }
        if required == 1 || root_set.len() == 1 {
            return Ok(IndependenceRouteCount {
                proven: 1,
                incomplete: false,
            });
        }

        let roots: Vec<EvidenceNodeId> = root_set.into_iter().collect();
        let mut search = IndependenceSearch {
            graph: self,
            roots: &roots,
            states: 0,
            max_states: max_search_states,
            exhausted: false,
        };
        let mut best = 1usize;
        let target_limit = required.min(roots.len());

        for target in 2..=target_limit {
            let mut chosen = Vec::with_capacity(target);
            if search.search_exact(target, 0, &mut chosen)? {
                best = target;
                if best >= required {
                    return Ok(IndependenceRouteCount {
                        proven: best,
                        incomplete: false,
                    });
                }
            } else if search.exhausted {
                return Ok(IndependenceRouteCount {
                    proven: best,
                    incomplete: true,
                });
            } else {
                break;
            }
        }

        Ok(IndependenceRouteCount {
            proven: best,
            incomplete: false,
        })
    }

    /// Distinct root-family count across a support set.
    ///
    /// Compatibility/diagnostic API only. Verification-capable paths must use
    /// explicit tri-state independence semantics instead of this cardinality.
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

    /// Compatibility/diagnostic API retaining the historical disjoint-family
    /// behavior. Verification-capable paths must use [`Self::independence_state`].
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
