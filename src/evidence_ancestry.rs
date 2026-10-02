//! Evidence ancestry and independence.
//!
//! Module count is not source independence.  This graph retains upstream
//! ancestry so a mirror, deterministic derivation, recall path, or copied
//! corpus cannot manufacture corroboration merely by being emitted again.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

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
    /// Stable family/corpus/provider-origin identifier. Different module names
    /// that reproduce the same upstream family must use the same value.
    pub source_family: String,
    /// Direct evidence parents. Empty means this is an observed root.
    pub parents: BTreeSet<EvidenceNodeId>,
    /// True for deterministic/enrichment/recall derivations.
    pub derived: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceAncestryGraph {
    nodes: BTreeMap<EvidenceNodeId, EvidenceAncestryNode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AncestryError {
    DuplicateNode(EvidenceNodeId),
    MissingNode(EvidenceNodeId),
    Cycle(EvidenceNodeId),
    EmptySourceFamily(EvidenceNodeId),
}

impl fmt::Display for AncestryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateNode(id) => write!(f, "duplicate evidence node {}", id.0),
            Self::MissingNode(id) => write!(f, "missing evidence node {}", id.0),
            Self::Cycle(id) => write!(f, "evidence ancestry cycle at {}", id.0),
            Self::EmptySourceFamily(id) => {
                write!(f, "evidence node {} has an empty source family", id.0)
            }
        }
    }
}

impl std::error::Error for AncestryError {}

impl EvidenceAncestryGraph {
    pub fn insert(&mut self, node: EvidenceAncestryNode) -> Result<(), AncestryError> {
        if node.source_family.trim().is_empty() {
            return Err(AncestryError::EmptySourceFamily(node.id));
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

    /// Root source families contributing to `id`.
    ///
    /// Derived nodes contribute no new family of their own while they have
    /// parents. An observed root contributes exactly its own source family.
    pub fn root_families(
        &self,
        id: &EvidenceNodeId,
    ) -> Result<BTreeSet<String>, AncestryError> {
        let mut roots = BTreeSet::new();
        let mut visiting = BTreeSet::new();
        self.collect_roots(id, &mut visiting, &mut roots)?;
        Ok(roots)
    }

    fn collect_roots(
        &self,
        id: &EvidenceNodeId,
        visiting: &mut BTreeSet<EvidenceNodeId>,
        roots: &mut BTreeSet<String>,
    ) -> Result<(), AncestryError> {
        let node = self
            .nodes
            .get(id)
            .ok_or_else(|| AncestryError::MissingNode(id.clone()))?;

        if !visiting.insert(id.clone()) {
            return Err(AncestryError::Cycle(id.clone()));
        }

        if node.parents.is_empty() {
            roots.insert(node.source_family.clone());
        } else {
            for parent in &node.parents {
                self.collect_roots(parent, visiting, roots)?;
            }
        }

        visiting.remove(id);
        Ok(())
    }

    /// Count distinct independent root families across a support set.
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

    /// True only when the two evidence nodes have no root family in common.
    pub fn are_independent(
        &self,
        a: &EvidenceNodeId,
        b: &EvidenceNodeId,
    ) -> Result<bool, AncestryError> {
        let a_roots = self.root_families(a)?;
        let b_roots = self.root_families(b)?;
        Ok(a_roots.is_disjoint(&b_roots))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(
        id: &str,
        family: &str,
        parents: &[&str],
        derived: bool,
    ) -> EvidenceAncestryNode {
        EvidenceAncestryNode {
            id: id.into(),
            source_family: family.to_owned(),
            parents: parents.iter().copied().map(EvidenceNodeId::from).collect(),
            derived,
        }
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

        assert!(!graph
            .are_independent(&"mirror-a".into(), &"mirror-b".into())
            .unwrap());
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
}
