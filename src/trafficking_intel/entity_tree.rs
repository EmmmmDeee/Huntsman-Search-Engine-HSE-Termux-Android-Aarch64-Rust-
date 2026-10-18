//! Evidence-backed entity tree for public-record investigations.
//! This graph does not infer criminal involvement from association or proximity.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Investigation, Organisation, Person, DigitalAsset, Location, FinancialEntity, Evidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityNode {
    pub id: String,
    pub kind: EntityKind,
    /// Public-facing label only. Do not store identifying details of potential victims.
    pub label: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipKind {
    EmployedBy, DirectorOf, RegisteredAt, OperatesDomain, MentionedIn,
    RecruitedBy, AllegedAssociation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityEdge {
    pub from: String,
    pub to: String,
    pub kind: RelationshipKind,
    pub evidence_refs: Vec<String>,
    pub alleged: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntityTree {
    pub nodes: Vec<EntityNode>,
    pub edges: Vec<EntityEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    EmptyIdentifier,
    DuplicateNode(String),
    UnknownEndpoint(String),
    MissingEvidence,
    SelfLink,
}

impl EntityTree {
    /// Rejects ambiguous nodes, unsupported links and accidental self-links.
    pub fn validate(&self) -> Result<(), GraphError> {
        let mut ids = BTreeSet::new();
        for node in &self.nodes {
            if node.id.trim().is_empty() || node.label.trim().is_empty() {
                return Err(GraphError::EmptyIdentifier);
            }
            if !ids.insert(node.id.as_str()) {
                return Err(GraphError::DuplicateNode(node.id.clone()));
            }
        }
        for edge in &self.edges {
            if edge.from == edge.to { return Err(GraphError::SelfLink); }
            for endpoint in [&edge.from, &edge.to] {
                if !ids.contains(endpoint.as_str()) {
                    return Err(GraphError::UnknownEndpoint(endpoint.clone()));
                }
            }
            if edge.evidence_refs.is_empty()
                || edge.evidence_refs.iter().any(|r| r.trim().is_empty())
            {
                return Err(GraphError::MissingEvidence);
            }
        }
        Ok(())
    }

    /// A deterministic adjacency view, including both directions of each documented link.
    pub fn adjacency(&self) -> Result<BTreeMap<String, Vec<String>>, GraphError> {
        self.validate()?;
        let mut result: BTreeMap<String, BTreeSet<String>> = self.nodes.iter()
            .map(|node| (node.id.clone(), BTreeSet::new())).collect();
        for edge in &self.edges {
            result.entry(edge.from.clone()).or_default().insert(edge.to.clone());
            result.entry(edge.to.clone()).or_default().insert(edge.from.clone());
        }
        Ok(result.into_iter().map(|(k, v)| (k, v.into_iter().collect())).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn graph() -> EntityTree {
        EntityTree {
            nodes: vec![
                EntityNode { id: "company".into(), kind: EntityKind::Organisation, label: "Example Ltd".into() },
                EntityNode { id: "record".into(), kind: EntityKind::Evidence, label: "Published filing".into() },
            ],
            edges: vec![EntityEdge {
                from: "company".into(), to: "record".into(),
                kind: RelationshipKind::MentionedIn,
                evidence_refs: vec!["public-record-1".into()], alleged: false,
            }],
        }
    }
    #[test]
    fn validates_supported_graph() { assert!(graph().validate().is_ok()); }
    #[test]
    fn rejects_missing_evidence() {
        let mut g = graph();
        g.edges[0].evidence_refs.clear();
        assert_eq!(g.validate(), Err(GraphError::MissingEvidence));
    }
    #[test]
    fn rejects_unknown_endpoints() {
        let mut g = graph();
        g.edges[0].to = "missing".into();
        assert_eq!(g.validate(), Err(GraphError::UnknownEndpoint("missing".into())));
    }
    #[test]
    fn rejects_duplicate_ids() {
        let mut g = graph();
        g.nodes.push(g.nodes[0].clone());
        assert_eq!(g.validate(), Err(GraphError::DuplicateNode("company".into())));
    }
    #[test]
    fn produces_deterministic_adjacency() {
        let a = graph().adjacency().unwrap();
        assert_eq!(a["company"], vec!["record"]);
        assert_eq!(a["record"], vec!["company"]);
    }
}
