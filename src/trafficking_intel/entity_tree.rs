//! Evidence-backed entity tree for public-record investigations.
//! This graph does not infer criminal involvement from association or proximity.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Investigation,
    Organisation,
    Person,
    DigitalAsset,
    Location,
    FinancialEntity,
    Evidence,
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
    EmployedBy,
    DirectorOf,
    RegisteredAt,
    OperatesDomain,
    MentionedIn,
    RecruitedBy,
    AllegedAssociation,
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
    EmptyEndpoint,
    DuplicateEvidenceReference,
    ResourceLimitExceeded,
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
            if edge.from.trim().is_empty() || edge.to.trim().is_empty() {
                return Err(GraphError::EmptyEndpoint);
            }
            if edge.from == edge.to {
                return Err(GraphError::SelfLink);
            }
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
            let mut refs = BTreeSet::new();
            if edge.evidence_refs.iter().any(|r| !refs.insert(r.as_str())) {
                return Err(GraphError::DuplicateEvidenceReference);
            }
        }
        Ok(())
    }

    /// A deterministic adjacency view, including both directions of each documented link.
    pub fn adjacency(&self) -> Result<BTreeMap<String, Vec<String>>, GraphError> {
        self.validate()?;
        let mut result: BTreeMap<String, BTreeSet<String>> = self
            .nodes
            .iter()
            .map(|node| (node.id.clone(), BTreeSet::new()))
            .collect();
        for edge in &self.edges {
            result
                .entry(edge.from.clone())
                .or_default()
                .insert(edge.to.clone());
            result
                .entry(edge.to.clone())
                .or_default()
                .insert(edge.from.clone());
        }
        Ok(result
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeEntry {
    pub id: String,
    pub depth: usize,
    pub parent: Option<String>,
}

impl EntityTree {
    /// Traverse only non-alleged relationships. This does not authenticate
    /// caller-supplied evidence references or establish factual culpability.
    pub fn expand_documented(
        &self,
        root: &str,
        max_depth: usize,
        max_nodes: usize,
    ) -> Result<Vec<TreeEntry>, GraphError> {
        self.expand_filtered(root, max_depth, max_nodes, |edge| {
            !edge.alleged && edge.kind != RelationshipKind::AllegedAssociation
        })
    }

    /// Bounded breadth-first expansion for a simple, cycle-safe entity tree.
    /// The returned view is not an inference of ownership or criminal hierarchy.
    pub fn expand(
        &self,
        root: &str,
        max_depth: usize,
        max_nodes: usize,
    ) -> Result<Vec<TreeEntry>, GraphError> {
        self.expand_filtered(root, max_depth, max_nodes, |_| true)
    }

    fn expand_filtered(
        &self,
        root: &str,
        max_depth: usize,
        max_nodes: usize,
        include: impl Fn(&EntityEdge) -> bool,
    ) -> Result<Vec<TreeEntry>, GraphError> {
        self.validate()?;
        if !self.nodes.iter().any(|node| node.id == root) {
            return Err(GraphError::UnknownEndpoint(root.to_owned()));
        }
        // Cap work on malformed or oversized inputs before building adjacency.
        // Existing public graph representation remains unchanged.
        const MAX_GRAPH_NODES: usize = 100_000;
        const MAX_GRAPH_EDGES: usize = 200_000;
        if self.nodes.len() > MAX_GRAPH_NODES || self.edges.len() > MAX_GRAPH_EDGES {
            return Err(GraphError::ResourceLimitExceeded);
        }
        let limit = max_nodes.min(10_000);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut adj: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for edge in self.edges.iter().filter(|edge| include(edge)) {
            adj.entry(&edge.from).or_default().insert(&edge.to);
            adj.entry(&edge.to).or_default().insert(&edge.from);
        }
        let mut visited = BTreeSet::new();
        let mut queue = std::collections::VecDeque::new();
        let mut result = Vec::new();
        visited.insert(root.to_owned());
        queue.push_back(TreeEntry {
            id: root.to_owned(),
            depth: 0,
            parent: None,
        });
        while let Some(entry) = queue.pop_front() {
            let depth = entry.depth;
            let parent_id = entry.id.clone();
            result.push(entry);
            if result.len() >= limit {
                break;
            }
            if depth >= max_depth {
                continue;
            }
            if let Some(neighbours) = adj.get(parent_id.as_str()) {
                for neighbour in neighbours {
                    if visited.len() >= limit {
                        break;
                    }
                    if visited.insert((*neighbour).to_owned()) {
                        queue.push_back(TreeEntry {
                            id: (*neighbour).to_owned(),
                            depth: depth + 1,
                            parent: Some(parent_id.clone()),
                        });
                    }
                }
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn graph() -> EntityTree {
        EntityTree {
            nodes: vec![
                EntityNode {
                    id: "company".into(),
                    kind: EntityKind::Organisation,
                    label: "Example Ltd".into(),
                },
                EntityNode {
                    id: "record".into(),
                    kind: EntityKind::Evidence,
                    label: "Published filing".into(),
                },
            ],
            edges: vec![EntityEdge {
                from: "company".into(),
                to: "record".into(),
                kind: RelationshipKind::MentionedIn,
                evidence_refs: vec!["public-record-1".into()],
                alleged: false,
            }],
        }
    }
    #[test]
    fn documented_traversal_excludes_alleged_edges_without_changing_legacy_view() {
        let mut g = graph();
        g.edges[0].alleged = true;
        assert_eq!(g.expand("company", 1, 10).unwrap().len(), 2);
        assert_eq!(g.expand_documented("company", 1, 10).unwrap().len(), 1);
        g.edges[0].alleged = false;
        g.edges[0].kind = RelationshipKind::AllegedAssociation;
        assert_eq!(g.expand_documented("company", 1, 10).unwrap().len(), 1);
        g.edges[0].kind = RelationshipKind::MentionedIn;
        assert_eq!(g.expand_documented("company", 1, 10).unwrap().len(), 2);
    }

    #[test]
    fn documented_traversal_preserves_bounds_and_rejects_unknown_root() {
        let g = graph();
        assert!(g.expand_documented("company", 1, 0).unwrap().is_empty());
        assert_eq!(g.expand_documented("company", 0, 10).unwrap().len(), 1);
        assert_eq!(g.expand_documented("company", 10, 1).unwrap().len(), 1);
        assert_eq!(
            g.expand_documented("unknown", 0, 0),
            Err(GraphError::UnknownEndpoint("unknown".into()))
        );
    }

    #[test]
    fn oversized_graph_is_rejected_before_adjacency_build() {
        let mut g = graph();
        g.nodes = (0..100_001)
            .map(|i| EntityNode {
                id: format!("node-{i}"),
                kind: EntityKind::Organisation,
                label: "public record".into(),
            })
            .collect();
        g.edges.clear();
        assert_eq!(
            g.expand_documented("node-0", 1, 10),
            Err(GraphError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn validates_supported_graph() {
        assert!(graph().validate().is_ok());
    }
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
        assert_eq!(
            g.validate(),
            Err(GraphError::UnknownEndpoint("missing".into()))
        );
    }
    #[test]
    fn rejects_duplicate_ids() {
        let mut g = graph();
        g.nodes.push(g.nodes[0].clone());
        assert_eq!(
            g.validate(),
            Err(GraphError::DuplicateNode("company".into()))
        );
    }
    #[test]
    fn produces_deterministic_adjacency() {
        let a = graph().adjacency().unwrap();
        assert_eq!(a["company"], vec!["record"]);
        assert_eq!(a["record"], vec!["company"]);
    }
}

#[cfg(test)]
mod traversal_tests {
    use super::*;
    #[test]
    fn cycle_is_visited_once_and_depth_bounded() {
        let g = EntityTree {
            nodes: ["a", "b", "c"]
                .iter()
                .map(|id| EntityNode {
                    id: (*id).into(),
                    kind: EntityKind::Organisation,
                    label: (*id).into(),
                })
                .collect(),
            edges: [("a", "b"), ("b", "c"), ("c", "a")]
                .iter()
                .map(|(from, to)| EntityEdge {
                    from: (*from).into(),
                    to: (*to).into(),
                    kind: RelationshipKind::MentionedIn,
                    evidence_refs: vec!["record".into()],
                    alleged: false,
                })
                .collect(),
        };
        let view = g.expand("a", 1, 10).unwrap();
        assert_eq!(view.len(), 3);
        assert_eq!(view[0].depth, 0);
        assert!(view[1..].iter().all(|e| e.depth == 1));
        assert_eq!(g.expand("a", 10, 2).unwrap().len(), 2);
        assert!(g.expand("a", 10, 0).unwrap().is_empty());
    }
}

#[cfg(test)]
mod validation_regression_tests {
    use super::*;

    fn base() -> EntityTree {
        EntityTree {
            nodes: vec![
                EntityNode {
                    id: "a".into(),
                    kind: EntityKind::Organisation,
                    label: "A".into(),
                },
                EntityNode {
                    id: "b".into(),
                    kind: EntityKind::Evidence,
                    label: "B".into(),
                },
            ],
            edges: vec![EntityEdge {
                from: "a".into(),
                to: "b".into(),
                kind: RelationshipKind::MentionedIn,
                evidence_refs: vec!["record-1".into()],
                alleged: false,
            }],
        }
    }

    #[test]
    fn rejects_empty_edge_endpoint() {
        let mut graph = base();
        graph.edges[0].from.clear();
        assert_eq!(graph.validate(), Err(GraphError::EmptyEndpoint));
    }

    #[test]
    fn rejects_duplicate_evidence_reference_on_edge() {
        let mut graph = base();
        graph.edges[0].evidence_refs.push("record-1".into());
        assert_eq!(
            graph.validate(),
            Err(GraphError::DuplicateEvidenceReference)
        );
    }

    #[test]
    fn depth_zero_yields_root_only() {
        let graph = base();
        let nodes = graph.expand("a", 0, 10).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, "a");
    }

    #[test]
    fn unknown_root_fails_even_with_zero_budget() {
        assert_eq!(
            base().expand("unknown", 0, 0),
            Err(GraphError::UnknownEndpoint("unknown".into()))
        );
    }
}
