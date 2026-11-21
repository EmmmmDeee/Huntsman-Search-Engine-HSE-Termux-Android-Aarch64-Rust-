//! Offline, source-cited relationship clustering for an explicitly reviewed case.
//! A multi-hop path is an investigational traversal, never a new relationship,
//! identity merge, criminal allegation or assertion of source independence.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::breach_ci::{FindingInput, rank};
use crate::canonical::canonical_domain;
use crate::scan_route::{ScanKind, canonical_selector};
use crate::people_discovery;
use crate::union_find::UnionFind;

pub const MAX_CLUSTER_INPUT_BYTES: usize = 256 * 1024;
const MAX_NODES: usize = 128;
const MAX_LINK_OBSERVATIONS: usize = 256;
const MAX_LABEL_BYTES: usize = 160;
const MAX_URL_BYTES: usize = 2048;
const MAX_ID_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Person,
    Organisation,
    Domain,
    IpAddress,
    Asn,
    Netblock,
    PublicAccount,
    Document,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub id: String,
    pub kind: NodeKind,
    pub label: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Relation {
    DocumentedAssociation,
    PublishedTogether,
    DirectorOf,
    MemberOf,
    Uses,
    Owns,
    NamedIn,
    ReportedLink,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinkObservation {
    pub from_id: String,
    pub to_id: String,
    pub relation: Relation,
    /// Full original HTTPS URL, preserved verbatim in output.
    pub source_url: String,
    /// Original source dataset identifier, NOT merely a collecting service.
    pub source_root: String,
    /// Manually established evidence descriptors. They are never authentication.
    pub primary_record: bool,
    pub exact_identifier: bool,
    pub temporal_consistency: bool,
    pub contradicted: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseInput {
    nodes: Vec<Node>,
    links: Vec<LinkObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceReference {
    pub url: String,
    pub source_root: String,
    pub primary_record: bool,
    pub exact_identifier: bool,
    pub temporal_consistency: bool,
    pub contradicted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CitedRelation {
    pub from_id: String,
    pub to_id: String,
    pub relation: Relation,
    pub confidence_index: u8,
    pub score_type: &'static str,
    pub claimed_original_roots: usize,
    pub source_references: Vec<SourceReference>,
    pub state: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TraversalStep {
    pub node_id: String,
    pub hop: usize,
    pub reached_from: Option<String>,
    pub via_relation: Option<Relation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelationshipCluster {
    pub root_id: String,
    pub nodes: Vec<Node>,
    pub full_names: Vec<String>,
    pub source_cited_relations: Vec<CitedRelation>,
    pub traversal: Vec<TraversalStep>,
    pub highest_link_ci: Option<u8>,
    pub interpretation: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClusterReport {
    pub clusters: Vec<RelationshipCluster>,
    pub disputed_relations: Vec<CitedRelation>,
    pub non_connecting_leads: Vec<CitedRelation>,
    pub input_nodes: usize,
    pub unique_relationships: usize,
    pub duplicate_observations: usize,
    pub source_observations: usize,
    pub scope: &'static str,
    pub provenance_status: &'static str,
    pub recursive_policy: &'static str,
}

fn opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

fn validate_node(node: &Node) -> bool {
    if !opaque_id(&node.id)
        || node.label.is_empty()
        || node.label.len() > MAX_LABEL_BYTES
        || node.label.trim() != node.label
        || node.label.chars().any(char::is_control)
    {
        return false;
    }
    match node.kind {
        NodeKind::Person => {
            people_discovery::checked_name(&node.label).is_ok()
                && node.label.chars().all(|ch| {
                    ch.is_alphabetic() || matches!(ch, ' ' | '-' | '\'' | '’')
                })
        }
        NodeKind::Domain => canonical_domain(&node.label).is_some(),
        NodeKind::IpAddress => canonical_selector(ScanKind::Ip, &node.label).is_some(),
        NodeKind::Asn => canonical_selector(ScanKind::Asn, &node.label).is_some(),
        NodeKind::Netblock => canonical_selector(ScanKind::Netblock, &node.label).is_some(),
        NodeKind::PublicAccount => valid_public_source_url(&node.label),
        _ => true,
    }
}

/// Only HTTPS public-domain source links; no embedded auth, secret parameters,
/// URL truncation, or silent redaction of a source identifier.
fn valid_public_source_url(url: &str) -> bool {
    if url.len() > MAX_URL_BYTES
        || url.bytes().any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return false;
    }
    let Some(tail) = url.strip_prefix("https://") else {
        return false;
    };
    let authority = tail.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') || authority.contains('[') {
        return false;
    }
    let host = authority.split(':').next().unwrap_or("");
    if canonical_domain(host).is_none() {
        return false;
    }
    let lower = url.to_ascii_lowercase();
    for component in lower.split(['?', '&']) {
        let name = component.split('=').next().unwrap_or("");
        if matches!(
            name,
            "token" | "access_token" | "api_key" | "apikey" | "key" | "password"
                | "secret" | "auth" | "authorization" | "signature" | "sig"
        ) {
            return false;
        }
    }
    true
}

fn cited_relation(
    from_id: String,
    to_id: String,
    relation: Relation,
    refs: &[LinkObservation],
) -> Result<CitedRelation, &'static str> {
    let contradictory = refs.iter().any(|observation| observation.contradicted);
    let unique_roots: BTreeSet<_> = refs.iter().map(|item| item.source_root.as_str()).collect();
    if unique_roots.len() > 8 {
        return Err("relationship has more than eight claimed original dataset roots");
    }
    let input = FindingInput {
        id: "edge".to_owned(),
        exact_identifier: refs.iter().all(|item| item.exact_identifier),
        fuzzy_match: refs.iter().any(|item| !item.exact_identifier),
        primary_record: refs.iter().any(|item| item.primary_record),
        original_dataset_ids: unique_roots.iter().map(|root| (*root).to_owned()).collect(),
        temporal_consistency: refs.iter().all(|item| item.temporal_consistency),
        contradicted: contradictory,
    };
    // Input limits and validation guarantee that this has one valid record.
    let score = rank(vec![input])
        .map_err(|_| "relationship cannot be scored from the supplied evidence metadata")?
        .findings[0]
        .confidence_index;
    let mut sources: Vec<_> = refs
        .iter()
        .map(|item| SourceReference {
            url: item.source_url.clone(),
            source_root: item.source_root.clone(),
            primary_record: item.primary_record,
            exact_identifier: item.exact_identifier,
            temporal_consistency: item.temporal_consistency,
            contradicted: item.contradicted,
        })
        .collect();
    sources.sort_by(|a, b| {
        a.url
            .cmp(&b.url)
            .then_with(|| a.source_root.cmp(&b.source_root))
    });
    Ok(CitedRelation {
        from_id,
        to_id,
        relation,
        confidence_index: score,
        score_type: "uncalibrated_operator_asserted_evidence_quality",
        claimed_original_roots: unique_roots.len(),
        source_references: sources,
        state: if contradictory {
            "disputed_excluded_from_graph"
        } else {
            "explicit_source_claim_not_identity_verification"
        },
    })
}

/// Analyse exactly the supplied source-cited relationships, not inferred
/// account ownership, name similarity or breach coincidence. Connectivity is
/// undirected for traversal but recorded relation direction is preserved.
/// Contradicted relationships remain visible but cannot join two clusters.
///
/// # Errors
/// Refuses malformed, oversized, uncited, unreferenced or secret-bearing input.
#[allow(clippy::too_many_lines)]
pub fn analyze_json(bytes: &[u8]) -> Result<ClusterReport, &'static str> {
    if bytes.len() > MAX_CLUSTER_INPUT_BYTES {
        return Err("cluster input exceeds 256 KiB");
    }
    let input: CaseInput =
        serde_json::from_slice(bytes).map_err(|_| "invalid cluster JSON schema")?;
    if input.nodes.is_empty()
        || input.nodes.len() > MAX_NODES
        || input.links.len() > MAX_LINK_OBSERVATIONS
    {
        return Err("cluster input must contain 1..=128 nodes and at most 256 links");
    }

    let mut nodes = input.nodes;
    nodes.sort_by(|a, b| a.id.cmp(&b.id));
    if nodes
        .iter()
        .any(|node| !validate_node(node))
        || nodes.windows(2).any(|pair| pair[0].id == pair[1].id)
    {
        return Err("invalid or duplicate entity ID, name or label");
    }

    let ids: BTreeMap<&str, usize> = nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (node.id.as_str(), index))
        .collect();
    let mut grouped: BTreeMap<(String, String, Relation), Vec<LinkObservation>> = BTreeMap::new();
    let mut duplicate_observations = 0;
    let mut total_observations = 0;
    for link in input.links {
        if !ids.contains_key(link.from_id.as_str())
            || !ids.contains_key(link.to_id.as_str())
            || link.from_id == link.to_id
            || !opaque_id(&link.source_root)
            || !valid_public_source_url(&link.source_url)
        {
            return Err("relation requires distinct known entity IDs, source root and safe full public URL");
        }
        total_observations += 1;
        let key = (link.from_id.clone(), link.to_id.clone(), link.relation);
        let entries = grouped.entry(key).or_default();
        if entries.iter().any(|prior| prior == &link) {
            duplicate_observations += 1;
        } else {
            entries.push(link);
        }
    }
    let unique_relationships = grouped.len();
    let mut union_find = UnionFind::new(nodes.len());
    let mut admitted = Vec::new();
    let mut disputed = Vec::new();
    let mut non_connecting = Vec::new();
    for ((from_id, to_id, relation), evidence) in grouped {
        let observation = cited_relation(from_id, to_id, relation, &evidence)?;
        if observation.state == "disputed_excluded_from_graph" {
            disputed.push(observation);
        } else if matches!(
            relation,
            Relation::PublishedTogether | Relation::NamedIn | Relation::ReportedLink
        ) {
            let mut observation = observation;
            observation.state = "co_mention_or_generic_lead_not_connected";
            non_connecting.push(observation);
        } else {
            union_find.union(ids[observation.from_id.as_str()], ids[observation.to_id.as_str()]);
            admitted.push(observation);
        }
    }

    let mut clusters = Vec::new();
    for indices in union_find.groups() {
        let selected: BTreeSet<usize> = indices.iter().copied().collect();
        let cluster_nodes: Vec<_> = indices.iter().map(|&i| nodes[i].clone()).collect();
        let links: Vec<_> = admitted
            .iter()
            .filter(|edge| {
                selected.contains(&ids[edge.from_id.as_str()])
                    && selected.contains(&ids[edge.to_id.as_str()])
            })
            .cloned()
            .collect();
        let mut adjacency: BTreeMap<usize, Vec<(usize, Relation)>> = BTreeMap::new();
        for edge in &links {
            let a = ids[edge.from_id.as_str()];
            let b = ids[edge.to_id.as_str()];
            adjacency.entry(a).or_default().push((b, edge.relation));
            adjacency.entry(b).or_default().push((a, edge.relation));
        }
        for neighbors in adjacency.values_mut() {
            neighbors.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
            neighbors.dedup();
        }

        // Recursive breadth-first closure over all known links: no guesswork,
        // network lookups, or arbitrary hop limit beyond the input bounds.
        let root = indices[0];
        let mut seen = BTreeSet::new();
        let mut queue = VecDeque::new();
        let mut traversal = Vec::with_capacity(indices.len());
        queue.push_back((root, 0_usize, None, None));
        seen.insert(root);
        while let Some((node, hop, parent, via)) = queue.pop_front() {
            traversal.push(TraversalStep {
                node_id: nodes[node].id.clone(),
                hop,
                reached_from: parent.map(|i: usize| nodes[i].id.clone()),
                via_relation: via,
            });
            if let Some(neighbors) = adjacency.get(&node) {
                for &(next, relation) in neighbors {
                    if seen.insert(next) {
                        queue.push_back((next, hop + 1, Some(node), Some(relation)));
                    }
                }
            }
        }
        let full_names = cluster_nodes
            .iter()
            .filter(|node| node.kind == NodeKind::Person)
            .map(|node| node.label.clone())
            .collect();
        let highest_link_ci = links.iter().map(|edge| edge.confidence_index).max();
        clusters.push(RelationshipCluster {
            root_id: nodes[root].id.clone(),
            nodes: cluster_nodes,
            full_names,
            source_cited_relations: links,
            traversal,
            highest_link_ci,
            interpretation: "source-cited connected-component lead only; multi-hop reachability does not assert direct relationships, shared identity or wrongdoing",
        });
    }
    clusters.sort_by(|a, b| {
        b.highest_link_ci
            .cmp(&a.highest_link_ci)
            .then_with(|| a.root_id.cmp(&b.root_id))
    });
    Ok(ClusterReport {
        clusters,
        disputed_relations: disputed,
        non_connecting_leads: non_connecting,
        input_nodes: nodes.len(),
        unique_relationships,
        duplicate_observations,
        source_observations: total_observations,
        scope: "operator-supplied source references only; no external records collected",
        provenance_status: "all cited links are operator-asserted and have not been independently authenticated; claimed dataset roots are not proof of independent sources",
        recursive_policy: "complete bounded BFS traversal of explicit non-disputed links; no missing edge, namesake, common address or breach record is inferred",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, label: &str, kind: NodeKind) -> Node {
        Node { id: id.into(), kind, label: label.into() }
    }

    fn link(from: &str, to: &str, root: &str, url: &str) -> LinkObservation {
        LinkObservation {
            from_id: from.into(),
            to_id: to.into(),
            relation: Relation::DocumentedAssociation,
            source_root: root.into(),
            source_url: url.into(),
            primary_record: true,
            exact_identifier: true,
            temporal_consistency: true,
            contradicted: false,
        }
    }

    #[test]
    fn joins_explicit_links_recursively_and_preserves_complete_urls() {
        let case = CaseInput {
            nodes: vec![
                node("c-person", "Jane Mary Example", NodeKind::Person),
                node("b-company", "Example Organisation", NodeKind::Organisation),
                node("a-person", "Jordan Avery Example", NodeKind::Person),
            ],
            links: vec![
                link("a-person", "b-company", "registry-a", "https://example.org/records/director?id=123&year=2024"),
                link("b-company", "c-person", "registry-b", "https://example.net/records/association/456"),
            ],
        };
        let input = serde_json::json!({"nodes":case.nodes, "links":case.links});
        let result = analyze_json(input.to_string().as_bytes()).unwrap();
        assert_eq!(result.clusters.len(), 1);
        assert_eq!(result.clusters[0].full_names.len(), 2);
        assert_eq!(result.clusters[0].traversal.len(), 3);
        assert_eq!(result.clusters[0].traversal[2].hop, 2);
        assert_eq!(
            result.clusters[0].source_cited_relations[0].source_references[0].url,
            "https://example.org/records/director?id=123&year=2024"
        );
        assert!(result.clusters[0].interpretation.contains("does not assert"));
    }

    #[test]
    fn co_mentions_are_visible_but_cannot_create_relationship_clusters() {
        let mut weak = link("p1", "p2", "article-root", "https://example.org/news?id=7");
        weak.relation = Relation::PublishedTogether;
        let input = serde_json::json!({"nodes":[
            {"id":"p1","kind":"person","label":"Jordan Avery Example"},
            {"id":"p2","kind":"person","label":"Jane Mary Example"}
        ],"links":[weak]});
        let result = analyze_json(input.to_string().as_bytes()).unwrap();
        assert_eq!(result.clusters.len(), 2);
        assert_eq!(result.non_connecting_leads.len(), 1);
        assert!(result.non_connecting_leads[0].state.contains("not_connected"));
        assert_eq!(
            result.non_connecting_leads[0].source_references[0].url,
            "https://example.org/news?id=7"
        );
    }

    #[test]
    fn namesakes_do_not_merge_and_uncited_nodes_remain_isolated() {
        let input = serde_json::json!({"nodes":[
            {"id":"a","kind":"person","label":"Jane Mary Example"},
            {"id":"b","kind":"person","label":"Jane Mary Example"}
        ],"links":[]});
        let result = analyze_json(input.to_string().as_bytes()).unwrap();
        assert_eq!(result.clusters.len(), 2);
        assert!(result.clusters.iter().all(|cluster| cluster.highest_link_ci.is_none()));
    }

    #[test]
    fn contradiction_blocks_cluster_bridge_but_keeps_full_source() {
        let mut disputed = link("p1", "p2", "root-a", "https://example.org/disputed?id=7");
        disputed.contradicted = true;
        let input = serde_json::json!({"nodes":[
            {"id":"p1","kind":"person","label":"Jordan Avery Example"},
            {"id":"p2","kind":"person","label":"Jane Mary Example"}
        ],"links":[disputed]});
        let result = analyze_json(input.to_string().as_bytes()).unwrap();
        assert_eq!(result.clusters.len(), 2);
        assert_eq!(result.disputed_relations.len(), 1);
        assert!(result.disputed_relations[0].confidence_index <= 39);
        assert_eq!(result.disputed_relations[0].source_references[0].url, "https://example.org/disputed?id=7");
    }

    #[test]
    fn duplicates_and_same_original_dataset_never_count_as_independent_roots() {
        let a = link("p1","p2","shared-origin","https://example.org/a");
        let b = link("p1","p2","shared-origin","https://example.net/mirror");
        let input = serde_json::json!({"nodes":[
            {"id":"p1","kind":"person","label":"Jordan Avery Example"},
            {"id":"p2","kind":"person","label":"Jane Mary Example"}
        ],"links":[a.clone(), a, b]});
        let result = analyze_json(input.to_string().as_bytes()).unwrap();
        assert_eq!(result.duplicate_observations, 1);
        assert_eq!(result.source_observations, 3);
        assert_eq!(result.clusters[0].source_cited_relations[0].claimed_original_roots, 1);
        assert_eq!(result.clusters[0].source_cited_relations[0].source_references.len(), 2);
    }

    #[test]
    fn forbids_unknown_entities_untrusted_urls_and_secret_fields() {
        let nodes = serde_json::json!([{"id":"p1","kind":"person","label":"Jordan Avery Example"}]);
        let unknown = serde_json::json!({"nodes":nodes,"links":[{
            "from_id":"p1","to_id":"not-known","relation":"reported_link",
            "source_url":"https://example.org/","source_root":"root",
            "primary_record":true,"exact_identifier":true,
            "temporal_consistency":true,"contradicted":false
        }]});
        assert!(analyze_json(unknown.to_string().as_bytes()).is_err());
        for url in [
            "http://example.org/a",
            "https://example.org/a?token=secret",
            "https://user@example.org/data",
            "https://127.0.0.1/private",
        ] {
            assert!(!valid_public_source_url(url), "{url}");
        }
        let unknown_field = br#"{"nodes":[{"id":"p1","kind":"person","label":"Jordan Avery Example","password":"secret"}],"links":[]}"#;
        assert!(analyze_json(unknown_field).is_err());
    }
}
