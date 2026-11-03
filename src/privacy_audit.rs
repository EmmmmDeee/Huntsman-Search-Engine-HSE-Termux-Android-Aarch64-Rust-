//! Offline public-evidence privacy assessment. No networking, identity resolution or account access.
//! This complements breach exposure scoring; it does not reuse breach scores for public links.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Maximum bounded input, suitable for rootless Android userland.
pub const MAX_GRAPH_BYTES: u64 = 1024 * 1024;
const MAX_NODES: usize = 5000;
const MAX_EDGES: usize = 10000;

#[derive(Debug, Deserialize)]
struct Graph {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    source_definitions: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct Node {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    sources: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Edge {
    #[serde(rename = "from")]
    from: String,
    to: String,
    predicate: String,
    #[serde(default)]
    sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub category: &'static str,
    pub disciplines: &'static [&'static str],
    pub priority: &'static str,
    pub subjects: Vec<String>,
    pub source_ids: Vec<String>,
    pub observation: &'static str,
    pub countermeasure: &'static str,
    pub ownership_verified: bool,
    pub remediation_verified: bool,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub mode: &'static str,
    pub input_nodes: usize,
    pub input_edges: usize,
    pub source_definitions: usize,
    pub advertised_links: usize,
    pub findings: Vec<Finding>,
    pub not_assessed: Vec<&'static str>,
    pub identity_verified: bool,
    pub remediation_verified: bool,
}

fn add(
    findings: &mut Vec<Finding>,
    category: &'static str,
    disciplines: &'static [&'static str],
    priority: &'static str,
    subjects: Vec<String>,
    sources: BTreeSet<String>,
    observation: &'static str,
    countermeasure: &'static str,
) {
    findings.push(Finding {
        category,
        disciplines,
        priority,
        subjects,
        source_ids: sources.into_iter().collect(),
        observation,
        countermeasure,
        ownership_verified: false,
        remediation_verified: false,
    });
}

/// Validate and assess an explicitly supplied public-entity graph without network requests.
/// Only public disclosure indicators are emitted. An absent finding does not certify safety.
///
/// # Errors
/// Refuses oversized, malformed, dangling, duplicate or unsourced input.
pub fn assess_public_graph(input: &[u8]) -> Result<Report, String> {
    if input.len() > MAX_GRAPH_BYTES as usize {
        return Err("public graph exceeds 1 MiB".into());
    }
    let graph: Graph =
        serde_json::from_slice(input).map_err(|e| format!("invalid public graph: {e}"))?;
    if graph.nodes.len() > MAX_NODES || graph.edges.len() > MAX_EDGES {
        return Err("public graph exceeds entity or relationship limits".into());
    }
    let mut nodes = BTreeMap::new();
    for node in &graph.nodes {
        if node.id.trim().is_empty() || nodes.insert(node.id.as_str(), node).is_some() {
            return Err("missing or duplicate entity identifier".into());
        }
        if node.sources.is_empty()
            || node
                .sources
                .iter()
                .any(|s| !graph.source_definitions.contains_key(s))
        {
            return Err("entity has missing or unknown provenance".into());
        }
    }
    for edge in &graph.edges {
        if !nodes.contains_key(edge.from.as_str()) || !nodes.contains_key(edge.to.as_str()) {
            return Err("relationship references a missing entity".into());
        }
        if edge.sources.is_empty()
            || edge
                .sources
                .iter()
                .any(|s| !graph.source_definitions.contains_key(s))
        {
            return Err("relationship has missing or unknown provenance".into());
        }
    }

    let mut findings = Vec::new();
    let mut public_links: BTreeMap<&str, BTreeMap<&str, BTreeSet<String>>> = BTreeMap::new();
    let mut payment_targets = BTreeSet::new();
    let mut geo = BTreeSet::new();
    let mut geo_subjects = BTreeSet::new();
    let mut campaigns = BTreeSet::new();
    let mut media = BTreeSet::new();
    let mut claims = BTreeSet::new();
    let mut payment_sources: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    let mut campaign_sources: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    let mut media_sources: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    let mut claim_sources: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();

    for edge in &graph.edges {
        let target = nodes[edge.to.as_str()];
        match edge.predicate.as_str() {
            "publicly_links_to" => {
                public_links
                    .entry(&edge.from)
                    .or_default()
                    .entry(&edge.to)
                    .or_default()
                    .extend(edge.sources.iter().cloned());
            }
            "self_reports_location" | "platform_displays_location" => {
                geo_subjects.insert(edge.from.clone());
                geo_subjects.insert(edge.to.clone());
                geo.extend(edge.sources.iter().cloned());
            }
            "organises" if target.kind == "fundraising_campaign" => {
                campaigns.insert(edge.to.as_str());
                campaign_sources
                    .entry(&edge.to)
                    .or_default()
                    .extend(edge.sources.iter().cloned());
            }
            "contains_media" if target.kind == "media_collection" => {
                media.insert(edge.to.as_str());
                media_sources
                    .entry(&edge.to)
                    .or_default()
                    .extend(edge.sources.iter().cloned());
            }
            "publishes_claim" if target.kind == "self_reported_relationship_claim" => {
                claims.insert(edge.to.as_str());
                claim_sources
                    .entry(&edge.to)
                    .or_default()
                    .extend(edge.sources.iter().cloned());
            }
            _ => {}
        }
        if matches!(
            target.kind.as_str(),
            "payment_handle" | "advertised_payment_handle"
        ) && matches!(
            edge.predicate.as_str(),
            "publicly_links_to" | "advertises_identifier"
        ) {
            payment_targets.insert(edge.to.as_str());
            payment_sources
                .entry(&edge.to)
                .or_default()
                .extend(edge.sources.iter().cloned());
        }
    }

    let advertised_links = public_links.values().map(BTreeMap::len).sum();
    for (source, dests) in &public_links {
        if dests.len() >= 2 {
            let refs = dests.values().flat_map(|ids| ids.iter().cloned()).collect();
            let subjects = std::iter::once((*source).to_string())
                .chain(dests.keys().map(|s| (*s).to_string()))
                .collect();
            add(
                &mut findings,
                "public_account_correlation",
                &["OSINT", "SOCMINT"],
                "P2",
                subjects,
                refs,
                "One public account hub explicitly links multiple destinations; shared legal ownership is not established.",
                "The authorised account owner can remove unnecessary cross-links and separate unrelated public personas.",
            );
        }
    }
    for target in payment_targets {
        add(
            &mut findings,
            "payment_alias_visibility",
            &["FININT", "OSINT"],
            "P2",
            vec![target.to_string()],
            payment_sources.remove(target).unwrap_or_default(),
            "A payment alias is publicly advertised, but account ownership and transaction visibility have not been established.",
            "The authorised owner can review recipient display names and segregate payment accounts where necessary.",
        );
    }
    if !geo.is_empty() {
        add(
            &mut findings,
            "geographic_statement",
            &["GEOINT", "OSINT"],
            "P2",
            geo_subjects.into_iter().collect(),
            geo,
            "Public geographic statements were observed; they do not prove current residence or whereabouts.",
            "The authorised publisher can remove unnecessarily specific location disclosures.",
        );
    }
    for target in campaigns {
        add(
            &mut findings,
            "public_fundraiser",
            &["OSINT", "SOCMINT", "FININT"],
            "P2",
            vec![target.to_string()],
            campaign_sources.remove(target).unwrap_or_default(),
            "A public fundraising campaign is associated with a linked organiser; the event and beneficiary are unverified.",
            "The campaign administrator can review public story details and media for unnecessary disclosure.",
        );
    }
    for target in media {
        add(
            &mut findings,
            "public_media",
            &["IMINT"],
            "P3",
            vec![target.to_string()],
            media_sources.remove(target).unwrap_or_default(),
            "Public media exists; embedded metadata and visible location cues were not evaluated.",
            "The publisher can inspect photo metadata and visual context before publication.",
        );
    }
    for target in claims {
        add(
            &mut findings,
            "social_statement",
            &["HUMINT", "SOCMINT"],
            "P3",
            vec![target.to_string()],
            claim_sources.remove(target).unwrap_or_default(),
            "A self-reported biographical statement is publicly visible; its truth is unverified.",
            "Minimise unnecessary personal statements and verify unsolicited requests out of band.",
        );
    }
    Ok(Report {
        mode: "OFFLINE_EXISTING_PUBLIC_EVIDENCE_ONLY",
        input_nodes: graph.nodes.len(),
        input_edges: graph.edges.len(),
        source_definitions: graph.source_definitions.len(),
        advertised_links,
        findings,
        not_assessed: vec![
            "SIGINT", "MASINT", "CYBINT", "TECHINT", "AUTHSEC", "EMAIL", "SNAPCHAT",
        ],
        identity_verified: false,
        remediation_verified: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "source_definitions": {"S1": {"url":"https://example.org"}},
            "nodes": [
                {"id":"hub","type":"link_hub","sources":["S1"]},
                {"id":"social","type":"social_profile","sources":["S1"]},
                {"id":"pay","type":"payment_handle","sources":["S1"]},
                {"id":"geo","type":"stated_region","sources":["S1"]}
            ],
            "edges": [
                {"from":"hub","to":"social","predicate":"publicly_links_to","sources":["S1"]},
                {"from":"hub","to":"pay","predicate":"publicly_links_to","sources":["S1"]},
                {"from":"hub","to":"geo","predicate":"self_reports_location","sources":["S1"]}
            ]
        }))
        .unwrap()
    }

    #[test]
    fn public_links_do_not_verify_identity_or_ownership() {
        let report = assess_public_graph(&fixture()).unwrap();
        assert_eq!(report.advertised_links, 2);
        assert_eq!(report.findings.len(), 3);
        assert!(report.findings.iter().all(|f| !f.ownership_verified));
        assert!(!report.identity_verified);
        assert!(!report.remediation_verified);
    }

    #[test]
    fn missing_entity_and_provenance_fail_closed() {
        let mut value: serde_json::Value = serde_json::from_slice(&fixture()).unwrap();
        value["edges"][0]["to"] = serde_json::json!("missing");
        assert!(assess_public_graph(value.to_string().as_bytes()).is_err());
        value["edges"][0]["to"] = serde_json::json!("social");
        value["edges"][0]["sources"] = serde_json::json!(["unknown"]);
        assert!(assess_public_graph(value.to_string().as_bytes()).is_err());
    }

    #[test]
    fn no_evidence_does_not_create_an_exposure_or_clearance() {
        let input = br#"{"nodes":[],"edges":[],"source_definitions":{}}"#;
        let report = assess_public_graph(input).unwrap();
        assert!(report.findings.is_empty());
        assert!(report.not_assessed.contains(&"SIGINT"));
        assert!(!report.identity_verified);
    }

    #[test]
    fn duplicate_links_do_not_inflate_correlation() {
        let mut value: serde_json::Value = serde_json::from_slice(&fixture()).unwrap();
        let first_edge = value["edges"][0].clone();
        value["edges"].as_array_mut().unwrap().push(first_edge);
        let report = assess_public_graph(value.to_string().as_bytes()).unwrap();
        assert_eq!(report.advertised_links, 2);
        assert_eq!(report.findings.len(), 3);
    }
}
