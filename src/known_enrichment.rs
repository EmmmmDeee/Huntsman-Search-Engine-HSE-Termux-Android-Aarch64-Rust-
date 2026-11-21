//! Offline, provenance-gated expansion planning from an existing recursive report.
//! Does not make network requests, infer personal identifiers or change claims.

use std::collections::BTreeSet;
use serde::{Deserialize, Serialize};

use crate::canonical::canonical_domain;
use crate::scan_route::{canonical_selector, ScanKind};
use crate::tags;

pub const MAX_REPORT_BYTES: u64 = 1024 * 1024;
const MAX_ENTITIES: usize = 1024;
const MAX_PROPOSALS: usize = 128;

#[derive(Debug, Deserialize)]
struct Seed {
    kind: String,
    selector: String,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    source: String,
}

#[derive(Debug, Deserialize)]
struct Observation {
    provenance: Provenance,
    #[serde(default)]
    is_inferred: bool,
}

#[derive(Debug, Deserialize)]
struct Entity {
    kind: String,
    value: String,
    #[serde(default)]
    evidence: Vec<Observation>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Edge {
    from_kind: String,
    from_selector: String,
}

#[derive(Debug, Deserialize)]
struct RecursiveReport {
    accepted: Vec<Seed>,
    entities: Vec<Entity>,
    #[serde(default)]
    lineage: Vec<Edge>,
    #[serde(default)]
    truncated: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct NextCheck {
    pub kind: &'static str,
    pub selector: String,
    pub priority: u8,
    pub confidence_index: Option<u8>,
    pub observed_source_count: usize,
    pub state: &'static str,
    pub next_step: &'static str,
}

#[derive(Debug, Serialize)]
pub struct EnrichmentPlan {
    pub input_entities: usize,
    pub considered_public_identifiers: usize,
    pub excluded_unobserved_or_inferred: usize,
    pub excluded_name_leads: usize,
    pub excluded_nonpublic_identifiers: usize,
    pub already_seen_in_lineage: usize,
    pub candidates: Vec<NextCheck>,
    pub truncated: bool,
    pub status: &'static str,
    pub limitation: &'static str,
}

fn route(kind: &str, raw: &str) -> Option<(&'static str, String)> {
    // Public infrastructure only. No personal identifiers or breach-derived
    // accounts automatically expand the frontier.
    if kind.eq_ignore_ascii_case("domain") {
        return canonical_domain(raw).map(|name| ("domain", name));
    }
    if kind.eq_ignore_ascii_case("ipaddress") || kind.eq_ignore_ascii_case("ip_address") {
        return canonical_selector(ScanKind::Ip, raw).map(|addr| ("ip", addr));
    }
    if kind.eq_ignore_ascii_case("asn") {
        return canonical_selector(ScanKind::Asn, raw).map(|asn| ("asn", asn));
    }
    if kind.eq_ignore_ascii_case("netblock") {
        return canonical_selector(ScanKind::Netblock, raw).map(|block| ("netblock", block));
    }
    None
}

fn source_observed(source: &str) -> bool {
    // A collector label is NOT authentication or source-independence proof.
    let source = source.to_ascii_lowercase();
    !source.is_empty()
        && !matches!(source.as_str(),
            "seed" | "operator_input" | "recall" | "cross_scan_history"
            | "breach_consensus" | "multipath_corroboration")
        && !["dehashed", "oathnet", "stolen_tax", "stolen.tax", "hibp", "leakcheck"]
            .iter()
            .any(|marker| source.contains(marker))
}

/// Return only the exact, source-observed public infrastructure selectors
/// not already recorded as scanned. Never dispatch a network request.
///
/// # Errors
/// Rejects malformed or oversized reports without pretending they are complete.
pub fn enrich_json(bytes: &[u8]) -> Result<EnrichmentPlan, &'static str> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_REPORT_BYTES {
        return Err("recursive report exceeds 1 MiB");
    }
    let input: RecursiveReport = serde_json::from_slice(bytes)
        .map_err(|_| "recursive report schema is invalid")?;
    if input.entities.len() > MAX_ENTITIES || input.accepted.len() > 64 || input.lineage.len() > 4096 {
        return Err("recursive report exceeds bounded entity or lineage limits");
    }
    let mut visited = BTreeSet::new();
    for seed in &input.accepted {
        visited.insert((seed.kind.to_ascii_lowercase(), seed.selector.to_ascii_lowercase()));
    }
    for edge in &input.lineage {
        visited.insert((edge.from_kind.to_ascii_lowercase(), edge.from_selector.to_ascii_lowercase()));
    }
    let mut unique = BTreeSet::new();
    let mut plan = EnrichmentPlan {
        input_entities: input.entities.len(),
        considered_public_identifiers: 0,
        excluded_unobserved_or_inferred: 0,
        excluded_name_leads: 0,
        excluded_nonpublic_identifiers: 0,
        already_seen_in_lineage: 0,
        candidates: Vec::new(),
        truncated: input.truncated,
        status: "source_observed_candidates_not_verified",
        limitation: "Offline proposals require scope review before network execution; collector names do not prove independent origins; namesakes never expand; CI is undefined without reviewed metadata. Lineage may omit zero-hit dispatches.",
    };
    for entity in input.entities {
        if entity.tags.iter().any(|tag| tag == tags::NAME_SEARCH_LEAD || tag == "wikidata-name-lead") {
            plan.excluded_name_leads += 1;
            continue;
        }
        let Some((kind, selector)) = route(&entity.kind, &entity.value) else {
            plan.excluded_nonpublic_identifiers += 1;
            continue;
        };
        plan.considered_public_identifiers += 1;
        let observed_sources: BTreeSet<&str> = entity.evidence.iter()
            .filter(|e| !e.is_inferred && source_observed(&e.provenance.source))
            .map(|e| e.provenance.source.as_str()).collect();
        if observed_sources.is_empty() {
            plan.excluded_unobserved_or_inferred += 1;
            continue;
        }
        if visited.contains(&(kind.to_owned(), selector.to_ascii_lowercase())) {
            plan.already_seen_in_lineage += 1;
            continue;
        }
        if !unique.insert((kind, selector.clone())) {
            continue;
        }
        if plan.candidates.len() >= MAX_PROPOSALS {
            plan.truncated = true;
            continue;
        }
        let (priority, next_step) = match kind {
            "domain" => (95, "Check public DNS, RDAP, CT and source-specific archives"),
            "ip" => (80, "Check public IP RDAP, ASN and passive DNS chronology"),
            "asn" => (70, "Check registry, announced prefix history and origin"),
            _ => (60, "Check public routing and registration evidence"),
        };
        plan.candidates.push(NextCheck {
            kind,
            selector,
            priority,
            confidence_index: None,
            observed_source_count: observed_sources.len(),
            state: "source_observed_unverified",
            next_step,
        });
    }
    plan.candidates.sort_by(|a, b| {
        b.priority.cmp(&a.priority).then_with(|| a.kind.cmp(b.kind))
            .then_with(|| a.selector.cmp(&b.selector))
    });
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_source_observed_public_identifiers_expand() {
        let input = r#"{"accepted":[{"kind":"people","selector":"A Person"}],
          "entities":[
            {"kind":"Domain","value":"Example.org","evidence":[{"provenance":{"source":"dns"}}]},
            {"kind":"Email","value":"private@example.org","evidence":[{"provenance":{"source":"dehashed"}}]},
            {"kind":"Domain","value":"guessed.org","evidence":[{"is_inferred":true,"provenance":{"source":"dns"}}]},
            {"kind":"Domain","value":"leak.example.org","evidence":[{"provenance":{"source":"dehashed"}}]},
            {"kind":"Domain","value":"name.example.org","tags":["name-search-lead"],"evidence":[{"provenance":{"source":"dns"}}]}
          ]}"#;
        let result = enrich_json(input.as_bytes()).unwrap();
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.candidates[0].selector, "example.org");
        assert_eq!(result.candidates[0].confidence_index, None);
        assert_eq!(result.excluded_nonpublic_identifiers, 1);
    }

    #[test]
    fn previously_scanned_selector_is_not_requeued() {
        let input = r#"{"accepted":[{"kind":"domain","selector":"example.org"}],
          "entities":[{"kind":"Domain","value":"example.org","evidence":[{"provenance":{"source":"dns"}}]}]}"#;
        let result = enrich_json(input.as_bytes()).unwrap();
        assert!(result.candidates.is_empty());
        assert_eq!(result.already_seen_in_lineage, 1);
    }

    #[test]
    fn rejects_partial_or_unstructured_content() {
        assert!(enrich_json(b"{}").is_err());
        assert!(enrich_json(&vec![0u8; MAX_REPORT_BYTES as usize + 1]).is_err());
    }
}
