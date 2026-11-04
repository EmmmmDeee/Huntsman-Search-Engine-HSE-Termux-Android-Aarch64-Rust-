//! Bounded, read-only OSINT acquisition gaps from one immutable entity snapshot.
//!
//! A *different modality* is NOT an independent evidence route. Collector categories
//! are used only to propose a check; claims, graph links, confidence and automatic
//! identity merging are never modified. The ancestry authority alone can prove
//! source independence. No network requests or additional runtime dependencies.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::correlator::source_family;
use crate::entity::{Entity, EntityKind};
use crate::evidence_ancestry::{
    DEFAULT_INDEPENDENCE_SEARCH_STATES, EvidenceAncestryGraph, EvidenceNodeId,
};
use crate::lineage::Lineage;

/// Cap proposals on resource-constrained, unprivileged Android devices.
pub const MAX_OPPORTUNITIES: usize = 192;
const MAX_ANCESTRY_IDS: usize = 64;

#[derive(Debug, Clone, Copy)]
struct Probe {
    modality: &'static str,
    check: &'static str,
}

/// This is an acquisition *hypothesis* catalogue, not a source capability
/// assertion. The correlator taxonomy is the default. A narrow, explicit
/// acquisition-only adapter recognises newer live collectors without changing
/// the global corroboration categories or their identity rules.
const DOMAIN: &[Probe] = &[
    Probe {
        modality: "infra",
        check: "Cross-check DNS, certificate transparency and RDAP primary records.",
    },
    Probe {
        modality: "code",
        check: "Check public code and package metadata for independently sourced domain references.",
    },
    Probe {
        modality: "search",
        check: "Check indexed and archived public pages, retaining original capture URLs and dates.",
    },
];
const EMAIL: &[Probe] = &[
    Probe {
        modality: "breach",
        check: "Check authorised breach notifications; keep mirrors of one corpus in one upstream family.",
    },
    Probe {
        modality: "email_intel",
        check: "Check published mail records and public-key metadata, not address-owner inference.",
    },
    Probe {
        modality: "code",
        check: "Check public code metadata for exact-address references, not username similarity.",
    },
];
const USERNAME: &[Probe] = &[
    Probe {
        modality: "code",
        check: "Check public code accounts; equal handles alone do not prove shared ownership.",
    },
    Probe {
        modality: "forum",
        check: "Check publicly accessible forum profiles for explicit cross-links.",
    },
    Probe {
        modality: "social",
        check: "Check public social profiles for independently verifiable links.",
    },
    Probe {
        modality: "human_public",
        check: "Review attributable published interviews and public statements for explicit account cross-links; no impersonation or elicitation.",
    },
    Probe {
        modality: "presence",
        check: "Check platform existence without turning existence into an identity match.",
    },
];
const ORG: &[Probe] = &[
    Probe {
        modality: "knowledge_graph",
        check: "Check source-attributed public knowledge-graph identifiers; community claims are not official registry records.",
    },
    Probe {
        modality: "identity_registry",
        check: "Check relevant authoritative business or organisation register identifiers.",
    },
    Probe {
        modality: "search",
        check: "Check dated public announcements and archives for the same legal identifier.",
    },
    Probe {
        modality: "code",
        check: "Check public package or repository publisher metadata, not name alone.",
    },
];
const IP: &[Probe] = &[
    Probe {
        modality: "infra",
        check: "Cross-check live authorised RDAP, BGP and passive DNS, recording each observation date.",
    },
    Probe {
        modality: "search",
        check: "Check public historical indexes; old IP attribution is not current ownership.",
    },
];
const PERSON: &[Probe] = &[
    Probe {
        modality: "knowledge_graph",
        check: "Cross-check explicitly sourced public knowledge-graph statements; namesakes and community assertions do not establish identity.",
    },
    Probe {
        modality: "identity_registry",
        check: "Check publicly available authoritative records with exact identifiers.",
    },
    Probe {
        modality: "search",
        check: "Check dated public records without treating namesakes as the same person.",
    },
    Probe {
        modality: "human_public",
        check: "Review dated, published statements or consensually supplied interviews; names alone cannot establish identity.",
    },
];
const COORDINATES: &[Probe] = &[
    Probe {
        modality: "geoint",
        check: "Compare geocoding and satellite-scene metadata with footprint, capture time and uncertainty; scenes do not identify people.",
    },
    Probe {
        modality: "transport",
        check: "Review dated public transport or aircraft observations as environmental context; proximity is not participation.",
    },
    Probe {
        modality: "netint",
        check: "Assess public network coverage and infrastructure geography coarsely; never infer subscriber or device location.",
    },
    Probe {
        modality: "rf",
        check: "Compare consented Wi-Fi and cellular observations with measurement time and accuracy; no passive person tracking.",
    },
    Probe {
        modality: "search",
        check: "Cross-check public local records and archives with dates and area bounds; location coincidence is not identity proof.",
    },
];
const RF: &[Probe] = &[Probe {
    modality: "rf",
    check: "Compare consented radio observations with their acquisition and freshness evidence; never infer location from a cache.",
}];

/// A more granular *acquisition* modality than the corroborator's family.
/// Keeping this adapter local avoids silently changing identity/correlation
/// rules that consume `correlator::source_family` for different purposes.
/// Exact IDs are the canonical live collector IDs, never user-supplied
/// `provenance.source_family` labels. Neither a collector ID nor a modality
/// proves that evidence is true or independent.
fn acquisition_modality(source: &str) -> &'static str {
    match source.trim().to_ascii_lowercase().as_str() {
        // Official registries and regulatory filing clients are source
        // modalities only; their lineage is NOT authenticated by this tag.
        "acnc" | "sec_edgar" | "gleif" | "asic_persons" | "asic_orgs" | "abn_lookup" => {
            "identity_registry"
        }
        // Wikidata is community-curated: never mislabel it as an official
        // identity registry or an independent identity proof.
        "wikidata" => "knowledge_graph",
        // GEOINT and transport source categories are acquisition hints, never
        // evidence of identity, co-presence or an operator's location.
        "nominatim" | "stac" => "geoint",
        "opensky" => "transport",
        "peeringdb" | "rdap" | "rdap_legs" | "dns" | "crtsh" | "certspotter" | "bgpview"
        | "dnsbl" => "infra",
        "wayback_cdx" | "common_crawl" | "archived_page" | "web_query" | "public_osint"
        | "bing" | "brave" | "mojeek" => "search",
        "gitlab_user" | "github_repos" | "docker_hub_user" | "codeberg_user"
        | "huggingface_user" | "codewars_user" => "code",
        "bluesky_user" | "mastodon_user" | "atproto" | "tiktok_public_contact" | "keybase" => {
            "social"
        }
        "wifi_radar" | "cell_radar" | "opencellid" => "rf",
        "xposedornot" => "breach",
        _ => source_family(source),
    }
}

fn probes(kind: &EntityKind) -> &'static [Probe] {
    match kind {
        EntityKind::Domain | EntityKind::Url => DOMAIN,
        EntityKind::Email => EMAIL,
        EntityKind::Username => USERNAME,
        EntityKind::Organisation | EntityKind::AbnAcn => ORG,
        EntityKind::IpAddress | EntityKind::Asn | EntityKind::Netblock => IP,
        EntityKind::Person => PERSON,
        EntityKind::Coordinates => COORDINATES,
        EntityKind::MacAddress | EntityKind::Ssid => RF,
        _ => &[],
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OrthogonalOpportunity {
    pub entity_uid: String,
    pub entity_kind: String,
    /// Acquisition modality derived from canonical collector IDs, not independently proven origins.
    pub observed_modalities: Vec<String>,
    pub missing_modality: &'static str,
    pub suggested_check: &'static str,
    /// Explicit dataset/registry lineage only; no collector-name independence.
    pub declared_upstream_families: Vec<String>,
    pub observed_collector_count: usize,
    /// Never inferred from distinct collectors or distinct modalities.
    pub proven_independent_routes: usize,
    pub independence_status: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OrthogonalReport {
    pub entities_examined: usize,
    pub eligible_entities: usize,
    pub opportunities: Vec<OrthogonalOpportunity>,
    pub omitted_opportunities: usize,
    pub truncated: bool,
    pub qualification: &'static str,
}

struct EvidenceSummary {
    kind: EntityKind,
    modalities: BTreeSet<&'static str>,
    collectors: BTreeSet<String>,
    upstream: BTreeSet<String>,
    ancestry_ids: BTreeSet<EvidenceNodeId>,
}

fn proof_status(
    ancestry: &EvidenceAncestryGraph,
    support: &BTreeSet<EvidenceNodeId>,
) -> (usize, &'static str) {
    if support.is_empty() {
        return (0, "not_recorded");
    }
    if support.len() > MAX_ANCESTRY_IDS {
        return (0, "budget_exceeded");
    }
    match ancestry.proven_independent_route_count(
        support.iter(),
        2,
        DEFAULT_INDEPENDENCE_SEARCH_STATES,
    ) {
        Ok(result) if result.incomplete => (result.proven, "bounded_incomplete"),
        Ok(result) if result.proven >= 2 => (result.proven, "proven"),
        Ok(result) => (result.proven, "not_proven"),
        Err(_) => (0, "invalid_or_missing_ancestry"),
    }
}

/// Recommend missing acquisition modalities without changing any observation.
///
/// - An inferred record is never treated as a source observation.
/// - Collector labels never establish source independence.
/// - Proposals are advisory and cannot auto-fetch data or promote evidence.
/// - Results are deterministic, de-duplicated by entity UID and bounded.
/// - A truncated source scan remains explicitly incomplete.
#[must_use]
pub fn discover(entities: &[Entity], ancestry: &EvidenceAncestryGraph) -> OrthogonalReport {
    let mut grouped = BTreeMap::<String, EvidenceSummary>::new();
    for entity in entities {
        if probes(&entity.kind).is_empty() {
            continue;
        }
        let entry = grouped
            .entry(entity.uid.clone())
            .or_insert_with(|| EvidenceSummary {
                kind: entity.kind.clone(),
                modalities: BTreeSet::new(),
                collectors: BTreeSet::new(),
                upstream: BTreeSet::new(),
                ancestry_ids: BTreeSet::new(),
            });
        for evidence in &entity.evidence {
            if evidence.is_inferred {
                continue;
            }
            let lineage = Lineage::of(evidence);
            let collector = evidence.provenance.corroboration_key();
            let classified = acquisition_modality(&evidence.provenance.source);
            // The ABR collector is admitted only through the existing verified
            // registry lineage gate, never through a user-written family label.
            let family = if classified == "other"
                && matches!(
                    lineage,
                    Lineage::Upstream {
                        kind: crate::lineage::UpstreamKind::Registry,
                        ..
                    }
                ) {
                "identity_registry"
            } else {
                classified
            };
            // "other" includes synthetic seeds and unsupported collectors.
            if family == "other" {
                continue;
            }
            entry.collectors.insert(collector);
            entry.modalities.insert(family);
            if let Some(upstream) = lineage.family() {
                entry.upstream.insert(upstream.to_owned());
            }
            if let Some(node) = &evidence.ancestry_node {
                entry.ancestry_ids.insert(node.clone());
            }
        }
    }

    let eligible_entities = grouped.len();
    let mut opportunities = Vec::new();
    let mut omitted_opportunities = 0usize;
    for (uid, summary) in grouped {
        let (proven, status) = proof_status(ancestry, &summary.ancestry_ids);
        for probe in probes(&summary.kind) {
            if summary.modalities.contains(probe.modality) {
                continue;
            }
            if opportunities.len() == MAX_OPPORTUNITIES {
                omitted_opportunities += 1;
                continue;
            }
            opportunities.push(OrthogonalOpportunity {
                entity_uid: uid.clone(),
                entity_kind: summary.kind.to_string(),
                observed_modalities: summary.modalities.iter().map(|s| (*s).to_owned()).collect(),
                missing_modality: probe.modality,
                suggested_check: probe.check,
                declared_upstream_families: summary.upstream.iter().cloned().collect(),
                observed_collector_count: summary.collectors.len(),
                proven_independent_routes: proven,
                independence_status: status,
            });
        }
    }
    OrthogonalReport {
        entities_examined: entities.len(),
        eligible_entities,
        opportunities,
        omitted_opportunities,
        truncated: omitted_opportunities > 0,
        qualification: "Missing modality means no eligible observation was recorded, not that a source was searched or an entity was absent. Distinct modalities and collector counts are not independent corroboration.",
    }
}
