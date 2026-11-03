//! Bounded, provenance-aware joins between different OSINT artefact families.
//! An edge is an investigation lead, never proof of ownership or identity.
//! A matching target observed by another source is not confirmation of the
//! relationship itself. This distinction is part of the serialized contract.

use std::collections::BTreeMap;
use serde::Serialize;

use crate::canonical::{canonical_asn, canonical_domain, canonical_ip_literal};
use crate::entity::{Entity, EntityKind, Evidence, is_non_corroborating_source};

const MAX_ENTITIES: usize = 512;
const MAX_EVIDENCE_PER_ENTITY: usize = 32;
const MAX_VALUES_PER_ATTRIBUTE: usize = 16;
const MAX_LINKS: usize = 256;

/// Whether the target itself was observed by a different source family.
/// Neither status establishes that the claimed relationship is true.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinStatus {
    SourceClaimOnly,
    IndependentlyObservedTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SynergyLink {
    pub from_uid: String,
    pub to_uid: String,
    pub relation: &'static str,
    pub attribute: &'static str,
    pub source: String,
    pub target_source: Option<String>,
    pub source_scan_id: Option<String>,
    pub target_scan_id: Option<String>,
    pub status: JoinStatus,
    pub interpretation: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SynergyReport {
    pub links: Vec<SynergyLink>,
    pub examined_entities: usize,
    pub truncated: bool,
    pub evidence_policy: &'static str,
}

fn eligible(evidence: &Evidence) -> bool {
    !evidence.is_inferred
        && !evidence.is_operator_seed()
        && !is_non_corroborating_source(&evidence.provenance.corroboration_key())
}

fn target_observation<'a>(
    target: &'a Entity,
    source_family: &str,
) -> Option<&'a Evidence> {
    target
        .evidence
        .iter()
        .take(MAX_EVIDENCE_PER_ENTITY)
        .find(|evidence| {
            eligible(evidence)
                && evidence.provenance.corroboration_key() != source_family
        })
}

/// Attribute contracts already emitted by Huntsman collectors.
/// Never parse prose or usernames as relationship claims.
fn attributes(kind: &EntityKind) -> &'static [(&'static str, EntityKind, &'static str)] {
    match kind {
        EntityKind::Domain => &[
            ("ip", EntityKind::IpAddress, "reported_dns_address"),
            ("ipv4", EntityKind::IpAddress, "reported_dns_address"),
            ("ipv6", EntityKind::IpAddress, "reported_dns_address"),
            ("hostname", EntityKind::Domain, "reported_hostname"),
        ],
        EntityKind::IpAddress => &[
            ("asn", EntityKind::Asn, "reported_routing_asn"),
            ("hostname", EntityKind::Domain, "reported_reverse_hostname"),
        ],
        _ => &[],
    }
}

fn normalize(kind: &EntityKind, value: &str) -> Option<String> {
    match kind {
        EntityKind::IpAddress => canonical_ip_literal(value),
        EntityKind::Domain => canonical_domain(value),
        EntityKind::Asn => canonical_asn(value),
        _ => None,
    }
}

/// Cross-reference concrete source attributes with independently collected
/// entities. Only emits bounded *leads*; never appends derived evidence or
/// increments any entity's corroboration/confidence.
///
/// This is a pure, deterministic pass over the supplied snapshot.
#[must_use]
pub fn discover(entities: &[Entity]) -> SynergyReport {
    let inspected = &entities[..entities.len().min(MAX_ENTITIES)];
    let mut truncated = entities.len() > MAX_ENTITIES;
    let mut index: BTreeMap<(EntityKind, String), Vec<&Entity>> = BTreeMap::new();
    for entity in inspected {
        if let Some(value) = normalize(&entity.kind, &entity.value) {
            index.entry((entity.kind.clone(), value)).or_default().push(entity);
        }
    }
    let mut links: BTreeMap<(String, String, &'static str), SynergyLink> = BTreeMap::new();
    'entities: for entity in inspected {
        if entity.evidence.len() > MAX_EVIDENCE_PER_ENTITY {
            truncated = true;
        }
        for evidence in entity.evidence.iter().take(MAX_EVIDENCE_PER_ENTITY) {
            if !eligible(evidence) {
                continue;
            }
            let family = evidence.provenance.corroboration_key();
            for &(attribute, ref target_kind, relation) in attributes(&entity.kind) {
                for value in evidence.attr_values(attribute).take(MAX_VALUES_PER_ATTRIBUTE) {
                    let Some(normalized) = normalize(target_kind, value) else {
                        continue;
                    };
                    let Some(targets) = index.get(&(target_kind.clone(), normalized)) else {
                        continue;
                    };
                    for target in targets {
                        if target.uid == entity.uid {
                            continue;
                        }
                        let independent = target_observation(target, &family);
                        let key = (entity.uid.clone(), target.uid.clone(), relation);
                        let new_link = SynergyLink {
                            from_uid: entity.uid.clone(),
                            to_uid: target.uid.clone(),
                            relation,
                            attribute,
                            source: evidence.provenance.source.clone(),
                            target_source: independent.map(|item| item.provenance.source.clone()),
                            source_scan_id: evidence.provenance.scan_id.clone(),
                            target_scan_id: independent.and_then(|item| item.provenance.scan_id.clone()),
                            status: if independent.is_some() {
                                JoinStatus::IndependentlyObservedTarget
                            } else {
                                JoinStatus::SourceClaimOnly
                            },
                            interpretation: "discovery lead only; relationship not independently verified",
                        };
                        match links.entry(key) {
                            std::collections::btree_map::Entry::Occupied(mut entry) => {
                                if entry.get().status == JoinStatus::SourceClaimOnly
                                    && new_link.status == JoinStatus::IndependentlyObservedTarget
                                {
                                    entry.insert(new_link);
                                }
                            }
                            std::collections::btree_map::Entry::Vacant(entry) => {
                                if links.len() >= MAX_LINKS {
                                    truncated = true;
                                    break 'entities;
                                }
                                entry.insert(new_link);
                            }
                        }
                    }
                }
            }
        }
    }
    SynergyReport {
        links: links.into_values().collect(),
        examined_entities: inspected.len(),
        truncated,
        evidence_policy: "derived leads only; no change to entity confidence, evidence or verification",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{EvidenceProvenance, Entity};

    fn observed(kind: EntityKind, value: &str, source: &str, scan: &str) -> Entity {
        let mut entity = Entity::new(kind, value, 0.8, scan);
        entity.add_evidence(Evidence::new(
            EvidenceProvenance::for_scan(source, scan),
            "collected observation",
        ));
        entity
    }

    #[test]
    fn cross_source_join_is_a_lead_not_a_verified_relation() {
        let mut domain = observed(EntityKind::Domain, "example.org", "dns", "scan-a");
        domain.add_evidence(
            Evidence::new(EvidenceProvenance::for_scan("dns", "scan-a"), "A record")
                .with_attr("ip", "192.0.2.5"),
        );
        let address = observed(EntityKind::IpAddress, "192.0.2.5", "rdap", "scan-b");
        let result = discover(&[domain, address]);
        assert_eq!(result.links.len(), 1);
        assert_eq!(result.links[0].status, JoinStatus::IndependentlyObservedTarget);
        assert_eq!(result.links[0].source_scan_id.as_deref(), Some("scan-a"));
        assert_eq!(result.links[0].target_scan_id.as_deref(), Some("scan-b"));
        assert!(!result.truncated);
    }

    #[test]
    fn seeds_inference_and_invalid_attributes_do_not_create_false_links() {
        let mut domain = observed(EntityKind::Domain, "example.org", "dns", "a");
        domain.add_evidence(Evidence::new(EvidenceProvenance::new("seed"), "operator")
            .with_attr("ip", "192.0.2.5"));
        domain.add_evidence(Evidence::new(EvidenceProvenance::new("dns"), "parse")
            .inferred().with_attr("ip", "192.0.2.5"));
        domain.add_evidence(Evidence::new(EvidenceProvenance::new("dns"), "invalid")
            .with_attr("ip", "not-an-address"));
        let target = observed(EntityKind::IpAddress, "192.0.2.5", "rdap", "b");
        assert!(discover(&[domain, target]).links.is_empty());
    }

    #[test]
    fn same_source_and_no_other_observation_cannot_claim_independence() {
        let mut domain = observed(EntityKind::Domain, "example.org", "dns", "a");
        domain.add_evidence(Evidence::new(EvidenceProvenance::new("dns"), "A")
            .with_attr("ip", "192.0.2.5"));
        let target = observed(EntityKind::IpAddress, "192.0.2.5", "dns", "a");
        let result = discover(&[domain, target]);
        assert_eq!(result.links.len(), 1);
        assert_eq!(result.links[0].status, JoinStatus::SourceClaimOnly);
    }

    #[test]
    fn deterministic_and_bounded_for_many_inputs() {
        let entities: Vec<_> = (0..600)
            .map(|index| observed(EntityKind::Domain, &format!("n{index}.example.org"), "dns", "a"))
            .collect();
        let first = discover(&entities);
        assert_eq!(first.examined_entities, 512);
        assert!(first.truncated);
        assert_eq!(first, discover(&entities));
    }
}
