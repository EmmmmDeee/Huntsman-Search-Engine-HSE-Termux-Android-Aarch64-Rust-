//! Bounded, provenance-aware joins between different OSINT artefact families.
//! An edge is an investigation lead, never proof of ownership or identity.
//! A matching target observed by another source is not confirmation of the
//! relationship itself. This distinction is part of the serialized contract.

use serde::Serialize;
use std::collections::BTreeMap;

use crate::canonical::{canonical_asn, canonical_domain, canonical_ip_literal};
use crate::entity::{Entity, EntityKind, Evidence, is_non_corroborating_source};

const MAX_ENTITIES: usize = 512;
const MAX_EVIDENCE_PER_ENTITY: usize = 32;
const MAX_VALUES_PER_ATTRIBUTE: usize = 16;
const MAX_LINKS: usize = 256;

/// Whether the target itself was observed via another collector. This is NOT
/// proof that the upstream datasets were independent or that the relation is true.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinStatus {
    SourceClaimOnly,
    SeparatelyObservedTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SynergyLink {
    pub from_uid: String,
    pub to_uid: String,
    pub from_kind: &'static str,
    pub from_value: String,
    pub to_kind: &'static str,
    pub to_value: String,
    pub relation: &'static str,
    pub attribute: &'static str,
    pub source: String,
    pub target_source: Option<String>,
    pub source_scan_id: Option<String>,
    pub target_scan_id: Option<String>,
    pub status: JoinStatus,
    /// Only an evidence-ancestry proof can establish independence. Collector
    /// names and different scan IDs cannot, so a join never claims it.
    pub independence_status: &'static str,
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

/// Filter unverified and identity-inconsistent records only from derived joins.
/// Original entities, including candidate observations, remain in raw evidence.
#[must_use]
pub(crate) fn admissible_entity(entity: &Entity) -> bool {
    !entity
        .tags
        .iter()
        .any(|tag| tag == crate::tags::CANDIDATE || tag == "quarantined" || tag == "promoted")
        && entity.uid == crate::entity::derive_uid(&entity.kind, &entity.value)
}

fn target_observation<'a>(target: &'a Entity, source_family: &str) -> Option<&'a Evidence> {
    target
        .evidence
        .iter()
        .take(MAX_EVIDENCE_PER_ENTITY)
        .find(|evidence| {
            eligible(evidence) && evidence.provenance.corroboration_key() != source_family
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
            ("ns", EntityKind::Domain, "reported_name_server"),
            ("mx", EntityKind::Domain, "reported_mail_exchanger"),
        ],
        EntityKind::IpAddress => &[
            ("asn", EntityKind::Asn, "reported_routing_asn"),
            ("hostname", EntityKind::Domain, "reported_reverse_hostname"),
            ("ptr", EntityKind::Domain, "reported_reverse_hostname"),
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
            if !admissible_entity(entity) {
                truncated = true;
                continue;
            }
            index
                .entry((entity.kind.clone(), value))
                .or_default()
                .push(entity);
        }
    }
    let mut links: BTreeMap<(String, String, &'static str), SynergyLink> = BTreeMap::new();
    'entities: for entity in inspected {
        if !attributes(&entity.kind).is_empty() && !admissible_entity(entity) {
            truncated = true;
            continue;
        }
        if entity.evidence.len() > MAX_EVIDENCE_PER_ENTITY {
            truncated = true;
        }
        for evidence in entity.evidence.iter().take(MAX_EVIDENCE_PER_ENTITY) {
            if !eligible(evidence) {
                continue;
            }
            let family = evidence.provenance.corroboration_key();
            for &(attribute, ref target_kind, relation) in attributes(&entity.kind) {
                // Never silently omit a collector's additional multi-valued attributes.
                if evidence
                    .attr_values(attribute)
                    .nth(MAX_VALUES_PER_ATTRIBUTE)
                    .is_some()
                {
                    truncated = true;
                }
                for value in evidence
                    .attr_values(attribute)
                    .take(MAX_VALUES_PER_ATTRIBUTE)
                {
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
                            from_kind: entity.kind.as_str(),
                            from_value: entity.value.clone(),
                            to_kind: target.kind.as_str(),
                            to_value: target.value.clone(),
                            relation,
                            attribute,
                            source: evidence.provenance.source.clone(),
                            target_source: independent.map(|item| item.provenance.source.clone()),
                            source_scan_id: evidence.provenance.scan_id.clone(),
                            target_scan_id: independent
                                .and_then(|item| item.provenance.scan_id.clone()),
                            status: if independent.is_some() {
                                JoinStatus::SeparatelyObservedTarget
                            } else {
                                JoinStatus::SourceClaimOnly
                            },
                            independence_status: "not_proven",
                            interpretation: "separate source observation only; independence and relationship not proven",
                        };
                        if !links.contains_key(&key) && links.len() >= MAX_LINKS {
                            truncated = true;
                            break 'entities;
                        }
                        match links.entry(key) {
                            std::collections::btree_map::Entry::Occupied(mut entry) => {
                                if entry.get().status == JoinStatus::SourceClaimOnly
                                    && new_link.status == JoinStatus::SeparatelyObservedTarget
                                {
                                    entry.insert(new_link);
                                }
                            }
                            std::collections::btree_map::Entry::Vacant(entry) => {
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
    use crate::entity::{Entity, EvidenceProvenance};

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
        assert_eq!(result.links[0].status, JoinStatus::SeparatelyObservedTarget);
        assert_eq!(result.links[0].source_scan_id.as_deref(), Some("scan-a"));
        assert_eq!(result.links[0].target_scan_id.as_deref(), Some("scan-b"));
        assert!(!result.truncated);
    }

    #[test]
    fn seeds_inference_and_invalid_attributes_do_not_create_false_links() {
        let mut domain = observed(EntityKind::Domain, "example.org", "dns", "a");
        domain.add_evidence(
            Evidence::new(EvidenceProvenance::new("seed"), "operator").with_attr("ip", "192.0.2.5"),
        );
        domain.add_evidence(
            Evidence::new(EvidenceProvenance::new("dns"), "parse")
                .inferred()
                .with_attr("ip", "192.0.2.5"),
        );
        domain.add_evidence(
            Evidence::new(EvidenceProvenance::new("dns"), "invalid")
                .with_attr("ip", "not-an-address"),
        );
        let target = observed(EntityKind::IpAddress, "192.0.2.5", "rdap", "b");
        assert!(discover(&[domain, target]).links.is_empty());
    }

    #[test]
    fn same_source_and_no_other_observation_cannot_claim_independence() {
        let mut domain = observed(EntityKind::Domain, "example.org", "dns", "a");
        domain.add_evidence(
            Evidence::new(EvidenceProvenance::new("dns"), "A").with_attr("ip", "192.0.2.5"),
        );
        let target = observed(EntityKind::IpAddress, "192.0.2.5", "dns", "a");
        let result = discover(&[domain, target]);
        assert_eq!(result.links.len(), 1);
        assert_eq!(result.links[0].status, JoinStatus::SourceClaimOnly);
    }

    #[test]
    fn distinct_name_server_and_mail_exchanger_leads_from_live_dns() {
        let mut apex = observed(EntityKind::Domain, "example.org", "dns", "live");
        apex.add_evidence(
            Evidence::new(EvidenceProvenance::for_scan("dns", "live"), "zone records")
                .with_attr("ns", "NS1.example.org")
                .with_attr("mx", "mail.example.org"),
        );
        let ns = observed(EntityKind::Domain, "ns1.example.org", "rdap", "registrar");
        let mx = observed(EntityKind::Domain, "mail.example.org", "dns", "live");
        let joins = discover(&[apex, ns, mx]);
        assert_eq!(joins.links.len(), 2);
        assert!(joins.links.iter().any(|join| {
            join.relation == "reported_name_server"
                && join.status == JoinStatus::SeparatelyObservedTarget
        }));
        assert!(joins.links.iter().any(|join| {
            join.relation == "reported_mail_exchanger" && join.status == JoinStatus::SourceClaimOnly
        }));
    }

    #[test]
    fn mirrored_collectors_cannot_claim_proven_independence() {
        let mut domain = observed(EntityKind::Domain, "example.org", "feed-a", "one");
        domain.add_evidence(
            Evidence::new(
                EvidenceProvenance::for_scan("feed-a", "one"),
                "upstream record",
            )
            .with_attr("ip", "192.0.2.7")
            .with_attr("dataset", "same upstream"),
        );
        let mut target = observed(EntityKind::IpAddress, "192.0.2.7", "feed-b", "two");
        target.add_evidence(
            Evidence::new(
                EvidenceProvenance::for_scan("feed-b", "two"),
                "mirror record",
            )
            .with_attr("dataset", "same upstream"),
        );
        let report = discover(&[domain, target]);
        assert_eq!(report.links.len(), 1);
        assert_eq!(report.links[0].status, JoinStatus::SeparatelyObservedTarget);
        assert_eq!(report.links[0].independence_status, "not_proven");
        assert!(report.links[0].interpretation.contains("not proven"));
    }

    #[test]
    fn candidate_and_quarantined_entities_cannot_supply_synergy_links() {
        let mut candidate = observed(EntityKind::Domain, "example.org", "dns", "scan-a");
        candidate.tag(crate::tags::CANDIDATE);
        candidate.add_evidence(
            Evidence::new(EvidenceProvenance::for_scan("dns", "scan-a"), "unverified A")
                .with_attr("ip", "192.0.2.40"),
        );
        let address = observed(EntityKind::IpAddress, "192.0.2.40", "rdap", "scan-b");
        let candidate_result = discover(&[candidate, address.clone()]);
        assert!(candidate_result.links.is_empty());
        assert!(candidate_result.truncated);

        let mut valid = observed(EntityKind::Domain, "example.org", "dns", "scan-a");
        valid.add_evidence(
            Evidence::new(EvidenceProvenance::for_scan("dns", "scan-a"), "confirmed A")
                .with_attr("ip", "192.0.2.40"),
        );
        let mut quarantined_address = address.clone();
        quarantined_address.tag("quarantined");
        let quarantined = discover(&[valid.clone(), quarantined_address]);
        assert!(quarantined.links.is_empty());
        assert!(quarantined.truncated);

        let mut candidate_address = address.clone();
        candidate_address.tag(crate::tags::CANDIDATE);
        assert!(discover(&[valid.clone(), candidate_address]).links.is_empty());

        let admitted = discover(&[valid, address]);
        assert_eq!(admitted.links.len(), 1);
        assert_eq!(admitted.links[0].status, JoinStatus::SeparatelyObservedTarget);
        assert!(!admitted.truncated);
    }

    #[test]
    fn forged_uid_cannot_supply_or_confirm_a_synergy_link() {
        let mut legitimate = observed(EntityKind::Domain, "example.org", "dns", "scan-a");
        legitimate.add_evidence(
            Evidence::new(EvidenceProvenance::for_scan("dns", "scan-a"), "A record")
                .with_attr("ip", "192.0.2.41"),
        );
        let address = observed(EntityKind::IpAddress, "192.0.2.41", "rdap", "scan-b");

        let mut forged_source = observed(EntityKind::Domain, "evil.org", "dns", "scan-a");
        forged_source.uid.clone_from(&legitimate.uid);
        forged_source.add_evidence(
            Evidence::new(EvidenceProvenance::for_scan("dns", "scan-a"), "unrelated A")
                .with_attr("ip", "192.0.2.41"),
        );
        let result = discover(&[forged_source, address.clone()]);
        assert!(result.links.is_empty());
        assert!(result.truncated);

        let mut forged_target = address.clone();
        forged_target.uid = Entity::new(
            EntityKind::IpAddress,
            "192.0.2.42",
            0.9,
            "scan-b",
        )
        .uid;
        let result = discover(&[legitimate.clone(), forged_target]);
        assert!(result.links.is_empty());
        assert!(result.truncated);

        let admitted = discover(&[legitimate, address]);
        assert_eq!(admitted.links.len(), 1);
        assert!(!admitted.truncated);
    }

    #[test]
    fn deterministic_and_bounded_for_many_inputs() {
        let entities: Vec<_> = (0..600)
            .map(|index| {
                observed(
                    EntityKind::Domain,
                    &format!("n{index}.example.org"),
                    "dns",
                    "a",
                )
            })
            .collect();
        let first = discover(&entities);
        assert_eq!(first.examined_entities, 512);
        assert!(first.truncated);
        assert_eq!(first, discover(&entities));
    }
}
