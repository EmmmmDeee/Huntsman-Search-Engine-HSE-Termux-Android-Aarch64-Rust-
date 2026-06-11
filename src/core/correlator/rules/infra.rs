//! AU correlation rules — infra family. See `super` (rules/mod.rs) for the
//! shared helpers; every rule reaches them through `use super::*`.

use super::*;

pub(in crate::core::correlator) fn rule_au_004_malicious_infrastructure(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| {
            matches!(
                e.kind,
                EntityKind::Domain | EntityKind::IpAddress | EntityKind::Url
            )
        })
        // A GreyNoise RIOT/benign verdict vetoes a `malicious` tag picked up on
        // the same (shared-edge) IP from a weaker source.
        .filter(|e| e.has_tag(crate::core::tags::MALICIOUS) && !is_benign_infra(e))
        .map(|e| Correlation {
            rule_id: "AU-004".into(),
            rule_name: "Malicious infrastructure".into(),
            severity: Severity::Critical,
            description: format!(
                "{} '{}' flagged malicious by blocklist sources",
                e.kind, e.value
            ),
            entity_uids: vec![e.uid.clone()],
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_005_anonymous_network(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const ANON_TAGS: &[&str] = &["tor-exit", "tor", "anonymous-network", "anonymous-vpn"];
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        .filter(|e| ANON_TAGS.iter().any(|t| e.has_tag(t)))
        .map(|e| {
            let hits: Vec<&str> = ANON_TAGS.iter().copied().filter(|t| e.has_tag(t)).collect();
            Correlation {
                rule_id: "AU-005".into(),
                rule_name: "Anonymous-network exit".into(),
                severity: Severity::High,
                description: format!(
                    "IP {} is an anonymous-network exit ({})",
                    e.value,
                    hits.join(", ")
                ),
                entity_uids: vec![e.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            }
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_006_proxy_vpn(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const ANON_TAGS: &[&str] = &["tor-exit", "tor", "anonymous-network", "anonymous-vpn"];
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        .filter(|e| {
            (e.has_tag("proxy") || e.has_tag("vpn")) && !ANON_TAGS.iter().any(|t| e.has_tag(t))
        })
        .map(|e| {
            let mut hits: Vec<&str> = Vec::new();
            if e.has_tag("proxy") {
                hits.push("proxy");
            }
            if e.has_tag("vpn") {
                hits.push("vpn");
            }
            Correlation {
                rule_id: "AU-006".into(),
                rule_name: "Proxy/VPN-fronted IP".into(),
                severity: Severity::Medium,
                description: format!("IP {} is fronted by {}", e.value, hits.join(" + ")),
                entity_uids: vec![e.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            }
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_007_high_risk_reputation(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const RISK_TAGS: &[&str] = &[
        crate::core::tags::HIGH_RISK,
        "high-risk-inbound",
        "high-risk-outbound",
        "recent-abuse",
        "scanner",
    ];
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        .filter(|e| RISK_TAGS.iter().any(|t| e.has_tag(t)))
        .map(|e| {
            let hits: Vec<&str> = RISK_TAGS.iter().copied().filter(|t| e.has_tag(t)).collect();
            Correlation {
                rule_id: "AU-007".into(),
                rule_name: "High-risk IP reputation".into(),
                severity: Severity::High,
                description: format!(
                    "IP {} has high-risk reputation signals: {}",
                    e.value,
                    hits.join(", ")
                ),
                entity_uids: vec![e.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            }
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_008_exposed_service(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // `vulnerable` routed through the canonical constant (emit side: cloud_storage,
    // etc.); `ssh-exposed`/`leak` stay descriptive module-local literals.
    const EXPOSURE_TAGS: &[&str] = &[crate::core::tags::VULNERABLE, "ssh-exposed", "leak"];
    entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Domain | EntityKind::IpAddress))
        // GreyNoise RIOT/benign exonerates a shared CDN/cloud edge that a CVE
        // scanner tagged `vulnerable` — don't report it as an exposed service.
        .filter(|e| EXPOSURE_TAGS.iter().any(|t| e.has_tag(t)) && !is_benign_infra(e))
        .map(|e| {
            let hits: Vec<&str> = EXPOSURE_TAGS
                .iter()
                .copied()
                .filter(|t| e.has_tag(t))
                .collect();
            Correlation {
                rule_id: "AU-008".into(),
                rule_name: "Exposed service".into(),
                severity: Severity::High,
                description: format!(
                    "{} '{}' exposes service signals: {}",
                    e.kind,
                    e.value,
                    hits.join(", ")
                ),
                entity_uids: vec![e.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            }
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_010_infra_consensus(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let mut out = Vec::new();
    for e in entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Domain | EntityKind::IpAddress))
    {
        let sources = e.evidence_sources();
        if sources.len() >= 3 {
            let mut names: Vec<&str> = sources.into_iter().collect();
            names.sort_unstable();
            out.push(Correlation {
                rule_id: "AU-010".into(),
                rule_name: "Infrastructure consensus".into(),
                severity: Severity::Medium,
                description: format!(
                    "{} '{}' confirmed by {} infrastructure sources: {}",
                    e.kind,
                    e.value,
                    names.len(),
                    names.join(", ")
                ),
                entity_uids: vec![e.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            });
        }
    }
    out
}

pub(in crate::core::correlator) fn rule_au_015_threat_intel_hit(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const TI_SOURCES: &[&str] = &["ip_reputation", "threatfox"];

    entities
        .iter()
        // A GreyNoise RIOT/benign IP that a reputation feed also flagged is a
        // shared-edge false positive — exonerate it.
        .filter(|e| e.has_tag(crate::core::tags::THREAT_INTEL) && !is_benign_infra(e))
        .map(|e| {
            let sources: std::collections::BTreeSet<&str> = e
                .evidence
                .iter()
                .map(|ev| ev.source.as_str())
                .filter(|s| TI_SOURCES.contains(s))
                .collect();
            let attribution = if sources.is_empty() {
                "a curated threat-intel feed".to_string()
            } else {
                sources.into_iter().collect::<Vec<_>>().join(" + ")
            };
            let ti_hints: Vec<&str> = e
                .tags
                .iter()
                .filter_map(|t| t.strip_prefix("ti:"))
                .collect();
            let detail = if ti_hints.is_empty() {
                String::new()
            } else {
                format!(": {}", ti_hints.join(", "))
            };
            Correlation {
                rule_id: "AU-015".into(),
                rule_name: "Threat-intel hit".into(),
                severity: Severity::High,
                description: format!("{} '{}' present in {attribution}{detail}", e.kind, e.value),
                entity_uids: vec![e.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            }
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_028_subdomain_takeover_risk(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain && e.has_tag("subdomain-takeover"))
        .map(|e| {
            Correlation::new(
                "AU-028",
                "Subdomain takeover vulnerability",
                Severity::Critical,
                format!(
                    "Domain '{}' has a dangling CNAME vulnerable to takeover",
                    e.value
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            )
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_029_cloud_storage_exposure(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let exposed: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.has_tag("cloud-storage") && e.has_tag(crate::core::tags::VULNERABLE))
        .collect();
    if exposed.is_empty() {
        return Vec::new();
    }
    let uids: Vec<String> = exposed.iter().map(|e| e.uid.clone()).collect();
    vec![Correlation::new(
        "AU-029",
        "Exposed cloud storage",
        Severity::Critical,
        format!(
            "{} publicly accessible cloud storage bucket(s) discovered",
            exposed.len()
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// AU-031 — Malicious adjacency (graph-aware). Surfaces a *benign* entity that
/// is one relation-edge away from a known-bad entity (tagged malicious /
/// threat-intel / vulnerable): a subdomain of a malicious apex, an entity
/// derived from a flagged node during expansion, or coordinates co-located with
/// bad infra.
///
/// **Ground-truth veto, then fan-out backstop.** Most "shared infrastructure"
/// is identified explicitly in the data — a CDN/cloud edge IP carries a GreyNoise
/// RIOT/benign verdict ([`is_benign_infra`]) — so such a node is never treated as
/// bad here, and an adjacency explosion (a real scan produced 792 rows from four
/// shared parents) cannot start. For shared infra that LACKS such a verdict
/// (e.g. a flagged ESP/mail *domain*), a fan-out backstop applies: a bad node
/// with more than `FANOUT_CAP` distinct benign neighbours collapses to ONE
/// aggregated finding (Medium, or High when the reason is `malicious` — a
/// genuine large malicious cluster stays loud) instead of N rows; dedicated
/// infra (≤ cap) still fires per-neighbour at High. Edges between two
/// already-flagged nodes are left to AU-004/AU-008/AU-015. Deterministic
/// (BTreeMap-ordered).
pub(in crate::core::correlator) fn rule_au_031_malicious_adjacency(
    entities: &[Entity],
    relations: &[Relation],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use crate::core::relation::RelationKind;
    use std::collections::{BTreeMap, HashMap};

    /// A flagged node with more than this many distinct benign neighbours is
    /// shared hosting/CDN/ESP: emit one aggregate, not one row per neighbour.
    const FANOUT_CAP: usize = 8;
    /// Benign uids to carry on an aggregate finding (the full count is in text).
    const AGG_SAMPLE: usize = 12;

    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
    let bad_reason = |e: &Entity| -> Option<&'static str> {
        // Ground-truth veto: a GreyNoise RIOT/benign node is not bad
        // infrastructure even if a scanner also tagged it, so it never anchors an
        // adjacency explosion. The fan-out cap below is only the backstop for
        // shared infra that carries no such verdict.
        if is_benign_infra(e) {
            return None;
        }
        ADJACENCY_BAD_TAGS.iter().copied().find(|t| e.has_tag(t))
    };

    // Group benign neighbours under each flagged node, deduped by benign uid (a
    // node can reach the same bad node by more than one edge). BTreeMaps keep
    // the whole pass deterministic regardless of relation order.
    #[allow(clippy::type_complexity)]
    let mut groups: BTreeMap<
        &str,
        (
            &Entity,
            &'static str,
            BTreeMap<&str, (&Entity, RelationKind)>,
        ),
    > = BTreeMap::new();
    for r in relations {
        let (Some(&from), Some(&to)) = (
            by_uid.get(r.from_uid.as_str()),
            by_uid.get(r.to_uid.as_str()),
        ) else {
            continue;
        };
        // Exactly one endpoint flagged → the other is "adjacent to bad".
        let (benign, bad, reason) = match (bad_reason(from), bad_reason(to)) {
            (None, Some(reason)) => (from, to, reason),
            (Some(reason), None) => (to, from, reason),
            _ => continue,
        };
        let entry = groups
            .entry(bad.uid.as_str())
            .or_insert_with(|| (bad, reason, BTreeMap::new()));
        entry
            .2
            .entry(benign.uid.as_str())
            .or_insert((benign, r.kind));
    }

    let mut out = Vec::new();
    for (_bad_uid, (bad, reason, neighbours)) in groups {
        if neighbours.len() <= FANOUT_CAP {
            // Dedicated infra — meaningful per-neighbour attribution.
            for (benign, rkind) in neighbours.values() {
                out.push(Correlation::new(
                    "AU-031",
                    "Adjacency to known-bad infrastructure",
                    Severity::High,
                    format!(
                        "{} ({}) is {} flagged-{} {} ({})",
                        benign.value, benign.kind, rkind, reason, bad.value, bad.kind
                    ),
                    vec![benign.uid.clone(), bad.uid.clone()],
                    scan_id,
                    ts,
                ));
            }
        } else {
            // High fan-out without a benign verdict — shared hosting/ESP. One
            // aggregate, not N noise rows. A large *malicious* cluster is a real
            // threat and stays High; weaker reasons (vulnerable/threat-intel on
            // shared infra) are Medium.
            let agg_sev = if reason == crate::core::tags::MALICIOUS {
                Severity::High
            } else {
                Severity::Medium
            };
            let mut uids: Vec<String> = neighbours
                .keys()
                .take(AGG_SAMPLE)
                .map(|u| u.to_string())
                .collect();
            uids.push(bad.uid.clone());
            out.push(Correlation::new(
                "AU-031",
                "Adjacency to known-bad infrastructure",
                agg_sev,
                format!(
                    "{} entities are adjacent to flagged-{} shared infrastructure {} ({}) — likely shared hosting/CDN, not a dedicated link",
                    neighbours.len(),
                    reason,
                    bad.value,
                    bad.kind
                ),
                uids,
                scan_id,
                ts,
            ));
        }
    }
    out
}
