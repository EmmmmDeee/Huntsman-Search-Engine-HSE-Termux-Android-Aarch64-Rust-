use std::collections::HashSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::core::{
    entity::{Entity, EntityKind, unix_now},
    error::Result,
};
use crate::storage::store::Store;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_canonical(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Correlation {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub description: String,
    pub entity_uids: Vec<String>,
    pub scan_id: String,
    pub ts: u64,
}

impl Correlation {
    fn new(
        rule_id: &str,
        rule_name: &str,
        severity: Severity,
        description: String,
        entity_uids: Vec<String>,
        scan_id: &str,
        ts: u64,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            rule_name: rule_name.into(),
            severity,
            description,
            entity_uids,
            scan_id: scan_id.into(),
            ts,
        }
    }
}

pub struct Correlator {
    store: Arc<Store>,
}

impl Correlator {
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    pub fn run(&self, scan_id: &str) -> Result<Vec<Correlation>> {
        let entities = self.store.entities_for_scan(scan_id)?;
        if entities.is_empty() {
            return Ok(Vec::new());
        }
        let firings = evaluate_rules(&entities, scan_id);
        for c in &firings {
            self.store.upsert_correlation(c)?;
        }
        debug!(scan_id, fired = firings.len(), "correlator done");
        Ok(firings)
    }
}

fn evaluate_rules(entities: &[Entity], scan_id: &str) -> Vec<Correlation> {
    let now = unix_now();
    let mut out = Vec::new();
    out.extend(rule_au_001_multi_breach(entities, scan_id, now));
    out.extend(rule_au_002_identity_cluster(entities, scan_id, now));
    out.extend(rule_au_003_high_corroboration(entities, scan_id, now));
    out.extend(rule_au_004_malicious_infrastructure(entities, scan_id, now));
    out.extend(rule_au_005_anonymous_network(entities, scan_id, now));
    out.extend(rule_au_006_proxy_vpn(entities, scan_id, now));
    out.extend(rule_au_007_high_risk_reputation(entities, scan_id, now));
    out.extend(rule_au_008_exposed_service(entities, scan_id, now));
    out.extend(rule_au_009_stealer_log(entities, scan_id, now));
    out.extend(rule_au_010_infra_consensus(entities, scan_id, now));
    out.extend(rule_au_011_cross_platform_username(entities, scan_id, now));
    out.extend(rule_au_012_identity_linked_domain(entities, scan_id, now));
    out.extend(rule_au_013_local_network_discovery(entities, scan_id, now));
    out.extend(rule_au_014_geo_cluster(entities, scan_id, now));
    out.extend(rule_au_015_threat_intel_hit(entities, scan_id, now));
    out.extend(rule_au_016_credential_cluster(entities, scan_id, now));
    out.extend(rule_au_017_ransomware_and_breach(entities, scan_id, now));
    out.extend(rule_au_018_stealer_family_spread(entities, scan_id, now));
    out
}

/// Threshold at 2 (not 3) so the rule fires on free-only configurations
/// (hudsonrock + xposed_or_not). Restore to 3 once paid breach modules land.
fn rule_au_001_multi_breach(entities: &[Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    const BREACH_SOURCES: &[&str] = &[
        "hudsonrock",
        "xposed_or_not",
        "breach_directory",
        "dehashed",
        "hibp",
        "oathnet_pro",
    ];
    let mut out = Vec::new();
    for e in entities.iter().filter(|e| e.kind == EntityKind::Email) {
        let sources: HashSet<&str> = e
            .evidence
            .iter()
            .filter(|ev| BREACH_SOURCES.contains(&ev.source.as_str()))
            .map(|ev| ev.source.as_str())
            .collect();
        if sources.len() >= 2 {
            let mut names: Vec<&str> = sources.into_iter().collect();
            names.sort_unstable();
            out.push(Correlation::new(
                "AU-001",
                "Multi-source breach corroboration",
                Severity::Critical,
                format!(
                    "{} found in {} breach sources: {}",
                    e.value,
                    names.len(),
                    names.join(", ")
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            ));
        }
    }
    out
}

fn rule_au_002_identity_cluster(entities: &[Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    let emails: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .collect();
    let usernames: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .collect();
    let phones: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Phone)
        .collect();

    if emails.is_empty() || usernames.is_empty() || phones.is_empty() {
        return Vec::new();
    }

    let mut uids: Vec<String> = emails.iter().map(|e| e.uid.clone()).collect();
    uids.extend(usernames.iter().map(|e| e.uid.clone()));
    uids.extend(phones.iter().map(|e| e.uid.clone()));

    vec![Correlation {
        rule_id: "AU-002".into(),
        rule_name: "Identity cluster".into(),
        severity: Severity::High,
        description: format!(
            "Email + Username + Phone co-located: {} email(s), {} username(s), {} phone(s)",
            emails.len(),
            usernames.len(),
            phones.len()
        ),
        entity_uids: uids,
        scan_id: scan_id.into(),
        ts,
    }]
}

/// Threshold at 3 (not 5) so v0.4's module set can actually fire it.
fn rule_au_003_high_corroboration(entities: &[Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.corroboration >= 3)
        .map(|e| Correlation {
            rule_id: "AU-003".into(),
            rule_name: "High cross-source corroboration".into(),
            severity: Severity::Medium,
            description: format!(
                "{} entity '{}' corroborated by {} independent sources (C_eff={:.3})",
                e.kind,
                e.value,
                e.corroboration,
                e.c_effective()
            ),
            entity_uids: vec![e.uid.clone()],
            scan_id: scan_id.into(),
            ts,
        })
        .collect()
}

/// Differs from AU-003: counts evidence-level source diversity, not the
/// `corroboration` field (which only increments on merge).
fn rule_au_010_infra_consensus(entities: &[Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    let mut out = Vec::new();
    for e in entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Domain | EntityKind::IpAddress))
    {
        let sources: HashSet<&str> = e.evidence.iter().map(|ev| ev.source.as_str()).collect();
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
            });
        }
    }
    out
}

fn rule_au_004_malicious_infrastructure(
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
        .filter(|e| e.has_tag("malicious"))
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
        })
        .collect()
}

fn rule_au_005_anonymous_network(entities: &[Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
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
            }
        })
        .collect()
}

/// Excludes IPs that also match AU-005 anonymous-network tags.
fn rule_au_006_proxy_vpn(entities: &[Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    // Keep in sync with AU-005's ANON_TAGS.
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
            }
        })
        .collect()
}

fn rule_au_007_high_risk_reputation(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const RISK_TAGS: &[&str] = &[
        "high-risk",
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
            }
        })
        .collect()
}

fn rule_au_008_exposed_service(entities: &[Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    const EXPOSURE_TAGS: &[&str] = &["vulnerable", "ssh-exposed", "leak"];
    entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Domain | EntityKind::IpAddress))
        .filter(|e| EXPOSURE_TAGS.iter().any(|t| e.has_tag(t)))
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
            }
        })
        .collect()
}

fn rule_au_009_stealer_log(entities: &[Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Email | EntityKind::Username | EntityKind::Phone | EntityKind::Domain) && e.has_tag("stealer-log"))
        .map(|e| Correlation {
            rule_id: "AU-009".into(),
            rule_name: "Stealer-log compromise".into(),
            severity: Severity::High,
            description: format!("{} {} observed in info-stealer log dumps", e.kind, e.value),
            entity_uids: vec![e.uid.clone()],
            scan_id: scan_id.into(),
            ts,
        })
        .collect()
}

/// Reads `platforms_count`/`platforms` attrs from evidence rows (not tags)
/// because `username_search` puts platform info in evidence attrs.
fn rule_au_011_cross_platform_username(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .filter_map(|e| {
            let mut max_count: u64 = 0;
            let mut best_list: Option<&str> = None;
            for ev in &e.evidence {
                let count = ev
                    .attributes
                    .get("platforms_count")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                if count > max_count {
                    max_count = count;
                    best_list = ev.attributes.get("platforms").map(String::as_str);
                }
            }
            if max_count >= 3 {
                let detail = best_list.map(|s| format!(": {s}")).unwrap_or_default();
                Some(Correlation {
                    rule_id: "AU-011".into(),
                    rule_name: "Cross-platform username footprint".into(),
                    severity: Severity::Medium,
                    description: format!(
                        "Username '{}' present on {max_count} platforms{detail}",
                        e.value
                    ),
                    entity_uids: vec![e.uid.clone()],
                    scan_id: scan_id.into(),
                    ts,
                })
            } else {
                None
            }
        })
        .collect()
}

fn rule_au_012_identity_linked_domain(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let username_uids: Vec<String> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .map(|u| u.uid.clone())
        .collect();
    if username_uids.is_empty() {
        return Vec::new();
    }
    entities
        .iter()
        .filter(|e| {
            matches!(e.kind, EntityKind::Url | EntityKind::Domain) && e.has_tag("personal-site")
        })
        .map(|d| {
            let mut uids = Vec::with_capacity(1 + username_uids.len());
            uids.push(d.uid.clone());
            uids.extend(username_uids.iter().cloned());
            Correlation {
                rule_id: "AU-012".into(),
                rule_name: "Identity-linked site".into(),
                severity: Severity::Medium,
                description: format!(
                    "Personal site '{}' co-occurs with {} username(s) in scan",
                    d.value,
                    username_uids.len()
                ),
                entity_uids: uids,
                scan_id: scan_id.into(),
                ts,
            }
        })
        .collect()
}

fn rule_au_013_local_network_discovery(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const LAN_TAGS: &[&str] = &["local-arp", "local-interface", "wifi-ap"];
    // Restrict to IpAddress/MacAddress to avoid false positives from tag collisions.
    let hits: Vec<&Entity> = entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::IpAddress | EntityKind::MacAddress))
        .filter(|e| LAN_TAGS.iter().any(|t| e.has_tag(t)))
        .collect();
    if hits.len() < 2 {
        return Vec::new();
    }
    vec![Correlation {
        rule_id: "AU-013".into(),
        rule_name: "Local-network discovery".into(),
        severity: Severity::Low,
        description: format!(
            "{} entities observed on the local network (ARP / interfaces / Wi-Fi APs)",
            hits.len()
        ),
        entity_uids: hits.iter().map(|e| e.uid.clone()).collect(),
        scan_id: scan_id.into(),
        ts,
    }]
}

fn rule_au_014_geo_cluster(entities: &[Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    const GEO_TAGS: &[&str] = &["geoint", "wifi-observed"];
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Coordinates)
        .filter_map(|e| {
            let hits: Vec<&str> = GEO_TAGS.iter().copied().filter(|t| e.has_tag(t)).collect();
            let sources: HashSet<&str> = e.evidence.iter().map(|ev| ev.source.as_str()).collect();
            if hits.len() >= 2 || sources.len() >= 2 {
                Some(Correlation {
                    rule_id: "AU-014".into(),
                    rule_name: "Geolocation cluster".into(),
                    severity: Severity::Medium,
                    description: format!(
                        "Coordinates '{}' confirmed by {} geo source(s)",
                        e.value,
                        sources.len().max(hits.len())
                    ),
                    entity_uids: vec![e.uid.clone()],
                    scan_id: scan_id.into(),
                    ts,
                })
            } else {
                None
            }
        })
        .collect()
}

fn rule_au_015_threat_intel_hit(entities: &[Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    // Only count evidence from known TI modules to avoid misattributing
    // the tag to non-TI evidence merged onto the same entity.
    const TI_SOURCES: &[&str] = &["alienvault_otx", "threatfox"];

    entities
        .iter()
        .filter(|e| e.has_tag("threat-intel"))
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
            }
        })
        .collect()
}

fn rule_au_016_credential_cluster(entities: &[Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    let creds: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Credential && e.has_tag("stealer-log"))
        .collect();
    if creds.len() < 3 {
        return Vec::new();
    }
    vec![Correlation::new(
        "AU-016",
        "Compromised credential cluster",
        Severity::Critical,
        format!(
            "{} stolen credentials found in stealer logs — indicates systemic device compromise",
            creds.len()
        ),
        creds.iter().map(|e| e.uid.clone()).collect(),
        scan_id,
        ts,
    )]
}

fn rule_au_017_ransomware_and_breach(entities: &[Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain && e.has_tag("ransomware-victim") && e.has_tag("breach"))
        .map(|e| Correlation::new(
            "AU-017",
            "Ransomware victim with breached employees",
            Severity::Critical,
            format!(
                "Domain '{}' is both a ransomware victim and has employees in breach databases",
                e.value
            ),
            vec![e.uid.clone()],
            scan_id,
            ts,
        ))
        .collect()
}

fn rule_au_018_stealer_family_spread(entities: &[Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    let mut family_entities: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for e in entities {
        for tag in &e.tags {
            if let Some(family) = tag.strip_prefix("stealer:") {
                family_entities
                    .entry(family.to_string())
                    .or_default()
                    .push(e.uid.clone());
            }
        }
    }
    family_entities
        .into_iter()
        .filter(|(_, uids)| uids.len() >= 2)
        .map(|(family, uids)| {
            let count = uids.len();
            Correlation::new(
                "AU-018",
                "Stealer family spread",
                Severity::High,
                format!(
                    "Stealer family '{family}' compromised {count} identities — indicates coordinated malware campaign"
                ),
                uids,
                scan_id,
                ts,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind, Evidence};

    fn email(value: &str, sources: &[&str]) -> Entity {
        let mut e = Entity::new(EntityKind::Email, value, 0.9, "scan-test");
        for src in sources {
            e.add_evidence(Evidence::new(*src, "test"));
        }
        e
    }

    fn domain(value: &str, sources: &[&str]) -> Entity {
        let mut e = Entity::new(EntityKind::Domain, value, 0.9, "scan-test");
        for src in sources {
            e.add_evidence(Evidence::new(*src, "test"));
        }
        e
    }

    #[test]
    fn au001_fires_at_two_breach_sources() {
        let e = email("x@y.com", &["hudsonrock", "breach_directory"]);
        let r = rule_au_001_multi_breach(&[e], "s1", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "AU-001");
        assert_eq!(r[0].severity, Severity::Critical);
    }

    #[test]
    fn au001_no_fire_at_one_source() {
        let e = email("x@y.com", &["hudsonrock"]);
        assert!(rule_au_001_multi_breach(&[e], "s1", 0).is_empty());
    }

    #[test]
    fn au001_ignores_non_breach_sources() {
        let e = email("x@y.com", &["crtsh", "dns_resolver"]);
        assert!(rule_au_001_multi_breach(&[e], "s1", 0).is_empty());
    }

    #[test]
    fn au002_fires_with_all_three_kinds() {
        let entities = vec![
            Entity::new(EntityKind::Email, "x@y.com", 0.9, "s"),
            Entity::new(EntityKind::Username, "xuser", 0.8, "s"),
            Entity::new(EntityKind::Phone, "+61400000000", 0.8, "s"),
        ];
        let r = rule_au_002_identity_cluster(&entities, "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "AU-002");
        assert_eq!(r[0].entity_uids.len(), 3);
    }

    #[test]
    fn au002_no_fire_missing_kind() {
        let entities = vec![
            Entity::new(EntityKind::Email, "x@y.com", 0.9, "s"),
            Entity::new(EntityKind::Username, "xuser", 0.8, "s"),
            // no Phone
        ];
        assert!(rule_au_002_identity_cluster(&entities, "s", 0).is_empty());
    }

    #[test]
    fn au003_fires_at_corroboration_three() {
        let mut e = Entity::new(EntityKind::Domain, "x.com", 0.9, "s");
        e.corroboration = 3;
        let r = rule_au_003_high_corroboration(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "AU-003");
    }

    #[test]
    fn au003_no_fire_at_two() {
        let mut e = Entity::new(EntityKind::Domain, "x.com", 0.9, "s");
        e.corroboration = 2;
        assert!(rule_au_003_high_corroboration(&[e], "s", 0).is_empty());
    }

    #[test]
    fn au010_fires_at_three_sources_on_domain() {
        let e = domain("x.com", &["crtsh", "dns_resolver", "hudsonrock"]);
        let r = rule_au_010_infra_consensus(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "AU-010");
    }

    #[test]
    fn au010_no_fire_at_two_sources() {
        let e = domain("x.com", &["crtsh", "dns_resolver"]);
        assert!(rule_au_010_infra_consensus(&[e], "s", 0).is_empty());
    }

    #[test]
    fn au010_ignores_non_infrastructure_kinds() {
        let e = email("x@y.com", &["a", "b", "c"]);
        assert!(rule_au_010_infra_consensus(&[e], "s", 0).is_empty());
    }

    #[test]
    fn severity_orders_correctly() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    fn tagged(kind: EntityKind, value: &str, tags: &[&str]) -> Entity {
        let mut e = Entity::new(kind, value, 0.9, "scan-test");
        for t in tags {
            e.tag(*t);
        }
        e
    }

    #[test]
    fn au004_fires_on_malicious_domain() {
        let e = tagged(EntityKind::Domain, "evil.example", &["malicious"]);
        let r = rule_au_004_malicious_infrastructure(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "AU-004");
        assert_eq!(r[0].severity, Severity::Critical);
    }

    #[test]
    fn au004_no_fire_without_tag() {
        let e = tagged(EntityKind::Domain, "ok.example", &[]);
        assert!(rule_au_004_malicious_infrastructure(&[e], "s", 0).is_empty());
    }

    #[test]
    fn au005_fires_on_tor_exit() {
        let e = tagged(EntityKind::IpAddress, "1.1.1.1", &["tor-exit"]);
        let r = rule_au_005_anonymous_network(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity, Severity::High);
    }

    #[test]
    fn au006_fires_on_vpn_but_not_tor() {
        let vpn_ip = tagged(EntityKind::IpAddress, "2.2.2.2", &["vpn"]);
        let tor_ip = tagged(EntityKind::IpAddress, "3.3.3.3", &["tor-exit", "vpn"]);
        let r = rule_au_006_proxy_vpn(&[vpn_ip, tor_ip], "s", 0);
        assert_eq!(r.len(), 1);
        assert!(r[0].description.contains("2.2.2.2"));
    }

    #[test]
    fn au006_excludes_all_anon_tags_not_just_tor_exit() {
        // Regression: a previous version only excluded `tor-exit`, so an
        // IP tagged `tor` / `anonymous-network` / `anonymous-vpn` would
        // double-fire AU-005 + AU-006. Now AU-006 silences all four.
        let tor_short = tagged(EntityKind::IpAddress, "4.4.4.4", &["tor", "vpn"]);
        let anon_net = tagged(
            EntityKind::IpAddress,
            "5.5.5.5",
            &["anonymous-network", "vpn"],
        );
        let anon_vpn = tagged(EntityKind::IpAddress, "6.6.6.6", &["anonymous-vpn", "vpn"]);
        assert!(rule_au_006_proxy_vpn(&[tor_short], "s", 0).is_empty());
        assert!(rule_au_006_proxy_vpn(&[anon_net], "s", 0).is_empty());
        assert!(rule_au_006_proxy_vpn(&[anon_vpn], "s", 0).is_empty());
    }

    #[test]
    fn au007_fires_on_high_risk() {
        let e = tagged(EntityKind::IpAddress, "4.4.4.4", &["high-risk", "scanner"]);
        let r = rule_au_007_high_risk_reputation(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity, Severity::High);
    }

    #[test]
    fn au008_fires_on_vulnerable_tag() {
        let e = tagged(EntityKind::Domain, "vuln.example", &["vulnerable"]);
        let r = rule_au_008_exposed_service(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "AU-008");
    }

    #[test]
    fn au009_fires_on_stealer_log() {
        let e = tagged(EntityKind::Email, "x@y.com", &["stealer-log"]);
        let r = rule_au_009_stealer_log(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity, Severity::High);
    }

    /// Build a `username_search`-shaped summary entity: Username with
    /// the `platforms_count` + `platforms` attrs on an evidence row.
    /// Mirrors the real entity emitted at src/modules/username_search.rs:360.
    fn username_summary(value: &str, count: u64, platforms: &str) -> Entity {
        let mut e = Entity::new(EntityKind::Username, value, 0.95, "scan-test");
        e.tag("multi-platform");
        e.add_evidence(
            Evidence::new("username_search", "summary")
                .with_attr("platforms_count", count.to_string())
                .with_attr("platforms", platforms),
        );
        e
    }

    #[test]
    fn au011_fires_on_three_platforms() {
        let e = username_summary("alice", 3, "github, reddit, twitter");
        let r = rule_au_011_cross_platform_username(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert!(r[0].description.contains("3 platforms"));
        assert!(r[0].description.contains("github"));
    }

    #[test]
    fn au011_no_fire_on_two_platforms() {
        let e = username_summary("alice", 2, "github, reddit");
        assert!(rule_au_011_cross_platform_username(&[e], "s", 0).is_empty());
    }

    #[test]
    fn au012_fires_when_username_and_personal_site_url_present() {
        // `github_user` emits `personal-site` on a Url entity (the blog
        // field of a profile), not a Domain — this fixture matches that.
        let entities = vec![
            tagged(EntityKind::Username, "alice", &[]),
            tagged(
                EntityKind::Url,
                "https://alice.example/",
                &["personal-site"],
            ),
        ];
        let r = rule_au_012_identity_linked_domain(&entities, "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].entity_uids.len(), 2);
        assert!(r[0].description.contains("co-occurs"));
    }

    #[test]
    fn au012_also_fires_on_personal_site_domain() {
        // Forward-compatibility: any future module that tags a Domain
        // (not a Url) with `personal-site` should still fire AU-012.
        let entities = vec![
            tagged(EntityKind::Username, "alice", &[]),
            tagged(EntityKind::Domain, "alice.example", &["personal-site"]),
        ];
        let r = rule_au_012_identity_linked_domain(&entities, "s", 0);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn au012_no_fire_without_username() {
        let entities = vec![tagged(
            EntityKind::Url,
            "https://alice.example/",
            &["personal-site"],
        )];
        assert!(rule_au_012_identity_linked_domain(&entities, "s", 0).is_empty());
    }

    #[test]
    fn au013_fires_on_two_lan_entities() {
        let entities = vec![
            tagged(EntityKind::IpAddress, "192.168.1.1", &["local-arp"]),
            tagged(EntityKind::MacAddress, "aa:bb:cc:dd:ee:ff", &["local-arp"]),
        ];
        let r = rule_au_013_local_network_discovery(&entities, "s", 0);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn au013_no_fire_on_one_lan_entity() {
        let entities = vec![tagged(EntityKind::IpAddress, "192.168.1.1", &["local-arp"])];
        assert!(rule_au_013_local_network_discovery(&entities, "s", 0).is_empty());
    }

    #[test]
    fn au014_fires_on_two_geo_sources() {
        // Use sources that actually produce Coordinates entities:
        // `gps_fix` (geoint) + `wigle` (wifi-observed) + `ip_geo` (geoint).
        // (cell_survey emits DeviceId, not Coordinates, so it isn't a
        // valid source for this rule.)
        let mut e = Entity::new(EntityKind::Coordinates, "0,0", 0.9, "s");
        e.add_evidence(Evidence::new("wigle", "test"));
        e.add_evidence(Evidence::new("gps_fix", "test"));
        let r = rule_au_014_geo_cluster(&[e], "s", 0);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn au015_fires_on_threat_intel_tag() {
        let e = tagged(
            EntityKind::Domain,
            "bad.example",
            &["threat-intel", "ti:malware"],
        );
        let r = rule_au_015_threat_intel_hit(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert!(r[0].description.contains("malware"));
    }

    #[test]
    fn au015_attribution_names_evidence_source_not_otx() {
        // Hard-coding 'OTX pulse(s)' in the description misattributed
        // ThreatFox hits to AlienVault OTX (code-review C3). The fix
        // pulls the feed name from evidence.source.
        let mut e = Entity::new(EntityKind::Domain, "bad.example", 0.9, "s");
        e.tag("threat-intel");
        e.add_evidence(Evidence::new("threatfox", "t"));
        let r = rule_au_015_threat_intel_hit(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert!(r[0].description.contains("threatfox"));
        assert!(!r[0].description.contains("OTX"));
    }

    #[test]
    fn au015_attribution_excludes_non_ti_evidence() {
        // An entity tagged `threat-intel` can carry evidence rows from
        // non-TI modules (e.g. a Domain enriched by both `alienvault_otx`
        // AND `whois` during expansion). The attribution must NOT include
        // the non-TI source name; the AU-015 whitelist gates exactly
        // which modules are authoritative for the threat-intel claim.
        let mut e = Entity::new(EntityKind::Domain, "bad.example", 0.9, "s");
        e.tag("threat-intel");
        e.add_evidence(Evidence::new("alienvault_otx", "ti-hit"));
        e.add_evidence(Evidence::new("whois", "registry-data"));
        e.add_evidence(Evidence::new("dns_resolver", "a-record"));
        let r = rule_au_015_threat_intel_hit(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert!(r[0].description.contains("alienvault_otx"));
        assert!(
            !r[0].description.contains("whois"),
            "non-TI evidence source must not appear in TI attribution: {}",
            r[0].description
        );
        assert!(
            !r[0].description.contains("dns_resolver"),
            "non-TI evidence source must not appear in TI attribution: {}",
            r[0].description
        );
    }

    #[test]
    fn au015_attribution_falls_back_when_source_unknown() {
        let e = tagged(EntityKind::Domain, "bad.example", &["threat-intel"]);
        let r = rule_au_015_threat_intel_hit(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert!(r[0].description.contains("curated threat-intel feed"));
    }

    #[test]
    fn au009_fires_on_username_with_stealer_log() {
        let e = tagged(EntityKind::Username, "alice", &["stealer-log"]);
        let r = rule_au_009_stealer_log(&[e], "s", 0);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn au016_fires_on_three_credentials() {
        let entities = vec![
            tagged(EntityKind::Credential, "u1@http://a.com", &["stealer-log"]),
            tagged(EntityKind::Credential, "u2@http://b.com", &["stealer-log"]),
            tagged(EntityKind::Credential, "u3@http://c.com", &["stealer-log"]),
        ];
        let r = rule_au_016_credential_cluster(&entities, "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity, Severity::Critical);
    }

    #[test]
    fn au016_no_fire_on_two_credentials() {
        let entities = vec![
            tagged(EntityKind::Credential, "u1@http://a.com", &["stealer-log"]),
            tagged(EntityKind::Credential, "u2@http://b.com", &["stealer-log"]),
        ];
        assert!(rule_au_016_credential_cluster(&entities, "s", 0).is_empty());
    }

    #[test]
    fn au017_fires_on_ransomware_plus_breach() {
        let e = tagged(EntityKind::Domain, "victim.com", &["ransomware-victim", "breach"]);
        let r = rule_au_017_ransomware_and_breach(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity, Severity::Critical);
    }

    #[test]
    fn au018_fires_on_stealer_family_spread() {
        let entities = vec![
            tagged(EntityKind::Email, "a@b.com", &["stealer:redline"]),
            tagged(EntityKind::Username, "alice", &["stealer:redline"]),
        ];
        let r = rule_au_018_stealer_family_spread(&entities, "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity, Severity::High);
    }

    #[test]
    fn evaluate_rules_total_count_15() {
        // Sanity: every rule wired into evaluate_rules. Build an entity
        // surface that fires AU-001/004/005/008/009/015 to confirm the
        // engine actually returns more than the original four firings.
        let mut email = Entity::new(EntityKind::Email, "x@y.com", 0.9, "s");
        email.add_evidence(Evidence::new("hudsonrock", "t"));
        email.add_evidence(Evidence::new("xposed_or_not", "t"));
        email.tag("stealer-log");
        let domain = tagged(
            EntityKind::Domain,
            "evil.example",
            &["malicious", "vulnerable", "threat-intel"],
        );
        let ip = tagged(EntityKind::IpAddress, "1.1.1.1", &["tor-exit"]);
        let firings = evaluate_rules(&[email, domain, ip], "s");
        let ids: HashSet<&str> = firings.iter().map(|c| c.rule_id.as_str()).collect();
        for expected in &["AU-001", "AU-004", "AU-005", "AU-008", "AU-009", "AU-015"] {
            assert!(
                ids.contains(expected),
                "expected {expected} in firings, got {ids:?}"
            );
        }
    }
}
