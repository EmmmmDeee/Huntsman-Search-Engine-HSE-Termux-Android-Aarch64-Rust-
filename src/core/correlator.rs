//! Correlator — rule-based post-scan analysis.
//!
//! Runs after all modules complete (engine hook). Loads the entities the
//! scan produced and evaluates a fixed set of declarative rules. Each
//! firing rule produces a [`Correlation`] record persisted alongside the
//! scan and emitted on the event bus as
//! [`EventKind::CorrelationFound`](crate::core::event::EventKind::CorrelationFound).
//!
//! Rules are deterministic — no LLMs, no fuzzy matching. They reflect
//! invariants the v0.4 module set can actually exhibit. Adding a new rule
//! is a 10-line addition to [`evaluate_rules`].

use std::collections::HashSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::core::{
    entity::{Entity, EntityKind, unix_now},
    error::Result,
};
use crate::storage::store::Store;

// ─── Severity ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Canonical, lowercase, stable identifier. This is the form serialised to
    /// JSON (via `#[serde(rename_all = "lowercase")]`), persisted in the
    /// SQLite `correlations.severity` column, and matched in the
    /// `correlations_for_scan` ORDER BY expression. Use this everywhere a
    /// machine-readable severity string is required — the [`Display`] impl
    /// produces an uppercase form for human-facing tables.
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

// ─── Correlation ─────────────────────────────────────────────────────────────

/// A single firing of a correlation rule.
///
/// Persisted in the `correlations` table; surfaced via CLI table output,
/// the HTTP API (`GET /api/v1/scans/{id}/correlations`), and the SPA.
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

// ─── Correlator ──────────────────────────────────────────────────────────────

pub struct Correlator {
    store: Arc<Store>,
}

impl Correlator {
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    /// Load entities for `scan_id`, evaluate every rule, persist firings.
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

// ─── Rules ───────────────────────────────────────────────────────────────────
//
// Adding a rule = append one function call to `evaluate_rules` returning
// `Vec<Correlation>`. Each rule is pure and side-effect-free.

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
    out
}

/// `AU-001` — same email appears in ≥2 distinct breach-tagged sources.
///
/// "Breach source" = any evidence whose `source` is in the breach-modules
/// allowlist below. Active with the current free-module set:
/// `hudsonrock` (stealer logs) + `xposed_or_not` (named-breach lookup)
/// → 2 sources, rule fires Critical when both confirm the same email.
/// Threshold stays at 2 (lowered from the spec's 3) to keep the rule
/// alive on free-only configurations; it can be restored to 3 once paid
/// breach modules (`hibp`, `dehashed`, `oathnet_pro`) land.
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
            out.push(Correlation {
                rule_id: "AU-001".into(),
                rule_name: "Multi-source breach corroboration".into(),
                severity: Severity::Critical,
                description: format!(
                    "{} found in {} breach sources: {}",
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

/// `AU-002` — identity cluster: at least one Email, Username, **and** Phone
/// were collected in the same scan, suggesting a coherent identity surface.
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

/// `AU-003` — any entity has `corroboration ≥ 3`, i.e. three or more
/// independent sources reported the same fact. Threshold lowered from the
/// spec's 5 → 3 so v0.4's 5-module set can actually fire it for popular
/// domains (e.g. dns_resolver + crtsh + hudsonrock on the same name).
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

/// `AU-010` — Infrastructure consensus: a single Domain or IpAddress has
/// evidence from ≥3 distinct module sources. Differs from `AU-003` in that
/// it counts module diversity at the **evidence** level rather than the
/// `corroboration` field (which only increments on merge). Catches the
/// "same entity discovered independently by infrastructure modules"
/// pattern that the v0.3+ expansion engine produces.
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

/// `AU-004` — Malicious infrastructure: any Domain or IpAddress carries
/// a `malicious` tag (set by `urlhaus`) — the highest-confidence signal
/// the malware-blocklist modules emit. One firing per offending entity.
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

/// `AU-005` — Anonymous-network exit: IpAddress tagged `tor-exit`,
/// `tor`, `anonymous-network` or `anonymous-vpn`. Together these cover
/// the `tor_exit_check`, `criminal_ip` and `ipqs` modules.
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

/// `AU-006` — Proxy / VPN fronting: IpAddress tagged `proxy` or `vpn`
/// (without also being a Tor exit — that's already AU-005). Source set:
/// `criminal_ip` + `ipqs`.
fn rule_au_006_proxy_vpn(entities: &[Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        .filter(|e| (e.has_tag("proxy") || e.has_tag("vpn")) && !e.has_tag("tor-exit"))
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

/// `AU-007` — High-risk reputation: IpAddress tagged with any of
/// `high-risk`, `high-risk-inbound`, `high-risk-outbound`, `recent-abuse`,
/// or `scanner`. Emitted by `ipqs` and `criminal_ip`.
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

/// `AU-008` — Exposed service: any Domain or IpAddress tagged
/// `vulnerable` (shodan), `ssh-exposed` (leakix), or `leak` (leakix).
/// One firing per offending entity.
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

/// `AU-009` — Stealer-log compromise: Email entity carrying the
/// `stealer-log` tag set by `hudsonrock`. Distinct from AU-001 because
/// it fires on a single (but highly specific) source.
fn rule_au_009_stealer_log(entities: &[Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email && e.has_tag("stealer-log"))
        .map(|e| Correlation {
            rule_id: "AU-009".into(),
            rule_name: "Stealer-log compromise".into(),
            severity: Severity::High,
            description: format!("Email {} observed in info-stealer log dumps", e.value),
            entity_uids: vec![e.uid.clone()],
            scan_id: scan_id.into(),
            ts,
        })
        .collect()
}

/// `AU-011` — Cross-platform username footprint: a Username entity
/// confirmed on three or more services. Counts distinct `platform:*`
/// tags emitted by `username_search`.
fn rule_au_011_cross_platform_username(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .filter_map(|e| {
            let platforms: HashSet<&str> = e
                .tags
                .iter()
                .filter_map(|t| t.strip_prefix("platform:"))
                .collect();
            if platforms.len() >= 3 {
                let mut names: Vec<&str> = platforms.into_iter().collect();
                names.sort_unstable();
                Some(Correlation {
                    rule_id: "AU-011".into(),
                    rule_name: "Cross-platform username footprint".into(),
                    severity: Severity::Medium,
                    description: format!(
                        "Username '{}' present on {} platforms: {}",
                        e.value,
                        names.len(),
                        names.join(", ")
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

/// `AU-012` — Identity-linked domain: a Domain tagged `personal-site`
/// (set by `github_user` when a user lists a personal site in their
/// profile) occurs together with the originating Username entity.
fn rule_au_012_identity_linked_domain(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let usernames: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .collect();
    if usernames.is_empty() {
        return Vec::new();
    }
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain && e.has_tag("personal-site"))
        .map(|d| {
            let mut uids = vec![d.uid.clone()];
            uids.extend(usernames.iter().map(|u| u.uid.clone()));
            Correlation {
                rule_id: "AU-012".into(),
                rule_name: "Identity-linked domain".into(),
                severity: Severity::Medium,
                description: format!(
                    "Personal site '{}' linked from {} username profile(s)",
                    d.value,
                    usernames.len()
                ),
                entity_uids: uids,
                scan_id: scan_id.into(),
                ts,
            }
        })
        .collect()
}

/// `AU-013` — Local-network discovery: two or more entities carry tags
/// indicating they were observed on the operator's own LAN
/// (`local-arp`, `local-interface`, `wifi-ap`). Useful for warning that
/// the scan included a passive sweep of the host's adjacent network.
fn rule_au_013_local_network_discovery(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const LAN_TAGS: &[&str] = &["local-arp", "local-interface", "wifi-ap"];
    let hits: Vec<&Entity> = entities
        .iter()
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

/// `AU-014` — Geolocation cluster: a Coordinates entity is corroborated
/// by two or more distinct geo-tagged sources (`wifi-observed`, plus
/// any `geoint`-tagged evidence). Useful when WiGLE + cell-survey +
/// GPS agree on a location.
fn rule_au_014_geo_cluster(entities: &[Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    const GEO_TAGS: &[&str] = &["geoint", "wifi-observed", "cell-tower"];
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Coordinates)
        .filter_map(|e| {
            let hits: Vec<&str> = GEO_TAGS.iter().copied().filter(|t| e.has_tag(t)).collect();
            // Also count distinct evidence sources — the canonical
            // multi-source cluster looks like (wigle + cell_survey + gps_fix)
            // all writing to the same Coordinates value.
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

/// `AU-015` — Threat-intel hit: any entity tagged `threat-intel`.
/// Sources include `alienvault_otx` and `threatfox` (and any future
/// curated-IOC feed that opts into the tag). Severity High because
/// these feeds are hand-curated.
fn rule_au_015_threat_intel_hit(entities: &[Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.has_tag("threat-intel"))
        .map(|e| {
            // Source attribution from evidence: every threat-intel
            // module sets its evidence.source, so this is the
            // authoritative feed name rather than a hard-coded one.
            const TI_SOURCES: &[&str] = &["alienvault_otx", "threatfox"];
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

// ─── Tests ───────────────────────────────────────────────────────────────────

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

    #[test]
    fn au011_fires_on_three_platforms() {
        let e = tagged(
            EntityKind::Username,
            "alice",
            &["platform:github", "platform:reddit", "platform:twitter"],
        );
        let r = rule_au_011_cross_platform_username(&[e], "s", 0);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn au011_no_fire_on_two_platforms() {
        let e = tagged(
            EntityKind::Username,
            "alice",
            &["platform:github", "platform:reddit"],
        );
        assert!(rule_au_011_cross_platform_username(&[e], "s", 0).is_empty());
    }

    #[test]
    fn au012_fires_when_username_and_personal_site_present() {
        let entities = vec![
            tagged(EntityKind::Username, "alice", &[]),
            tagged(EntityKind::Domain, "alice.example", &["personal-site"]),
        ];
        let r = rule_au_012_identity_linked_domain(&entities, "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].entity_uids.len(), 2);
    }

    #[test]
    fn au012_no_fire_without_username() {
        let entities = vec![tagged(
            EntityKind::Domain,
            "alice.example",
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
        let mut e = Entity::new(EntityKind::Coordinates, "0,0", 0.9, "s");
        e.add_evidence(Evidence::new("wigle", "test"));
        e.add_evidence(Evidence::new("cell_survey", "test"));
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
    fn au015_attribution_falls_back_when_source_unknown() {
        let e = tagged(EntityKind::Domain, "bad.example", &["threat-intel"]);
        let r = rule_au_015_threat_intel_hit(&[e], "s", 0);
        assert_eq!(r.len(), 1);
        assert!(r[0].description.contains("curated threat-intel feed"));
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
