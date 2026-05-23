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
    out.extend(rule_au_010_infra_consensus(entities, scan_id, now));
    out
}

/// `AU-001` — same email appears in ≥2 distinct breach-tagged sources.
///
/// "Breach source" = any evidence whose `source` is in the breach-modules
/// allowlist below. With v0.4's module set, only `hudsonrock` populates
/// this for emails — the rule stays dormant until v0.5 adds more breach
/// modules (`breach_directory`, `dehashed`, `hibp` etc.). Threshold lowered
/// from spec's 3 → 2 so a small scan can demonstrate it once v0.5 ships.
fn rule_au_001_multi_breach(entities: &[Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    const BREACH_SOURCES: &[&str] = &[
        "hudsonrock",
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
}
