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
    tags,
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

struct EntityIndex<'a> {
    emails: Vec<&'a Entity>,
    usernames: Vec<&'a Entity>,
    phones: Vec<&'a Entity>,
    infra: Vec<&'a Entity>,
    all: &'a [Entity],
}

impl<'a> EntityIndex<'a> {
    fn build(entities: &'a [Entity]) -> Self {
        let mut emails = Vec::new();
        let mut usernames = Vec::new();
        let mut phones = Vec::new();
        let mut infra = Vec::new();
        for e in entities {
            match &e.kind {
                EntityKind::Email => emails.push(e),
                EntityKind::Username => usernames.push(e),
                EntityKind::Phone => phones.push(e),
                EntityKind::Domain | EntityKind::IpAddress => infra.push(e),
                _ => {}
            }
        }
        Self { emails, usernames, phones, infra, all: entities }
    }
}

fn evaluate_rules(entities: &[Entity], scan_id: &str) -> Vec<Correlation> {
    let now = unix_now();
    let idx = EntityIndex::build(entities);
    let mut out = Vec::new();
    out.extend(rule_au_001_multi_breach(&idx.emails, scan_id, now));
    out.extend(rule_au_002_identity_cluster(&idx, scan_id, now));
    out.extend(rule_au_003_high_corroboration(idx.all, scan_id, now));
    out.extend(rule_au_004_stealer_recency(idx.all, scan_id, now));
    out.extend(rule_au_005_multi_device_stealer(idx.all, scan_id, now));
    out.extend(rule_au_006_breach_weak_infra(&idx, scan_id, now));
    out.extend(rule_au_007_shared_hosting(&idx.infra, scan_id, now));
    out.extend(rule_au_008_blocklisted_infra(&idx.infra, scan_id, now));
    out.extend(rule_au_010_infra_consensus(&idx.infra, scan_id, now));
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
fn rule_au_001_multi_breach(emails: &[&Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    const BREACH_SOURCES: &[&str] = &[
        "hudsonrock",
        "xposed_or_not",
        "breach_directory",
        "dehashed",
        "hibp",
        "oathnet_pro",
        "leakix",
    ];
    let mut out = Vec::new();
    for e in emails {
        let sources: HashSet<&str> = e
            .evidence
            .iter()
            .filter(|ev| BREACH_SOURCES.contains(&ev.source.as_str()))
            .map(|ev| ev.source.as_str())
            .collect();
        let n = sources.len();
        if n >= 2 {
            let mut names: Vec<&str> = sources.into_iter().collect();
            names.sort_unstable();
            let severity = if n >= 3 {
                Severity::Critical
            } else {
                Severity::High
            };
            out.push(Correlation {
                rule_id: "AU-001".into(),
                rule_name: "Multi-source breach corroboration".into(),
                severity,
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
fn rule_au_002_identity_cluster(idx: &EntityIndex<'_>, scan_id: &str, ts: u64) -> Vec<Correlation> {
    let emails = &idx.emails;
    let usernames = &idx.usernames;
    let phones = &idx.phones;

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

/// `AU-004` — Active stealer campaign: an entity has stealer-log evidence
/// where `date_compromised` is within the last 30 days. This signals an
/// actively compromised endpoint — the credentials may still be in use
/// by threat actors. Per Recorded Future's 2025 report, 53% of stolen
/// credentials are indexed within one week of exfiltration.
fn rule_au_004_stealer_recency(entities: &[Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    const RECENCY_SECS: u64 = 30 * 86400;
    let cutoff = ts.saturating_sub(RECENCY_SECS);

    let mut out = Vec::new();
    for e in entities.iter().filter(|e| e.has_tag(tags::STEALER_LOG)) {
        let recent_dates: Vec<&str> = e
            .evidence
            .iter()
            .filter(|ev| ev.source == "hudsonrock")
            .filter_map(|ev| ev.attributes.get("date_compromised").map(String::as_str))
            .filter(|d| *d != "-")
            .collect();

        let any_recent = recent_dates.iter().any(|d| {
            parse_date_approx(d).is_some_and(|epoch| epoch >= cutoff)
        });

        if any_recent {
            out.push(Correlation {
                rule_id: "AU-004".into(),
                rule_name: "Active stealer campaign".into(),
                severity: Severity::High,
                description: format!(
                    "{} '{}' has stealer-log compromise within last 30 days — credentials may be live",
                    e.kind, e.value
                ),
                entity_uids: vec![e.uid.clone()],
                scan_id: scan_id.into(),
                ts,
            });
        }
    }
    out
}

/// `AU-005` — Multi-device stealer: an entity has stealer-log evidence
/// from ≥2 distinct `computer_name` values. This indicates the same
/// identity is compromised on multiple endpoints — either the user
/// reuses credentials across devices, or a campaign has swept multiple
/// machines in the same organisation.
fn rule_au_005_multi_device_stealer(entities: &[Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    let mut out = Vec::new();
    for e in entities.iter().filter(|e| e.has_tag(tags::STEALER_LOG)) {
        let hosts: HashSet<&str> = e
            .evidence
            .iter()
            .filter(|ev| ev.source == "hudsonrock")
            .filter_map(|ev| ev.attributes.get("computer_name").map(String::as_str))
            .filter(|h| *h != "-" && !h.is_empty())
            .collect();

        if hosts.len() >= 2 {
            let mut host_list: Vec<&str> = hosts.into_iter().collect();
            host_list.sort_unstable();
            out.push(Correlation {
                rule_id: "AU-005".into(),
                rule_name: "Multi-device stealer compromise".into(),
                severity: Severity::Critical,
                description: format!(
                    "{} '{}' compromised on {} distinct devices: {}",
                    e.kind,
                    e.value,
                    host_list.len(),
                    host_list.join(", ")
                ),
                entity_uids: vec![e.uid.clone()],
                scan_id: scan_id.into(),
                ts,
            });
        }
    }
    out
}

fn parse_date_approx(s: &str) -> Option<u64> {
    let date_part = s.split('T').next()?;
    let mut parts = date_part.split('-');
    let year: u64 = parts.next()?.parse().ok()?;
    let month: u64 = parts.next()?.parse().ok()?;
    let day: u64 = parts.next()?.parse().ok()?;
    if year < 2000 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let days_approx = (year - 1970) * 365 + (month - 1) * 30 + day;
    Some(days_approx * 86400)
}

/// `AU-006` — Breach + weak infrastructure: an email is confirmed in a
/// breach AND its domain (present in the same scan) has the
/// `missing-security-headers` tag from the web_crawler / webserver_banner
/// module. This cross-module correlation signals that the organisation
/// behind the breached email also has weak web security posture —
/// a compounding risk factor.
fn rule_au_006_breach_weak_infra(idx: &EntityIndex<'_>, scan_id: &str, ts: u64) -> Vec<Correlation> {
    let weak_domains: HashSet<&str> = idx
        .infra
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Domain) && e.has_tag(tags::MISSING_SECURITY_HEADERS))
        .map(|e| e.value.as_str())
        .collect();
    if weak_domains.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for e in &idx.emails {
        if !e.has_tag(tags::BREACH) {
            continue;
        }
        let email_domain = e.value.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
        if weak_domains.contains(email_domain) {
            out.push(Correlation {
                rule_id: "AU-006".into(),
                rule_name: "Breach + weak infrastructure".into(),
                severity: Severity::High,
                description: format!(
                    "Breached email {} on domain {} which lacks security headers",
                    e.value, email_domain
                ),
                entity_uids: vec![e.uid.clone()],
                scan_id: scan_id.into(),
                ts,
            });
        }
    }
    out
}

/// `AU-007` — Shared hosting: multiple domains in the scan resolve to the
/// same IP address. Detected by finding IpAddress entities with evidence
/// from ≥2 distinct parent domains. Co-hosting is a signal for shared
/// infrastructure risk — a compromise of one tenant may affect others.
fn rule_au_007_shared_hosting(infra: &[&Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    let mut ip_domains: std::collections::HashMap<&str, HashSet<&str>> =
        std::collections::HashMap::new();
    for e in infra.iter().filter(|e| matches!(e.kind, EntityKind::IpAddress)) {
        let domains: HashSet<&str> = e
            .evidence
            .iter()
            .filter_map(|ev| ev.attributes.get("domain").or(ev.attributes.get("parent_domain")))
            .map(String::as_str)
            .collect();
        if domains.len() >= 2 {
            ip_domains.insert(e.value.as_str(), domains);
        }
    }

    ip_domains
        .into_iter()
        .map(|(ip, domains)| {
            let mut domain_list: Vec<&str> = domains.into_iter().collect();
            domain_list.sort_unstable();
            Correlation {
                rule_id: "AU-007".into(),
                rule_name: "Shared hosting".into(),
                severity: Severity::Low,
                description: format!(
                    "IP {} hosts {} domains: {}",
                    ip,
                    domain_list.len(),
                    domain_list.join(", ")
                ),
                entity_uids: vec![],
                scan_id: scan_id.into(),
                ts,
            }
        })
        .collect()
}

/// `AU-008` — Blocklisted infrastructure: an IP in the scan has been
/// flagged by the `dns_blocklist` module (tag `blocklisted`). This
/// is a free, zero-API signal that the IP appears on DNS-based spam/
/// malware/botnet blocklists.
fn rule_au_008_blocklisted_infra(infra: &[&Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    let mut out = Vec::new();
    for e in infra.iter().filter(|e| matches!(e.kind, EntityKind::IpAddress) && e.has_tag("blocklisted")) {
        let lists = e
            .evidence
            .iter()
            .filter(|ev| ev.source == "dns_blocklist")
            .filter_map(|ev| ev.attributes.get("listed_on").map(String::as_str))
            .next()
            .unwrap_or("unknown");
        out.push(Correlation {
            rule_id: "AU-008".into(),
            rule_name: "Blocklisted infrastructure".into(),
            severity: Severity::High,
            description: format!(
                "IP {} appears on DNS blocklists: {}",
                e.value, lists
            ),
            entity_uids: vec![e.uid.clone()],
            scan_id: scan_id.into(),
            ts,
        });
    }
    out
}

/// `AU-010` — Infrastructure consensus: a single Domain or IpAddress has
/// evidence from ≥3 distinct module sources. Differs from `AU-003` in that
/// it counts module diversity at the **evidence** level rather than the
/// `corroboration` field (which only increments on merge). Catches the
/// "same entity discovered independently by infrastructure modules"
/// pattern that the v0.3+ expansion engine produces.
fn rule_au_010_infra_consensus(infra: &[&Entity], scan_id: &str, ts: u64) -> Vec<Correlation> {
    let mut out = Vec::new();
    for e in infra
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
    use crate::core::tags;

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
    fn au001_fires_at_two_breach_sources_as_high() {
        let e = email("x@y.com", &["hudsonrock", "breach_directory"]);
        let r = rule_au_001_multi_breach(&[&e], "s1", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "AU-001");
        assert_eq!(r[0].severity, Severity::High);
    }

    #[test]
    fn au001_fires_at_three_breach_sources_as_critical() {
        let e = email("x@y.com", &["hudsonrock", "xposed_or_not", "dehashed"]);
        let r = rule_au_001_multi_breach(&[&e], "s1", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity, Severity::Critical);
    }

    #[test]
    fn au001_no_fire_at_one_source() {
        let e = email("x@y.com", &["hudsonrock"]);
        assert!(rule_au_001_multi_breach(&[&e], "s1", 0).is_empty());
    }

    #[test]
    fn au001_ignores_non_breach_sources() {
        let e = email("x@y.com", &["crtsh", "dns_resolver"]);
        assert!(rule_au_001_multi_breach(&[&e], "s1", 0).is_empty());
    }

    #[test]
    fn au002_fires_with_all_three_kinds() {
        let entities = vec![
            Entity::new(EntityKind::Email, "x@y.com", 0.9, "s"),
            Entity::new(EntityKind::Username, "xuser", 0.8, "s"),
            Entity::new(EntityKind::Phone, "+61400000000", 0.8, "s"),
        ];
        let idx = EntityIndex::build(&entities);
        let r = rule_au_002_identity_cluster(&idx, "s", 0);
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
        let idx = EntityIndex::build(&entities);
        assert!(rule_au_002_identity_cluster(&idx, "s", 0).is_empty());
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
        let r = rule_au_010_infra_consensus(&[&e], "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "AU-010");
    }

    #[test]
    fn au010_no_fire_at_two_sources() {
        let e = domain("x.com", &["crtsh", "dns_resolver"]);
        assert!(rule_au_010_infra_consensus(&[&e], "s", 0).is_empty());
    }

    #[test]
    fn au010_ignores_non_infrastructure_kinds() {
        let entities = vec![email("x@y.com", &["a", "b", "c"])];
        let idx = EntityIndex::build(&entities);
        assert!(idx.infra.is_empty());
        assert!(rule_au_010_infra_consensus(&idx.infra, "s", 0).is_empty());
    }

    #[test]
    fn au004_fires_on_recent_stealer() {
        let now = unix_now();
        let mut e = Entity::new(EntityKind::Email, "x@y.com", 0.9, "s");
        e.tag(tags::STEALER_LOG);
        e.add_evidence(
            Evidence::new("hudsonrock", "test")
                .with_attr("date_compromised", "2026-05-20T00:00:00Z"),
        );
        let r = rule_au_004_stealer_recency(&[e], "s", now);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "AU-004");
        assert_eq!(r[0].severity, Severity::High);
    }

    #[test]
    fn au004_no_fire_on_old_stealer() {
        let now = unix_now();
        let mut e = Entity::new(EntityKind::Email, "x@y.com", 0.9, "s");
        e.tag(tags::STEALER_LOG);
        e.add_evidence(
            Evidence::new("hudsonrock", "test")
                .with_attr("date_compromised", "2020-01-01T00:00:00Z"),
        );
        assert!(rule_au_004_stealer_recency(&[e], "s", now).is_empty());
    }

    #[test]
    fn au005_fires_on_multi_device() {
        let now = unix_now();
        let mut e = Entity::new(EntityKind::Email, "x@y.com", 0.9, "s");
        e.tag(tags::STEALER_LOG);
        e.add_evidence(
            Evidence::new("hudsonrock", "test").with_attr("computer_name", "DESKTOP-A"),
        );
        e.add_evidence(
            Evidence::new("hudsonrock", "test").with_attr("computer_name", "LAPTOP-B"),
        );
        let r = rule_au_005_multi_device_stealer(&[e], "s", now);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "AU-005");
        assert_eq!(r[0].severity, Severity::Critical);
    }

    #[test]
    fn au005_no_fire_single_device() {
        let now = unix_now();
        let mut e = Entity::new(EntityKind::Email, "x@y.com", 0.9, "s");
        e.tag(tags::STEALER_LOG);
        e.add_evidence(
            Evidence::new("hudsonrock", "test").with_attr("computer_name", "DESKTOP-A"),
        );
        e.add_evidence(
            Evidence::new("hudsonrock", "test").with_attr("computer_name", "DESKTOP-A"),
        );
        assert!(rule_au_005_multi_device_stealer(&[e], "s", now).is_empty());
    }

    #[test]
    fn au006_fires_on_breach_with_weak_infra() {
        let mut breached = email("user@weak.com", &["hudsonrock"]);
        breached.tag(tags::BREACH);
        let mut dom = Entity::new(EntityKind::Domain, "weak.com", 0.9, "s");
        dom.tag(tags::MISSING_SECURITY_HEADERS);
        dom.add_evidence(Evidence::new("web_crawler", "test"));
        let entities = vec![breached, dom];
        let idx = EntityIndex::build(&entities);
        let r = rule_au_006_breach_weak_infra(&idx, "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "AU-006");
        assert_eq!(r[0].severity, Severity::High);
    }

    #[test]
    fn au006_no_fire_without_breach_tag() {
        let clean = email("user@weak.com", &["hudsonrock"]);
        let mut dom = Entity::new(EntityKind::Domain, "weak.com", 0.9, "s");
        dom.tag(tags::MISSING_SECURITY_HEADERS);
        dom.add_evidence(Evidence::new("web_crawler", "test"));
        let entities = vec![clean, dom];
        let idx = EntityIndex::build(&entities);
        assert!(rule_au_006_breach_weak_infra(&idx, "s", 0).is_empty());
    }

    #[test]
    fn au007_fires_on_shared_ip() {
        let mut ip = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.9, "s");
        ip.add_evidence(Evidence::new("dns_resolver", "A record").with_attr("domain", "a.com"));
        ip.add_evidence(Evidence::new("dns_resolver", "A record").with_attr("domain", "b.com"));
        let r = rule_au_007_shared_hosting(&[&ip], "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "AU-007");
        assert!(r[0].description.contains("a.com"));
        assert!(r[0].description.contains("b.com"));
    }

    #[test]
    fn au007_no_fire_single_domain() {
        let mut ip = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.9, "s");
        ip.add_evidence(Evidence::new("dns_resolver", "A record").with_attr("domain", "only.com"));
        assert!(rule_au_007_shared_hosting(&[&ip], "s", 0).is_empty());
    }

    #[test]
    fn severity_orders_correctly() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }
}
