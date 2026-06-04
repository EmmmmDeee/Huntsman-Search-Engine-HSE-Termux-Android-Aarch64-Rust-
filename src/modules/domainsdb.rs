//! domainsdb.info — free domain registration search (no key, unlimited).
//!
//! Endpoint: GET https://api.domainsdb.info/v1/domains/search?domain={query}&zone={tld}&limit=20
//!
//! Searches registered domains matching a keyword — useful for finding
//! related/typosquatting domains from an Organisation or FullName target.
//!
//! Both response fields are used: `update_date` is surfaced (a recently-updated
//! look-alike domain is a live-threat signal), and the per-zone `total` gates a
//! `broad-match` dampening — a keyword that matches hundreds of domains in one
//! TLD is generic, so those hits are weakly related to the target and their
//! confidence is reduced. The per-entry mapping lives in the pure
//! [`build_domain_entity`] so it is unit-tested without a live API.

use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "domainsdb";

/// A keyword matching more than this many domains in a single TLD is generic;
/// its hits are keyword coincidences, not target-specific, so they are tagged
/// `broad-match` and down-weighted.
const BROAD_MATCH_THRESHOLD: u64 = 200;

#[derive(Deserialize)]
struct DbResp {
    #[serde(default)]
    domains: Vec<DomainEntry>,
    #[serde(default)]
    total: Option<u64>,
}

#[derive(Deserialize)]
struct DomainEntry {
    #[serde(default)]
    domain: String,
    #[serde(default)]
    create_date: Option<String>,
    #[serde(default)]
    update_date: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default, rename = "isDead")]
    is_dead: Option<String>,
}

/// Trimmed, non-empty view of an optional string field.
fn nonempty(o: &Option<String>) -> Option<&str> {
    o.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// Map one registered-domain record to a `Domain` entity. **Pure** (no
/// network/IO). `broad_match` (from the zone's `total` exceeding
/// [`BROAD_MATCH_THRESHOLD`]) flags + dampens generic keyword coincidences.
/// Returns `None` for a blank domain.
fn build_domain_entity(entry: &DomainEntry, broad_match: bool, scan_id: &str) -> Option<Entity> {
    let domain = entry.domain.trim();
    if domain.is_empty() {
        return None;
    }
    let is_dead = entry.is_dead.as_deref() == Some("True");
    // Live domain 0.55, dead 0.35; a broad keyword match is weakly related to
    // the target, so dampen it (0.7×).
    let mut conf = if is_dead { 0.35 } else { 0.55 };
    if broad_match {
        conf *= 0.7;
    }

    let mut e = Entity::new(EntityKind::Domain, domain, conf, scan_id);
    e.tag("domainsdb");
    if is_dead {
        e.tag("dead-domain");
    }
    if broad_match {
        e.tag("broad-match");
    }
    let mut ev = Evidence::new(SRC, format!("Registered domain: {domain}"));
    if let Some(d) = nonempty(&entry.create_date) {
        ev = ev.with_attr("created", d);
    }
    if let Some(d) = nonempty(&entry.update_date) {
        ev = ev.with_attr("updated", d);
    }
    if let Some(c) = nonempty(&entry.country) {
        ev = ev.with_attr("country", c);
    }
    e.add_evidence(ev);
    Some(e)
}

pub struct DomainsDb;

#[async_trait]
impl Module for DomainsDb {
    fn name(&self) -> &'static str {
        "domainsdb"
    }
    fn description(&self) -> &'static str {
        "Domain registration search via domainsdb.info (free, no key)"
    }
    fn priority(&self) -> u8 {
        19
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Domain | TargetKind::Organisation | TargetKind::FullName
        )
    }
    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = match target.kind {
            TargetKind::Domain => {
                let base = target
                    .value
                    .trim()
                    .split('.')
                    .next()
                    .unwrap_or("")
                    .to_lowercase();
                if base.len() < 3 {
                    return Ok(ModuleResult::new());
                }
                base
            }
            TargetKind::Organisation | TargetKind::FullName => {
                let cleaned: String = target
                    .value
                    .to_lowercase()
                    .chars()
                    .filter(|c| c.is_alphanumeric() || *c == ' ')
                    .collect();
                let parts: Vec<&str> = cleaned.split_whitespace().collect();
                if parts.is_empty() {
                    return Ok(ModuleResult::new());
                }
                parts.join("")
            }
            _ => return Ok(ModuleResult::new()),
        };

        let mut result = ModuleResult::new();
        let mut seen: HashSet<String> = HashSet::new();

        for zone in &["com", "net", "org", "io", "com.au", "co.uk"] {
            if ctx.cancel.is_cancelled() {
                break;
            }
            let url = format!(
                "https://api.domainsdb.info/v1/domains/search?domain={}&zone={zone}&limit=20",
                crate::util::http::urlencode(&query)
            );
            let resp = ctx
                .http
                .get(&url)
                .timeout(std::time::Duration::from_secs(8))
                .send()
                .await;
            let Ok(r) = resp else { continue };
            if !r.status().is_success() {
                continue;
            }
            let Ok(data) = r.json::<DbResp>().await else {
                continue;
            };

            let broad_match = data.total.is_some_and(|t| t > BROAD_MATCH_THRESHOLD);
            for entry in &data.domains {
                if !seen.insert(entry.domain.trim().to_lowercase()) {
                    continue;
                }
                if let Some(e) = build_domain_entity(entry, broad_match, &ctx.scan_id) {
                    result.push(e);
                }
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(json: &str) -> DomainEntry {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn accepts_domain_org_name() {
        let m = DomainsDb;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme")));
        assert!(m.accepts(&Target::new(TargetKind::FullName, "John Doe")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
    }

    #[test]
    fn cost_is_free() {
        assert!(matches!(
            DomainsDb.cost(),
            crate::core::module::ModuleCost::Free
        ));
    }

    #[test]
    fn deser() {
        let j = r#"{"domains":[{"domain":"example.com","create_date":"2020-01-01","isDead":"False"}],"total":1}"#;
        let r: DbResp = serde_json::from_str(j).unwrap();
        assert_eq!(r.domains.len(), 1);
        assert_eq!(r.total, Some(1));
    }

    #[test]
    fn live_domain_surfaces_created_and_updated() {
        let e = build_domain_entity(
            &entry(
                r#"{"domain":"acme-corp.com","create_date":"2019-03-01",
                    "update_date":"2024-06-15","country":"US","isDead":"False"}"#,
            ),
            false,
            "s",
        )
        .unwrap();
        assert_eq!(e.kind, EntityKind::Domain);
        assert!(e.has_tag("domainsdb") && !e.has_tag("dead-domain") && !e.has_tag("broad-match"));
        assert!((e.confidence - 0.55).abs() < 1e-9);
        let ev = &e.evidence[0];
        assert_eq!(
            ev.attributes.get("created").map(String::as_str),
            Some("2019-03-01")
        );
        // `updated` — the field the struct-level allow used to bury.
        assert_eq!(
            ev.attributes.get("updated").map(String::as_str),
            Some("2024-06-15")
        );
        assert_eq!(ev.attributes.get("country").map(String::as_str), Some("US"));
    }

    #[test]
    fn dead_domain_is_tagged_and_lower_confidence() {
        let e = build_domain_entity(
            &entry(r#"{"domain":"gone.com","isDead":"True"}"#),
            false,
            "s",
        )
        .unwrap();
        assert!(e.has_tag("dead-domain"));
        assert!((e.confidence - 0.35).abs() < 1e-9);
    }

    #[test]
    fn broad_match_dampens_and_tags() {
        // A generic keyword (high `total`) → broad-match: tagged + 0.7× damped.
        let e = build_domain_entity(&entry(r#"{"domain":"john-smith.com"}"#), true, "s").unwrap();
        assert!(e.has_tag("broad-match"));
        assert!((e.confidence - 0.55 * 0.7).abs() < 1e-9);
        // Dead + broad stacks both penalties.
        let dead = build_domain_entity(&entry(r#"{"domain":"x.com","isDead":"True"}"#), true, "s")
            .unwrap();
        assert!((dead.confidence - 0.35 * 0.7).abs() < 1e-9);
    }

    #[test]
    fn blank_domain_is_skipped() {
        assert!(build_domain_entity(&entry(r#"{"domain":"  "}"#), false, "s").is_none());
    }
}
