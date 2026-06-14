//! domainsdb.info — free domain registration search (no key, unlimited).
//!
//! Endpoint: `GET https://api.domainsdb.info/v1/domains/search?domain={query}&zone={tld}&limit=20`
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
use futures::future::join_all;
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

use crate::util::str_util::nonempty;

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

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Domain/passive-DNS database — ATT&CK DNS/Passive DNS (T1596.001).
        &["T1596.001"]
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

        let encoded = crate::util::http::urlencode(&query);
        let futures = ["com", "net", "org", "io", "com.au", "co.uk"].map(|zone| {
            let url = format!(
                "https://api.domainsdb.info/v1/domains/search?domain={encoded}&zone={zone}&limit=20"
            );
            let http = ctx.http.clone();
            async move {
                let resp = http
                    .get(&url)
                    .timeout(std::time::Duration::from_secs(8))
                    .send()
                    .await;
                let Ok(r) = resp else { return None };
                if !r.status().is_success() {
                    return None;
                }
                crate::util::http::json_scanned::<DbResp>(r, SRC).await.ok()
            }
        });

        let responses = join_all(futures).await;
        for data in responses.into_iter().flatten() {
            let broad_match = data.total.is_some_and(|t| t > BROAD_MATCH_THRESHOLD);
            result.extend(data.domains.iter().filter_map(|entry| {
                if !seen.insert(entry.domain.trim().to_lowercase()) {
                    return None;
                }
                build_domain_entity(entry, broad_match, &ctx.scan_id)
            }));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
