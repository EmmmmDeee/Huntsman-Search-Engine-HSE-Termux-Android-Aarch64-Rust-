//! domainsdb.info — free domain registration search (no key, unlimited).
//!
//! Endpoint: GET https://api.domainsdb.info/v1/domains/search?domain={query}&zone={tld}&limit=50
//!
//! Searches registered domains matching a keyword. Useful for finding
//! related/typosquatting domains from an Organisation or FullName target.

use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "domainsdb";

#[derive(Deserialize)]
struct DbResp {
    #[serde(default)]
    domains: Vec<DomainEntry>,
    #[serde(default)]
    #[allow(dead_code)]
    total: Option<u64>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
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

            for entry in &data.domains {
                if entry.domain.is_empty() || !seen.insert(entry.domain.clone()) {
                    continue;
                }
                let is_dead = entry.is_dead.as_deref() == Some("True");
                let conf = if is_dead { 0.35 } else { 0.55 };
                let mut e = Entity::new(EntityKind::Domain, &entry.domain, conf, &ctx.scan_id);
                e.tag("domainsdb");
                if is_dead {
                    e.tag("dead-domain");
                }
                let mut ev = Evidence::new(SRC, format!("Registered domain: {}", entry.domain));
                if let Some(d) = entry.create_date.as_deref() {
                    ev = ev.with_attr("created", d);
                }
                if let Some(c) = entry.country.as_deref() {
                    ev = ev.with_attr("country", c);
                }
                e.add_evidence(ev);
                result.push(e);
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    }
}
