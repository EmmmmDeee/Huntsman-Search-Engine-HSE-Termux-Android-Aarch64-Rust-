//! RDAP — Registration Data Access Protocol for domains. Free, no key.
//!
//! Endpoint: `https://rdap.org/domain/{domain}`
//!
//! Complements `whois` with structured registry data: status flags,
//! events (registration / expiration / last-changed), nameservers,
//! and contact roles. The rdap.org redirector resolves the right
//! bootstrap registry for any TLD, so we don't need to maintain our
//! own bootstrap table.
//!
//! Per project invariants we surface contact role names (`registrant`,
//! `administrative`, etc.) but never raw contact PII (email/phone/postal).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

#[derive(Deserialize)]
struct RdapResp {
    #[serde(default)]
    handle: Option<String>,
    #[serde(default)]
    status: Vec<String>,
    #[serde(default)]
    events: Vec<Event>,
    #[serde(default)]
    entities: Vec<EntityRef>,
    #[serde(default)]
    nameservers: Vec<Nameserver>,
    #[serde(default, rename = "secureDNS")]
    secure_dns: Option<SecureDns>,
}

#[derive(Deserialize)]
struct Event {
    #[serde(default, rename = "eventAction")]
    action: Option<String>,
    #[serde(default, rename = "eventDate")]
    date: Option<String>,
}

#[derive(Deserialize)]
struct EntityRef {
    #[serde(default)]
    roles: Vec<String>,
}

#[derive(Deserialize)]
struct Nameserver {
    #[serde(default, rename = "ldhName")]
    name: Option<String>,
}

#[derive(Deserialize)]
struct SecureDns {
    #[serde(default, rename = "delegationSigned")]
    delegation_signed: Option<bool>,
}

pub struct RdapDomain;

#[async_trait]
impl Module for RdapDomain {
    fn name(&self) -> &'static str {
        "rdap_domain"
    }

    fn priority(&self) -> u8 {
        // Slightly below whois — same registry layer, prefer whois as the
        // primary record holder when both run.
        49
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }

    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let domain = target.value.trim();
        if domain.is_empty() {
            return Ok(ModuleResult::new());
        }

        let url = format!("https://rdap.org/domain/{domain}");
        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/rdap+json")
            .send()
            .await
            .map_err(|e| Error::module("rdap_domain", e.to_string()))?;

        let status = resp.status();
        if status.as_u16() == 404 {
            // Unregistered or not-in-rdap-bootstrap — clean no-result.
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
            return Err(Error::module(
                "rdap_domain",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let body: RdapResp = resp
            .json()
            .await
            .map_err(|e| Error::module("rdap_domain", e.to_string()))?;

        let mut entity = Entity::new(EntityKind::Domain, domain, 0.88, &ctx.scan_id);
        entity.tag("rdap");
        let mut ev = Evidence::new("rdap_domain", format!("RDAP record for {domain}"));

        if let Some(h) = body.handle.as_deref() {
            ev = ev.with_attr("handle", h);
        }
        if !body.status.is_empty() {
            ev = ev.with_attr("status", body.status.join(","));
            for s in &body.status {
                entity.tag(format!("status:{s}"));
            }
        }
        for e in &body.events {
            if let (Some(action), Some(date)) = (e.action.as_deref(), e.date.as_deref()) {
                ev = ev.with_attr(format!("event_{action}"), date);
            }
        }
        if !body.entities.is_empty() {
            let roles: std::collections::BTreeSet<&str> = body
                .entities
                .iter()
                .flat_map(|e| e.roles.iter().map(String::as_str))
                .collect();
            if !roles.is_empty() {
                ev = ev.with_attr(
                    "contact_roles",
                    roles.into_iter().collect::<Vec<_>>().join(","),
                );
            }
        }
        if let Some(sd) = &body.secure_dns
            && let Some(signed) = sd.delegation_signed
        {
            entity.tag(if signed {
                "dnssec:signed"
            } else {
                "dnssec:unsigned"
            });
            ev = ev.with_attr("dnssec_signed", signed.to_string());
        }
        let ns_names: Vec<&str> = body
            .nameservers
            .iter()
            .filter_map(|n| n.name.as_deref())
            .collect();
        if !ns_names.is_empty() {
            ev = ev.with_attr("nameservers", ns_names.join(","));
        }
        entity.add_evidence(ev);

        let mut result = ModuleResult::new();
        result.push(entity);

        // One Domain entity per nameserver — complements whois `whois-ns`.
        for n in body.nameservers {
            let Some(name) = n.name else { continue };
            let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
            if name.is_empty() {
                continue;
            }
            let mut ns = Entity::new(EntityKind::Domain, &name, 0.80, &ctx.scan_id);
            ns.tag("rdap-ns");
            ns.tag("ns");
            ns.add_evidence(
                Evidence::new("rdap_domain", format!("RDAP nameserver for {domain}"))
                    .with_attr("parent", domain),
            );
            result.push(ns);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_domain() {
        let m = RdapDomain;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }
}
