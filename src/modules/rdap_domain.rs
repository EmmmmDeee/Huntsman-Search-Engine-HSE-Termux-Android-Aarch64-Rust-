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
use crate::util::http::{error_snippet, urlencode};

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

/// Replace each run of ASCII whitespace with a single `-` so RDAP's
/// human-readable status phrases ("client transfer prohibited") fit
/// the project's whitespace-free tag convention.
fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_dash = false;
    for ch in s.chars() {
        if ch.is_ascii_whitespace() {
            if !prev_dash {
                out.push('-');
                prev_dash = true;
            }
        } else {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        }
    }
    out
}

pub struct RdapDomain;

#[async_trait]
impl Module for RdapDomain {
    fn name(&self) -> &'static str {
        "rdap_domain"
    }

    fn priority(&self) -> u8 {
        // One step below whois (32) so whois — the canonical record
        // holder — runs first; rdap fills structured gaps after.
        // (Engine sorts highest-priority-first.)
        31
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }

    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(domain) = target.trimmed() else {
            return Ok(ModuleResult::new());
        };

        // urlencode the path segment defensively: TargetKind::Domain
        // values are already DNS-label-shape per validation, but
        // encoding makes us robust to upstream changes and consistent
        // with the rest of the module set.
        let url = format!("https://rdap.org/domain/{}", urlencode(domain));
        // ctx.http carries a 3 s default timeout (MODULE_TIMEOUT_MS),
        // shorter than this module's declared 15 s budget; an explicit
        // per-request timeout matches the budget we publish.
        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/rdap+json")
            .timeout(std::time::Duration::from_millis(self.max_timeout_ms()))
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
                // RDAP status values are human phrases ("client transfer
                // prohibited"); slugify so tags match the codebase's
                // whitespace-free convention.
                entity.tag(format!("status:{}", slugify(s)));
            }
        }
        // RDAP commonly carries multiple events with the same action
        // (e.g. two `transfer` events from successive registrar moves).
        // Group dates by action so each appears in evidence.
        let mut events_by_action: std::collections::BTreeMap<&str, Vec<&str>> =
            std::collections::BTreeMap::new();
        for e in &body.events {
            if let (Some(action), Some(date)) = (e.action.as_deref(), e.date.as_deref()) {
                events_by_action.entry(action).or_default().push(date);
            }
        }
        for (action, dates) in events_by_action {
            // Slugify the action so attr keys stay whitespace-free
            // (RDAP eventAction values like "last changed" and
            // "registrar expiration" contain spaces).
            ev = ev.with_attr(format!("event_{}", slugify(action)), dates.join(","));
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
        // Cap at the first 16; heavyweight TLDs / anycast registries can
        // list many NS plus glue records and we don't want one module
        // call to fan out into hundreds of entities.
        const MAX_NS: usize = 16;
        for n in body.nameservers.into_iter().take(MAX_NS) {
            let Some(name) = n.name else { continue };
            // Entity::new normalises EntityKind::Domain (trim, lowercase,
            // strip trailing dot) per src/core/entity.rs — no need to
            // pre-normalise here. We only guard the empty/whitespace
            // case which normalise() preserves as empty.
            if name.trim().is_empty() {
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

    #[test]
    fn priority_runs_after_whois() {
        // Whois (priority 32) is the canonical record holder; rdap fills
        // structured gaps after. Engine sorts highest-first.
        assert!(RdapDomain.priority() < 32);
    }

    #[test]
    fn slugify_collapses_whitespace_and_lowercases() {
        assert_eq!(
            slugify("client transfer prohibited"),
            "client-transfer-prohibited"
        );
        assert_eq!(slugify("Active"), "active");
        assert_eq!(slugify("a  b   c"), "a-b-c");
        assert_eq!(slugify("no-spaces"), "no-spaces");
        assert_eq!(slugify(""), "");
    }
}
