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
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use crate::util::http::urlencode;
use crate::util::str_util::slugify;

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

const SRC: &str = "rdap_domain";

/// One Domain entity per nameserver complements whois `whois-ns`. Cap at the
/// first 16; heavyweight TLDs / anycast registries can list many NS plus glue
/// records and we don't want one module call to fan out into hundreds.
const MAX_NS: usize = 16;

/// Build the primary `Domain` entity from an RDAP record. **Pure** (no
/// network/IO): slugifies the status phrases into `status:` tags, groups event
/// dates by action into `event_<action>` attributes (RDAP can repeat an action,
/// e.g. successive `transfer` events), surfaces the deduplicated contact *role*
/// names (never raw PII), the DNSSEC delegation state, and the nameserver list.
fn build_domain_entity(domain: &str, body: &RdapResp, scan_id: &str) -> Entity {
    use std::collections::{BTreeMap, BTreeSet};

    let mut entity = Entity::new(EntityKind::Domain, domain, 0.88, scan_id);
    entity.tag("rdap");
    let mut ev = Evidence::new(SRC, format!("RDAP record for {domain}"));

    if let Some(h) = body.handle.as_deref() {
        ev = ev.with_attr("handle", h);
    }
    if !body.status.is_empty() {
        ev = ev.with_attr("status", body.status.join(","));
        // RDAP status values are human phrases ("client transfer prohibited");
        // slugify so tags match the whitespace-free convention.
        body.status
            .iter()
            .for_each(|s| entity.tag(format!("status:{}", slugify(s))));
    }
    // RDAP commonly carries multiple events with the same action (e.g. two
    // `transfer` events from successive registrar moves). Group dates by action.
    let mut events_by_action: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for e in &body.events {
        if let (Some(action), Some(date)) = (e.action.as_deref(), e.date.as_deref()) {
            events_by_action.entry(action).or_default().push(date);
        }
    }
    for (action, dates) in events_by_action {
        // Slugify the action so attr keys stay whitespace-free (RDAP
        // eventAction values like "last changed" contain spaces).
        ev = ev.with_attr(format!("event_{}", slugify(action)), dates.join(","));
    }
    let roles: BTreeSet<&str> = body
        .entities
        .iter()
        .flat_map(|e| e.roles.iter().map(String::as_str))
        .collect();
    if !roles.is_empty() {
        ev = ev.with_attr(
            "contact_roles",
            roles
                .into_iter()
                .enumerate()
                .fold(String::new(), |mut acc, (i, s)| {
                    if i > 0 {
                        acc.push(',');
                    }
                    acc.push_str(s);
                    acc
                }),
        );
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
    entity
}

/// Build a `Domain` entity for one RDAP nameserver. **Pure** (no network/IO).
/// `Entity::new` normalises the domain (trim, lowercase, strip trailing dot), so
/// we only reject a blank/whitespace name here. Returns `None` for a blank name.
fn build_ns_entity(domain: &str, name: &str, scan_id: &str) -> Option<Entity> {
    if name.trim().is_empty() {
        return None;
    }
    let mut ns = Entity::new(EntityKind::Domain, name, 0.80, scan_id);
    ns.tag("rdap-ns");
    ns.tag("ns");
    ns.add_evidence(
        Evidence::new(SRC, format!("RDAP nameserver for {domain}")).with_attr("parent", domain),
    );
    Some(ns)
}

pub struct RdapDomain;

#[async_trait]
impl Module for RdapDomain {
    fn name(&self) -> &'static str {
        "rdap_domain"
    }

    fn description(&self) -> &'static str {
        "RDAP registry record lookup for domain registration data"
    }

    fn priority(&self) -> u8 {
        // One step below whois (32) so whois — the canonical record
        // holder — runs first; rdap fills structured gaps after.
        // (Engine sorts highest-priority-first.)
        31
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::Url)
    }

    fn max_timeout_ms(&self) -> u64 {
        // RDAP servers (IANA bootstrap + registrar endpoints) respond within
        // 4-6 s on healthy paths; 8 s provides margin and cuts the ceiling
        // from 15 s, freeing concurrency slots faster.
        8_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // RDAP registration data — ATT&CK WHOIS (T1596.002).
        &["T1596.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let domain = match target.kind {
            TargetKind::Url => match crate::util::url_util::host_from_url(&target.value) {
                Some(h) => h,
                None => return Ok(ModuleResult::new()),
            },
            _ => target.value.trim().to_string(),
        };
        let domain = domain.as_str();
        if domain.is_empty() {
            return Ok(ModuleResult::new());
        }

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
            .send_tagged(SRC)
            .await?;

        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
            return Err(crate::util::http::http_status_error(SRC, resp).await);
        }

        let body: RdapResp = crate::util::http::json_decode(SRC, resp).await?;

        let mut result = ModuleResult::new();
        result.push(build_domain_entity(domain, &body, &ctx.scan_id));

        result.extend(
            body.nameservers
                .iter()
                .take(MAX_NS)
                .filter_map(|n| build_ns_entity(domain, n.name.as_deref()?, &ctx.scan_id)),
        );

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
